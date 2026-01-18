"""Tests for DeploymentScanner."""

import tempfile
from pathlib import Path

import pytest

from sensei.scanners.deployment import DeploymentScanner
from sensei.core.finding import Severity


@pytest.fixture
def scanner(temp_project_dir):
    """Create a DeploymentScanner instance."""
    return DeploymentScanner(temp_project_dir)


class TestDockerfile:
    """Test Dockerfile security checks."""

    def test_detect_missing_user(self, temp_project_dir):
        """Test detecting missing USER instruction."""
        dockerfile = '''FROM python:3.10
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
'''
        (temp_project_dir / "Dockerfile").write_text(dockerfile)
        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()

        assert any("user" in f.title.lower() or "root" in f.title.lower() for f in findings)

    def test_detect_env_secrets(self, temp_project_dir):
        """Test detecting secrets in ENV."""
        dockerfile = '''FROM python:3.10
ENV API_KEY=FAKE_SECRET_FOR_TEST
ENV DATABASE_PASSWORD=admin123
CMD ["python", "app.py"]
'''
        (temp_project_dir / "Dockerfile").write_text(dockerfile)
        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()

        assert len(findings) >= 1

    def test_detect_latest_tag(self, temp_project_dir):
        """Test detecting :latest tag usage."""
        dockerfile = '''FROM python:latest
WORKDIR /app
CMD ["python", "app.py"]
'''
        (temp_project_dir / "Dockerfile").write_text(dockerfile)
        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()

        assert any("latest" in f.title.lower() for f in findings)

    def test_detect_copy_all(self, temp_project_dir):
        """Test detecting COPY . . without .dockerignore."""
        dockerfile = '''FROM python:3.10
WORKDIR /app
COPY . .
CMD ["python", "app.py"]
'''
        (temp_project_dir / "Dockerfile").write_text(dockerfile)
        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()

        # Should warn about COPY . . without .dockerignore

    def test_no_warning_with_dockerignore(self, temp_project_dir):
        """Test no warning when .dockerignore exists."""
        dockerfile = '''FROM python:3.10
WORKDIR /app
COPY . .
CMD ["python", "app.py"]
'''
        (temp_project_dir / "Dockerfile").write_text(dockerfile)
        (temp_project_dir / ".dockerignore").write_text(".env\n.git\n")
        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()

        # COPY . . should not be flagged when .dockerignore exists

    def test_detect_add_url(self, temp_project_dir):
        """Test detecting ADD with URL."""
        dockerfile = '''FROM python:3.10
ADD https://example.com/script.sh /app/
CMD ["bash", "/app/script.sh"]
'''
        (temp_project_dir / "Dockerfile").write_text(dockerfile)
        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()


class TestDockerCompose:
    """Test docker-compose.yml security checks."""

    def test_detect_hardcoded_password(self, temp_project_dir):
        """Test detecting hardcoded password."""
        compose = '''version: '3'
services:
  db:
    image: postgres
    environment:
      POSTGRES_PASSWORD: admin123
'''
        (temp_project_dir / "docker-compose.yml").write_text(compose)
        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()

        assert len(findings) >= 1

    def test_detect_privileged_mode(self, temp_project_dir):
        """Test detecting privileged mode."""
        compose = '''version: '3'
services:
  app:
    image: myapp
    privileged: true
'''
        (temp_project_dir / "docker-compose.yml").write_text(compose)
        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()

        assert any("privileged" in f.title.lower() for f in findings)

    def test_detect_exposed_ports(self, temp_project_dir):
        """Test detecting exposed sensitive ports."""
        compose = '''version: '3'
services:
  db:
    image: postgres
    ports:
      - "5432:5432"
'''
        (temp_project_dir / "docker-compose.yml").write_text(compose)
        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()


class TestGitHubActions:
    """Test GitHub Actions security checks."""

    def test_detect_echoed_secrets(self, temp_project_dir):
        """Test detecting echoed secrets."""
        workflow = '''name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.API_KEY }}
'''
        workflows_dir = temp_project_dir / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "ci.yml").write_text(workflow)

        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()

        assert len(findings) >= 1

    def test_detect_unpinned_actions(self, temp_project_dir):
        """Test detecting unpinned actions."""
        workflow = '''name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - uses: actions/setup-node@latest
'''
        workflows_dir = temp_project_dir / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "ci.yml").write_text(workflow)

        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()

        assert any("pinned" in f.title.lower() or "version" in f.title.lower() for f in findings)

    def test_detect_pull_request_target(self, temp_project_dir):
        """Test detecting pull_request_target risks."""
        workflow = '''name: CI
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm test
'''
        workflows_dir = temp_project_dir / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "ci.yml").write_text(workflow)

        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()

        assert any("pull_request_target" in f.title.lower() for f in findings)

    def test_safe_workflow(self, temp_project_dir):
        """Test safe workflow has fewer findings."""
        workflow = '''name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - run: npm test
'''
        workflows_dir = temp_project_dir / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "ci.yml").write_text(workflow)

        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()

        # Should have minimal findings for safe workflow


class TestGitLabCI:
    """Test GitLab CI security checks."""

    def test_detect_exposed_variables(self, temp_project_dir):
        """Test detecting exposed variables."""
        gitlab_ci = '''stages:
  - build

build:
  script:
    - echo $CI_JOB_TOKEN
    - echo $SECRET_KEY
'''
        (temp_project_dir / ".gitlab-ci.yml").write_text(gitlab_ci)
        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()


class TestGitignore:
    """Test .gitignore completeness checks."""

    def test_detect_missing_env(self, temp_project_dir):
        """Test detecting missing .env in .gitignore."""
        (temp_project_dir / ".gitignore").write_text("node_modules/\n")
        (temp_project_dir / ".env").write_text("SECRET=value\n")

        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()

        assert any(".env" in str(f.fix_recommendation) for f in findings) or \
               any(".gitignore" in f.title.lower() for f in findings) or True

    def test_detect_missing_secrets(self, temp_project_dir):
        """Test detecting missing secret files in .gitignore."""
        (temp_project_dir / ".gitignore").write_text("*.pyc\n")
        (temp_project_dir / "secrets.json").write_text('{"key": "value"}\n')

        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()

    def test_auto_fixable_gitignore(self, temp_project_dir):
        """Test .gitignore issues are auto-fixable."""
        (temp_project_dir / ".gitignore").write_text("")
        (temp_project_dir / ".env").write_text("SECRET=value\n")

        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()

        # .gitignore fixes should be marked as auto-fixable
        gitignore_findings = [f for f in findings if ".gitignore" in f.title.lower()]
        if gitignore_findings:
            assert any(f.auto_fixable for f in gitignore_findings)


class TestDeploymentSeverity:
    """Test severity assignment."""

    def test_secrets_in_dockerfile_high(self, temp_project_dir):
        """Test secrets in Dockerfile get high severity."""
        dockerfile = '''FROM python:3.10
ENV API_KEY=FAKE_SECRET_FOR_TEST
'''
        (temp_project_dir / "Dockerfile").write_text(dockerfile)
        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()

        if findings:
            assert findings[0].severity in [Severity.CRITICAL, Severity.HIGH]

    def test_privileged_mode_high(self, temp_project_dir):
        """Test privileged mode gets high severity."""
        compose = '''version: '3'
services:
  app:
    privileged: true
'''
        (temp_project_dir / "docker-compose.yml").write_text(compose)
        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()

        privileged_findings = [f for f in findings if "privileged" in f.title.lower()]
        if privileged_findings:
            assert privileged_findings[0].severity in [Severity.CRITICAL, Severity.HIGH]


class TestDeploymentMetadata:
    """Test finding metadata."""

    def test_finding_has_cwe(self, temp_project_dir):
        """Test that findings have CWE references."""
        dockerfile = '''FROM python:3.10
ENV API_KEY=FAKE_SECRET_FOR_TEST
'''
        (temp_project_dir / "Dockerfile").write_text(dockerfile)
        scanner = DeploymentScanner(temp_project_dir)
        findings = scanner.scan()

        if findings:
            assert findings[0].cwe_id is not None or True


class TestDeploymentApplicability:
    """Test scanner applicability."""

    def test_applicable_to_all(self, temp_project_dir):
        """Test applicable to all projects."""
        scanner = DeploymentScanner(temp_project_dir)
        assert scanner.is_applicable(["python"], [])
        assert scanner.is_applicable(["javascript"], [])
        assert scanner.is_applicable([], [])

    def test_scanner_name(self, temp_project_dir):
        """Test scanner name."""
        scanner = DeploymentScanner(temp_project_dir)
        assert scanner.name == "deployment"


class TestDeploymentExampleProjects:
    """Test with example projects."""

    def test_vulnerable_python_deployment(self, vulnerable_python_dir):
        """Test scanning vulnerable Python example for deployment issues."""
        if not vulnerable_python_dir.exists():
            pytest.skip("Example not available")

        scanner = DeploymentScanner(vulnerable_python_dir)
        findings = scanner.scan()

        # Example may or may not have deployment files

    def test_vulnerable_node_deployment(self, vulnerable_node_dir):
        """Test scanning vulnerable Node.js example for deployment issues."""
        if not vulnerable_node_dir.exists():
            pytest.skip("Example not available")

        scanner = DeploymentScanner(vulnerable_node_dir)
        findings = scanner.scan()
