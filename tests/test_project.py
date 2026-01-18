"""Tests for ProjectAnalyzer."""

import json
import tempfile
from pathlib import Path

import pytest

from sensei.core.project import ProjectAnalyzer


class TestProjectAnalyzerPython:
    """Tests for Python project detection."""

    def test_detect_python_from_requirements(self, temp_project_dir):
        """Test detecting Python from requirements.txt."""
        (temp_project_dir / "requirements.txt").write_text("flask==2.0.0\n")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "python" in result["languages"]
        assert "pip" in result["package_managers"]

    def test_detect_python_from_pyproject(self, temp_project_dir):
        """Test detecting Python from pyproject.toml."""
        pyproject = """[build-system]
requires = ["setuptools"]

[project]
name = "test"
"""
        (temp_project_dir / "pyproject.toml").write_text(pyproject)

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "python" in result["languages"]
        assert "setuptools" in result["package_managers"]

    def test_detect_python_from_py_files(self, temp_project_dir):
        """Test detecting Python from .py files."""
        (temp_project_dir / "app.py").write_text("print('hello')\n")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "python" in result["languages"]

    def test_detect_poetry(self, temp_project_dir):
        """Test detecting Poetry package manager."""
        pyproject = """[tool.poetry]
name = "test"
version = "0.1.0"
"""
        (temp_project_dir / "pyproject.toml").write_text(pyproject)
        (temp_project_dir / "poetry.lock").write_text("")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "poetry" in result["package_managers"]

    def test_detect_pipenv(self, temp_project_dir):
        """Test detecting Pipenv package manager."""
        (temp_project_dir / "Pipfile").write_text("[packages]\n")
        (temp_project_dir / "Pipfile.lock").write_text("{}")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "pipenv" in result["package_managers"]

    def test_detect_flask_framework(self, temp_project_dir):
        """Test detecting Flask framework."""
        (temp_project_dir / "requirements.txt").write_text("flask==2.0.0\n")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "flask" in result["frameworks"]

    def test_detect_django_framework(self, temp_project_dir):
        """Test detecting Django framework."""
        (temp_project_dir / "requirements.txt").write_text("django>=4.0\n")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "django" in result["frameworks"]

    def test_detect_fastapi_framework(self, temp_project_dir):
        """Test detecting FastAPI framework."""
        (temp_project_dir / "requirements.txt").write_text("fastapi[all]\n")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "fastapi" in result["frameworks"]


class TestProjectAnalyzerNode:
    """Tests for Node.js project detection."""

    def test_detect_node_from_package_json(self, temp_project_dir):
        """Test detecting Node.js from package.json."""
        package_json = '{"name": "test", "dependencies": {}}'
        (temp_project_dir / "package.json").write_text(package_json)

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "javascript" in result["languages"]

    def test_detect_npm(self, temp_project_dir):
        """Test detecting npm package manager."""
        (temp_project_dir / "package.json").write_text('{"name": "test"}')
        (temp_project_dir / "package-lock.json").write_text("{}")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "npm" in result["package_managers"]

    def test_detect_yarn(self, temp_project_dir):
        """Test detecting Yarn package manager."""
        (temp_project_dir / "package.json").write_text('{"name": "test"}')
        (temp_project_dir / "yarn.lock").write_text("")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "yarn" in result["package_managers"]

    def test_detect_pnpm(self, temp_project_dir):
        """Test detecting pnpm package manager."""
        (temp_project_dir / "package.json").write_text('{"name": "test"}')
        (temp_project_dir / "pnpm-lock.yaml").write_text("")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "pnpm" in result["package_managers"]

    def test_detect_typescript(self, temp_project_dir):
        """Test detecting TypeScript."""
        (temp_project_dir / "tsconfig.json").write_text("{}")
        (temp_project_dir / "app.ts").write_text("const x: string = 'hello';\n")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "typescript" in result["languages"]

    def test_detect_react_framework(self, temp_project_dir):
        """Test detecting React framework."""
        package_json = json.dumps({
            "name": "test",
            "dependencies": {"react": "^18.0.0"}
        })
        (temp_project_dir / "package.json").write_text(package_json)

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "react" in result["frameworks"]

    def test_detect_vue_framework(self, temp_project_dir):
        """Test detecting Vue framework."""
        package_json = json.dumps({
            "name": "test",
            "dependencies": {"vue": "^3.0.0"}
        })
        (temp_project_dir / "package.json").write_text(package_json)

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "vue" in result["frameworks"]

    def test_detect_express_framework(self, temp_project_dir):
        """Test detecting Express framework."""
        package_json = json.dumps({
            "name": "test",
            "dependencies": {"express": "^4.18.0"}
        })
        (temp_project_dir / "package.json").write_text(package_json)

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "express" in result["frameworks"]

    def test_detect_nextjs_framework(self, temp_project_dir):
        """Test detecting Next.js framework."""
        package_json = json.dumps({
            "name": "test",
            "dependencies": {"next": "^13.0.0", "react": "^18.0.0"}
        })
        (temp_project_dir / "package.json").write_text(package_json)

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "nextjs" in result["frameworks"]
        assert "react" in result["frameworks"]


class TestProjectAnalyzerIOS:
    """Tests for iOS project detection."""

    def test_detect_swift_from_package_swift(self, temp_project_dir):
        """Test detecting Swift from Package.swift."""
        (temp_project_dir / "Package.swift").write_text("// swift-tools-version:5.5\n")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "swift" in result["languages"]
        assert "spm" in result["package_managers"]

    def test_detect_swift_from_swift_files(self, temp_project_dir):
        """Test detecting Swift from .swift files."""
        (temp_project_dir / "App.swift").write_text("import Foundation\n")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "swift" in result["languages"]

    def test_detect_swiftui_framework(self, temp_project_dir):
        """Test detecting SwiftUI framework."""
        package_swift = """// swift-tools-version:5.5
import PackageDescription
// Uses SwiftUI
"""
        (temp_project_dir / "Package.swift").write_text(package_swift)

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "swiftui" in result["frameworks"]

    def test_detect_cocoapods(self, temp_project_dir):
        """Test detecting CocoaPods."""
        (temp_project_dir / "Podfile").write_text("platform :ios, '14.0'\n")
        (temp_project_dir / "Podfile.lock").write_text("")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "cocoapods" in result["package_managers"]

    def test_detect_objective_c(self, temp_project_dir):
        """Test detecting Objective-C."""
        (temp_project_dir / "AppDelegate.m").write_text("#import <Foundation/Foundation.h>\n")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "objective-c" in result["languages"]


class TestProjectAnalyzerMultiLanguage:
    """Tests for multi-language project detection."""

    def test_detect_multiple_languages(self, multi_language_project):
        """Test detecting multiple languages."""
        analyzer = ProjectAnalyzer(str(multi_language_project))
        result = analyzer.analyze()

        assert "python" in result["languages"]
        assert "javascript" in result["languages"]
        assert "typescript" in result["languages"]

    def test_detect_multiple_package_managers(self, temp_project_dir):
        """Test detecting multiple package managers."""
        (temp_project_dir / "requirements.txt").write_text("flask\n")
        (temp_project_dir / "package.json").write_text('{"name": "test"}')
        (temp_project_dir / "package-lock.json").write_text("{}")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "pip" in result["package_managers"]
        assert "npm" in result["package_managers"]


class TestProjectAnalyzerConfigFiles:
    """Tests for config file detection."""

    def test_detect_env_file(self, temp_project_dir):
        """Test detecting .env file."""
        (temp_project_dir / ".env").write_text("KEY=value\n")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert ".env" in result["config_files"]

    def test_detect_dockerfile(self, temp_project_dir):
        """Test detecting Dockerfile."""
        (temp_project_dir / "Dockerfile").write_text("FROM python:3.10\n")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "Dockerfile" in result["config_files"]

    def test_detect_docker_compose(self, temp_project_dir):
        """Test detecting docker-compose.yml."""
        (temp_project_dir / "docker-compose.yml").write_text("version: '3'\n")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert "docker-compose.yml" in result["config_files"]

    def test_detect_github_workflow(self, temp_project_dir):
        """Test detecting GitHub Actions workflow."""
        workflows_dir = temp_project_dir / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "ci.yml").write_text("name: CI\n")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        # Check for workflow file (handle Windows vs Unix path separators)
        config_files = result["config_files"]
        assert any("ci.yml" in f and "workflows" in f for f in config_files)


class TestProjectAnalyzerGit:
    """Tests for git detection."""

    def test_detect_git_repo(self, temp_project_dir):
        """Test detecting git repository."""
        (temp_project_dir / ".git").mkdir()

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert result["has_git"] is True

    def test_no_git_repo(self, temp_project_dir):
        """Test no git repository."""
        analyzer = ProjectAnalyzer(str(temp_project_dir))
        result = analyzer.analyze()

        assert result["has_git"] is False


class TestProjectAnalyzerProperties:
    """Tests for analyzer properties."""

    def test_languages_property(self, python_project):
        """Test languages property."""
        analyzer = ProjectAnalyzer(str(python_project))
        # Access property before analyze()
        languages = analyzer.languages

        assert "python" in languages

    def test_frameworks_property(self, python_project):
        """Test frameworks property."""
        analyzer = ProjectAnalyzer(str(python_project))
        frameworks = analyzer.frameworks

        # Flask should be detected from requirements.txt
        assert "flask" in frameworks

    def test_package_managers_property(self, python_project):
        """Test package_managers property."""
        analyzer = ProjectAnalyzer(str(python_project))
        managers = analyzer.package_managers

        assert "pip" in managers

    def test_config_files_property(self, temp_project_dir):
        """Test config_files property."""
        (temp_project_dir / ".env").write_text("KEY=value\n")

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        config_files = analyzer.config_files

        assert ".env" in config_files

    def test_has_git_property(self, temp_project_dir):
        """Test has_git property."""
        (temp_project_dir / ".git").mkdir()

        analyzer = ProjectAnalyzer(str(temp_project_dir))
        assert analyzer.has_git is True


class TestProjectAnalyzerExamples:
    """Tests using example projects."""

    def test_vulnerable_python_example(self, vulnerable_python_dir):
        """Test analyzing vulnerable Python example."""
        if not vulnerable_python_dir.exists():
            pytest.skip("Example not available")

        analyzer = ProjectAnalyzer(str(vulnerable_python_dir))
        result = analyzer.analyze()

        assert "python" in result["languages"]
        assert "pip" in result["package_managers"]

    def test_vulnerable_node_example(self, vulnerable_node_dir):
        """Test analyzing vulnerable Node.js example."""
        if not vulnerable_node_dir.exists():
            pytest.skip("Example not available")

        analyzer = ProjectAnalyzer(str(vulnerable_node_dir))
        result = analyzer.analyze()

        assert "javascript" in result["languages"]

    def test_vulnerable_ios_example(self, vulnerable_ios_dir):
        """Test analyzing vulnerable iOS example."""
        if not vulnerable_ios_dir.exists():
            pytest.skip("Example not available")

        analyzer = ProjectAnalyzer(str(vulnerable_ios_dir))
        result = analyzer.analyze()

        assert "swift" in result["languages"]
        assert "spm" in result["package_managers"]
