"""Project analyzer for detecting languages, frameworks, and package managers."""

from pathlib import Path
from typing import List, Optional
import json
import re


class ProjectAnalyzer:
    """Analyzes a project to detect languages, frameworks, and package managers."""

    # File extensions to language mapping
    LANGUAGE_EXTENSIONS = {
        ".py": "python",
        ".js": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".jsx": "javascript",
        ".java": "java",
        ".kt": "kotlin",
        ".go": "go",
        ".rs": "rust",
        ".rb": "ruby",
        ".php": "php",
        ".swift": "swift",
        ".c": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".cs": "csharp",
        ".scala": "scala",
        ".m": "objective-c",
        ".mm": "objective-c",
    }

    # Marker files for languages
    LANGUAGE_MARKERS = {
        "python": ["pyproject.toml", "setup.py", "requirements.txt", "Pipfile", "setup.cfg"],
        "javascript": ["package.json"],
        "typescript": ["tsconfig.json"],
        "java": ["pom.xml", "build.gradle", "build.gradle.kts"],
        "kotlin": ["build.gradle.kts"],
        "go": ["go.mod"],
        "rust": ["Cargo.toml"],
        "ruby": ["Gemfile"],
        "php": ["composer.json"],
        "swift": ["Package.swift", "*.xcodeproj", "*.xcworkspace"],
        "csharp": ["*.csproj", "*.sln"],
        "scala": ["build.sbt"],
    }

    # Package manager marker files
    PACKAGE_MANAGER_MARKERS = {
        "pip": ["requirements.txt", "requirements-dev.txt"],
        "poetry": ["poetry.lock"],
        "pipenv": ["Pipfile", "Pipfile.lock"],
        "setuptools": ["setup.py", "setup.cfg"],
        "npm": ["package-lock.json"],
        "yarn": ["yarn.lock"],
        "pnpm": ["pnpm-lock.yaml"],
        "bun": ["bun.lockb"],
        "maven": ["pom.xml"],
        "gradle": ["build.gradle", "build.gradle.kts"],
        "cargo": ["Cargo.lock"],
        "bundler": ["Gemfile.lock"],
        "composer": ["composer.lock"],
        "go": ["go.sum"],
        "spm": ["Package.swift", "Package.resolved"],
        "cocoapods": ["Podfile", "Podfile.lock"],
        "carthage": ["Cartfile", "Cartfile.resolved"],
        "nuget": ["packages.config", "*.nuspec"],
    }

    # Config files to look for
    CONFIG_FILE_PATTERNS = [
        ".env", ".env.*",
        "docker-compose.yml", "docker-compose.yaml",
        "Dockerfile", "Dockerfile.*",
        ".dockerignore",
        "kubernetes.yml", "kubernetes.yaml",
        "k8s.yml", "k8s.yaml",
        ".gitlab-ci.yml",
        ".github/workflows/*.yml", ".github/workflows/*.yaml",
        "Jenkinsfile",
        ".travis.yml",
        "azure-pipelines.yml",
        "bitbucket-pipelines.yml",
        ".circleci/config.yml",
        "nginx.conf",
        "apache.conf", "httpd.conf",
        "webpack.config.js", "webpack.config.ts",
        "vite.config.js", "vite.config.ts",
        "rollup.config.js",
        ".eslintrc*", "eslint.config.*",
        ".prettierrc*",
        "tsconfig.json",
        "jest.config.*",
        "pytest.ini", "pyproject.toml", "setup.cfg",
        "tox.ini",
        ".flake8",
        "mypy.ini",
        ".babelrc", "babel.config.*",
        "serverless.yml", "serverless.yaml",
        "terraform.tf", "*.tf",
        "ansible.cfg", "playbook.yml",
    ]

    def __init__(self, path: str):
        self.path = Path(path).resolve()
        self._languages: List[str] = []
        self._frameworks: List[str] = []
        self._package_managers: List[str] = []
        self._config_files: List[str] = []
        self._has_git: bool = False
        self._analyzed: bool = False

    @property
    def languages(self) -> List[str]:
        """Get detected languages."""
        if not self._analyzed:
            self.analyze()
        return self._languages

    @property
    def frameworks(self) -> List[str]:
        """Get detected frameworks."""
        if not self._analyzed:
            self.analyze()
        return self._frameworks

    @property
    def package_managers(self) -> List[str]:
        """Get detected package managers."""
        if not self._analyzed:
            self.analyze()
        return self._package_managers

    @property
    def config_files(self) -> List[str]:
        """Get detected config files."""
        if not self._analyzed:
            self.analyze()
        return self._config_files

    @property
    def has_git(self) -> bool:
        """Check if project is a git repository."""
        if not self._analyzed:
            self.analyze()
        return self._has_git

    def analyze(self) -> dict:
        """Perform full project analysis."""
        self._has_git = self._detect_git()
        self._languages = self._detect_languages()
        self._package_managers = self._detect_package_managers()
        self._frameworks = self._detect_frameworks()
        self._config_files = self._detect_config_files()
        self._analyzed = True

        return {
            "languages": self._languages,
            "frameworks": self._frameworks,
            "package_managers": self._package_managers,
            "config_files": self._config_files,
            "has_git": self._has_git,
        }

    def _detect_git(self) -> bool:
        """Check if the project is a git repository."""
        return (self.path / ".git").exists()

    def _detect_languages(self) -> List[str]:
        """Detect programming languages used in the project."""
        languages = set()

        # Check marker files
        for lang, markers in self.LANGUAGE_MARKERS.items():
            for marker in markers:
                if "*" in marker:
                    if list(self.path.glob(marker)):
                        languages.add(lang)
                elif (self.path / marker).exists():
                    languages.add(lang)

        # Sample source files (limit depth to avoid performance issues)
        for ext, lang in self.LANGUAGE_EXTENSIONS.items():
            # Check top-level and one level deep
            if list(self.path.glob(f"*{ext}")) or list(self.path.glob(f"*/*{ext}")):
                languages.add(lang)

        return sorted(languages)

    def _detect_package_managers(self) -> List[str]:
        """Detect package managers used in the project."""
        managers = set()

        for manager, markers in self.PACKAGE_MANAGER_MARKERS.items():
            for marker in markers:
                if "*" in marker:
                    if list(self.path.glob(marker)):
                        managers.add(manager)
                elif (self.path / marker).exists():
                    managers.add(manager)

        # Check pyproject.toml for poetry
        pyproject = self.path / "pyproject.toml"
        if pyproject.exists():
            try:
                content = pyproject.read_text()
                if "[tool.poetry]" in content:
                    managers.add("poetry")
                if "[build-system]" in content:
                    managers.add("setuptools")
            except (IOError, UnicodeDecodeError):
                pass

        return sorted(managers)

    def _detect_frameworks(self) -> List[str]:
        """Detect frameworks used in the project."""
        frameworks = set()

        # Check package.json for JS/TS frameworks
        package_json = self.path / "package.json"
        if package_json.exists():
            frameworks.update(self._detect_js_frameworks(package_json))

        # Check Python dependency files for frameworks
        frameworks.update(self._detect_python_frameworks())

        # Check for Swift frameworks
        frameworks.update(self._detect_swift_frameworks())

        # Check for Java frameworks
        frameworks.update(self._detect_java_frameworks())

        # Check for Ruby frameworks
        frameworks.update(self._detect_ruby_frameworks())

        return sorted(frameworks)

    def _detect_js_frameworks(self, package_json: Path) -> List[str]:
        """Detect JavaScript/TypeScript frameworks from package.json."""
        frameworks = []
        try:
            data = json.loads(package_json.read_text())
            all_deps = {}
            all_deps.update(data.get("dependencies", {}))
            all_deps.update(data.get("devDependencies", {}))

            framework_packages = {
                "react": "react",
                "next": "nextjs",
                "vue": "vue",
                "nuxt": "nuxt",
                "@angular/core": "angular",
                "svelte": "svelte",
                "express": "express",
                "fastify": "fastify",
                "koa": "koa",
                "hapi": "hapi",
                "@hapi/hapi": "hapi",
                "nestjs": "nestjs",
                "@nestjs/core": "nestjs",
                "gatsby": "gatsby",
                "remix": "remix",
                "@remix-run/react": "remix",
                "electron": "electron",
                "react-native": "react-native",
                "expo": "expo",
            }

            for pkg, framework in framework_packages.items():
                if pkg in all_deps:
                    frameworks.append(framework)
        except (json.JSONDecodeError, IOError):
            pass
        return frameworks

    def _detect_python_frameworks(self) -> List[str]:
        """Detect Python frameworks from requirements or pyproject."""
        frameworks = []
        framework_packages = {
            "django": "django",
            "flask": "flask",
            "fastapi": "fastapi",
            "starlette": "starlette",
            "tornado": "tornado",
            "pyramid": "pyramid",
            "bottle": "bottle",
            "aiohttp": "aiohttp",
            "sanic": "sanic",
            "falcon": "falcon",
            "cherrypy": "cherrypy",
            "streamlit": "streamlit",
            "gradio": "gradio",
        }

        # Check requirements files
        req_files = list(self.path.glob("requirements*.txt"))
        for req_file in req_files:
            try:
                content = req_file.read_text().lower()
                for pkg, framework in framework_packages.items():
                    if re.search(rf"^{pkg}[=<>~\[]", content, re.MULTILINE):
                        frameworks.append(framework)
            except (IOError, UnicodeDecodeError):
                pass

        # Check pyproject.toml
        pyproject = self.path / "pyproject.toml"
        if pyproject.exists():
            try:
                content = pyproject.read_text().lower()
                for pkg, framework in framework_packages.items():
                    if f'"{pkg}"' in content or f"'{pkg}'" in content:
                        frameworks.append(framework)
            except (IOError, UnicodeDecodeError):
                pass

        return frameworks

    def _detect_swift_frameworks(self) -> List[str]:
        """Detect Swift/iOS frameworks."""
        frameworks = []

        # Check Package.swift
        package_swift = self.path / "Package.swift"
        if package_swift.exists():
            try:
                content = package_swift.read_text()
                if "SwiftUI" in content:
                    frameworks.append("swiftui")
                if "Vapor" in content:
                    frameworks.append("vapor")
            except (IOError, UnicodeDecodeError):
                pass

        # Check for Xcode project with SwiftUI
        for xcodeproj in self.path.glob("*.xcodeproj"):
            frameworks.append("uikit")  # Default assumption for Xcode projects
            break

        return frameworks

    def _detect_java_frameworks(self) -> List[str]:
        """Detect Java/Kotlin frameworks."""
        frameworks = []

        # Check pom.xml
        pom = self.path / "pom.xml"
        if pom.exists():
            try:
                content = pom.read_text()
                if "spring-boot" in content or "spring-framework" in content:
                    frameworks.append("spring")
                if "quarkus" in content:
                    frameworks.append("quarkus")
                if "micronaut" in content:
                    frameworks.append("micronaut")
            except (IOError, UnicodeDecodeError):
                pass

        # Check build.gradle
        for gradle_file in ["build.gradle", "build.gradle.kts"]:
            gradle = self.path / gradle_file
            if gradle.exists():
                try:
                    content = gradle.read_text()
                    if "spring" in content.lower():
                        frameworks.append("spring")
                    if "android" in content.lower():
                        frameworks.append("android")
                    if "ktor" in content.lower():
                        frameworks.append("ktor")
                except (IOError, UnicodeDecodeError):
                    pass

        return frameworks

    def _detect_ruby_frameworks(self) -> List[str]:
        """Detect Ruby frameworks."""
        frameworks = []

        gemfile = self.path / "Gemfile"
        if gemfile.exists():
            try:
                content = gemfile.read_text()
                if "'rails'" in content or '"rails"' in content:
                    frameworks.append("rails")
                if "'sinatra'" in content or '"sinatra"' in content:
                    frameworks.append("sinatra")
                if "'hanami'" in content or '"hanami"' in content:
                    frameworks.append("hanami")
            except (IOError, UnicodeDecodeError):
                pass

        return frameworks

    def _detect_config_files(self) -> List[str]:
        """Detect configuration files in the project."""
        config_files = []

        for pattern in self.CONFIG_FILE_PATTERNS:
            if "*" in pattern:
                for match in self.path.glob(pattern):
                    rel_path = str(match.relative_to(self.path))
                    config_files.append(rel_path)
            else:
                file_path = self.path / pattern
                if file_path.exists():
                    config_files.append(pattern)

        return sorted(set(config_files))
