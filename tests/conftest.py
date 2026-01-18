"""Pytest configuration and shared fixtures."""

import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def examples_dir():
    """Return path to examples directory."""
    return Path(__file__).parent.parent / "examples"


@pytest.fixture
def vulnerable_python_dir(examples_dir):
    """Return path to vulnerable Python example."""
    return examples_dir / "vulnerable-python"


@pytest.fixture
def vulnerable_node_dir(examples_dir):
    """Return path to vulnerable Node.js example."""
    return examples_dir / "vulnerable-node"


@pytest.fixture
def vulnerable_ios_dir(examples_dir):
    """Return path to vulnerable iOS example."""
    return examples_dir / "vulnerable-ios"


@pytest.fixture
def temp_project_dir():
    """Create a temporary project directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def python_project(temp_project_dir):
    """Create a minimal Python project."""
    # Create requirements.txt
    (temp_project_dir / "requirements.txt").write_text("flask==2.0.0\n")
    # Create a Python file
    (temp_project_dir / "app.py").write_text("print('hello')\n")
    return temp_project_dir


@pytest.fixture
def node_project(temp_project_dir):
    """Create a minimal Node.js project."""
    package_json = """{
  "name": "test-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0"
  }
}"""
    (temp_project_dir / "package.json").write_text(package_json)
    (temp_project_dir / "index.js").write_text("console.log('hello');\n")
    return temp_project_dir


@pytest.fixture
def ios_project(temp_project_dir):
    """Create a minimal iOS project."""
    info_plist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>TestApp</string>
</dict>
</plist>"""
    (temp_project_dir / "Info.plist").write_text(info_plist)
    (temp_project_dir / "App.swift").write_text("import Foundation\n")
    return temp_project_dir


@pytest.fixture
def multi_language_project(temp_project_dir):
    """Create a project with multiple languages."""
    # Python
    (temp_project_dir / "requirements.txt").write_text("flask==2.0.0\n")
    (temp_project_dir / "backend.py").write_text("print('hello')\n")

    # Node.js
    (temp_project_dir / "package.json").write_text('{"name": "test", "dependencies": {}}\n')
    (temp_project_dir / "frontend.js").write_text("console.log('hello');\n")

    # TypeScript
    (temp_project_dir / "app.ts").write_text("const x: string = 'hello';\n")

    return temp_project_dir
