"""The version is defined once (pyproject.toml); every place that reports it must agree."""

import re
import shutil
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

import pytest
from click.testing import CliRunner

import poam_generator
from poam_generator.cli import cli

ROOT = Path(__file__).resolve().parents[1]


def _pyproject_version() -> str:
    if sys.version_info >= (3, 11):
        import tomllib

        return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    return re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)


def test_dunder_version_matches_installed_metadata():
    assert poam_generator.__version__ == version("poam-generator")


def test_installed_metadata_matches_pyproject():
    # Catches a stale editable install after the version in pyproject.toml changes.
    assert version("poam-generator") == _pyproject_version()


def test_cli_version_option_matches():
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"poam, version {poam_generator.__version__}"


@pytest.mark.skipif(shutil.which("poam") is None, reason="the poam console script is not installed")
def test_poam_console_script_version_matches():
    out = subprocess.run(["poam", "--version"], capture_output=True, text=True, check=True).stdout
    assert out.strip() == f"poam, version {poam_generator.__version__}"


def test_no_hardcoded_version_strings_in_source():
    pattern = re.compile(r"\b\d+\.\d+\.\d+\b")
    for path in (ROOT / "src" / "poam_generator").glob("*.py"):
        for line in path.read_text(encoding="utf-8").splitlines():
            if "version" in line.lower() and "OSCAL_VERSION" not in line and "oscal-version" not in line:
                assert not pattern.search(line), f"{path.name}: {line.strip()}"
