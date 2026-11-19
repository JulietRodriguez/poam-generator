"""POAM Generator — FedRAMP/FISMA Plan of Action & Milestones CLI tool."""

from importlib.metadata import PackageNotFoundError, version

# The version is set in one place, pyproject.toml, and read here from the installed
# package's metadata, so the code, the CLI and the package can't disagree.
try:
    __version__ = version("poam-generator")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0+unknown"
