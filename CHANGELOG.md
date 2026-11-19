# Changelog

## 0.6.1 (2026-11-18)

### Fixed

- `poam_generator.__version__` reported 0.2.0 while the package and `poam --version`
  reported 0.6.0. The version is now set only in `pyproject.toml`; `__version__`, the
  CLI's `--version` and the dashboard sidebar all read it from the installed package
  metadata. Because OSCAL exports put `__version__` in `metadata.version`, they now
  show the real version too.
- Added `tests/test_version.py`, which fails if `__version__`, the package metadata,
  `pyproject.toml` and `poam --version` disagree, or if a version number is hardcoded
  in the source again.
