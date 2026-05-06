"""Shared project configuration paths."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
PACKAGES_DIR = ARTIFACTS_DIR / "packages"
EXTRACTED_DIR = ARTIFACTS_DIR / "extracted"
BASELINE_DIR = ARTIFACTS_DIR / "baseline"
BINDIFF_DIR = ARTIFACTS_DIR / "bindiff"
