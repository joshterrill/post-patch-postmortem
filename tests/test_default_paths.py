from ppp.bindiff_client import DEFAULT_BASELINE_DIR as BINDIFF_BASELINE_DIR
from ppp.bindiff_client import DEFAULT_BINDIFF_DIR, DEFAULT_EXTRACTED_DIR as BINDIFF_EXTRACTED_DIR
from ppp.catalog_client import DEFAULT_DOWNLOAD_DIR
from ppp.config import (
    ARTIFACTS_DIR,
    BASELINE_DIR,
    BINDIFF_DIR,
    EXTRACTED_DIR,
    PACKAGES_DIR,
    PROJECT_ROOT,
)
from ppp.extractor import DEFAULT_EXTRACTED_DIR, DEFAULT_PACKAGES_DIR
from ppp.winbindex_client import DEFAULT_BASELINE_DIR


def test_config_paths_use_artifacts_root() -> None:
    paths = [
        ARTIFACTS_DIR,
        PACKAGES_DIR,
        EXTRACTED_DIR,
        BASELINE_DIR,
        BINDIFF_DIR,
    ]

    assert ARTIFACTS_DIR == PROJECT_ROOT / "artifacts"
    for path in paths:
        assert "artifacts" in path.parts
        assert "downloads" not in path.parts


def test_legacy_default_path_aliases_use_shared_config() -> None:
    assert DEFAULT_DOWNLOAD_DIR == PACKAGES_DIR
    assert DEFAULT_PACKAGES_DIR == PACKAGES_DIR
    assert DEFAULT_EXTRACTED_DIR == EXTRACTED_DIR
    assert BINDIFF_EXTRACTED_DIR == EXTRACTED_DIR
    assert BINDIFF_BASELINE_DIR == BASELINE_DIR
    assert DEFAULT_BINDIFF_DIR == BINDIFF_DIR
    assert DEFAULT_BASELINE_DIR == BASELINE_DIR
