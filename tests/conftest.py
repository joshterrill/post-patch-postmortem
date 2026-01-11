"""Pytest fixtures for Patch Tuesday Analyzer tests."""

import tempfile
from datetime import datetime
from pathlib import Path
from typing import Generator

import pytest
from sqlite_utils import Database

from patch_tuesday.database import init_db, get_db
from patch_tuesday.models import (
    Architecture,
    CatalogEntry,
    CVE,
    DownloadedFile,
    Patch,
    Product,
    Severity,
    WinBIndexFile,
)


@pytest.fixture
def temp_db_path(tmp_path: Path) -> Path:
    """Create a temporary database path."""
    return tmp_path / "test_patches.db"


@pytest.fixture
def initialized_db(temp_db_path: Path) -> Generator[Database, None, None]:
    """Create an initialized temporary database."""
    init_db(temp_db_path)
    db = Database(temp_db_path)
    yield db
    db.close()


@pytest.fixture
def sample_product() -> Product:
    """Create a sample Product for testing."""
    return Product(
        product_id="11926",
        name="Windows 11 Version 23H2 for x64-based Systems",
        version="23H2",
    )


@pytest.fixture
def sample_product_2() -> Product:
    """Create another sample Product for testing."""
    return Product(
        product_id="11927",
        name="Windows 10 Version 22H2 for x64-based Systems",
        version="22H2",
    )


@pytest.fixture
def sample_cve() -> CVE:
    """Create a sample CVE for testing."""
    return CVE(
        cve_id="CVE-2024-12345",
        title="Windows Kernel Elevation of Privilege Vulnerability",
        severity=Severity.CRITICAL,
        description="A privilege escalation vulnerability exists in Windows Kernel.",
        impact="Elevation of Privilege",
    )


@pytest.fixture
def sample_cve_2() -> CVE:
    """Create another sample CVE for testing."""
    return CVE(
        cve_id="CVE-2024-12346",
        title="Windows Remote Desktop Services RCE Vulnerability",
        severity=Severity.IMPORTANT,
        description="A remote code execution vulnerability exists in RDS.",
        impact="Remote Code Execution",
    )


@pytest.fixture
def sample_patch() -> Patch:
    """Create a sample Patch for testing."""
    return Patch(
        kb_number="KB5034441",
        title="2024-01 Cumulative Update for Windows 11",
        release_date=datetime(2024, 1, 9, 10, 0, 0),
        description="This update includes security improvements.",
        severity=Severity.CRITICAL,
    )


@pytest.fixture
def sample_patch_2() -> Patch:
    """Create another sample Patch for testing."""
    return Patch(
        kb_number="KB5034442",
        title="2024-01 Cumulative Update for Windows 10",
        release_date=datetime(2024, 1, 9, 10, 0, 0),
        description="This update includes quality improvements.",
        severity=Severity.IMPORTANT,
    )


@pytest.fixture
def sample_downloaded_file() -> DownloadedFile:
    """Create a sample DownloadedFile for testing."""
    return DownloadedFile(
        kb_number="KB5034441",
        filename="ntdll.dll",
        file_path="/downloads/extracted/KB5034441/x64/ntdll.dll",
        file_type="extracted",
        architecture=Architecture.X64,
        version="10.0.22621.3007",
        sha256="abc123def456",
        downloaded_at=datetime(2024, 1, 10, 12, 0, 0),
    )


@pytest.fixture
def sample_catalog_entry() -> CatalogEntry:
    """Create a sample CatalogEntry for testing."""
    return CatalogEntry(
        update_id="12345678-1234-1234-1234-123456789abc",
        kb_number="KB5034441",
        title="2024-01 Cumulative Update for Windows 11 Version 23H2 for x64",
        products="Windows 11",
        classification="Security Updates",
        size="500 MB",
        download_url="https://catalog.update.microsoft.com/download/xxx.msu",
    )


@pytest.fixture
def sample_winbindex_file() -> WinBIndexFile:
    """Create a sample WinBIndexFile for testing."""
    return WinBIndexFile(
        filename="ntdll.dll",
        version="10.0.22621.3000",
        architecture=Architecture.X64,
        sha256="def456abc123",
        download_url="https://msdl.microsoft.com/download/symbols/ntdll.dll/xxx/ntdll.dll",
        timestamp=datetime(2024, 1, 1, 0, 0, 0),
    )


@pytest.fixture
def sample_cvrf_document() -> dict:
    """Create a sample CVRF document for testing."""
    return {
        "DocumentTracking": {
            "CurrentReleaseDate": "2024-01-09T08:00:00",
        },
        "ProductTree": {
            "FullProductName": [
                {
                    "ProductID": "11926",
                    "Value": "Windows 11 Version 23H2 for x64-based Systems",
                },
                {
                    "ProductID": "11927",
                    "Value": "Windows 10 Version 22H2 for x64-based Systems",
                },
                {
                    "ProductID": "99999",
                    "Value": "Microsoft Office 2019",  # Should be filtered out
                },
            ],
        },
        "Vulnerability": [
            {
                "CVE": "CVE-2024-12345",
                "Title": {"Value": "Windows Kernel Elevation of Privilege"},
                "Notes": [
                    {"Type": 1, "Value": "A privilege escalation vulnerability."},
                ],
                "Threats": [
                    {"Type": 3, "Description": {"Value": "Critical"}},
                ],
                "Remediations": [
                    {
                        "Type": 2,
                        "Description": {"Value": "KB5034441"},
                        "URL": "https://support.microsoft.com/kb5034441",
                        "ProductID": ["11926", "11927"],
                    },
                ],
            },
            {
                "CVE": "CVE-2024-12346",
                "Title": {"Value": "Windows RDS Vulnerability"},
                "Notes": [
                    {"Type": 1, "Value": "An RCE vulnerability."},
                ],
                "Threats": [
                    {"Type": 3, "Description": {"Value": "Important"}},
                ],
                "Remediations": [
                    {
                        "Type": 2,
                        "Description": {"Value": "Apply KB5034442"},
                        "URL": "https://support.microsoft.com/kb5034442",
                        "ProductID": "11926",  # String instead of list
                    },
                ],
            },
        ],
    }


@pytest.fixture
def sample_catalog_html() -> str:
    """Create sample Microsoft Update Catalog HTML response."""
    return """
    <html>
    <body>
    <table id="ctl00_catalogBody_updateMatches">
        <tr>
            <td></td>
            <td><a href="#">2024-01 Cumulative Update for Windows 11 x64</a></td>
            <td>Windows 11</td>
            <td>Security Updates</td>
            <td>500 MB</td>
            <td></td>
            <input type="button" class="flatBlueButtonDownload" id="12345678-1234-1234-1234-123456789abc" />
        </tr>
        <tr>
            <td></td>
            <td><a href="#">2024-01 Cumulative Update for Windows 11 ARM64</a></td>
            <td>Windows 11</td>
            <td>Security Updates</td>
            <td>450 MB</td>
            <td></td>
            <input type="button" class="flatBlueButtonDownload" id="87654321-4321-4321-4321-cba987654321" />
        </tr>
    </table>
    </body>
    </html>
    """


@pytest.fixture
def temp_package_dir(tmp_path: Path) -> Path:
    """Create a temporary packages directory."""
    packages_dir = tmp_path / "packages"
    packages_dir.mkdir()
    return packages_dir


@pytest.fixture
def temp_extracted_dir(tmp_path: Path) -> Path:
    """Create a temporary extracted directory."""
    extracted_dir = tmp_path / "extracted"
    extracted_dir.mkdir()
    return extracted_dir


@pytest.fixture
def temp_baseline_dir(tmp_path: Path) -> Path:
    """Create a temporary baseline directory."""
    baseline_dir = tmp_path / "baseline"
    baseline_dir.mkdir()
    return baseline_dir
