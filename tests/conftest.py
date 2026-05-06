from datetime import datetime

import pytest

from ppp.models import Architecture, CatalogEntry, DownloadedFile, WinBIndexFile


@pytest.fixture
def sample_downloaded_file() -> DownloadedFile:
    return DownloadedFile(
        kb_number="KB5034441",
        filename="ntdll.dll",
        file_path="/artifacts/extracted/KB5034441/x64/ntdll.dll",
        file_type="extracted",
        architecture=Architecture.X64,
        version="10.0.22621.3007",
        sha256="abc123def456",
        downloaded_at=datetime(2024, 1, 10, 12, 0, 0),
    )


@pytest.fixture
def sample_catalog_entry() -> CatalogEntry:
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
    return WinBIndexFile(
        filename="ntdll.dll",
        version="10.0.22621.3000",
        architecture=Architecture.X64,
        sha256="def456abc123",
        download_url="https://msdl.microsoft.com/download/symbols/ntdll.dll/xxx/ntdll.dll",
        timestamp=datetime(2024, 1, 1, 0, 0, 0),
    )


@pytest.fixture
def sample_catalog_html() -> str:
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
            <input class="flatBlueButtonDownload" id="12345678_1234_1234_1234_123456789abc" />
        </tr>
        <tr>
            <td></td>
            <td><a href="#">2024-01 Cumulative Update for Windows 11 x86</a></td>
            <td>Windows 11</td>
            <td>Security Updates</td>
            <td>300 MB</td>
            <td></td>
            <input class="flatBlueButtonDownload" id="87654321_4321_4321_4321_cba987654321" />
        </tr>
    </table>
    </body>
    </html>
    """
