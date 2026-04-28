"""Tests for active data models."""

from ppp.models import Architecture, CatalogEntry, DownloadedFile, WinBIndexFile


class TestArchitectureEnum:
    def test_architecture_values(self):
        assert Architecture.X86 == "x86"
        assert Architecture.X64 == "x64"
        assert Architecture.ARM64 == "arm64"


class TestDownloadedFileModel:
    def test_downloaded_file_creation(self, sample_downloaded_file: DownloadedFile):
        assert sample_downloaded_file.kb_number == "KB5034441"
        assert sample_downloaded_file.filename == "ntdll.dll"
        assert sample_downloaded_file.file_type == "extracted"
        assert sample_downloaded_file.architecture == Architecture.X64
        assert sample_downloaded_file.version == "10.0.22621.3007"

    def test_downloaded_file_minimal(self):
        entry = DownloadedFile(
            kb_number="KB1234567",
            filename="test.dll",
            file_path="/path/to/file",
            file_type="package",
        )
        assert entry.architecture is None
        assert entry.version is None
        assert entry.sha256 is None
        assert entry.downloaded_at is not None


class TestCatalogEntryModel:
    def test_catalog_entry_creation(self, sample_catalog_entry: CatalogEntry):
        assert sample_catalog_entry.update_id == "12345678-1234-1234-1234-123456789abc"
        assert sample_catalog_entry.kb_number == "KB5034441"
        assert sample_catalog_entry.classification == "Security Updates"
        assert sample_catalog_entry.download_url is not None


class TestWinBIndexFileModel:
    def test_winbindex_file_creation(self, sample_winbindex_file: WinBIndexFile):
        assert sample_winbindex_file.filename == "ntdll.dll"
        assert sample_winbindex_file.version == "10.0.22621.3000"
        assert sample_winbindex_file.architecture == Architecture.X64
        assert sample_winbindex_file.sha256 == "def456abc123"
        assert sample_winbindex_file.download_url is not None

    def test_winbindex_file_no_timestamp(self):
        entry = WinBIndexFile(
            filename="kernel32.dll",
            version="10.0.22621.1",
            architecture=Architecture.X64,
            sha256="abc123",
            download_url="https://example.com/file",
        )
        assert entry.timestamp is None
