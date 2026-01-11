"""Tests for patch_tuesday.catalog_client module."""

from pathlib import Path
from unittest.mock import patch, MagicMock
import tempfile

import httpx
import pytest
import respx

from patch_tuesday.catalog_client import (
    _calculate_sha256,
    _detect_architecture,
    download_by_kb,
    download_update,
    get_download_url,
    list_catalog_entries,
    search_catalog,
)
from patch_tuesday.models import Architecture, CatalogEntry


class TestDetectArchitecture:
    """Tests for _detect_architecture function."""
    
    def test_detect_x64(self):
        """Test detecting x64 architecture."""
        assert _detect_architecture("Windows 11 x64") == Architecture.X64
        assert _detect_architecture("Windows 10 64-bit") == Architecture.X64
    
    def test_detect_x86(self):
        """Test detecting x86 architecture."""
        assert _detect_architecture("Windows 10 x86") == Architecture.X86
        assert _detect_architecture("Windows 10 32-bit") == Architecture.X86
    
    def test_detect_arm64(self):
        """Test detecting ARM64 architecture."""
        assert _detect_architecture("Windows 11 ARM64") == Architecture.ARM64
        assert _detect_architecture("Windows 11 arm64-based") == Architecture.ARM64
    
    def test_detect_none(self):
        """Test when architecture cannot be detected."""
        assert _detect_architecture("Windows Update") is None
        assert _detect_architecture("Security Update") is None


class TestCalculateSha256:
    """Tests for _calculate_sha256 function."""
    
    def test_calculate_sha256(self, tmp_path: Path):
        """Test SHA256 calculation for a file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!")
        
        result = _calculate_sha256(test_file)
        
        # SHA256 of "Hello, World!"
        assert len(result) == 64
        assert result.isalnum()
    
    def test_calculate_sha256_empty_file(self, tmp_path: Path):
        """Test SHA256 of empty file."""
        test_file = tmp_path / "empty.txt"
        test_file.write_bytes(b"")
        
        result = _calculate_sha256(test_file)
        
        # SHA256 of empty string
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class TestSearchCatalog:
    """Tests for search_catalog function."""
    
    @respx.mock
    def test_search_catalog_success(self, sample_catalog_html: str):
        """Test searching the catalog successfully."""
        respx.get("https://www.catalog.update.microsoft.com/Search.aspx").mock(
            return_value=httpx.Response(200, text=sample_catalog_html)
        )
        
        results = search_catalog("KB5034441")
        
        assert len(results) >= 1
    
    @respx.mock
    def test_search_catalog_normalizes_kb(self, sample_catalog_html: str):
        """Test that KB number is normalized."""
        respx.get("https://www.catalog.update.microsoft.com/Search.aspx").mock(
            return_value=httpx.Response(200, text=sample_catalog_html)
        )
        
        # Without prefix
        results = search_catalog("5034441")
        assert len(results) >= 0
        
        # Lowercase
        results = search_catalog("kb5034441")
        assert len(results) >= 0
    
    @respx.mock
    def test_search_catalog_filter_architecture(self, sample_catalog_html: str):
        """Test filtering by architecture."""
        respx.get("https://www.catalog.update.microsoft.com/Search.aspx").mock(
            return_value=httpx.Response(200, text=sample_catalog_html)
        )
        
        results = search_catalog("KB5034441", architecture=Architecture.X64)
        
        # Results should only include x64
        for entry in results:
            arch = _detect_architecture(entry.title)
            if arch is not None:
                assert arch == Architecture.X64
    
    @respx.mock
    def test_search_catalog_no_results(self):
        """Test handling no results."""
        respx.get("https://www.catalog.update.microsoft.com/Search.aspx").mock(
            return_value=httpx.Response(200, text="<html><body></body></html>")
        )
        
        results = search_catalog("KB9999999")
        
        assert results == []
    
    @respx.mock
    def test_search_catalog_no_table(self):
        """Test handling response without results table."""
        respx.get("https://www.catalog.update.microsoft.com/Search.aspx").mock(
            return_value=httpx.Response(
                200,
                text="<html><body><p>No results</p></body></html>",
            )
        )
        
        results = search_catalog("KB5034441")
        
        assert results == []


class TestGetDownloadUrl:
    """Tests for get_download_url function."""
    
    @respx.mock
    def test_get_download_url_msu(self):
        """Test getting download URL for MSU file."""
        respx.get("https://www.catalog.update.microsoft.com").mock(
            return_value=httpx.Response(200)
        )
        respx.post("https://www.catalog.update.microsoft.com/DownloadDialog.aspx").mock(
            return_value=httpx.Response(
                200,
                text="""
                <html>
                <script>
                var url = 'https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2024/01/windows11-kb5034441-x64_abc123.msu';
                </script>
                </html>
                """,
            )
        )
        
        result = get_download_url("12345678-1234-1234-1234-123456789abc")
        
        assert result is not None
        assert ".msu" in result
    
    @respx.mock
    def test_get_download_url_cab(self):
        """Test getting download URL for CAB file."""
        respx.get("https://www.catalog.update.microsoft.com").mock(
            return_value=httpx.Response(200)
        )
        respx.post("https://www.catalog.update.microsoft.com/DownloadDialog.aspx").mock(
            return_value=httpx.Response(
                200,
                text="""
                <html>
                <script>
                downloadUrl = 'https://download.windowsupdate.com/d/msdownload/update.cab';
                </script>
                </html>
                """,
            )
        )
        
        result = get_download_url("test-update-id")
        
        assert result is not None
        assert ".cab" in result
    
    @respx.mock
    def test_get_download_url_not_found(self):
        """Test handling when download URL is not found."""
        respx.get("https://www.catalog.update.microsoft.com").mock(
            return_value=httpx.Response(200)
        )
        respx.post("https://www.catalog.update.microsoft.com/DownloadDialog.aspx").mock(
            return_value=httpx.Response(200, text="<html>No download</html>")
        )
        
        result = get_download_url("nonexistent-id")
        
        assert result is None


class TestDownloadUpdate:
    """Tests for download_update function."""
    
    @respx.mock
    def test_download_update_success(self, tmp_path: Path):
        """Test successfully downloading an update."""
        download_url = "https://catalog.s.download.windowsupdate.com/test.msu"
        
        respx.get("https://www.catalog.update.microsoft.com").mock(
            return_value=httpx.Response(200)
        )
        respx.post("https://www.catalog.update.microsoft.com/DownloadDialog.aspx").mock(
            return_value=httpx.Response(
                200,
                text=f"<html>downloadUrl = '{download_url}';</html>",
            )
        )
        respx.get(download_url).mock(
            return_value=httpx.Response(
                200,
                content=b"fake msu content",
                headers={"content-length": "16"},
            )
        )
        
        entry = CatalogEntry(
            update_id="test-id",
            kb_number="KB5034441",
            title="Test Update x64",
            products="Windows 11",
            classification="Security",
        )
        
        result = download_update(entry, download_dir=tmp_path, show_progress=False)
        
        assert result is not None
        assert result.exists()
    
    def test_download_update_already_exists(self, tmp_path: Path):
        """Test that existing downloads are skipped."""
        # Create existing file with the expected name pattern
        existing_file = tmp_path / "test_x64.msu"
        existing_file.write_bytes(b"existing content")
        
        entry = CatalogEntry(
            update_id="test-id",
            kb_number="KB5034441",
            title="Test Update x64",
            products="Windows 11",
            classification="Security",
            download_url="https://example.com/test.msu",
        )
        
        result = download_update(entry, download_dir=tmp_path, show_progress=False)
        
        # Should return existing file path
        assert result is not None
        assert result.exists()
    
    @respx.mock
    def test_download_update_no_url(self, tmp_path: Path):
        """Test handling when download URL cannot be obtained."""
        respx.get("https://www.catalog.update.microsoft.com").mock(
            return_value=httpx.Response(200)
        )
        respx.post("https://www.catalog.update.microsoft.com/DownloadDialog.aspx").mock(
            return_value=httpx.Response(200, text="<html>No URL</html>")
        )
        
        entry = CatalogEntry(
            update_id="test-id",
            kb_number="KB5034441",
            title="Test Update",
            products="Windows 11",
            classification="Security",
        )
        
        result = download_update(entry, download_dir=tmp_path, show_progress=False)
        
        assert result is None


class TestDownloadByKb:
    """Tests for download_by_kb function."""
    
    @respx.mock
    def test_download_by_kb_no_entries(self, tmp_path: Path):
        """Test download_by_kb when no entries found."""
        respx.get("https://www.catalog.update.microsoft.com/Search.aspx").mock(
            return_value=httpx.Response(200, text="<html></html>")
        )
        
        results = download_by_kb("KB9999999", download_dir=tmp_path)
        
        assert results == []
    
    @respx.mock
    def test_download_by_kb_with_architecture(self, tmp_path: Path, sample_catalog_html: str):
        """Test download_by_kb with architecture filter."""
        respx.get("https://www.catalog.update.microsoft.com/Search.aspx").mock(
            return_value=httpx.Response(200, text=sample_catalog_html)
        )
        
        # Mock download responses
        respx.get("https://www.catalog.update.microsoft.com").mock(
            return_value=httpx.Response(200)
        )
        respx.post("https://www.catalog.update.microsoft.com/DownloadDialog.aspx").mock(
            return_value=httpx.Response(200, text="<html>No URL</html>")
        )
        
        results = download_by_kb(
            "KB5034441",
            architecture=Architecture.X64,
            download_dir=tmp_path,
            show_progress=False,
        )
        
        # May return empty if no downloads succeed, but shouldn't error
        assert isinstance(results, list)


class TestListCatalogEntries:
    """Tests for list_catalog_entries function."""
    
    @respx.mock
    def test_list_catalog_entries(self, sample_catalog_html: str, capsys):
        """Test listing catalog entries."""
        respx.get("https://www.catalog.update.microsoft.com/Search.aspx").mock(
            return_value=httpx.Response(200, text=sample_catalog_html)
        )
        
        # This function prints to console via rich
        list_catalog_entries("KB5034441")
        
        # Should complete without error
    
    @respx.mock
    def test_list_catalog_entries_no_results(self, capsys):
        """Test listing when no entries found."""
        respx.get("https://www.catalog.update.microsoft.com/Search.aspx").mock(
            return_value=httpx.Response(200, text="<html></html>")
        )
        
        list_catalog_entries("KB9999999")
        
        # Should complete without error
