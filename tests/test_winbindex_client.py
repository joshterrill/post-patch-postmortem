"""Tests for ppp.winbindex_client module."""

import gzip
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import httpx
import pytest
import respx

from ppp.winbindex_client import (
    _build_symbol_server_urls,
    _calculate_sha256,
    _clean_filename,
    _extract_release_date,
    _parse_datetime,
    _parse_architecture,
    _parse_int,
    _parse_version,
    download_file_version,
    fetch_baseline_for_extracted,
    find_previous_version,
    get_file_info,
    list_file_versions,
)
from ppp.models import Architecture, WinBIndexFile


class TestParseArchitecture:
    """Tests for _parse_architecture function."""
    
    def test_parse_arm64_string(self):
        """Test parsing ARM64 architecture from string."""
        assert _parse_architecture("arm64") == Architecture.ARM64
        assert _parse_architecture("ARM64") == Architecture.ARM64
        assert _parse_architecture("aarch64") == Architecture.ARM64
    
    def test_parse_arm64_int(self):
        """Test parsing ARM64 architecture from machine type integer."""
        assert _parse_architecture(43620) == Architecture.ARM64
    
    def test_parse_x64_string(self):
        """Test parsing x64 architecture from string."""
        assert _parse_architecture("amd64") == Architecture.X64
        assert _parse_architecture("AMD64") == Architecture.X64
        assert _parse_architecture("x64") == Architecture.X64
    
    def test_parse_x64_int(self):
        """Test parsing x64 architecture from machine type integer."""
        assert _parse_architecture(34404) == Architecture.X64
    
    def test_parse_x86_string(self):
        """Test parsing x86 architecture from string."""
        assert _parse_architecture("x86") == Architecture.X86
        assert _parse_architecture("i386") == Architecture.X86
    
    def test_parse_x86_int(self):
        """Test parsing x86 architecture from machine type integer."""
        assert _parse_architecture(332) == Architecture.X86
    
    def test_parse_unknown_string(self):
        """Test parsing unknown architecture string."""
        assert _parse_architecture("unknown") is None
        assert _parse_architecture("") is None
    
    def test_parse_unknown_int(self):
        """Test parsing unknown architecture integer."""
        assert _parse_architecture(99999) is None
    
    def test_parse_none(self):
        """Test parsing None returns None."""
        assert _parse_architecture(None) is None


class TestParseVersion:
    """Tests for _parse_version function."""
    
    def test_parse_version_simple(self):
        """Test parsing simple version strings."""
        assert _parse_version("10.0.22621.1") == (10, 0, 22621, 1)
        assert _parse_version("1.2.3.4") == (1, 2, 3, 4)
    
    def test_parse_version_with_text(self):
        """Test parsing version strings with text."""
        assert _parse_version("v10.0.1") == (10, 0, 1)
    
    def test_parse_version_empty(self):
        """Test parsing empty version string."""
        assert _parse_version("") == ()


class TestUrlHelpers:
    """Tests for Winbindex-compatible URL helper logic."""
    
    def test_parse_int(self):
        """Test robust numeric parsing."""
        assert _parse_int(123) == 123
        assert _parse_int("123") == 123
        assert _parse_int("0x10") == 16
        assert _parse_int(None) is None
        assert _parse_int("abc") is None
    
    def test_build_symbol_server_urls_with_virtual_size(self):
        """Test standard timestamp+virtualSize symbol URL generation."""
        info = {"timestamp": 0x65B4E6D0, "virtualSize": 0x12345}
        urls = _build_symbol_server_urls("notepad.exe", info, "deadbeef")
        
        assert urls
        assert urls[0].startswith("https://msdl.microsoft.com/download/symbols/notepad.exe/")
        assert urls[0].endswith("/notepad.exe")
        assert any("/deadbeef/notepad.exe" in u for u in urls)
    
    def test_build_symbol_server_urls_with_sizeofimage_fallback(self):
        """Test Winbindex-style multiple candidate URLs when virtualSize is absent."""
        info = {
            "timestamp": 0x65B4E6D0,
            "size": 0xA000,
            "lastSectionPointerToRawData": 0x7000,
            "lastSectionVirtualAddress": 0x2000,
        }
        urls = _build_symbol_server_urls("notepad.exe", info, "hash123")
        
        # Should include multiple candidates + hash fallback
        assert len(urls) > 2
        assert any("/hash123/notepad.exe" in u for u in urls)


class TestDateHelpers:
    """Tests for release date extraction helpers."""
    
    def test_parse_datetime_timestamp_seconds(self):
        """Test UNIX timestamp parsing (seconds)."""
        dt = _parse_datetime(1700000000)
        assert dt is not None
        assert dt.year >= 2023
    
    def test_parse_datetime_iso(self):
        """Test ISO string date parsing."""
        dt = _parse_datetime("2026-02-10T12:34:56Z")
        assert dt is not None
        assert dt.year == 2026
        assert dt.month == 2
    
    def test_extract_release_date_prefers_windows_versions(self):
        """Test extracting explicit release date from windowsVersions metadata."""
        entry = {
            "windowsVersions": {
                "win11": {
                    "releaseDate": "2026-02-10",
                }
            }
        }
        file_info = {"timestamp": 1700000000}
        dt = _extract_release_date(entry, file_info)
        assert dt is not None
        assert dt.year == 2026
    
    def test_extract_release_date_falls_back_to_timestamp(self):
        """Test fallback to file timestamp when no explicit release date exists."""
        entry = {"windowsVersions": {}}
        file_info = {"timestamp": 1700000000}
        dt = _extract_release_date(entry, file_info)
        assert dt is not None


class TestCalculateSha256:
    """Tests for _calculate_sha256 function."""
    
    def test_calculate_sha256(self, tmp_path: Path):
        """Test SHA256 calculation."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"test content")
        
        result = _calculate_sha256(test_file)
        
        assert len(result) == 64
        assert result.isalnum()


class TestCleanFilename:
    """Tests for _clean_filename function."""
    
    def test_clean_filename_no_hash(self):
        """Test that filename without hash is unchanged."""
        assert _clean_filename("ntdll.dll") == "ntdll.dll"
    
    def test_clean_filename_with_8char_hash(self):
        """Test cleaning filename with 8-char hex hash suffix."""
        assert _clean_filename("ntdll_abc12345.dll") == "ntdll.dll"
        assert _clean_filename("test_01234567.exe") == "test.exe"
        assert _clean_filename("gdiplus_ABCDEF01.dll") == "gdiplus.dll"
    
    def test_clean_filename_hash_wrong_length(self):
        """Test that non-8-char hash is not removed."""
        assert _clean_filename("ntdll_abc123.dll") == "ntdll_abc123.dll"
        assert _clean_filename("test_0123456789.exe") == "test_0123456789.exe"
    
    def test_clean_filename_no_extension(self):
        """Test cleaning filename without extension is unchanged."""
        assert _clean_filename("ntdll") == "ntdll"
    
    def test_clean_filename_multiple_underscores(self):
        """Test filename with underscores but no hash is unchanged."""
        assert _clean_filename("my_file_name.dll") == "my_file_name.dll"
    
    def test_clean_filename_non_hex_suffix(self):
        """Test that non-hex suffix is not removed."""
        assert _clean_filename("ntdll_notahex1.dll") == "ntdll_notahex1.dll"


class TestGetFileInfo:
    """Tests for get_file_info function."""
    
    @respx.mock
    def test_get_file_info_success_gzip(self):
        """Test getting file info from gzipped response."""
        file_data = {
            "abc123def456": {
                "fileInfo": {
                    "version": "10.0.22621.1",
                    "machineType": 34404,
                    "sha256": "abc123def456",
                    "timestamp": 1234567890,
                    "virtualSize": 1000000,
                },
                "windowsVersions": {},
            }
        }
        compressed = gzip.compress(json.dumps(file_data).encode())
        
        respx.get(
            "https://winbindex.m417z.com/data/by_filename_compressed/ntdll.dll.json.gz"
        ).mock(return_value=httpx.Response(200, content=compressed))
        
        result = get_file_info("ntdll.dll")
        
        assert result is not None
        assert "fileInfo" in result
    
    @respx.mock
    def test_get_file_info_not_found(self):
        """Test handling 404 response."""
        respx.get(
            "https://winbindex.m417z.com/data/by_filename_compressed/nonexistent.dll.json.gz"
        ).mock(return_value=httpx.Response(404))
        
        result = get_file_info("nonexistent.dll")
        
        assert result is None
    
    @respx.mock
    def test_get_file_info_error_handling(self):
        """Test error handling during request."""
        respx.get(
            "https://winbindex.m417z.com/data/by_filename_compressed/test.dll.json.gz"
        ).mock(return_value=httpx.Response(500))
        
        result = get_file_info("test.dll")
        
        # Should handle error gracefully
        assert result is None


class TestListFileVersions:
    """Tests for list_file_versions function."""
    
    @respx.mock
    def test_list_file_versions_success(self):
        """Test listing file versions."""
        file_data = {
            "hash1": {
                "fileInfo": {
                    "version": "10.0.22621.2",
                    "machineType": 34404,
                    "sha256": "abc123",
                    "timestamp": 1234567890,
                    "virtualSize": 1000000,
                },
                "windowsVersions": {},
            },
            "hash2": {
                "fileInfo": {
                    "version": "10.0.22621.1",
                    "machineType": 34404,
                    "sha256": "def456",
                    "timestamp": 1234567880,
                    "virtualSize": 1000000,
                },
                "windowsVersions": {},
            },
        }
        compressed = gzip.compress(json.dumps(file_data).encode())
        
        respx.get(
            "https://winbindex.m417z.com/data/by_filename_compressed/ntdll.dll.json.gz"
        ).mock(return_value=httpx.Response(200, content=compressed))
        
        result = list_file_versions("ntdll.dll")
        
        assert len(result) == 2
        assert all(isinstance(f, WinBIndexFile) for f in result)
        assert all(f.download_urls for f in result)
        # Should be sorted by version descending
        if len(result) >= 2:
            assert _parse_version(result[0].version) >= _parse_version(result[1].version)
    
    @respx.mock
    def test_list_file_versions_filter_architecture(self):
        """Test filtering by architecture."""
        file_data = {
            "hash1": {
                "fileInfo": {
                    "version": "10.0.1",
                    "machineType": 34404,  # x64
                    "sha256": "abc",
                    "timestamp": 1234567890,
                    "virtualSize": 1000000,
                },
                "windowsVersions": {},
            },
            "hash2": {
                "fileInfo": {
                    "version": "10.0.1",
                    "machineType": 332,  # x86
                    "sha256": "def",
                    "timestamp": 1234567890,
                    "virtualSize": 1000000,
                },
                "windowsVersions": {},
            },
        }
        compressed = gzip.compress(json.dumps(file_data).encode())
        
        respx.get(
            "https://winbindex.m417z.com/data/by_filename_compressed/test.dll.json.gz"
        ).mock(return_value=httpx.Response(200, content=compressed))
        
        result = list_file_versions("test.dll", architecture=Architecture.X64)
        
        assert all(f.architecture == Architecture.X64 for f in result)
    
    @respx.mock
    def test_list_file_versions_limit(self):
        """Test version limit."""
        file_data = {
            f"hash{i}": {
                "fileInfo": {
                    "version": f"10.0.{i}",
                    "machineType": 34404,
                    "sha256": f"sha{i}",
                    "timestamp": 1234567890 + i,
                    "virtualSize": 1000000,
                },
                "windowsVersions": {},
            }
            for i in range(50)
        }
        compressed = gzip.compress(json.dumps(file_data).encode())
        
        respx.get(
            "https://winbindex.m417z.com/data/by_filename_compressed/test.dll.json.gz"
        ).mock(return_value=httpx.Response(200, content=compressed))
        
        result = list_file_versions("test.dll", limit=5)
        
        assert len(result) <= 5
    
    @respx.mock
    def test_list_file_versions_limit_applied_after_sort(self):
        """Test that limit is applied after sorting all discovered versions."""
        file_data = {
            "hash_old_1": {
                "fileInfo": {
                    "version": "10.0.1",
                    "machineType": 34404,
                    "sha256": "old1",
                    "timestamp": 1234567001,
                    "virtualSize": 1000000,
                },
                "windowsVersions": {},
            },
            "hash_old_2": {
                "fileInfo": {
                    "version": "10.0.2",
                    "machineType": 34404,
                    "sha256": "old2",
                    "timestamp": 1234567002,
                    "virtualSize": 1000000,
                },
                "windowsVersions": {},
            },
            "hash_new_1": {
                "fileInfo": {
                    "version": "11.0.100",
                    "machineType": 34404,
                    "sha256": "new1",
                    "timestamp": 2234567001,
                    "virtualSize": 1000000,
                },
                "windowsVersions": {},
            },
            "hash_new_2": {
                "fileInfo": {
                    "version": "11.0.200",
                    "machineType": 34404,
                    "sha256": "new2",
                    "timestamp": 2234567002,
                    "virtualSize": 1000000,
                },
                "windowsVersions": {},
            },
        }
        compressed = gzip.compress(json.dumps(file_data).encode())
        
        respx.get(
            "https://winbindex.m417z.com/data/by_filename_compressed/test.dll.json.gz"
        ).mock(return_value=httpx.Response(200, content=compressed))
        
        result = list_file_versions("test.dll", limit=2)
        
        assert len(result) == 2
        assert result[0].version == "11.0.200"
        assert result[1].version == "11.0.100"
    
    @respx.mock
    def test_list_file_versions_sorts_by_release_date_first(self):
        """Test that newer release dates are ranked above older ones."""
        file_data = {
            "hash_new_version_old_date": {
                "fileInfo": {
                    "version": "11.0.500",
                    "machineType": 34404,
                    "sha256": "newver",
                    "timestamp": 1234567890,  # old
                    "virtualSize": 1000000,
                },
                "windowsVersions": {"w11": {"releaseDate": "2020-01-01"}},
            },
            "hash_old_version_new_date": {
                "fileInfo": {
                    "version": "10.0.1",
                    "machineType": 34404,
                    "sha256": "oldver",
                    "timestamp": 2234567890,  # newer
                    "virtualSize": 1000000,
                },
                "windowsVersions": {"w11": {"releaseDate": "2026-02-10"}},
            },
        }
        compressed = gzip.compress(json.dumps(file_data).encode())
        
        respx.get(
            "https://winbindex.m417z.com/data/by_filename_compressed/test.dll.json.gz"
        ).mock(return_value=httpx.Response(200, content=compressed))
        
        result = list_file_versions("test.dll", limit=2)
        
        assert len(result) == 2
        assert result[0].version == "10.0.1"
        assert result[0].release_date is not None
    
    @respx.mock
    def test_list_file_versions_not_found(self):
        """Test handling file not found."""
        respx.get(
            "https://winbindex.m417z.com/data/by_filename_compressed/nonexistent.dll.json.gz"
        ).mock(return_value=httpx.Response(404))
        
        result = list_file_versions("nonexistent.dll")
        
        assert result == []

    @respx.mock
    def test_list_file_versions_extracts_kb_metadata(self):
        """Test extracting KB/update metadata for a file version."""
        file_data = {
            "hash1": {
                "fileInfo": {
                    "version": "10.0.17763.6189",
                    "machineType": 34404,
                    "sha256": "abc123",
                    "timestamp": 4002857474,
                    "virtualSize": 2990080,
                    "size": 2927600,
                },
                "windowsVersions": {
                    "1809": {
                        "KB5041578": {
                            "updateInfo": {
                                "heading": "August 13, 2024&#x2014;KB5041578",
                                "releaseDate": "2024-08-13",
                                "releaseVersion": "17763.6189",
                                "updateUrl": "https://support.microsoft.com/help/5041578",
                            }
                        }
                    }
                },
            },
        }
        compressed = gzip.compress(json.dumps(file_data).encode())

        respx.get(
            "https://winbindex.m417z.com/data/by_filename_compressed/tcpip.sys.json.gz"
        ).mock(return_value=httpx.Response(200, content=compressed))

        result = list_file_versions("tcpip.sys")

        assert len(result) == 1
        assert result[0].size == 2927600
        assert len(result[0].updates) == 1
        assert result[0].updates[0].kb_number == "KB5041578"
        assert result[0].updates[0].windows_version == "1809"
        assert result[0].updates[0].release_version == "17763.6189"


class TestFindPreviousVersion:
    """Tests for find_previous_version function."""
    
    @respx.mock
    def test_find_previous_version_success(self):
        """Test finding previous version."""
        file_data = {
            "hash1": {
                "fileInfo": {"version": "10.0.22621.3", "machineType": 34404, "sha256": "a", "timestamp": 1234567893, "virtualSize": 1000000},
                "windowsVersions": {},
            },
            "hash2": {
                "fileInfo": {"version": "10.0.22621.2", "machineType": 34404, "sha256": "b", "timestamp": 1234567892, "virtualSize": 1000000},
                "windowsVersions": {},
            },
            "hash3": {
                "fileInfo": {"version": "10.0.22621.1", "machineType": 34404, "sha256": "c", "timestamp": 1234567891, "virtualSize": 1000000},
                "windowsVersions": {},
            },
        }
        compressed = gzip.compress(json.dumps(file_data).encode())
        
        respx.get(
            "https://winbindex.m417z.com/data/by_filename_compressed/test.dll.json.gz"
        ).mock(return_value=httpx.Response(200, content=compressed))
        
        result = find_previous_version("test.dll", "10.0.22621.3")
        
        assert result is not None
        assert _parse_version(result.version) < _parse_version("10.0.22621.3")
    
    @respx.mock
    def test_find_previous_version_not_found(self):
        """Test when no previous version exists."""
        file_data = {
            "hash1": {
                "fileInfo": {"version": "10.0.22621.3", "machineType": 34404, "sha256": "a", "timestamp": 1234567893, "virtualSize": 1000000},
                "windowsVersions": {},
            },
        }
        compressed = gzip.compress(json.dumps(file_data).encode())
        
        respx.get(
            "https://winbindex.m417z.com/data/by_filename_compressed/test.dll.json.gz"
        ).mock(return_value=httpx.Response(200, content=compressed))
        
        result = find_previous_version("test.dll", "10.0.22621.1")
        
        # No version older than 10.0.22621.1 exists
        # Result depends on version comparison
        assert result is None or _parse_version(result.version) < _parse_version("10.0.22621.1")


class TestDownloadFileVersion:
    """Tests for download_file_version function."""
    
    @respx.mock
    def test_download_file_version_success(self, tmp_path: Path):
        """Test successful file download."""
        download_url = "https://msdl.microsoft.com/download/symbols/test.dll/abc/test.dll"
        
        respx.head(download_url).mock(return_value=httpx.Response(200))
        respx.get(download_url).mock(
            return_value=httpx.Response(
                200,
                content=b"fake dll content",
                headers={"content-length": "16"},
            )
        )
        
        file_info = WinBIndexFile(
            filename="test.dll",
            version="10.0.22621.1",
            architecture=Architecture.X64,
            sha256="abc123",
            download_url=download_url,
        )
        
        result = download_file_version(file_info, output_dir=tmp_path, show_progress=False)
        
        assert result is not None
        assert result.exists()
    
    @respx.mock
    def test_download_file_version_already_exists(self, tmp_path: Path):
        """Test that existing files are skipped."""
        output_dir = tmp_path / "x64"
        output_dir.mkdir()
        
        existing = output_dir / "test_10_0_22621_1.dll"
        existing.write_bytes(b"existing")
        
        file_info = WinBIndexFile(
            filename="test.dll",
            version="10.0.22621.1",
            architecture=Architecture.X64,
            sha256="abc",
            download_url="https://example.com/test.dll",
        )
        
        result = download_file_version(file_info, output_dir=tmp_path, show_progress=False)
        
        assert result == existing
    
    @respx.mock
    def test_download_file_version_all_urls_fail(self, tmp_path: Path):
        """Test handling when all download URLs fail."""
        # Mock specific URLs that the code will try
        respx.head("https://example.com/test.dll").mock(return_value=httpx.Response(404))
        respx.head(url__startswith="https://msdl.microsoft.com").mock(return_value=httpx.Response(404))
        respx.head(url__startswith="https://symbols.nuget.org").mock(return_value=httpx.Response(404))
        
        file_info = WinBIndexFile(
            filename="test.dll",
            version="10.0.1",
            architecture=Architecture.X64,
            sha256="abc123",
            download_url="https://example.com/test.dll",
        )
        
        result = download_file_version(file_info, output_dir=tmp_path, show_progress=False)
        
        assert result is None
    
    @respx.mock
    def test_download_file_version_tries_alternate_winbindex_urls(self, tmp_path: Path):
        """Test retrying alternate candidate URLs from Winbindex logic."""
        first_url = "https://msdl.microsoft.com/download/symbols/test.dll/AAAA/test.dll"
        second_url = "https://msdl.microsoft.com/download/symbols/test.dll/BBBB/test.dll"
        
        respx.head(first_url).mock(return_value=httpx.Response(404))
        respx.head(second_url).mock(return_value=httpx.Response(200))
        respx.get(second_url).mock(
            return_value=httpx.Response(
                200,
                content=b"candidate dll content",
                headers={"content-length": "21"},
            )
        )
        
        file_info = WinBIndexFile(
            filename="test.dll",
            version="10.0.22621.1",
            architecture=Architecture.X64,
            sha256="abc123",
            download_url=first_url,
            download_urls=[first_url, second_url],
        )
        
        result = download_file_version(file_info, output_dir=tmp_path, show_progress=False)
        
        assert result is not None
        assert result.exists()


class TestFetchBaselineForExtracted:
    """Tests for fetch_baseline_for_extracted function."""
    
    @respx.mock
    def test_fetch_baseline_no_binaries(self, tmp_path: Path):
        """Test when no binary files found."""
        extracted_dir = tmp_path / "extracted"
        extracted_dir.mkdir()
        
        result = fetch_baseline_for_extracted(extracted_dir, "KB5034441", tmp_path / "baseline")
        
        assert result == []
    
    @respx.mock
    def test_fetch_baseline_with_binaries(self, tmp_path: Path):
        """Test fetching baselines for extracted binaries."""
        extracted_dir = tmp_path / "extracted"
        x64_dir = extracted_dir / "x64"
        x64_dir.mkdir(parents=True)
        (x64_dir / "test.dll").write_bytes(b"binary")
        
        # Mock WinBIndex returning empty results for the data endpoint
        respx.get(
            "https://winbindex.m417z.com/data/by_filename_compressed/test.dll.json.gz"
        ).mock(return_value=httpx.Response(404))
        
        result = fetch_baseline_for_extracted(
            extracted_dir, "KB5034441", tmp_path / "baseline"
        )
        
        # No baselines found due to 404, but should not error
        assert isinstance(result, list)
