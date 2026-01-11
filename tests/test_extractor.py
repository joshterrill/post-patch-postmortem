"""Tests for patch_tuesday.extractor module."""

import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from patch_tuesday.extractor import (
    BINARY_EXTENSIONS,
    _calculate_sha256,
    _detect_architecture_from_path,
    _extract_cab,
    _find_nested_cabs,
    _get_cab_extractor,
    _get_file_version,
    _is_binary_file,
    extract_by_kb,
    extract_package,
    get_extraction_stats,
    list_extracted_files,
)
from patch_tuesday.models import Architecture


class TestBinaryExtensions:
    """Tests for binary extension constants."""
    
    def test_binary_extensions_contains_common_types(self):
        """Test that common binary types are included."""
        assert ".dll" in BINARY_EXTENSIONS
        assert ".exe" in BINARY_EXTENSIONS
        assert ".sys" in BINARY_EXTENSIONS
        assert ".ocx" in BINARY_EXTENSIONS
    
    def test_binary_extensions_are_lowercase(self):
        """Test that all extensions are lowercase."""
        for ext in BINARY_EXTENSIONS:
            assert ext == ext.lower()
            assert ext.startswith(".")


class TestGetCabExtractor:
    """Tests for _get_cab_extractor function."""
    
    def test_get_cab_extractor_windows(self):
        """Test getting extractor on Windows."""
        with patch("platform.system", return_value="Windows"):
            cmd, args = _get_cab_extractor()
            assert cmd == "expand"
            assert "-F:*" in args
    
    def test_get_cab_extractor_unix_with_cabextract(self):
        """Test getting extractor on Unix with cabextract installed."""
        with patch("platform.system", return_value="Linux"):
            with patch("shutil.which", return_value="/usr/bin/cabextract"):
                cmd, args = _get_cab_extractor()
                assert cmd == "cabextract"
                assert "-q" in args
    
    def test_get_cab_extractor_unix_no_cabextract(self):
        """Test error when cabextract is not installed."""
        with patch("platform.system", return_value="Linux"):
            with patch("shutil.which", return_value=None):
                with pytest.raises(RuntimeError, match="cabextract not found"):
                    _get_cab_extractor()


class TestCalculateSha256:
    """Tests for _calculate_sha256 function."""
    
    def test_calculate_sha256(self, tmp_path: Path):
        """Test SHA256 calculation."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x01\x02\x03")
        
        result = _calculate_sha256(test_file)
        
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)


class TestDetectArchitectureFromPath:
    """Tests for _detect_architecture_from_path function."""
    
    def test_detect_arm64(self, tmp_path: Path):
        """Test detecting ARM64 from path."""
        path = tmp_path / "arm64" / "test.dll"
        assert _detect_architecture_from_path(path) == Architecture.ARM64
        
        path = tmp_path / "aarch64" / "test.dll"
        assert _detect_architecture_from_path(path) == Architecture.ARM64
    
    def test_detect_x64(self, tmp_path: Path):
        """Test detecting x64 from path."""
        path = tmp_path / "amd64" / "test.dll"
        assert _detect_architecture_from_path(path) == Architecture.X64
        
        path = tmp_path / "x64" / "test.dll"
        assert _detect_architecture_from_path(path) == Architecture.X64
        
        path = tmp_path / "wow64" / "test.dll"
        assert _detect_architecture_from_path(path) == Architecture.X64
    
    def test_detect_x86(self, tmp_path: Path):
        """Test detecting x86 from path."""
        path = tmp_path / "x86" / "test.dll"
        assert _detect_architecture_from_path(path) == Architecture.X86
        
        path = tmp_path / "i386" / "test.dll"
        assert _detect_architecture_from_path(path) == Architecture.X86
    
    def test_detect_none(self, tmp_path: Path):
        """Test when architecture cannot be detected."""
        path = tmp_path / "unknown" / "test.dll"
        assert _detect_architecture_from_path(path) is None


class TestIsBinaryFile:
    """Tests for _is_binary_file function."""
    
    def test_is_binary_dll(self, tmp_path: Path):
        """Test detecting DLL files."""
        assert _is_binary_file(tmp_path / "test.dll")
        assert _is_binary_file(tmp_path / "test.DLL")
    
    def test_is_binary_exe(self, tmp_path: Path):
        """Test detecting EXE files."""
        assert _is_binary_file(tmp_path / "test.exe")
    
    def test_is_binary_sys(self, tmp_path: Path):
        """Test detecting SYS driver files."""
        assert _is_binary_file(tmp_path / "test.sys")
    
    def test_not_binary(self, tmp_path: Path):
        """Test non-binary files."""
        assert not _is_binary_file(tmp_path / "test.txt")
        assert not _is_binary_file(tmp_path / "test.xml")
        assert not _is_binary_file(tmp_path / "test.cat")


class TestGetFileVersion:
    """Tests for _get_file_version function."""
    
    def test_get_file_version_returns_none(self, tmp_path: Path):
        """Test that get_file_version returns None (not implemented)."""
        test_file = tmp_path / "test.dll"
        test_file.write_bytes(b"")
        
        result = _get_file_version(test_file)
        
        assert result is None


class TestExtractCab:
    """Tests for _extract_cab function."""
    
    def test_extract_cab_success(self, tmp_path: Path):
        """Test successful CAB extraction."""
        cab_path = tmp_path / "test.cab"
        output_dir = tmp_path / "output"
        
        # Mock successful extraction
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            with patch.object(
                __import__("patch_tuesday.extractor", fromlist=["_get_cab_extractor"]),
                "_get_cab_extractor",
                return_value=("cabextract", ["-q"]),
            ):
                result = _extract_cab(cab_path, output_dir)
        
        assert output_dir.exists()
    
    def test_extract_cab_failure(self, tmp_path: Path):
        """Test failed CAB extraction."""
        cab_path = tmp_path / "test.cab"
        output_dir = tmp_path / "output"
        
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            with patch.object(
                __import__("patch_tuesday.extractor", fromlist=["_get_cab_extractor"]),
                "_get_cab_extractor",
                return_value=("cabextract", ["-q"]),
            ):
                result = _extract_cab(cab_path, output_dir)
        
        assert result is False
    
    def test_extract_cab_exception(self, tmp_path: Path):
        """Test CAB extraction with exception."""
        cab_path = tmp_path / "test.cab"
        output_dir = tmp_path / "output"
        
        with patch("subprocess.run", side_effect=Exception("Test error")):
            with patch.object(
                __import__("patch_tuesday.extractor", fromlist=["_get_cab_extractor"]),
                "_get_cab_extractor",
                return_value=("cabextract", ["-q"]),
            ):
                result = _extract_cab(cab_path, output_dir)
        
        assert result is False


class TestFindNestedCabs:
    """Tests for _find_nested_cabs function."""
    
    def test_find_nested_cabs(self, tmp_path: Path):
        """Test finding nested CAB files."""
        # Create nested structure with CABs
        (tmp_path / "subdir").mkdir()
        (tmp_path / "outer.cab").touch()
        (tmp_path / "subdir" / "inner.cab").touch()
        (tmp_path / "not_a_cab.txt").touch()
        
        result = _find_nested_cabs(tmp_path)
        
        assert len(result) == 2
        assert all(p.suffix == ".cab" for p in result)
    
    def test_find_nested_cabs_empty(self, tmp_path: Path):
        """Test finding CABs in directory without CABs."""
        (tmp_path / "test.txt").touch()
        
        result = _find_nested_cabs(tmp_path)
        
        assert result == []


class TestExtractPackage:
    """Tests for extract_package function."""
    
    def test_extract_package_not_found(self, tmp_path: Path):
        """Test extracting non-existent package."""
        with pytest.raises(FileNotFoundError):
            extract_package(tmp_path / "nonexistent.msu")
    
    def test_extract_package_extracts_kb_from_filename(self, tmp_path: Path):
        """Test that KB number is extracted from filename."""
        package = tmp_path / "windows-kb5034441-x64.msu"
        package.write_bytes(b"fake cab content")
        
        with patch.object(
            __import__("patch_tuesday.extractor", fromlist=["_extract_cab"]),
            "_extract_cab",
            return_value=True,
        ):
            result = extract_package(package, tmp_path / "output")
        
        # Should not raise even if extraction finds no binaries
        assert isinstance(result, list)
    
    def test_extract_package_with_explicit_kb(self, tmp_path: Path):
        """Test extracting with explicit KB number."""
        package = tmp_path / "update.msu"
        package.write_bytes(b"fake content")
        
        with patch.object(
            __import__("patch_tuesday.extractor", fromlist=["_extract_cab"]),
            "_extract_cab",
            return_value=True,
        ):
            result = extract_package(package, kb_number="KB1234567")
        
        assert isinstance(result, list)


class TestExtractByKb:
    """Tests for extract_by_kb function."""
    
    def test_extract_by_kb_no_packages(self, tmp_path: Path):
        """Test extract_by_kb when no packages found."""
        result = extract_by_kb("KB9999999", packages_dir=tmp_path)
        
        assert result == []
    
    def test_extract_by_kb_normalizes_kb(self, tmp_path: Path):
        """Test that KB number is normalized."""
        # Create a package with lowercase kb
        package = tmp_path / "kb1234567.msu"
        package.write_bytes(b"fake")
        
        with patch.object(
            __import__("patch_tuesday.extractor", fromlist=["extract_package"]),
            "extract_package",
            return_value=[],
        ):
            result = extract_by_kb("1234567", packages_dir=tmp_path)
        
        # Should find package and call extract_package
        assert isinstance(result, list)


class TestListExtractedFiles:
    """Tests for list_extracted_files function."""
    
    def test_list_extracted_files(self, tmp_path: Path):
        """Test listing extracted files."""
        kb_dir = tmp_path / "KB5034441"
        x64_dir = kb_dir / "x64"
        x64_dir.mkdir(parents=True)
        
        # Create some binary files
        (x64_dir / "test.dll").write_bytes(b"")
        (x64_dir / "test.exe").write_bytes(b"")
        (x64_dir / "test.txt").write_bytes(b"")  # Should not be listed
        
        result = list_extracted_files("KB5034441", extracted_dir=tmp_path)
        
        assert len(result) == 2
        assert all(p.suffix in [".dll", ".exe"] for p in result)
    
    def test_list_extracted_files_normalizes_kb(self, tmp_path: Path):
        """Test that KB number is normalized."""
        kb_dir = tmp_path / "KB5034441"
        kb_dir.mkdir()
        (kb_dir / "test.dll").write_bytes(b"")
        
        # Without prefix
        result = list_extracted_files("5034441", extracted_dir=tmp_path)
        assert len(result) == 1
    
    def test_list_extracted_files_not_found(self, tmp_path: Path):
        """Test listing for non-existent KB."""
        result = list_extracted_files("KB9999999", extracted_dir=tmp_path)
        
        assert result == []


class TestGetExtractionStats:
    """Tests for get_extraction_stats function."""
    
    def test_get_extraction_stats_empty(self, tmp_path: Path):
        """Test stats for non-existent KB."""
        result = get_extraction_stats("KB9999999", extracted_dir=tmp_path)
        
        assert result["total"] == 0
        assert result["by_arch"] == {}
        assert result["by_type"] == {}
    
    def test_get_extraction_stats_with_files(self, tmp_path: Path):
        """Test stats with extracted files."""
        kb_dir = tmp_path / "KB5034441"
        x64_dir = kb_dir / "x64"
        x86_dir = kb_dir / "x86"
        x64_dir.mkdir(parents=True)
        x86_dir.mkdir(parents=True)
        
        (x64_dir / "test1.dll").write_bytes(b"")
        (x64_dir / "test2.dll").write_bytes(b"")
        (x86_dir / "test3.exe").write_bytes(b"")
        
        result = get_extraction_stats("KB5034441", extracted_dir=tmp_path)
        
        assert result["total"] == 3
        assert result["by_arch"]["x64"] == 2
        assert result["by_arch"]["x86"] == 1
        assert result["by_type"][".dll"] == 2
        assert result["by_type"][".exe"] == 1
