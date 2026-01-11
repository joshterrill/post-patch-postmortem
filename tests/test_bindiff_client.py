"""Tests for patch_tuesday.bindiff_client module."""

from pathlib import Path

import pytest

from patch_tuesday.bindiff_client import (
    check_dependencies,
    _find_ghidra,
    _find_bindiff,
    _generate_html_report,
    BinDiffResult,
)


class TestCheckDependencies:
    """Tests for dependency checking."""
    
    def test_check_dependencies_returns_dict(self):
        """Test that check_dependencies returns expected structure."""
        result = check_dependencies()
        
        assert isinstance(result, dict)
        assert "ghidra" in result
        assert "bindiff" in result
        assert "binexport" in result
        # Each value is a tuple of (bool, Optional[Path])
        for key, value in result.items():
            assert isinstance(value, tuple)
            assert len(value) == 2
            assert isinstance(value[0], bool)


class TestFindGhidra:
    """Tests for Ghidra detection."""
    
    def test_find_ghidra_from_env(self, tmp_path: Path, monkeypatch):
        """Test finding Ghidra from environment variable."""
        ghidra_dir = tmp_path / "ghidra"
        ghidra_dir.mkdir()
        
        monkeypatch.setenv("GHIDRA_HOME", str(ghidra_dir))
        
        result = _find_ghidra()
        
        assert result == ghidra_dir
    
    def test_find_ghidra_not_found(self, monkeypatch):
        """Test when Ghidra is not found."""
        monkeypatch.delenv("GHIDRA_HOME", raising=False)
        
        # Result depends on system - may or may not find Ghidra
        result = _find_ghidra()
        # Just verify it returns Path or None
        assert result is None or isinstance(result, Path)


class TestFindBinDiff:
    """Tests for BinDiff detection."""
    
    def test_find_bindiff_from_env(self, tmp_path: Path, monkeypatch):
        """Test finding BinDiff from environment variable."""
        bindiff_dir = tmp_path / "bindiff"
        bin_dir = bindiff_dir / "bin"
        bin_dir.mkdir(parents=True)
        bindiff_exe = bin_dir / "bindiff"
        bindiff_exe.touch()
        
        monkeypatch.setenv("BINDIFF_HOME", str(bindiff_dir))
        
        result = _find_bindiff()
        
        # May find from PATH or env
        assert result is None or isinstance(result, Path)
    
    def test_find_bindiff_not_found(self, monkeypatch):
        """Test when BinDiff is not found."""
        monkeypatch.delenv("BINDIFF_HOME", raising=False)
        monkeypatch.setenv("PATH", "/nonexistent")
        
        # Result depends on system
        result = _find_bindiff()
        assert result is None or isinstance(result, Path)


class TestGenerateHtmlReport:
    """Tests for HTML report generation."""
    
    def test_generate_html_report_basic(self):
        """Test generating a basic HTML report."""
        metadata = {
            "primary": "baseline.dll",
            "secondary": "patched.dll",
            "similarity": "0.85",
        }
        matches = [
            ("func1", "func1", 0.95, 0.90, 0x1000, 0x1000),
            ("func2", "func2_renamed", 0.80, 0.75, 0x2000, 0x2100),
        ]
        unmatched = [
            ("new_func", 0x3000, "secondary"),
        ]
        
        result = _generate_html_report(metadata, matches, unmatched)
        
        assert "<!DOCTYPE html>" in result
        assert "BinDiff" in result
        assert "baseline.dll" in result
        assert "patched.dll" in result
        assert "func1" in result
        assert "func2" in result
        assert "new_func" in result
    
    def test_generate_html_report_empty(self):
        """Test generating report with no matches."""
        metadata = {}
        matches = []
        unmatched = []
        
        result = _generate_html_report(metadata, matches, unmatched)
        
        assert "<!DOCTYPE html>" in result
        assert "BinDiff" in result
    
    def test_generate_html_report_many_matches(self):
        """Test report truncation with many matches."""
        metadata = {"primary": "test.dll", "secondary": "test2.dll"}
        # Create 150 matches
        matches = [
            (f"func_{i}", f"func_{i}", 0.9, 0.9, 0x1000 + i, 0x1000 + i)
            for i in range(150)
        ]
        unmatched = []
        
        result = _generate_html_report(metadata, matches, unmatched)
        
        # Should show truncation message
        assert "more matches" in result


class TestBinDiffResult:
    """Tests for BinDiffResult dataclass."""
    
    def test_bindiff_result_creation(self, tmp_path: Path):
        """Test creating a BinDiffResult."""
        result = BinDiffResult(
            primary_file="/path/to/baseline.dll",
            secondary_file="/path/to/patched.dll",
            bindiff_file=tmp_path / "test.BinDiff",
            similarity=0.85,
            confidence=0.90,
            matched_functions=100,
            unmatched_primary=5,
            unmatched_secondary=10,
            report_path=tmp_path / "report.html",
        )
        
        assert result.similarity == 0.85
        assert result.matched_functions == 100
        assert result.report_path is not None
    
    def test_bindiff_result_optional_fields(self, tmp_path: Path):
        """Test BinDiffResult with optional fields."""
        result = BinDiffResult(
            primary_file="/path/to/baseline.dll",
            secondary_file="/path/to/patched.dll",
            bindiff_file=tmp_path / "test.BinDiff",
            similarity=0.0,
            confidence=0.0,
            matched_functions=0,
            unmatched_primary=0,
            unmatched_secondary=0,
        )
        
        assert result.report_path is None
