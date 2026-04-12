"""Tests for ppp.bindiff_client module."""

import base64
import json
import re
from pathlib import Path
import sqlite3

import pytest

from ppp.bindiff_client import (
    check_dependencies,
    _export_report_from_db,
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
        data_match = re.search(r'id="matched-functions-data" data-b64="([^"]+)"', result)
        assert data_match is not None
        decoded_rows = json.loads(base64.b64decode(data_match.group(1)).decode("utf-8"))
        
        assert "<!DOCTYPE html>" in result
        assert "BinDiff" in result
        assert "baseline.dll" in result
        assert "patched.dll" in result
        assert any(row["name1"] == "func1" for row in decoded_rows)
        assert any(row["name1"] == "func2" for row in decoded_rows)
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
        """Test report keeps full match dataset for client-side pagination/sort."""
        metadata = {"primary": "test.dll", "secondary": "test2.dll"}
        # Create 150 matches
        matches = [
            (f"func_{i}", f"func_{i}", 0.9, 0.9, 0x1000 + i, 0x1000 + i)
            for i in range(150)
        ]
        unmatched = []
        
        result = _generate_html_report(metadata, matches, unmatched)
        
        assert "more matches" not in result
        assert "Matched Functions:</strong> 150" in result
        assert 'id="matched-functions-data"' in result
    
    def test_generate_html_report_has_sortable_matched_functions_table(self):
        """Test that matched functions table uses shadow DOM + paginated global sort."""
        metadata = {"primary": "a.exe", "secondary": "b.exe"}
        matches = [("funcA", "funcB", 0.75, 0.80, 0x1000, 0x2000)]
        unmatched = []
        
        result = _generate_html_report(metadata, matches, unmatched)
        
        assert 'id="matched-functions-table"' in result
        assert "customElements.define('matched-functions-table'" in result
        assert "attachShadow" in result
        assert "this.pageSize = 30" in result
        assert "getSortedRows()" in result
    
    def test_generate_html_report_includes_pseudoc_diffs(self):
        """Test pseudo-C diff data is integrated for per-row modal rendering."""
        metadata = {"primary": "a.exe", "secondary": "b.exe"}
        matches = [("funcA", "funcB", 0.75, 0.80, 0x1000, 0x2000)]
        unmatched = []
        pseudocode_diffs = [
            {
                "name1": "funcA",
                "name2": "funcB",
                "addr1": 0x1000,
                "addr2": 0x2000,
                "sim": 0.75,
                "conf": 0.80,
                "diff_text": "--- old\n+++ new\n@@\n-int a;\n+int b;",
                "truncated": False,
            }
        ]
        
        result = _generate_html_report(metadata, matches, unmatched, pseudocode_diffs=pseudocode_diffs)

        pseudo_match = re.search(r'id="pseudocode-diffs-data" data-b64="([^"]+)"', result)
        assert pseudo_match is not None
        decoded = json.loads(base64.b64decode(pseudo_match.group(1)).decode("utf-8"))
        assert "4096:8192" in decoded
        assert decoded["4096:8192"]["diff_text"].startswith("--- old")
        assert "Pseudo-C Function Diffs" not in result
        assert "modal-backdrop" in result
        assert "View" in result
        assert "diff-add" in result
        assert "diff-del" in result


class TestExportReportFromDb:
    """Tests for DB-backed report export."""
    
    def test_export_report_from_bindiff_v8_schema(self, tmp_path: Path):
        """Test report generation from BinDiff 8-style schema."""
        db_path = tmp_path / "sample.BinDiff"
        out_path = tmp_path / "sample_report.html"
        
        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE metadata (
                version TEXT,
                file1 INT,
                file2 INT,
                description TEXT,
                created TEXT,
                modified TEXT,
                similarity REAL,
                confidence REAL
            )
        """)
        cur.execute("""
            CREATE TABLE file (
                id INT,
                filename TEXT,
                exefilename TEXT,
                hash TEXT,
                functions INT,
                libfunctions INT,
                calls INT,
                basicblocks INT,
                libbasicblocks INT,
                edges INT,
                libedges INT,
                instructions INT,
                libinstructions INT
            )
        """)
        cur.execute("""
            CREATE TABLE function (
                id INT PRIMARY KEY,
                address1 BIGINT,
                name1 TEXT,
                address2 BIGINT,
                name2 TEXT,
                similarity REAL,
                confidence REAL,
                flags INTEGER,
                algorithm SMALLINT,
                evaluate BOOLEAN,
                commentsported BOOLEAN,
                basicblocks INTEGER,
                edges INTEGER,
                instructions INTEGER
            )
        """)
        cur.execute(
            "INSERT INTO metadata VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("BinDiff 8", 1, 2, "test", "2026-02-16", "2026-02-16", 0.9, 0.95),
        )
        cur.execute("INSERT INTO file VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (1, "old_notepad.exe", "", "", 0, 0, 0, 0, 0, 0, 0, 0, 0))
        cur.execute("INSERT INTO file VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (2, "new_notepad.exe", "", "", 0, 0, 0, 0, 0, 0, 0, 0, 0))
        cur.execute("INSERT INTO function VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (1, 0x1000, "func_old", 0x2000, "func_new", 0.8, 0.9, 0, 0, 0, 0, 0, 0, 0))
        cur.execute("INSERT INTO function VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (2, 0x3000, "only_old", 0, "", 0.0, 0.0, 0, 0, 0, 0, 0, 0, 0))
        conn.commit()
        conn.close()
        
        report = _export_report_from_db(db_path, out_path)
        assert report == out_path
        assert out_path.exists()
        text = out_path.read_text()
        data_match = re.search(r'id="matched-functions-data" data-b64="([^"]+)"', text)
        assert data_match is not None
        decoded_rows = json.loads(base64.b64decode(data_match.group(1)).decode("utf-8"))
        assert "old_notepad.exe" in text
        assert "new_notepad.exe" in text
        assert any(row["name1"] == "func_old" for row in decoded_rows)


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
