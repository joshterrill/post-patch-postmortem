"""Tests for patch_tuesday.cli module."""

from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from patch_tuesday.cli import (
    cli,
    print_header,
)
from patch_tuesday.models import CVE, Patch, Product, Severity


@pytest.fixture
def runner() -> CliRunner:
    """Create a CLI runner."""
    return CliRunner()


class TestPrintHeader:
    """Tests for print_header function."""
    
    def test_print_header(self, capsys):
        """Test that header prints without error."""
        print_header()
        # Should not raise


class TestCliGroup:
    """Tests for main CLI group."""
    
    def test_cli_help(self, runner: CliRunner):
        """Test CLI help output."""
        result = runner.invoke(cli, ["--help"])
        
        assert result.exit_code == 0
        assert "Patch Tuesday Analyzer" in result.output
    
    def test_cli_version(self, runner: CliRunner):
        """Test CLI version output."""
        result = runner.invoke(cli, ["--version"])
        
        assert result.exit_code == 0
        assert "0.1.0" in result.output


class TestFetchCommand:
    """Tests for fetch command."""
    
    def test_fetch_help(self, runner: CliRunner):
        """Test fetch help output."""
        result = runner.invoke(cli, ["fetch", "--help"])
        
        assert result.exit_code == 0
        assert "--date" in result.output
        assert "--count" in result.output
    
    def test_fetch_invalid_date(self, runner: CliRunner):
        """Test fetch with invalid date format."""
        result = runner.invoke(cli, ["fetch", "-d", "invalid"])
        
        assert result.exit_code == 0  # Click doesn't fail, we handle it
        assert "Invalid date format" in result.output
    
    def test_fetch_invalid_month(self, runner: CliRunner):
        """Test fetch with invalid month."""
        result = runner.invoke(cli, ["fetch", "-d", "2024-13"])
        
        assert "Invalid date format" in result.output or "Month must be" in result.output
    
    def test_fetch_by_date(self, runner: CliRunner, temp_db_path: Path):
        """Test fetch with date parameter."""
        with patch("patch_tuesday.cli.init_db"):
            with patch("patch_tuesday.cli.fetch_by_date") as mock_fetch:
                mock_fetch.return_value = {
                    "update_id": "2024-Jan",
                    "patches": 10,
                    "products": 5,
                    "cves": 100,
                }
                
                result = runner.invoke(cli, ["fetch", "-d", "2024-01"])
        
        assert result.exit_code == 0
        mock_fetch.assert_called_once_with(2024, 1, verbose=True)
    
    def test_fetch_latest(self, runner: CliRunner):
        """Test fetch without date (latest)."""
        with patch("patch_tuesday.cli.init_db"):
            with patch("patch_tuesday.cli.fetch_latest") as mock_fetch:
                mock_fetch.return_value = [{"update_id": "2024-Jan", "patches": 10, "cves": 100}]
                
                result = runner.invoke(cli, ["fetch", "-n", "1"])
        
        assert result.exit_code == 0
        mock_fetch.assert_called_once_with(1, verbose=True)


class TestUpdatesCommand:
    """Tests for updates command."""
    
    def test_updates_help(self, runner: CliRunner):
        """Test updates help output."""
        result = runner.invoke(cli, ["updates", "--help"])
        
        assert result.exit_code == 0
        assert "--year" in result.output
    
    def test_updates_list(self, runner: CliRunner):
        """Test listing available updates."""
        with patch("patch_tuesday.cli.get_update_ids") as mock_get:
            mock_get.return_value = ["2024-Jan", "2024-Feb", "2023-Dec"]
            
            result = runner.invoke(cli, ["updates"])
        
        assert result.exit_code == 0
        assert "2024-Jan" in result.output
    
    def test_updates_filter_year(self, runner: CliRunner):
        """Test listing updates filtered by year."""
        with patch("patch_tuesday.cli.get_update_ids") as mock_get:
            mock_get.return_value = ["2024-Jan", "2024-Feb"]
            
            result = runner.invoke(cli, ["updates", "-y", "2024"])
        
        assert result.exit_code == 0
        mock_get.assert_called_with(2024)


class TestListCommand:
    """Tests for list command."""
    
    def test_list_help(self, runner: CliRunner):
        """Test list help output."""
        result = runner.invoke(cli, ["list", "--help"])
        
        assert result.exit_code == 0
        assert "--date" in result.output
        assert "--product" in result.output
        assert "--severity" in result.output
    
    def test_list_no_patches(self, runner: CliRunner):
        """Test list with no patches in database."""
        with patch("patch_tuesday.cli.init_db"):
            with patch("patch_tuesday.cli.get_db") as mock_db:
                mock_db.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_db.return_value.__exit__ = MagicMock(return_value=False)
                
                with patch("patch_tuesday.cli.get_patches_by_date", return_value=[]):
                    result = runner.invoke(cli, ["list"])
        
        assert result.exit_code == 0
        assert "No patches found" in result.output
    
    def test_list_with_patches(self, runner: CliRunner, sample_patch: Patch):
        """Test list with patches."""
        with patch("patch_tuesday.cli.init_db"):
            with patch("patch_tuesday.cli.get_db") as mock_db:
                mock_db.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_db.return_value.__exit__ = MagicMock(return_value=False)
                
                with patch("patch_tuesday.cli.get_patches_by_date", return_value=[sample_patch]):
                    result = runner.invoke(cli, ["list"])
        
        assert result.exit_code == 0
        assert "KB5034441" in result.output
    
    def test_list_by_product(self, runner: CliRunner, sample_patch: Patch):
        """Test list filtered by product."""
        with patch("patch_tuesday.cli.init_db"):
            with patch("patch_tuesday.cli.get_db") as mock_db:
                mock_db.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_db.return_value.__exit__ = MagicMock(return_value=False)
                
                with patch("patch_tuesday.cli.get_patches_by_product", return_value=[sample_patch]):
                    result = runner.invoke(cli, ["list", "-p", "Windows 11"])
        
        assert result.exit_code == 0
    
    def test_list_invalid_date(self, runner: CliRunner):
        """Test list with invalid date."""
        with patch("patch_tuesday.cli.init_db"):
            with patch("patch_tuesday.cli.get_db") as mock_db:
                mock_db.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_db.return_value.__exit__ = MagicMock(return_value=False)
                
                result = runner.invoke(cli, ["list", "-d", "invalid"])
        
        assert result.exit_code == 0
        assert "Invalid date format" in result.output


class TestShowCommand:
    """Tests for show command."""
    
    def test_show_help(self, runner: CliRunner):
        """Test show help output."""
        result = runner.invoke(cli, ["show", "--help"])
        
        assert result.exit_code == 0
    
    def test_show_patch_not_found(self, runner: CliRunner):
        """Test showing non-existent patch."""
        with patch("patch_tuesday.cli.init_db"):
            with patch("patch_tuesday.cli.get_db") as mock_db:
                mock_db.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_db.return_value.__exit__ = MagicMock(return_value=False)
                
                with patch("patch_tuesday.cli.get_patch", return_value=None):
                    result = runner.invoke(cli, ["show", "KB9999999"])
        
        assert result.exit_code == 0
        assert "not found" in result.output
    
    def test_show_patch_with_details(
        self,
        runner: CliRunner,
        sample_patch: Patch,
        sample_product: Product,
        sample_cve: CVE,
    ):
        """Test showing patch with products and CVEs."""
        sample_patch.products = [sample_product]
        sample_patch.cves = [sample_cve]
        
        with patch("patch_tuesday.cli.init_db"):
            with patch("patch_tuesday.cli.get_db") as mock_db:
                mock_db.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_db.return_value.__exit__ = MagicMock(return_value=False)
                
                with patch("patch_tuesday.cli.get_patch", return_value=sample_patch):
                    result = runner.invoke(cli, ["show", "KB5034441"])
        
        assert result.exit_code == 0
        assert "KB5034441" in result.output
        assert "Windows 11" in result.output
        assert "CVE-2024-12345" in result.output


class TestStatsCommand:
    """Tests for stats command."""
    
    def test_stats(self, runner: CliRunner):
        """Test stats command."""
        with patch("patch_tuesday.cli.init_db"):
            with patch("patch_tuesday.cli.get_db") as mock_db:
                mock_db.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_db.return_value.__exit__ = MagicMock(return_value=False)
                
                with patch("patch_tuesday.cli.get_stats") as mock_stats:
                    mock_stats.return_value = {
                        "patches": 10,
                        "products": 5,
                        "cves": 100,
                        "downloaded_files": 2,
                        "latest_patch_date": "2024-01-09",
                    }
                    
                    result = runner.invoke(cli, ["stats"])
        
        assert result.exit_code == 0
        assert "10" in result.output
        assert "Database Statistics" in result.output


class TestDownloadCommand:
    """Tests for download command."""
    
    def test_download_help(self, runner: CliRunner):
        """Test download help output."""
        result = runner.invoke(cli, ["download", "--help"])
        
        assert result.exit_code == 0
        assert "--arch" in result.output
        assert "--list-only" in result.output
    
    def test_download_list_only(self, runner: CliRunner):
        """Test download with list-only flag."""
        with patch("patch_tuesday.cli.list_catalog_entries") as mock_list:
            result = runner.invoke(cli, ["download", "KB5034441", "-l"])
        
        assert result.exit_code == 0
        mock_list.assert_called_once()
    
    def test_download_packages(self, runner: CliRunner, tmp_path: Path):
        """Test downloading packages."""
        with patch("patch_tuesday.cli.download_by_kb") as mock_download:
            mock_download.return_value = [tmp_path / "test.msu"]
            
            result = runner.invoke(cli, ["download", "KB5034441"])
        
        assert result.exit_code == 0
        mock_download.assert_called_once()


class TestExtractCommand:
    """Tests for extract command."""
    
    def test_extract_help(self, runner: CliRunner):
        """Test extract help output."""
        result = runner.invoke(cli, ["extract", "--help"])
        
        assert result.exit_code == 0
        assert "--save-db" in result.output
    
    def test_extract_no_packages(self, runner: CliRunner):
        """Test extract with no packages found."""
        with patch("patch_tuesday.cli.init_db"):
            with patch("patch_tuesday.cli.extract_by_kb", return_value=[]):
                result = runner.invoke(cli, ["extract", "KB9999999"])
        
        assert result.exit_code == 0
        assert "No files extracted" in result.output
    
    def test_extract_with_save(self, runner: CliRunner, sample_downloaded_file):
        """Test extract with database save."""
        with patch("patch_tuesday.cli.init_db"):
            with patch("patch_tuesday.cli.extract_by_kb", return_value=[sample_downloaded_file]):
                with patch("patch_tuesday.cli.get_db") as mock_db:
                    mock_db.return_value.__enter__ = MagicMock(return_value=MagicMock())
                    mock_db.return_value.__exit__ = MagicMock(return_value=False)
                    
                    with patch("patch_tuesday.cli.add_downloaded_file"):
                        with patch("patch_tuesday.cli.get_extraction_stats") as mock_stats:
                            mock_stats.return_value = {"total": 1, "by_arch": {"x64": 1}, "by_type": {".dll": 1}}
                            
                            result = runner.invoke(cli, ["extract", "KB5034441", "-s"])
        
        assert result.exit_code == 0


class TestFilesCommand:
    """Tests for files command."""
    
    def test_files_no_files(self, runner: CliRunner):
        """Test files command with no extracted files."""
        with patch("patch_tuesday.cli.list_extracted_files", return_value=[]):
            result = runner.invoke(cli, ["files", "KB9999999"])
        
        assert result.exit_code == 0
        assert "No extracted files found" in result.output
    
    def test_files_with_files(self, runner: CliRunner, tmp_path: Path):
        """Test files command with extracted files."""
        test_file = tmp_path / "test.dll"
        test_file.write_bytes(b"test content")
        
        with patch("patch_tuesday.cli.list_extracted_files", return_value=[test_file]):
            result = runner.invoke(cli, ["files", "KB5034441"])
        
        assert result.exit_code == 0
        assert "test.dll" in result.output


class TestBaselineCommand:
    """Tests for baseline command."""
    
    def test_baseline_help(self, runner: CliRunner):
        """Test baseline help output."""
        result = runner.invoke(cli, ["baseline", "--help"])
        
        assert result.exit_code == 0
    
    def test_baseline_no_extracted(self, runner: CliRunner, tmp_path: Path):
        """Test baseline with no extracted files."""
        with patch("patch_tuesday.cli.init_db"):
            with patch("patch_tuesday.cli.DEFAULT_EXTRACTED_DIR", tmp_path):
                result = runner.invoke(cli, ["baseline", "KB9999999"])
        
        assert result.exit_code == 0
        assert "No extracted files found" in result.output


class TestVersionsCommand:
    """Tests for versions command."""
    
    def test_versions_help(self, runner: CliRunner):
        """Test versions help output."""
        result = runner.invoke(cli, ["versions", "--help"])
        
        assert result.exit_code == 0
        assert "--arch" in result.output
    
    def test_versions_lookup(self, runner: CliRunner):
        """Test looking up file versions."""
        with patch("patch_tuesday.cli.show_file_versions") as mock_show:
            result = runner.invoke(cli, ["versions", "ntdll.dll"])
        
        assert result.exit_code == 0
        mock_show.assert_called_once()


class TestDiffCommand:
    """Tests for diff command."""
    
    def test_diff_help(self, runner: CliRunner):
        """Test diff help output."""
        result = runner.invoke(cli, ["diff", "--help"])
        
        assert result.exit_code == 0
    
    def test_diff_no_extracted(self, runner: CliRunner, tmp_path: Path):
        """Test diff with no extracted files."""
        with patch("patch_tuesday.cli.init_db"):
            with patch("patch_tuesday.cli.DEFAULT_EXTRACTED_DIR", tmp_path):
                result = runner.invoke(cli, ["diff", "KB9999999"])
        
        assert result.exit_code == 0
        assert "No extracted files found" in result.output
    
    def test_diff_with_files(self, runner: CliRunner, tmp_path: Path):
        """Test diff with extracted files."""
        kb_dir = tmp_path / "KB5034441"
        x64_dir = kb_dir / "x64"
        x64_dir.mkdir(parents=True)
        test_file = x64_dir / "test.dll"
        test_file.write_bytes(b"content")
        
        with patch("patch_tuesday.cli.init_db"):
            with patch("patch_tuesday.cli.DEFAULT_EXTRACTED_DIR", tmp_path):
                with patch("patch_tuesday.cli.DEFAULT_BASELINE_DIR", tmp_path / "baseline"):
                    with patch("patch_tuesday.cli.list_extracted_files", return_value=[test_file]):
                        result = runner.invoke(cli, ["diff", "KB5034441"])
        
        assert result.exit_code == 0
        assert "test.dll" in result.output


class TestBindiffCommand:
    """Tests for bindiff command."""
    
    def test_bindiff_help(self, runner: CliRunner):
        """Test bindiff help output."""
        result = runner.invoke(cli, ["bindiff", "--help"])
        
        assert result.exit_code == 0
        assert "BinDiff" in result.output or "bindiff" in result.output.lower()
    
    def test_bindiff_check_deps(self, runner: CliRunner):
        """Test bindiff --check-deps flag."""
        with patch("patch_tuesday.bindiff_client.check_dependencies") as mock_check:
            with patch("patch_tuesday.bindiff_client._find_binexport_extension", return_value=None):
                mock_check.return_value = {
                    "ghidra": (False, None),
                    "bindiff": (False, None),
                    "binexport": (False, None),
                }
                
                result = runner.invoke(cli, ["bindiff", "KB5034441", "--check-deps"])
        
        assert result.exit_code == 0
        mock_check.assert_called_once()
    
    def test_bindiff_no_kb(self, runner: CliRunner):
        """Test bindiff without KB number and without check-deps."""
        result = runner.invoke(cli, ["bindiff"])
        
        # Should show missing argument or help
        assert result.exit_code != 0 or "KB" in result.output or "Missing" in result.output or "Usage" in result.output
    
    def test_bindiff_no_extracted_files(self, runner: CliRunner, tmp_path: Path):
        """Test bindiff when no extracted files exist."""
        with patch("patch_tuesday.cli.init_db"):
            with patch("patch_tuesday.cli.DEFAULT_EXTRACTED_DIR", tmp_path):
                result = runner.invoke(cli, ["bindiff", "KB9999999"])
        
        assert result.exit_code == 0
        assert "No extracted files" in result.output or "not found" in result.output.lower()
    
    def test_bindiff_with_extracted_no_baseline(self, runner: CliRunner, tmp_path: Path):
        """Test bindiff with extracted files but no baseline."""
        kb_dir = tmp_path / "KB5034441"
        x64_dir = kb_dir / "x64"
        x64_dir.mkdir(parents=True)
        test_file = x64_dir / "test.dll"
        test_file.write_bytes(b"content")
        
        baseline_dir = tmp_path / "baseline"
        
        with patch("patch_tuesday.cli.init_db"):
            with patch("patch_tuesday.cli.DEFAULT_EXTRACTED_DIR", tmp_path):
                with patch("patch_tuesday.cli.DEFAULT_BASELINE_DIR", baseline_dir):
                    result = runner.invoke(cli, ["bindiff", "KB5034441"])
        
        assert result.exit_code == 0
    
    def test_bindiff_deps_found(self, runner: CliRunner):
        """Test bindiff --check-deps when tools are found."""
        with patch("patch_tuesday.bindiff_client.check_dependencies") as mock_check:
            with patch("patch_tuesday.bindiff_client._find_binexport_extension", return_value=Path("/opt/ghidra/Extensions/BinExport")):
                mock_check.return_value = {
                    "ghidra": (True, Path("/opt/ghidra")),
                    "bindiff": (True, Path("/usr/local/bin/bindiff")),
                    "binexport": (True, Path("/opt/ghidra/Extensions/BinExport")),
                }
                
                result = runner.invoke(cli, ["bindiff", "KB5034441", "--check-deps"])
        
        assert result.exit_code == 0
        mock_check.assert_called_once()
