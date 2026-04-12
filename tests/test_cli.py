"""Tests for ppp.cli module."""

from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from ppp.cli import (
    cli,
    print_header,
)
from ppp.models import Architecture, CVE, Patch, Product, Severity, WinBIndexFile


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
        assert "analyze" in result.output
        assert "lookup" in result.output
        assert "fetch" in result.output
        assert "list" in result.output
        assert "show" in result.output
        assert "binary-diff" not in result.output
        assert "bindiff" not in result.output
        assert "versions" not in result.output
    
    def test_cli_version(self, runner: CliRunner):
        """Test CLI version output."""
        result = runner.invoke(cli, ["--version"])
        
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_lookup_help(self, runner: CliRunner):
        """Test lookup group help output."""
        result = runner.invoke(cli, ["lookup", "--help"])

        assert result.exit_code == 0
        assert "file" in result.output
        assert "cve" in result.output

    def test_analyze_help(self, runner: CliRunner):
        """Test analyze group help output."""
        result = runner.invoke(cli, ["analyze", "--help"])

        assert result.exit_code == 0
        assert "file" in result.output
        assert "kb" in result.output
        assert "month" in result.output
        assert "cve" in result.output


class TestSimplifiedCommands:
    """Tests for the simplified lookup/analyze front door."""

    def test_lookup_file_delegates_to_show_versions(self, runner: CliRunner):
        """Test lookup file delegates to Winbindex listing."""
        with patch("ppp.cli.show_file_versions") as mock_show:
            result = runner.invoke(cli, ["lookup", "file", "tcpip.sys", "-a", "x64", "--limit", "150"])

        assert result.exit_code == 0
        mock_show.assert_called_once_with("tcpip.sys", Architecture.X64, limit=150)

    def test_analyze_file_delegates_to_binary_diff(self, runner: CliRunner):
        """Test analyze file uses the simplified binary workflow."""
        with patch("ppp.cli._run_binary_diff") as mock_binary_diff:
            result = runner.invoke(cli, ["analyze", "file", "tcpip.sys", "-a", "x64", "--kb", "KB5041578", "-l"])

        assert result.exit_code == 0
        mock_binary_diff.assert_called_once_with(
            filename="tcpip.sys",
            arch="x64",
            kb="KB5041578",
            new_version=None,
            old_version=None,
            new_build=None,
            old_build=None,
            new_date=None,
            old_date=None,
            limit=200,
            list_only=True,
            report=False,
            pseudo_c=False,
            overwrite=False,
        )

    def test_analyze_kb_runs_pipeline(self, runner: CliRunner):
        """Test analyze kb uses the end-to-end KB pipeline."""
        with patch("ppp.cli.print_header"):
            with patch("ppp.cli.init_db"):
                with patch("ppp.cli._run_kb_pipeline") as mock_pipeline:
                    result = runner.invoke(cli, ["analyze", "kb", "KB5041578", "-a", "x64"])

        assert result.exit_code == 0
        mock_pipeline.assert_called_once_with(
            "KB5041578",
            architecture=Architecture.X64,
            save_db=False,
            report=True,
        )


class TestFetchCommand:
    """Tests for fetch command."""
    
    def test_fetch_help(self, runner: CliRunner):
        """Test fetch help output."""
        result = runner.invoke(cli, ["fetch", "--help"])
        
        assert result.exit_code == 0
        assert "--date" in result.output
        assert "--count" in result.output
        assert "--source" in result.output
    
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
        with patch("ppp.cli.init_db"):
            with patch("ppp.cli.fetch_by_date") as mock_fetch:
                mock_fetch.return_value = {
                    "update_id": "2024-Jan",
                    "patches": 10,
                    "products": 5,
                    "cves": 100,
                }
                
                result = runner.invoke(cli, ["fetch", "-d", "2024-01"])
        
        assert result.exit_code == 0
        mock_fetch.assert_called_once_with(2024, 1, verbose=False)
    
    def test_fetch_latest(self, runner: CliRunner):
        """Test fetch without date (latest)."""
        with patch("ppp.cli.init_db"):
            with patch("ppp.cli.fetch_latest") as mock_fetch:
                mock_fetch.return_value = [{"update_id": "2024-Jan", "patches": 10, "cves": 100}]
                
                result = runner.invoke(cli, ["fetch", "-n", "1"])
        
        assert result.exit_code == 0
        mock_fetch.assert_called_once_with(1, verbose=False, prefer_rss=True)


class TestUpdatesCommand:
    """Tests for updates command."""
    
    def test_updates_help(self, runner: CliRunner):
        """Test updates help output."""
        result = runner.invoke(cli, ["updates", "--help"])
        
        assert result.exit_code == 0
        assert "--year" in result.output
    
    def test_updates_list(self, runner: CliRunner):
        """Test listing available updates."""
        with patch("ppp.cli.get_update_ids") as mock_get:
            mock_get.return_value = ["2024-Jan", "2024-Feb", "2023-Dec"]
            
            result = runner.invoke(cli, ["updates"])
        
        assert result.exit_code == 0
        assert "2024-Jan" in result.output
    
    def test_updates_filter_year(self, runner: CliRunner):
        """Test listing updates filtered by year."""
        with patch("ppp.cli.get_update_ids") as mock_get:
            mock_get.return_value = ["2024-Jan", "2024-Feb"]
            
            result = runner.invoke(cli, ["updates", "-y", "2024"])
        
        assert result.exit_code == 0
        mock_get.assert_called_with(2024, prefer_rss=True)


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
        with patch("ppp.cli.init_db"):
            with patch("ppp.cli.get_db") as mock_db:
                mock_db.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_db.return_value.__exit__ = MagicMock(return_value=False)
                
                with patch("ppp.cli.get_patches_by_date", return_value=[]):
                    result = runner.invoke(cli, ["list"])
        
        assert result.exit_code == 0
        assert "No patches found" in result.output
    
    def test_list_with_patches(self, runner: CliRunner, sample_patch: Patch):
        """Test list with patches."""
        with patch("ppp.cli.init_db"):
            with patch("ppp.cli.get_db") as mock_db:
                mock_db.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_db.return_value.__exit__ = MagicMock(return_value=False)
                
                with patch("ppp.cli.get_patches_by_date", return_value=[sample_patch]):
                    result = runner.invoke(cli, ["list"])
        
        assert result.exit_code == 0
        assert "KB5034441" in result.output
        assert sample_patch.release_date.strftime("%Y-%m-%d") in result.output
    
    def test_list_by_product(self, runner: CliRunner, sample_patch: Patch):
        """Test list filtered by product."""
        with patch("ppp.cli.init_db"):
            with patch("ppp.cli.get_db") as mock_db:
                mock_db.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_db.return_value.__exit__ = MagicMock(return_value=False)
                
                with patch("ppp.cli.get_patches_by_product", return_value=[sample_patch]):
                    result = runner.invoke(cli, ["list", "-p", "Windows 11"])
        
        assert result.exit_code == 0
    
    def test_list_invalid_date(self, runner: CliRunner):
        """Test list with invalid date."""
        with patch("ppp.cli.init_db"):
            with patch("ppp.cli.get_db") as mock_db:
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
        with patch("ppp.cli.init_db"):
            with patch("ppp.cli.get_db") as mock_db:
                mock_db.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_db.return_value.__exit__ = MagicMock(return_value=False)
                
                with patch("ppp.cli.get_patch", return_value=None):
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
        
        with patch("ppp.cli.init_db"):
            with patch("ppp.cli.get_db") as mock_db:
                mock_db.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_db.return_value.__exit__ = MagicMock(return_value=False)
                
                with patch("ppp.cli.get_patch", return_value=sample_patch):
                    result = runner.invoke(cli, ["show", "KB5034441"])
        
        assert result.exit_code == 0
        assert "KB5034441" in result.output
        assert "Windows 11" in result.output
        assert "CVE-2024-12345" in result.output


class TestStatsCommand:
    """Tests for stats command."""
    
    def test_stats(self, runner: CliRunner):
        """Test stats command."""
        with patch("ppp.cli.init_db"):
            with patch("ppp.cli.get_db") as mock_db:
                mock_db.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_db.return_value.__exit__ = MagicMock(return_value=False)
                
                with patch("ppp.cli.get_stats") as mock_stats:
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
        with patch("ppp.cli.list_catalog_entries") as mock_list:
            result = runner.invoke(cli, ["download", "KB5034441", "-l"])
        
        assert result.exit_code == 0
        mock_list.assert_called_once()
    
    def test_download_packages(self, runner: CliRunner, tmp_path: Path):
        """Test downloading packages."""
        with patch("ppp.cli.download_by_kb") as mock_download:
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
        with patch("ppp.cli.init_db"):
            with patch("ppp.cli.extract_by_kb", return_value=[]):
                result = runner.invoke(cli, ["extract", "KB9999999"])
        
        assert result.exit_code == 0
        assert "No files extracted" in result.output
    
    def test_extract_with_save(self, runner: CliRunner, sample_downloaded_file):
        """Test extract with database save."""
        with patch("ppp.cli.init_db"):
            with patch("ppp.cli.extract_by_kb", return_value=[sample_downloaded_file]):
                with patch("ppp.cli.get_db") as mock_db:
                    mock_db.return_value.__enter__ = MagicMock(return_value=MagicMock())
                    mock_db.return_value.__exit__ = MagicMock(return_value=False)
                    
                    with patch("ppp.cli.add_downloaded_file"):
                        with patch("ppp.cli.get_extraction_stats") as mock_stats:
                            mock_stats.return_value = {"total": 1, "by_arch": {"x64": 1}, "by_type": {".dll": 1}}
                            
                            result = runner.invoke(cli, ["extract", "KB5034441", "-s"])
        
        assert result.exit_code == 0


class TestFilesCommand:
    """Tests for files command."""
    
    def test_files_no_files(self, runner: CliRunner):
        """Test files command with no extracted files."""
        with patch("ppp.cli.list_extracted_files", return_value=[]):
            result = runner.invoke(cli, ["files", "KB9999999"])
        
        assert result.exit_code == 0
        assert "No extracted files found" in result.output
    
    def test_files_with_files(self, runner: CliRunner, tmp_path: Path):
        """Test files command with extracted files."""
        test_file = tmp_path / "test.dll"
        test_file.write_bytes(b"test content")
        
        with patch("ppp.cli.list_extracted_files", return_value=[test_file]):
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
        with patch("ppp.cli.init_db"):
            with patch("ppp.cli.DEFAULT_EXTRACTED_DIR", tmp_path):
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
        assert "--limit" in result.output
    
    def test_versions_lookup(self, runner: CliRunner):
        """Test looking up file versions."""
        with patch("ppp.cli.show_file_versions") as mock_show:
            result = runner.invoke(cli, ["versions", "ntdll.dll"])
        
        assert result.exit_code == 0
        mock_show.assert_called_once()

    def test_versions_lookup_with_limit(self, runner: CliRunner):
        """Test looking up file versions with explicit limit."""
        with patch("ppp.cli.show_file_versions") as mock_show:
            result = runner.invoke(cli, ["versions", "ntdll.dll", "-a", "x64", "--limit", "150"])

        assert result.exit_code == 0
        mock_show.assert_called_once_with("ntdll.dll", Architecture.X64, limit=150)


class TestBinaryDiffCommand:
    """Tests for binary-diff command."""
    
    def test_binary_diff_help(self, runner: CliRunner):
        """Test binary-diff help output."""
        result = runner.invoke(cli, ["binary-diff", "--help"])
        
        assert result.exit_code == 0
        assert "--kb" in result.output
        assert "--new-version" in result.output
        assert "--old-version" in result.output
        assert "--new-build" in result.output
        assert "--old-build" in result.output
        assert "--report" in result.output
        assert "--pseudo-c" in result.output
        assert "--overwrite" in result.output
    
    def test_binary_diff_list_only(self, runner: CliRunner):
        """Test binary-diff list-only mode."""
        versions = [
            WinBIndexFile(
                filename="notepad.exe",
                version="11.0.2",
                architecture=Architecture.X64,
                sha256="b" * 64,
                download_url="https://example.com/new",
            ),
            WinBIndexFile(
                filename="notepad.exe",
                version="11.0.1",
                architecture=Architecture.X64,
                sha256="a" * 64,
                download_url="https://example.com/old",
            ),
        ]
        
        with patch("ppp.cli.list_file_versions", return_value=versions):
            with patch("ppp.cli.show_file_versions") as mock_show:
                result = runner.invoke(cli, ["binary-diff", "notepad.exe", "--list-only"])
        
        assert result.exit_code == 0
        mock_show.assert_called_once()
    
    def test_binary_diff_no_versions(self, runner: CliRunner):
        """Test binary-diff when no versions are available."""
        with patch("ppp.cli.list_file_versions", return_value=[]):
            result = runner.invoke(cli, ["binary-diff", "notepad.exe"])
        
        assert result.exit_code == 0
        assert "No versions found" in result.output
    
    def test_binary_diff_runs_pipeline(self, runner: CliRunner, tmp_path: Path):
        """Test end-to-end binary-diff pipeline with mocked dependencies."""
        old_download = tmp_path / "old_notepad.exe"
        new_download = tmp_path / "new_notepad.exe"
        old_download.write_bytes(b"old")
        new_download.write_bytes(b"new")
        bindiff_file = tmp_path / "out.BinDiff"
        bindiff_file.write_bytes(b"sqlite")
        report_file = tmp_path / "out.html"
        report_file.write_text("<html></html>")
        
        versions = [
            WinBIndexFile(
                filename="notepad.exe",
                version="11.0.2",
                architecture=Architecture.X64,
                sha256="b" * 64,
                download_url="https://example.com/new",
            ),
            WinBIndexFile(
                filename="notepad.exe",
                version="11.0.1",
                architecture=Architecture.X64,
                sha256="a" * 64,
                download_url="https://example.com/old",
            ),
        ]
        
        with patch("ppp.cli.list_file_versions", return_value=versions):
            with patch("ppp.bindiff_client.check_dependencies") as mock_deps:
                with patch("ppp.bindiff_client._find_binexport_extension", return_value=tmp_path / "BinExport"):
                    with patch("ppp.cli.download_file_version", side_effect=[old_download, new_download]):
                        with patch("ppp.bindiff_client.export_with_ghidra", return_value=True):
                            with patch("ppp.bindiff_client.run_bindiff", return_value=bindiff_file):
                                with patch("ppp.bindiff_client.export_bindiff_report", return_value=report_file):
                                    mock_deps.return_value = {
                                        "ghidra": (True, tmp_path / "ghidra"),
                                        "bindiff": (True, tmp_path / "bindiff"),
                                        "binexport": (True, tmp_path / "BinExport"),
                                    }
                                    result = runner.invoke(cli, ["binary-diff", "notepad.exe"])
        
        assert result.exit_code == 0
        assert "Binary diff completed" in result.output

    def test_binary_diff_report_auto_includes_pseudocode(self, runner: CliRunner, tmp_path: Path):
        """Test --report automatically enables pseudo-C report generation."""
        old_download = tmp_path / "old_notepad.exe"
        new_download = tmp_path / "new_notepad.exe"
        old_download.write_bytes(b"old")
        new_download.write_bytes(b"new")
        bindiff_file = tmp_path / "out.BinDiff"
        bindiff_file.write_bytes(b"sqlite")
        report_file = tmp_path / "out.html"
        report_file.write_text("<html></html>")

        versions = [
            WinBIndexFile(
                filename="notepad.exe",
                version="11.0.2",
                architecture=Architecture.X64,
                sha256="b" * 64,
                download_url="https://example.com/new",
            ),
            WinBIndexFile(
                filename="notepad.exe",
                version="11.0.1",
                architecture=Architecture.X64,
                sha256="a" * 64,
                download_url="https://example.com/old",
            ),
        ]

        with patch("ppp.cli.list_file_versions", return_value=versions):
            with patch("ppp.bindiff_client.check_dependencies") as mock_deps:
                with patch("ppp.bindiff_client._find_binexport_extension", return_value=tmp_path / "BinExport"):
                    with patch("ppp.cli.download_file_version", side_effect=[old_download, new_download]):
                        with patch("ppp.bindiff_client.export_with_ghidra", return_value=True):
                            with patch("ppp.bindiff_client.run_bindiff", return_value=bindiff_file):
                                with patch("ppp.bindiff_client.export_bindiff_report", return_value=report_file) as mock_export_report:
                                    mock_deps.return_value = {
                                        "ghidra": (True, tmp_path / "ghidra"),
                                        "bindiff": (True, tmp_path / "bindiff"),
                                        "binexport": (True, tmp_path / "BinExport"),
                                    }
                                    result = runner.invoke(cli, ["binary-diff", "notepad.exe", "--report"])

        assert result.exit_code == 0
        assert "`--report` enabled" in result.output
        assert mock_export_report.call_args.kwargs["include_pseudocode"] is True

    def test_binary_diff_selects_newer_by_kb(self, runner: CliRunner, tmp_path: Path):
        """Test selecting the patched side using --kb."""
        old_download = tmp_path / "old_tcpip.sys"
        new_download = tmp_path / "new_tcpip.sys"
        old_download.write_bytes(b"old")
        new_download.write_bytes(b"new")
        bindiff_file = tmp_path / "out.BinDiff"
        bindiff_file.write_bytes(b"sqlite")

        newest_other = WinBIndexFile(
            filename="tcpip.sys",
            version="10.0.17763.7000",
            architecture=Architecture.X64,
            sha256="c" * 64,
            download_url="https://example.com/newest",
            updates=[{"kb_number": "KB9999999", "windows_version": "1809"}],
        )
        selected_kb = WinBIndexFile(
            filename="tcpip.sys",
            version="10.0.17763.6189",
            architecture=Architecture.X64,
            sha256="b" * 64,
            download_url="https://example.com/selected",
            updates=[{"kb_number": "KB5041578", "windows_version": "1809"}],
        )
        previous = WinBIndexFile(
            filename="tcpip.sys",
            version="10.0.17763.6050",
            architecture=Architecture.X64,
            sha256="a" * 64,
            download_url="https://example.com/old",
            updates=[{"kb_number": "KB5040000", "windows_version": "1809"}],
        )

        with patch("ppp.cli.list_file_versions", return_value=[newest_other, selected_kb, previous]):
            with patch("ppp.bindiff_client.check_dependencies") as mock_deps:
                with patch("ppp.bindiff_client._find_binexport_extension", return_value=tmp_path / "BinExport"):
                    with patch("ppp.cli.download_file_version", side_effect=[old_download, new_download]) as mock_download:
                        with patch("ppp.bindiff_client.export_with_ghidra", return_value=True):
                            with patch("ppp.bindiff_client.run_bindiff", return_value=bindiff_file):
                                mock_deps.return_value = {
                                    "ghidra": (True, tmp_path / "ghidra"),
                                    "bindiff": (True, tmp_path / "bindiff"),
                                    "binexport": (True, tmp_path / "BinExport"),
                                }
                                result = runner.invoke(cli, ["binary-diff", "tcpip.sys", "--kb", "KB5041578"])

        assert result.exit_code == 0
        assert "KB5041578" in result.output
        first_call = mock_download.call_args_list[0].args[0]
        second_call = mock_download.call_args_list[1].args[0]
        assert first_call.version == "10.0.17763.6050"
        assert second_call.version == "10.0.17763.6189"

    def test_binary_diff_kb_prefers_same_windows_branch_for_previous(self, runner: CliRunner, tmp_path: Path):
        """Test --kb prefers an older file from the same Windows branch."""
        old_download = tmp_path / "old_tcpip.sys"
        new_download = tmp_path / "new_tcpip.sys"
        old_download.write_bytes(b"old")
        new_download.write_bytes(b"new")
        bindiff_file = tmp_path / "out.BinDiff"
        bindiff_file.write_bytes(b"sqlite")

        selected_kb = WinBIndexFile(
            filename="tcpip.sys",
            version="10.0.17763.6189",
            architecture=Architecture.X64,
            sha256="b" * 64,
            download_url="https://example.com/selected",
            updates=[{"kb_number": "KB5041578", "windows_version": "1809"}],
        )
        wrong_branch_previous = WinBIndexFile(
            filename="tcpip.sys",
            version="10.0.14393.7254",
            architecture=Architecture.X64,
            sha256="c" * 64,
            download_url="https://example.com/wrong",
            updates=[{"kb_number": "KB5041773", "windows_version": "1607"}],
        )
        same_branch_previous = WinBIndexFile(
            filename="tcpip.sys",
            version="10.0.17763.6050",
            architecture=Architecture.X64,
            sha256="a" * 64,
            download_url="https://example.com/right",
            updates=[{"kb_number": "KB5040000", "windows_version": "1809"}],
        )

        with patch(
            "ppp.cli.list_file_versions",
            return_value=[selected_kb, wrong_branch_previous, same_branch_previous],
        ):
            with patch("ppp.bindiff_client.check_dependencies") as mock_deps:
                with patch("ppp.bindiff_client._find_binexport_extension", return_value=tmp_path / "BinExport"):
                    with patch("ppp.cli.download_file_version", side_effect=[old_download, new_download]) as mock_download:
                        with patch("ppp.bindiff_client.export_with_ghidra", return_value=True):
                            with patch("ppp.bindiff_client.run_bindiff", return_value=bindiff_file):
                                mock_deps.return_value = {
                                    "ghidra": (True, tmp_path / "ghidra"),
                                    "bindiff": (True, tmp_path / "bindiff"),
                                    "binexport": (True, tmp_path / "BinExport"),
                                }
                                result = runner.invoke(cli, ["binary-diff", "tcpip.sys", "--kb", "KB5041578"])

        assert result.exit_code == 0
        first_call = mock_download.call_args_list[0].args[0]
        second_call = mock_download.call_args_list[1].args[0]
        assert first_call.version == "10.0.17763.6050"
        assert second_call.version == "10.0.17763.6189"
    
    def test_binary_diff_reuses_cached_exports_and_bindiff(self, runner: CliRunner, tmp_path: Path):
        """Test binary-diff skips expensive steps when cached artifacts exist."""
        old_download = tmp_path / "old_notepad.exe"
        new_download = tmp_path / "new_notepad.exe"
        old_download.write_bytes(b"old")
        new_download.write_bytes(b"new")
        
        versions = [
            WinBIndexFile(
                filename="notepad.exe",
                version="11.0.2",
                architecture=Architecture.X64,
                sha256="b" * 64,
                download_url="https://example.com/new",
            ),
            WinBIndexFile(
                filename="notepad.exe",
                version="11.0.1",
                architecture=Architecture.X64,
                sha256="a" * 64,
                download_url="https://example.com/old",
            ),
        ]
        
        bindiff_root = tmp_path / "bindiff-root"
        exports_root = bindiff_root / "binary" / "notepad.exe" / "exports"
        exports_root.mkdir(parents=True, exist_ok=True)
        (exports_root / "11.0.1_old.BinExport").write_bytes(b"old-export")
        (exports_root / "11.0.2_new.BinExport").write_bytes(b"new-export")
        cached_bindiff = exports_root / "notepad_11.0.1_to_11.0.2.BinDiff"
        cached_bindiff.write_bytes(b"sqlite")
        
        with patch("ppp.cli.list_file_versions", return_value=versions):
            with patch("ppp.bindiff_client.DEFAULT_BINDIFF_DIR", bindiff_root):
                with patch("ppp.bindiff_client.check_dependencies") as mock_deps:
                    with patch("ppp.bindiff_client._find_binexport_extension", return_value=tmp_path / "BinExport"):
                        with patch("ppp.cli.download_file_version", side_effect=[old_download, new_download]):
                            with patch("ppp.bindiff_client.export_with_ghidra") as mock_export:
                                with patch("ppp.bindiff_client.run_bindiff") as mock_run_bindiff:
                                    mock_deps.return_value = {
                                        "ghidra": (True, tmp_path / "ghidra"),
                                        "bindiff": (True, tmp_path / "bindiff"),
                                        "binexport": (True, tmp_path / "BinExport"),
                                    }
                                    result = runner.invoke(cli, ["binary-diff", "notepad.exe"])
        
        assert result.exit_code == 0
        assert "Reusing existing export" in result.output
        assert "Reusing existing BinDiff DB" in result.output
        mock_export.assert_not_called()
        mock_run_bindiff.assert_not_called()
    
    def test_binary_diff_overwrite_forces_regeneration(self, runner: CliRunner, tmp_path: Path):
        """Test --overwrite forces rerun instead of using cached artifacts."""
        old_download = tmp_path / "old_notepad.exe"
        new_download = tmp_path / "new_notepad.exe"
        old_download.write_bytes(b"old")
        new_download.write_bytes(b"new")
        
        versions = [
            WinBIndexFile(
                filename="notepad.exe",
                version="11.0.2",
                architecture=Architecture.X64,
                sha256="b" * 64,
                download_url="https://example.com/new",
            ),
            WinBIndexFile(
                filename="notepad.exe",
                version="11.0.1",
                architecture=Architecture.X64,
                sha256="a" * 64,
                download_url="https://example.com/old",
            ),
        ]
        
        bindiff_root = tmp_path / "bindiff-root"
        exports_root = bindiff_root / "binary" / "notepad.exe" / "exports"
        reports_root = bindiff_root / "binary" / "notepad.exe" / "reports"
        exports_root.mkdir(parents=True, exist_ok=True)
        reports_root.mkdir(parents=True, exist_ok=True)
        (exports_root / "11.0.1_old.BinExport").write_bytes(b"old-export")
        (exports_root / "11.0.2_new.BinExport").write_bytes(b"new-export")
        (exports_root / "notepad_11.0.1_to_11.0.2.BinDiff").write_bytes(b"sqlite-old")
        report_file = reports_root / "notepad_11.0.1_to_11.0.2_report.html"
        report_file.write_text("<html>old</html>")
        
        new_bindiff = tmp_path / "new.BinDiff"
        new_bindiff.write_bytes(b"sqlite-new")
        new_report = tmp_path / "new_report.html"
        new_report.write_text("<html>new</html>")
        
        with patch("ppp.cli.list_file_versions", return_value=versions):
            with patch("ppp.bindiff_client.DEFAULT_BINDIFF_DIR", bindiff_root):
                with patch("ppp.bindiff_client.check_dependencies") as mock_deps:
                    with patch("ppp.bindiff_client._find_binexport_extension", return_value=tmp_path / "BinExport"):
                        with patch("ppp.cli.download_file_version", side_effect=[old_download, new_download]):
                            with patch("ppp.bindiff_client.export_with_ghidra", return_value=True) as mock_export:
                                with patch("ppp.bindiff_client.run_bindiff", return_value=new_bindiff) as mock_run_bindiff:
                                    with patch("ppp.bindiff_client.export_bindiff_report", return_value=new_report) as mock_export_report:
                                        mock_deps.return_value = {
                                            "ghidra": (True, tmp_path / "ghidra"),
                                            "bindiff": (True, tmp_path / "bindiff"),
                                            "binexport": (True, tmp_path / "BinExport"),
                                        }
                                        result = runner.invoke(cli, ["binary-diff", "notepad.exe", "--report", "--overwrite"])
        
        assert result.exit_code == 0
        assert "Overwriting existing export" in result.output
        assert "Overwriting existing BinDiff DB" in result.output
        assert "Overwriting existing report" in result.output
        assert mock_export.call_count == 2
        mock_run_bindiff.assert_called_once()
        mock_export_report.assert_called_once()


class TestCveCommand:
    """Tests for CVE workflow command."""
    
    def test_cve_help(self, runner: CliRunner):
        """Test cve help output."""
        result = runner.invoke(cli, ["cve", "--help"])
        
        assert result.exit_code == 0
        assert "--fetch-count" in result.output
        assert "--run-bindiff" in result.output
        assert "--pseudo-c" in result.output
    
    def test_cve_invalid_format(self, runner: CliRunner):
        """Test cve command rejects invalid IDs."""
        with patch("ppp.cli.init_db"):
            result = runner.invoke(cli, ["cve", "not-a-cve"])
        
        assert result.exit_code == 0
        assert "Invalid CVE format" in result.output
    
    def test_cve_list_only(self, runner: CliRunner, sample_patch: Patch, sample_product: Product):
        """Test cve --list-only resolves and lists KB mappings."""
        with patch("ppp.cli.init_db"):
            with patch("ppp.cli.get_db") as mock_db:
                mock_db.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_db.return_value.__exit__ = MagicMock(return_value=False)
                with patch("ppp.cli.get_patches_for_cve", return_value=[sample_patch]):
                    with patch("ppp.cli.get_products_for_patch", return_value=[sample_product]):
                        result = runner.invoke(
                            cli,
                            ["cve", "CVE-2024-12345", "--list-only"],
                            terminal_width=200,
                        )
        
        assert result.exit_code == 0
        assert "KB5034441" in result.output
        assert "Release" in result.output
        assert "Products" in result.output
    
    def test_cve_fetch_then_run_pipeline(
        self,
        runner: CliRunner,
        sample_patch: Patch,
        sample_product: Product,
        tmp_path: Path,
    ):
        """Test cve command fetches updates if missing and runs pipeline."""
        with patch("ppp.cli.init_db"):
            with patch("ppp.cli.get_db") as mock_db:
                mock_db.return_value.__enter__ = MagicMock(return_value=MagicMock())
                mock_db.return_value.__exit__ = MagicMock(return_value=False)
                with patch("ppp.cli.get_patches_for_cve", side_effect=[[], [sample_patch]]):
                    with patch("ppp.cli.get_products_for_patch", return_value=[sample_product]):
                        with patch("ppp.cli.fetch_latest") as mock_fetch_latest:
                            with patch("ppp.cli.download_by_kb", return_value=[]):
                                with patch("ppp.cli.extract_by_kb", return_value=[MagicMock()]):
                                    with patch("ppp.cli.fetch_baseline_for_extracted", return_value=[]):
                                        with patch("ppp.cli.list_extracted_files", return_value=[]):
                                            with patch("ppp.cli.DEFAULT_EXTRACTED_DIR", tmp_path):
                                                result = runner.invoke(cli, ["cve", "CVE-2024-12345"])
        
        assert result.exit_code == 0
        mock_fetch_latest.assert_called_once_with(24, verbose=True, prefer_rss=True)


class TestDiffCommand:
    """Tests for diff command."""
    
    def test_diff_help(self, runner: CliRunner):
        """Test diff help output."""
        result = runner.invoke(cli, ["diff", "--help"])
        
        assert result.exit_code == 0
    
    def test_diff_no_extracted(self, runner: CliRunner, tmp_path: Path):
        """Test diff with no extracted files."""
        with patch("ppp.cli.init_db"):
            with patch("ppp.cli.DEFAULT_EXTRACTED_DIR", tmp_path):
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
        
        with patch("ppp.cli.init_db"):
            with patch("ppp.cli.DEFAULT_EXTRACTED_DIR", tmp_path):
                with patch("ppp.cli.DEFAULT_BASELINE_DIR", tmp_path / "baseline"):
                    with patch("ppp.cli.list_extracted_files", return_value=[test_file]):
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
        assert "--binary" in result.output
        assert "--report" in result.output
        assert "--pseudo-c" in result.output

    def test_bindiff_report_auto_enables_pseudocode(self, runner: CliRunner, tmp_path: Path):
        """Test bindiff --report auto-enables pseudo-C generation in automatic mode."""
        with patch("ppp.bindiff_client.compare_binaries_for_kb", return_value=[] ) as mock_compare:
            result = runner.invoke(cli, ["bindiff", "KB5034441", "--report"])

        assert result.exit_code == 0
        assert "`--report` enabled" in result.output
        assert mock_compare.call_args.kwargs["include_pseudocode"] is True
    
    def test_bindiff_check_deps(self, runner: CliRunner):
        """Test bindiff --check-deps flag."""
        with patch("ppp.bindiff_client.check_dependencies") as mock_check:
            with patch("ppp.bindiff_client._find_binexport_extension", return_value=None):
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
        with patch("ppp.cli.init_db"):
            with patch("ppp.cli.DEFAULT_EXTRACTED_DIR", tmp_path):
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
        
        with patch("ppp.cli.init_db"):
            with patch("ppp.cli.DEFAULT_EXTRACTED_DIR", tmp_path):
                with patch("ppp.cli.DEFAULT_BASELINE_DIR", baseline_dir):
                    result = runner.invoke(cli, ["bindiff", "KB5034441"])
        
        assert result.exit_code == 0
    
    def test_bindiff_deps_found(self, runner: CliRunner):
        """Test bindiff --check-deps when tools are found."""
        with patch("ppp.bindiff_client.check_dependencies") as mock_check:
            with patch("ppp.bindiff_client._find_binexport_extension", return_value=Path("/opt/ghidra/Extensions/BinExport")):
                mock_check.return_value = {
                    "ghidra": (True, Path("/opt/ghidra")),
                    "bindiff": (True, Path("/usr/local/bin/bindiff")),
                    "binexport": (True, Path("/opt/ghidra/Extensions/BinExport")),
                }
                
                result = runner.invoke(cli, ["bindiff", "KB5034441", "--check-deps"])
        
        assert result.exit_code == 0
        mock_check.assert_called_once()
