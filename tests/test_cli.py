"""Tests for the simplified public CLI."""

from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from ppp.cli import (
    _format_sha256,
    _format_windows,
    cli,
    print_header,
)
from ppp.models import Architecture, WinBIndexFile
from ppp.windows_versions import matches_windows_version_filter


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestPrintHeader:
    def test_print_header(self) -> None:
        print_header()


class TestCliSurface:
    def test_main_help_only_shows_list_and_diff(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--help"])

        assert result.exit_code == 0
        assert "list" in result.output
        assert "diff" in result.output
        assert "fetch" not in result.output
        assert "lookup" not in result.output
        assert "analyze" not in result.output
        assert "show" not in result.output
        assert "clean" not in result.output

    def test_version(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])

        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_list_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["list", "--help"])

        assert result.exit_code == 0
        assert "--arch" in result.output
        assert "--limit" in result.output
        assert "--window-version" in result.output

    def test_diff_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["diff", "--help"])

        assert result.exit_code == 0
        assert "--arch" in result.output
        assert "--window-version" in result.output
        assert "--compare" in result.output
        assert "--force" in result.output


class TestListCommand:
    def test_windows_version_is_humanized(self) -> None:
        entry = WinBIndexFile(
            filename="tcpip.sys",
            version="10.0.17763.6189",
            architecture=Architecture.X64,
            sha256="a" * 64,
            download_url="https://example.com/a",
            updates=[{"kb_number": "KB5041578", "windows_version": "1809"}],
        )

        assert _format_windows(entry) == "1809 (Windows 10 1809)"

    def test_sha256_is_middle_truncated_for_display(self) -> None:
        assert _format_sha256("abcdef" + ("1" * 52) + "123456") == "abcdef...123456"
        assert _format_sha256("abc123") == "abc123"

    def test_windows_version_filter_matches_raw_and_humanized_values(self) -> None:
        entry = WinBIndexFile(
            filename="tcpip.sys",
            version="10.0.17763.6189",
            architecture=Architecture.X64,
            sha256="a" * 64,
            download_url="https://example.com/a",
            updates=[{"kb_number": "KB5041578", "windows_version": "1809"}],
        )

        assert matches_windows_version_filter(entry, "1809") is True
        assert matches_windows_version_filter(entry, "Windows 10 1809") is True
        assert matches_windows_version_filter(entry, "1607") is False

    def test_list_binary_renders_recent_versions(self, runner: CliRunner) -> None:
        versions = [
            WinBIndexFile(
                filename="tcpip.sys",
                version="10.0.19041.1",
                architecture=Architecture.X64,
                sha256="abcdef" + ("1" * 52) + "123456",
                download_url="https://example.com/a",
                size=1024,
                updates=[{"kb_number": "KB5041578", "windows_version": "Windows 10 22H2"}],
            ),
            WinBIndexFile(
                filename="tcpip.sys",
                version="10.0.19041.0",
                architecture=Architecture.X64,
                sha256="b" * 64,
                download_url="https://example.com/b",
                size=2048,
                updates=[{"kb_number": "KB5040000", "windows_version": "Windows 10 22H2"}],
            ),
        ]

        with patch("ppp.cli.list_file_versions", return_value=versions) as mock_versions:
            result = runner.invoke(cli, ["list", "tcpip.sys", "--arch", "x64"], terminal_width=200)

        assert result.exit_code == 0
        mock_versions.assert_called_once_with("tcpip.sys", architecture=Architecture.X64, limit=10)
        assert "Recent versions of tcpip.sys" in result.output
        assert "abcdef...123456" in result.output
        assert "abcdef" + ("1" * 52) + "123456" not in result.output

    def test_list_binary_filters_by_window_version(self, runner: CliRunner) -> None:
        versions = [
            WinBIndexFile(
                filename="tcpip.sys",
                version="10.0.17763.6189",
                architecture=Architecture.X64,
                sha256="a" * 64,
                download_url="https://example.com/a",
                updates=[{"kb_number": "KB5041578", "windows_version": "1809"}],
            ),
            WinBIndexFile(
                filename="tcpip.sys",
                version="10.0.14393.7254",
                architecture=Architecture.X64,
                sha256="b" * 64,
                download_url="https://example.com/b",
                updates=[{"kb_number": "KB5041773", "windows_version": "1607"}],
            ),
        ]

        with patch("ppp.cli.list_file_versions", return_value=versions):
            with patch("ppp.cli._render_rows") as mock_render_rows:
                result = runner.invoke(cli, ["list", "tcpip.sys", "--window-version", "Windows 10 1809"])

        assert result.exit_code == 0
        rows = mock_render_rows.call_args.args[1]
        assert len(rows) == 1
        assert rows[0]["windows"] == "1809 (Windows 10 1809)"

    def test_list_kb_uses_cached_extraction_and_winbindex(self, runner: CliRunner, tmp_path: Path) -> None:
        kb_file = tmp_path / "KB5041578" / "x64" / "tcpip_a1b2c3d4.sys"
        kb_file.parent.mkdir(parents=True)
        kb_file.write_bytes(b"patched")

        versions = [
            WinBIndexFile(
                filename="tcpip.sys",
                version="10.0.19041.1",
                architecture=Architecture.X64,
                sha256="c" * 64,
                download_url="https://example.com/c",
                size=4096,
                updates=[{"kb_number": "KB5041578", "windows_version": "Windows 10 22H2"}],
            )
        ]

        with patch("ppp.cli.list_extracted_files", return_value=[kb_file]):
            with patch("ppp.cli.list_file_versions", return_value=versions) as mock_versions:
                result = runner.invoke(cli, ["list", "KB5041578", "--arch", "x64"], terminal_width=200)

        assert result.exit_code == 0
        mock_versions.assert_called_once_with("tcpip.sys", architecture=Architecture.X64, limit=200)
        assert "Files in KB5041578" in result.output

    def test_list_kb_downloads_and_extracts_when_cache_is_missing(
        self,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        kb_file = tmp_path / "KB5041578" / "x64" / "tcpip_a1b2c3d4.sys"
        kb_file.parent.mkdir(parents=True)
        kb_file.write_bytes(b"patched")

        with patch("ppp.cli.list_extracted_files", side_effect=[[], [kb_file]]) as mock_list:
            with patch("ppp.cli.download_by_kb") as mock_download:
                with patch("ppp.cli.extract_by_kb") as mock_extract:
                    with patch("ppp.cli.list_file_versions", return_value=[]):
                        result = runner.invoke(cli, ["list", "KB5041578"])

        assert result.exit_code == 0
        assert mock_list.call_count == 2
        mock_download.assert_called_once_with("KB5041578", None)
        mock_extract.assert_called_once_with("KB5041578")


class TestDiffCommand:
    def test_diff_binary_delegates_to_direct_binary_workflow(self, runner: CliRunner) -> None:
        with patch("ppp.cli.run_binary_diff") as mock_binary_diff:
            result = runner.invoke(cli, ["diff", "tcpip.sys", "--arch", "x64"])

        assert result.exit_code == 0
        mock_binary_diff.assert_called_once_with(
            filename="tcpip.sys",
            arch="x64",
            window_version=None,
            compare_sha_pair=None,
            force=False,
            report=True,
        )

    def test_diff_binary_defaults_to_x64(self, runner: CliRunner) -> None:
        with patch("ppp.cli.run_binary_diff") as mock_binary_diff:
            result = runner.invoke(cli, ["diff", "tcpip.sys"])

        assert result.exit_code == 0
        assert mock_binary_diff.call_args.kwargs["arch"] == "x64"

    def test_diff_binary_supports_compare_and_force(self, runner: CliRunner) -> None:
        with patch("ppp.cli.run_binary_diff") as mock_binary_diff:
            result = runner.invoke(
                cli,
                ["diff", "tcpip.sys", "--compare", "aaa,bbb", "--force", "--arch", "x64", "--window-version", "1809"],
            )

        assert result.exit_code == 0
        kwargs = mock_binary_diff.call_args.kwargs
        assert kwargs["force"] is True
        assert kwargs["compare_sha_pair"] == ("aaa", "bbb")
        assert kwargs["window_version"] is None

    def test_diff_binary_rejects_invalid_compare(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["diff", "tcpip.sys", "--compare", "onlyone"])

        assert result.exit_code != 0
        assert "--compare" in result.output

    def test_diff_kb_delegates_to_kb_pipeline(self, runner: CliRunner) -> None:
        with patch("ppp.cli.print_header"):
            with patch("ppp.cli.run_kb_diff") as mock_pipeline:
                result = runner.invoke(cli, ["diff", "KB5041578", "--arch", "x64", "--window-version", "1809", "--force"])

        assert result.exit_code == 0
        mock_pipeline.assert_called_once_with(
            "KB5041578",
            architecture=Architecture.X64,
            report=True,
            force=True,
            window_version="1809",
        )

    def test_diff_kb_rejects_compare(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["diff", "KB5041578", "--compare", "aaa,bbb"])

        assert result.exit_code != 0
        assert "--compare" in result.output


class TestPreservedBinaryDiffLogic:
    def test_kb_selection_prefers_matching_branch(self, tmp_path: Path) -> None:
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
            "ppp.workflows.list_file_versions",
            return_value=[selected_kb, wrong_branch_previous, same_branch_previous],
        ):
            with patch("ppp.bindiff_client.check_dependencies") as mock_deps:
                with patch("ppp.bindiff_client._find_binexport_extension", return_value=tmp_path / "BinExport"):
                    with patch("ppp.workflows.download_file_version", side_effect=[old_download, new_download]) as mock_download:
                        with patch("ppp.bindiff_client.export_with_ghidra", return_value=True):
                            with patch("ppp.bindiff_client.run_bindiff", return_value=bindiff_file):
                                mock_deps.return_value = {
                                    "ghidra": (True, tmp_path / "ghidra"),
                                    "bindiff": (True, tmp_path / "bindiff"),
                                    "binexport": (True, tmp_path / "BinExport"),
                                }

                                from ppp.workflows import run_binary_diff

                                run_binary_diff(
                                    filename="tcpip.sys",
                                    arch="x64",
                                    window_version=None,
                                    compare_sha_pair=None,
                                    force=False,
                                    report=False,
                                )

        first_call = mock_download.call_args_list[0].args[0]
        second_call = mock_download.call_args_list[1].args[0]
        assert first_call.version == "10.0.17763.6050"
        assert second_call.version == "10.0.17763.6189"
