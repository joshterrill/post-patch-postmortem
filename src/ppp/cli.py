from pathlib import Path
import re
from typing import Optional

import click
from rich.table import Table

from . import __version__
from .catalog_client import download_by_kb
from .extractor import (
    _calculate_sha256 as _calculate_extracted_sha256,
    _get_file_version as _get_extracted_file_version,
    extract_by_kb,
    list_extracted_files,
)
from .models import Architecture, WinBIndexFile
from .winbindex_client import list_file_versions
from .windows_versions import (
    entry_windows_versions,
    format_windows_version_value,
    matches_windows_version_filter,
)
from .workflows import (
    console,
    normalize_kb_number,
    print_header,
    run_binary_diff,
    run_kb_diff,
    select_version_entry,
)


KB_TARGET_RE = re.compile(r"^(?:kb)?\d{6,8}$", re.IGNORECASE)
HASH_SUFFIX_RE = re.compile(r"_[a-f0-9]{8}(\.[a-z0-9]+)$", re.IGNORECASE)


@click.group()
@click.version_option(version=__version__)
def cli() -> None:
    """Post-patch Postmortem - list or diff Windows binaries and KBs."""
    pass


def _is_kb_target(target: str) -> bool:
    return bool(KB_TARGET_RE.fullmatch(target.strip()))


def _path_architecture(path: Path) -> Optional[Architecture]:
    try:
        return Architecture(path.parent.name.lower())
    except ValueError:
        return None


def _clean_extracted_name(filename: str) -> str:
    return HASH_SUFFIX_RE.sub(r"\1", filename)


def _format_size(size: Optional[int]) -> str:
    if not size or size <= 0:
        return "N/A"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / 1024 / 1024:.2f} MB"


def _format_windows(entry: WinBIndexFile) -> str:
    values = [format_windows_version_value(value) for value in entry_windows_versions(entry)]
    if not values:
        return "N/A"
    if len(values) <= 2:
        return ", ".join(values)
    return f"{', '.join(values[:2])} +{len(values) - 2}"


def _format_updates(entry: WinBIndexFile) -> str:
    values = sorted(
        {
            update.kb_number
            for update in getattr(entry, "updates", [])
            if getattr(update, "kb_number", None)
        }
    )
    if not values:
        return "N/A"
    if len(values) <= 2:
        return ", ".join(values)
    return f"{', '.join(values[:2])} +{len(values) - 2}"


def _row_from_winbindex(entry: WinBIndexFile, filename: Optional[str] = None) -> dict[str, str]:
    return {
        "filename": filename or entry.filename,
        "sha256": entry.sha256,
        "release_date": entry.release_date.strftime("%Y-%m-%d") if entry.release_date else "N/A",
        "windows": _format_windows(entry),
        "updates": _format_updates(entry),
        "arch": entry.architecture.value,
        "version": entry.version or "N/A",
        "size": _format_size(entry.size),
    }


def _row_from_local_file(path: Path, kb_number: str) -> dict[str, str]:
    arch = _path_architecture(path)
    return {
        "filename": _clean_extracted_name(path.name),
        "sha256": _calculate_extracted_sha256(path),
        "release_date": "N/A",
        "windows": "N/A",
        "updates": normalize_kb_number(kb_number),
        "arch": arch.value if arch else "unknown",
        "version": _get_extracted_file_version(path) or "N/A",
        "size": _format_size(path.stat().st_size),
    }


def _render_rows(title: str, rows: list[dict[str, str]], include_filename: bool) -> None:
    if not rows:
        console.print("[yellow]No results found[/yellow]")
        return

    table = Table(title=title)
    if include_filename:
        table.add_column("Filename", style="cyan", no_wrap=True)
    table.add_column("SHA256", style="dim", no_wrap=True)
    table.add_column("Release Date", style="magenta", no_wrap=True)
    table.add_column("Windows Version", style="blue", no_wrap=True)
    table.add_column("Update(s)", style="yellow", no_wrap=True)
    table.add_column("File Arch", style="green", no_wrap=True)
    table.add_column("File Version", style="cyan", no_wrap=True)
    table.add_column("File Size", style="white", justify="right")

    for row in rows:
        values = []
        if include_filename:
            values.append(row["filename"])
        values.extend(
            [
                row["sha256"],
                row["release_date"],
                row["windows"],
                row["updates"],
                row["arch"],
                row["version"],
                row["size"],
            ]
        )
        table.add_row(*values)

    console.print(table)


def _list_binary_versions(
    filename: str,
    architecture: Optional[Architecture],
    limit: int,
    window_version: Optional[str],
) -> None:
    versions = list_file_versions(filename, architecture=architecture, limit=limit)
    if not versions:
        console.print(f"[yellow]No versions found for {filename}[/yellow]")
        return
    versions = [entry for entry in versions if matches_windows_version_filter(entry, window_version)]
    if not versions:
        console.print(f"[yellow]No versions found for {filename} matching windows version filter[/yellow]")
        return
    rows = [_row_from_winbindex(entry) for entry in versions]
    _render_rows(f"Recent versions of {filename}", rows, include_filename=False)


def _ensure_kb_files(kb_number: str, architecture: Optional[Architecture]) -> list[Path]:
    files = list_extracted_files(kb_number)
    if files and (
        architecture is None
        or any(_path_architecture(path) == architecture for path in files)
    ):
        return files

    download_by_kb(kb_number, architecture)
    extract_by_kb(kb_number)
    return list_extracted_files(kb_number)


def _unique_kb_binary_paths(kb_number: str, architecture: Optional[Architecture]) -> list[Path]:
    files = _ensure_kb_files(kb_number, architecture)
    unique: dict[tuple[str, str], Path] = {}

    for path in files:
        path_arch = _path_architecture(path)
        if architecture and path_arch != architecture:
            continue
        clean_name = _clean_extracted_name(path.name)
        arch_key = path_arch.value if path_arch else "unknown"
        unique.setdefault((clean_name.lower(), arch_key), path)

    return sorted(unique.values(), key=lambda path: (_clean_extracted_name(path.name).lower(), str(path)))


def _list_kb_files(
    kb_number: str,
    architecture: Optional[Architecture],
    limit: int,
    window_version: Optional[str],
) -> None:
    kb = normalize_kb_number(kb_number)
    files = _unique_kb_binary_paths(kb, architecture)
    if not files:
        console.print(f"[yellow]No binary files found for {kb}[/yellow]")
        return

    rows: list[dict[str, str]] = []
    for path in files:
        clean_name = _clean_extracted_name(path.name)
        path_arch = _path_architecture(path)
        search_arch = path_arch or architecture
        versions = list_file_versions(clean_name, architecture=search_arch, limit=200)
        matched = select_version_entry(
            versions,
            version=None,
            build=None,
            release_date=None,
            kb_number=kb,
        )
        if matched:
            if not matches_windows_version_filter(matched, window_version):
                continue
            rows.append(_row_from_winbindex(matched, filename=clean_name))
        else:
            if window_version:
                continue
            rows.append(_row_from_local_file(path, kb))

    total_rows = len(rows)
    if not rows:
        console.print(f"[yellow]No binary files found for {kb} matching windows version filter[/yellow]")
        return
    rows = rows[:limit]
    _render_rows(f"Files in {kb}", rows, include_filename=True)
    if total_rows > limit:
        console.print(f"[dim]Showing {limit} of {total_rows} files. Use --limit to show more.[/dim]")


@cli.command(name="list")
@click.argument("target")
@click.option("--arch", "-a", type=click.Choice(["x64", "x86", "arm64"]), help="Architecture filter")
@click.option(
    "--limit",
    "-n",
    type=click.IntRange(1, None),
    default=10,
    show_default=True,
    help="How many rows to show",
)
@click.option(
    "--window-version",
    "--windows-version",
    "window_version",
    type=str,
    help="Filter by raw or friendly Windows version text",
)
def list_target(target: str, arch: Optional[str], limit: int, window_version: Optional[str]) -> None:
    """List recent versions for a file or changed files for a KB."""
    print_header()
    architecture = Architecture(arch) if arch else None

    if _is_kb_target(target):
        _list_kb_files(target, architecture, limit, window_version)
        return

    _list_binary_versions(target, architecture, limit, window_version)


@cli.command(name="diff")
@click.argument("target")
@click.option("--arch", "-a", type=click.Choice(["x64", "x86", "arm64"]), help="Architecture filter")
@click.option(
    "--window-version",
    "--windows-version",
    "window_version",
    type=str,
    help="Filter by raw or friendly Windows version text",
)
@click.option(
    "--compare",
    type=str,
    help="Compare two specific SHA256 versions of a binary: <sha1>,<sha2>",
)
@click.option(
    "--force",
    is_flag=True,
    help="Redownload binaries and regenerate cached diff artifacts",
)
def diff_target(target: str, arch: Optional[str], window_version: Optional[str], compare: Optional[str], force: bool) -> None:
    """Run the binary diff workflow for a file or KB."""
    compare_pair: tuple[str, str] | None = None
    if compare:
        parts = [part.strip() for part in compare.split(",")]
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise click.ClickException("`--compare` must be in the form <sha1>,<sha2>.")
        compare_pair = (parts[0], parts[1])

    if _is_kb_target(target):
        if compare_pair:
            raise click.ClickException("`--compare` is only supported when diffing a binary name, not a KB.")
        print_header()
        architecture = Architecture(arch) if arch else None
        run_kb_diff(
            target,
            architecture=architecture,
            report=True,
            force=force,
            window_version=window_version,
        )
        return

    if compare_pair and (arch or window_version):
        console.print("[dim]Ignoring `--arch` and `--window-version` because `--compare` was provided.[/dim]")

    run_binary_diff(
        filename=target,
        arch=(arch or Architecture.X64.value),
        window_version=None if compare_pair else window_version,
        compare_sha_pair=compare_pair,
        force=force,
        report=True,
    )


if __name__ == "__main__":
    cli()
