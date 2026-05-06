from __future__ import annotations

from datetime import datetime
from pathlib import Path
import re
import shutil
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .catalog_client import download_by_kb
from .config import BASELINE_DIR as DEFAULT_BASELINE_DIR
from .config import BINDIFF_DIR as DEFAULT_BINDIFF_DIR
from .config import EXTRACTED_DIR as DEFAULT_EXTRACTED_DIR
from .config import PACKAGES_DIR as DEFAULT_PACKAGES_DIR
from .extractor import (
    extract_by_kb,
    list_extracted_files,
)
from .models import Architecture, WinBIndexFile
from .winbindex_client import (
    download_file_version,
    fetch_baseline_for_extracted,
    list_file_versions,
)
from .windows_versions import matches_windows_version_filter

console = Console()


def print_header() -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]Post-patch Postmortem[/bold cyan] v{__version__}\n"
            "[dim]Microsoft Security Update Analysis Tool[/dim]",
            border_style="cyan",
        )
    )


def normalize_kb_number(kb_number: str) -> str:
    kb = kb_number.strip().upper()
    if not kb.startswith("KB"):
        kb = f"KB{kb}"
    return kb


def _safe_label(text: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", text.strip())
    cleaned = cleaned.strip("._-")
    return cleaned or "unknown"


def _parse_date_option(date_str: Optional[str], field_name: str) -> Optional[datetime]:
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError(f"Invalid {field_name}: {date_str}. Use YYYY-MM-DD format.") from exc


def _parse_version_text(version_text: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version_text or "")
    return tuple(int(part) for part in parts)


def select_version_entry(
    entries: list[WinBIndexFile],
    version: Optional[str],
    build: Optional[str],
    release_date: Optional[datetime],
    kb_number: Optional[str] = None,
) -> Optional[WinBIndexFile]:
    selected = entries
    if version:
        selected = [entry for entry in selected if entry.version == version]
    if build:
        selected = [entry for entry in selected if build in (entry.version or "")]
    if release_date:
        selected = [
            entry
            for entry in selected
            if entry.release_date and entry.release_date.date() == release_date.date()
        ]
    if kb_number:
        normalized_kb = normalize_kb_number(kb_number)
        selected = [
            entry
            for entry in selected
            if any(update.kb_number == normalized_kb for update in entry.updates)
        ]
    return selected[0] if selected else None


def _select_previous_distinct_entry(
    entries: list[WinBIndexFile],
    selected_entry: WinBIndexFile,
) -> Optional[WinBIndexFile]:
    candidates = [
        entry
        for entry in entries
        if entry.sha256 != selected_entry.sha256 and entry is not selected_entry
    ]
    if not candidates:
        return None

    selected_windows = {
        update.windows_version
        for update in getattr(selected_entry, "updates", [])
        if update.windows_version
    }
    if selected_windows:
        for entry in candidates:
            entry_windows = {
                update.windows_version
                for update in getattr(entry, "updates", [])
                if update.windows_version
            }
            if selected_windows & entry_windows:
                return entry

    selected_version_tuple = _parse_version_text(getattr(selected_entry, "version", ""))
    if selected_version_tuple:
        selected_branch = selected_version_tuple[:3]
        for entry in candidates:
            entry_branch = _parse_version_text(getattr(entry, "version", ""))[:3]
            if entry_branch and entry_branch == selected_branch:
                return entry

    return candidates[0]


def run_kb_diff(
    kb_number: str,
    architecture: Optional[Architecture] = None,
    report: bool = True,
    force: bool = False,
    window_version: Optional[str] = None,
):
    from .bindiff_client import compare_binaries_for_kb, show_comparison_summary

    kb = normalize_kb_number(kb_number)
    console.print(f"\n[bold cyan]Processing {kb}[/bold cyan]")

    if force:
        for package_path in list(DEFAULT_PACKAGES_DIR.glob(f"*{kb}*")) + list(DEFAULT_PACKAGES_DIR.glob(f"*{kb.lower()}*")):
            if package_path.is_file():
                package_path.unlink(missing_ok=True)
        shutil.rmtree(DEFAULT_EXTRACTED_DIR / kb, ignore_errors=True)
        shutil.rmtree(DEFAULT_BASELINE_DIR / kb, ignore_errors=True)
        shutil.rmtree(DEFAULT_BINDIFF_DIR / kb, ignore_errors=True)

    downloaded_packages = download_by_kb(kb, architecture)
    if not downloaded_packages:
        console.print("[yellow]No new packages downloaded (continuing with local cache if available).[/yellow]")

    extracted = extract_by_kb(kb)
    if not extracted:
        console.print(f"[yellow]Skipping {kb}: no extracted binaries available.[/yellow]")
        return []

    extracted_dir = DEFAULT_EXTRACTED_DIR / kb
    baseline_files = fetch_baseline_for_extracted(extracted_dir, kb)
    total_extracted = len(list_extracted_files(kb))
    console.print(
        f"[green]✓ {kb}: extracted {total_extracted} files, baseline candidates {len(baseline_files)}[/green]"
    )

    allowed_binaries: Optional[list[str]] = None
    if window_version:
        extracted_paths = list_extracted_files(kb)
        filtered: list[str] = []
        seen: set[str] = set()
        for file_path in extracted_paths:
            if architecture:
                try:
                    if Architecture(file_path.parent.name) != architecture:
                        continue
                except ValueError:
                    continue
            clean_name = re.sub(r"_[a-f0-9]{8}(\.[a-z]+)$", r"\1", file_path.name.lower())
            versions = list_file_versions(clean_name, architecture=architecture, limit=200)
            matched = select_version_entry(
                versions,
                version=None,
                build=None,
                release_date=None,
                kb_number=kb,
            )
            if not matched or not matches_windows_version_filter(matched, window_version):
                continue
            if clean_name not in seen:
                seen.add(clean_name)
                filtered.append(clean_name)
        allowed_binaries = filtered
        if not allowed_binaries:
            console.print(f"[yellow]No binaries in {kb} matched windows version filter[/yellow]")
            return []

    results = []
    target_binaries = allowed_binaries if allowed_binaries is not None else [None]
    for target_binary in target_binaries:
        target_results = compare_binaries_for_kb(
            kb,
            binary_name=target_binary,
            generate_reports=report,
            include_pseudocode=report,
        )
        results.extend(target_results)

    if results:
        console.print(f"[green]✓ Generated {len(results)} BinDiff comparison(s) for {kb}[/green]")
        show_comparison_summary(results)
    else:
        console.print(f"[yellow]No BinDiff outputs generated for {kb}[/yellow]")
    return results


def run_binary_diff(
    filename: str,
    arch: str,
    window_version: Optional[str] = None,
    compare_sha_pair: Optional[tuple[str, str]] = None,
    force: bool = False,
    report: bool = True,
) -> None:
    from .bindiff_client import (
        _find_binexport_extension,
        check_dependencies,
        export_bindiff_report,
        export_with_ghidra,
        run_bindiff,
    )

    architecture = Architecture(arch)
    pseudo_c = report
    overwrite = force

    console.print(f"[dim]`--report` enabled: including pseudo-C diffs for non-identical matched functions[/dim]")
    console.print(f"\n[cyan]Resolving versions for {filename} ({architecture.value})...[/cyan]\n")

    compare_mode = bool(compare_sha_pair)
    lookup_architecture = None if compare_mode else architecture
    versions_list = list_file_versions(filename, architecture=lookup_architecture, limit=200)
    if not versions_list:
        console.print(f"[yellow]No versions found for {filename}[/yellow]")
        return

    if not compare_mode and window_version:
        versions_list = [entry for entry in versions_list if matches_windows_version_filter(entry, window_version)]
        if not versions_list:
            console.print(f"[yellow]No versions found for {filename} matching windows version filter[/yellow]")
            return

    if compare_mode:
        new_sha, old_sha = compare_sha_pair
        selected_by_sha = {entry.sha256.lower(): entry for entry in versions_list}
        first = selected_by_sha.get(new_sha.lower())
        second = selected_by_sha.get(old_sha.lower())
        if not first or not second:
            console.print("[red]Could not resolve one or both SHA256 values for this binary[/red]")
            return
        first_idx = next(idx for idx, entry in enumerate(versions_list) if entry.sha256 == first.sha256)
        second_idx = next(idx for idx, entry in enumerate(versions_list) if entry.sha256 == second.sha256)
        newer, older = (first, second) if first_idx < second_idx else (second, first)
    else:
        newer = versions_list[0]
        remaining = [entry for entry in versions_list if entry.sha256 != newer.sha256]
        if not remaining:
            console.print("[red]Could not find a second distinct version to diff against[/red]")
            return
        newer_index = next(
            (idx for idx, entry in enumerate(versions_list) if entry.sha256 == newer.sha256),
            None,
        )
        older = None
        if newer_index is not None:
            older = _select_previous_distinct_entry(versions_list[newer_index + 1 :], newer)
        if not older:
            older = remaining[0]

    select_table = Table(title=f"Selected Versions for {filename}")
    select_table.add_column("Role", style="cyan", width=8)
    select_table.add_column("Version", style="green", max_width=45)
    select_table.add_column("Release Date", style="magenta", width=12)
    select_table.add_column("SHA256", style="dim", max_width=16)

    for role, entry in [("New", newer), ("Old", older)]:
        release_str = entry.release_date.strftime("%Y-%m-%d") if entry.release_date else "N/A"
        sha_str = entry.sha256[:16] + "..." if len(entry.sha256) > 16 else entry.sha256
        version_str = entry.version or "<unknown>"
        kb_values = sorted({item.kb_number for item in entry.updates if item.kb_number})
        kb_suffix = (
            f" [{', '.join(kb_values[:2])}{' +' + str(len(kb_values) - 2) if len(kb_values) > 2 else ''}]"
            if kb_values
            else ""
        )
        select_table.add_row(role, f"{version_str}{kb_suffix}", release_str, sha_str)

    console.print(select_table)

    deps = check_dependencies()
    ghidra_found, ghidra_path = deps["ghidra"]
    bindiff_found, bindiff_path = deps["bindiff"]
    binexport_ext = _find_binexport_extension(ghidra_path) if ghidra_path else None

    if not ghidra_found or not bindiff_found or not binexport_ext:
        console.print("\n[red]Missing BinDiff dependencies.[/red]")
        if not ghidra_found:
            console.print("[dim]- Ghidra not found[/dim]")
        if not bindiff_found:
            console.print("[dim]- BinDiff not found[/dim]")
        if not binexport_ext:
            console.print("[dim]- Ghidra BinExport extension not found[/dim]")
        return

    binary_root = DEFAULT_BINDIFF_DIR / "binary" / _safe_label(Path(filename).name)
    downloads_root = binary_root / "downloads"
    exports_root = binary_root / "exports"
    reports_root = binary_root / "reports"
    if force:
        shutil.rmtree(binary_root, ignore_errors=True)
    exports_root.mkdir(parents=True, exist_ok=True)
    reports_root.mkdir(parents=True, exist_ok=True)

    console.print("\n[cyan]Downloading selected binaries...[/cyan]")
    old_path = download_file_version(older, output_dir=downloads_root / "old", show_progress=True)
    new_path = download_file_version(newer, output_dir=downloads_root / "new", show_progress=True)
    if not old_path or not new_path:
        console.print("[red]Failed to download one or both binaries[/red]")
        return

    old_label = _safe_label(older.version or older.sha256[:12])
    new_label = _safe_label(newer.version or newer.sha256[:12])
    old_export = exports_root / f"{old_label}_old.BinExport"
    new_export = exports_root / f"{new_label}_new.BinExport"

    console.print("\n[cyan]Exporting BinExport files with Ghidra...[/cyan]")
    if old_export.exists() and not overwrite:
        console.print(f"[dim]Reusing existing export: {old_export.name}[/dim]")
    else:
        if old_export.exists() and overwrite:
            console.print(f"[dim]Overwriting existing export: {old_export.name}[/dim]")
            old_export.unlink(missing_ok=True)
        if not export_with_ghidra(old_path, old_export, ghidra_path=ghidra_path):
            console.print(f"[red]Failed exporting old binary: {old_path}[/red]")
            return
    if new_export.exists() and not overwrite:
        console.print(f"[dim]Reusing existing export: {new_export.name}[/dim]")
    else:
        if new_export.exists() and overwrite:
            console.print(f"[dim]Overwriting existing export: {new_export.name}[/dim]")
            new_export.unlink(missing_ok=True)
        if not export_with_ghidra(new_path, new_export, ghidra_path=ghidra_path):
            console.print(f"[red]Failed exporting new binary: {new_path}[/red]")
            return

    bindiff_name = _safe_label(f"{Path(filename).stem}_{old_label}_to_{new_label}")
    expected_bindiff = exports_root / f"{bindiff_name}.BinDiff"
    if expected_bindiff.exists() and not overwrite:
        bindiff_file = expected_bindiff
        console.print(f"\n[dim]Reusing existing BinDiff DB: {bindiff_file.name}[/dim]")
    else:
        if expected_bindiff.exists() and overwrite:
            console.print(f"\n[dim]Overwriting existing BinDiff DB: {expected_bindiff.name}[/dim]")
            expected_bindiff.unlink(missing_ok=True)
        console.print("\n[cyan]Running BinDiff...[/cyan]")
        bindiff_file = run_bindiff(
            old_export,
            new_export,
            expected_bindiff,
            bindiff_path=bindiff_path,
        )
        if not bindiff_file:
            console.print("[red]BinDiff failed[/red]")
            return
        if bindiff_file.resolve() != expected_bindiff.resolve():
            try:
                shutil.copy2(bindiff_file, expected_bindiff)
                bindiff_file = expected_bindiff
                console.print(f"[dim]Cached BinDiff DB as: {bindiff_file.name}[/dim]")
            except Exception:
                pass

    report_path = None
    if report:
        expected_report = reports_root / f"{bindiff_file.stem}_report.html"
        if expected_report.exists() and not overwrite:
            report_path = expected_report
            console.print(f"[dim]Reusing existing report: {report_path.name}[/dim]")
        else:
            if expected_report.exists() and overwrite:
                console.print(f"[dim]Overwriting existing report: {expected_report.name}[/dim]")
                expected_report.unlink(missing_ok=True)
            report_path = export_bindiff_report(
                bindiff_file,
                reports_root,
                include_pseudocode=pseudo_c,
                primary_binary=old_path if pseudo_c else None,
                secondary_binary=new_path if pseudo_c else None,
                ghidra_path=ghidra_path if pseudo_c else None,
            )

    console.print("\n[green]✓ Binary diff completed[/green]")
    console.print(f"[dim]Old binary: {old_path}[/dim]")
    console.print(f"[dim]New binary: {new_path}[/dim]")
    console.print(f"[dim]BinDiff DB: {bindiff_file}[/dim]")
    if report_path:
        console.print(f"[dim]Report: {report_path}[/dim]")
