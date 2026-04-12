from datetime import datetime
from pathlib import Path
import re
import shutil
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from . import __version__
from .catalog_client import download_by_kb, list_catalog_entries, search_catalog
from .database import (
    add_downloaded_file,
    get_db,
    get_db_path,
    get_patch,
    get_patches_for_cve,
    get_patches_by_date,
    get_patches_by_product,
    get_products_for_patch,
    get_stats,
    init_db,
    summarize_products,
)
from .extractor import (
    extract_by_kb,
    get_extraction_stats,
    list_extracted_files,
    DEFAULT_EXTRACTED_DIR,
    DEFAULT_PACKAGES_DIR,
)
from .models import Architecture, Severity
from .msrc_client import fetch_by_date, fetch_latest, get_update_ids
from .winbindex_client import (
    download_file_version,
    fetch_baseline_for_extracted,
    list_file_versions,
    show_file_versions,
    DEFAULT_BASELINE_DIR,
)

console = Console()


def print_header() -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]Post-patch Postmortem[/bold cyan] v{__version__}\n"
            "[dim]Microsoft Security Update Analysis Tool[/dim]",
            border_style="cyan",
        )
    )


@click.group()
@click.version_option(version=__version__)
def cli() -> None:
    """Post-patch Postmortem - fetch, analyze, and download Windows security patches."""
    pass


def _normalize_binary_base_name(name: str) -> str:
    normalized = Path(name.strip().lower()).name
    if "." in normalized:
        return normalized.rsplit(".", 1)[0]
    return normalized


def _safe_label(text: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", text.strip())
    cleaned = cleaned.strip("._-")
    return cleaned or "unknown"


def _parse_date_option(date_str: Optional[str], field_name: str) -> Optional[datetime]:
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        raise click.ClickException(f"Invalid {field_name}: {date_str}. Use YYYY-MM-DD format.")


def _select_version_entry(
    entries: list,
    version: Optional[str],
    build: Optional[str],
    release_date: Optional[datetime],
    kb_number: Optional[str] = None,
):
    selected = entries
    if version:
        selected = [e for e in selected if e.version == version]
    if build:
        selected = [e for e in selected if build in (e.version or "")]
    if release_date:
        selected = [
            e for e in selected
            if e.release_date and e.release_date.date() == release_date.date()
        ]
    if kb_number:
        normalized_kb = kb_number.strip().upper()
        if not normalized_kb.startswith("KB"):
            normalized_kb = f"KB{normalized_kb}"
        selected = [
            e for e in selected
            if any(update.kb_number == normalized_kb for update in e.updates)
        ]
    return selected[0] if selected else None


def _select_previous_distinct_entry(entries: list, selected_entry):
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

    for entry in candidates:
        return entry
    return None


def _parse_version_text(version_text: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version_text or "")
    return tuple(int(part) for part in parts)


def _normalize_kb_number(kb_number: str) -> str:
    kb = kb_number.strip().upper()
    if not kb.startswith("KB"):
        kb = f"KB{kb}"
    return kb


def _resolve_cve_patches(normalized_cve: str, fetch_count: int) -> list:
    with get_db() as db:
        patches = get_patches_for_cve(db, normalized_cve)
    if patches:
        return patches

    console.print(f"\n[yellow]{normalized_cve} not found in local database.[/yellow]")
    console.print(f"[cyan]Fetching latest {fetch_count} updates via RSS/API and retrying...[/cyan]\n")
    fetch_latest(fetch_count, verbose=True, prefer_rss=True)
    with get_db() as db:
        return get_patches_for_cve(db, normalized_cve)


def _save_download_records(records: list) -> None:
    if not records:
        return
    with get_db() as db:
        for item in records:
            add_downloaded_file(db, item)


def _render_cve_patch_table(normalized_cve: str, patches: list) -> None:
    with get_db() as db:
        patch_products = {
            patch.id: summarize_products(get_products_for_patch(db, patch.id))
            for patch in patches
            if patch.id is not None
        }

    table = Table(title=f"{normalized_cve} - Related KB Patches")
    table.add_column("KB", style="cyan")
    table.add_column("Release Date", style="green")
    table.add_column("Severity", style="yellow")
    table.add_column("Products", style="green", width=30)
    table.add_column("Title", style="white", max_width=60)

    for patch in patches:
        table.add_row(
            patch.kb_number,
            patch.release_date.strftime("%Y-%m-%d"),
            patch.severity.value,
            patch_products.get(patch.id, ""),
            patch.title[:60] + ("..." if len(patch.title) > 60 else ""),
        )
    console.print()
    console.print(table)


def _run_kb_pipeline(
    kb_number: str,
    architecture: Optional[Architecture] = None,
    binary_name: Optional[str] = None,
    save_db: bool = False,
    report: bool = True,
):
    from .bindiff_client import compare_binaries_for_kb, show_comparison_summary

    kb = _normalize_kb_number(kb_number)
    console.print(f"\n[bold cyan]Processing {kb}[/bold cyan]")

    downloaded_packages = download_by_kb(kb, architecture)
    if not downloaded_packages:
        console.print("[yellow]No new packages downloaded (continuing with local cache if available).[/yellow]")

    extracted = extract_by_kb(kb)
    if not extracted:
        console.print(f"[yellow]Skipping {kb}: no extracted binaries available.[/yellow]")
        return []

    if save_db:
        _save_download_records(extracted)

    extracted_dir = DEFAULT_EXTRACTED_DIR / kb
    baseline_files = fetch_baseline_for_extracted(extracted_dir, kb)
    if save_db and baseline_files:
        _save_download_records(baseline_files)

    total_extracted = len(list_extracted_files(kb))
    console.print(
        f"[green]✓ {kb}: extracted {total_extracted} files, baseline candidates {len(baseline_files)}[/green]"
    )

    results = compare_binaries_for_kb(
        kb,
        binary_name=binary_name,
        generate_reports=report,
        include_pseudocode=report,
    )
    if results:
        console.print(f"[green]✓ Generated {len(results)} BinDiff comparison(s) for {kb}[/green]")
        show_comparison_summary(results)
    else:
        console.print(f"[yellow]No BinDiff outputs generated for {kb}[/yellow]")
    return results


def _run_binary_diff(
    filename: str,
    arch: str,
    kb: Optional[str],
    new_version: Optional[str],
    old_version: Optional[str],
    new_build: Optional[str],
    old_build: Optional[str],
    new_date: Optional[str],
    old_date: Optional[str],
    limit: int,
    list_only: bool,
    report: bool,
    pseudo_c: bool,
    overwrite: bool,
) -> None:
    from .bindiff_client import (
        check_dependencies,
        export_bindiff_report,
        export_with_ghidra,
        run_bindiff,
        DEFAULT_BINDIFF_DIR,
        _find_binexport_extension,
    )

    print_header()
    architecture = Architecture(arch)
    if pseudo_c and not report:
        report = True
        console.print("[dim]`--pseudo-c` enabled: generating HTML report automatically[/dim]")
    if report and not pseudo_c:
        pseudo_c = True
        console.print("[dim]`--report` enabled: including pseudo-C diffs for non-identical matched functions[/dim]")
    new_date_dt = _parse_date_option(new_date, "--new-date")
    old_date_dt = _parse_date_option(old_date, "--old-date")

    console.print(f"\n[cyan]Resolving versions for {filename} ({architecture.value})...[/cyan]\n")
    versions_list = list_file_versions(filename, architecture=architecture, limit=max(2, limit))
    if not versions_list:
        console.print(f"[yellow]No versions found for {filename}[/yellow]")
        return

    newer = _select_version_entry(versions_list, new_version, new_build, new_date_dt, kb_number=kb)
    if not newer:
        if any([kb, new_version, new_build, new_date_dt]):
            console.print("[red]No matching newer version found with provided selectors[/red]")
            return
        newer = versions_list[0]

    remaining = [v for v in versions_list if v.sha256 != newer.sha256]
    if not remaining:
        console.print("[red]Could not find a second distinct version to diff against[/red]")
        return

    older = None
    if any([old_version, old_build, old_date_dt]):
        older = _select_version_entry(remaining, old_version, old_build, old_date_dt)
    if not older:
        if any([old_version, old_build, old_date_dt]):
            console.print("[red]No matching older version found with provided selectors[/red]")
            return
        newer_index = next(
            (idx for idx, entry in enumerate(versions_list) if entry.sha256 == newer.sha256),
            None,
        )
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

    if list_only:
        console.print()
        show_file_versions(filename, architecture)
        return

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
        console.print("[dim]Run: ppp bindiff KBxxxx --check-deps[/dim]")
        return

    binary_root = DEFAULT_BINDIFF_DIR / "binary" / _safe_label(Path(filename).name)
    downloads_root = binary_root / "downloads"
    exports_root = binary_root / "exports"
    reports_root = binary_root / "reports"
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


@cli.group()
def lookup() -> None:
    """Look up KBs and file history without running BinDiff."""
    pass


@cli.group()
def analyze() -> None:
    """Run the main analysis workflows for a month, KB, CVE, or file."""
    pass


@lookup.command(name="file")
@click.argument("filename")
@click.option("--arch", "-a", type=click.Choice(["x64", "x86", "arm64"]), help="Architecture filter")
@click.option("--limit", "-n", type=int, default=50, show_default=True, help="How many Winbindex versions to list")
def lookup_file(filename: str, arch: Optional[str], limit: int) -> None:
    """List Winbindex history for one file, including KBs and release dates."""
    print_header()
    architecture = Architecture(arch) if arch else None
    console.print(f"\n[cyan]Looking up {filename}...[/cyan]\n")
    show_file_versions(filename, architecture, limit=limit)


@lookup.command(name="cve")
@click.argument("cve_id")
@click.option("--fetch-count", type=int, default=24, show_default=True, help="Fetch this many recent updates if the CVE is missing locally")
def lookup_cve(cve_id: str, fetch_count: int) -> None:
    """List KBs related to a CVE without running analysis."""
    print_header()
    init_db()
    normalized_cve = cve_id.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", normalized_cve):
        console.print(f"\n[red]Invalid CVE format: {cve_id}[/red]")
        console.print("[dim]Expected format: CVE-YYYY-NNNN[/dim]")
        return
    patches = _resolve_cve_patches(normalized_cve, fetch_count)
    if not patches:
        console.print(f"\n[red]No KB mappings found for {normalized_cve}.[/red]")
        console.print("[dim]Try: ppp fetch -d YYYY-MM[/dim]")
        return
    _render_cve_patch_table(normalized_cve, patches)


@analyze.command(name="file")
@click.argument("filename")
@click.option("--arch", "-a", type=click.Choice(["x64", "x86", "arm64"]), default="x64", show_default=True, help="Architecture filter")
@click.option("--kb", type=str, help="Select the patched/newer file by KB number")
@click.option("--limit", type=int, default=200, show_default=True, help="How many Winbindex entries to inspect")
@click.option("--list-only", "-l", is_flag=True, help="Only show the selected pair")
@click.option("--overwrite", is_flag=True, help="Regenerate exports, BinDiff, and reports")
def analyze_file(filename: str, arch: str, kb: Optional[str], limit: int, list_only: bool, overwrite: bool) -> None:
    """Analyze one binary directly from Winbindex and generate a BinDiff report."""
    _run_binary_diff(
        filename=filename,
        arch=arch,
        kb=kb,
        new_version=None,
        old_version=None,
        new_build=None,
        old_build=None,
        new_date=None,
        old_date=None,
        limit=limit,
        list_only=list_only,
        report=not list_only,
        pseudo_c=False,
        overwrite=overwrite,
    )


@analyze.command(name="kb")
@click.argument("kb_number")
@click.option("--arch", "-a", type=click.Choice(["x64", "x86", "arm64"]), help="Catalog architecture filter")
@click.option("--save-db", is_flag=True, help="Persist extracted and baseline records to the local DB")
def analyze_kb(kb_number: str, arch: Optional[str], save_db: bool) -> None:
    """Analyze one KB and generate BinDiff reports for all matched binaries."""
    print_header()
    init_db()
    architecture = Architecture(arch) if arch else None
    _run_kb_pipeline(kb_number, architecture=architecture, save_db=save_db, report=True)


@analyze.command(name="month")
@click.argument("date")
@click.option("--arch", "-a", type=click.Choice(["x64", "x86", "arm64"]), help="Catalog architecture filter")
@click.option("--save-db", is_flag=True, help="Persist extracted and baseline records to the local DB")
def analyze_month(date: str, arch: Optional[str], save_db: bool) -> None:
    """Analyze every KB for a Patch Tuesday month (YYYY-MM)."""
    print_header()
    init_db()
    try:
        year, month = map(int, date.split("-"))
        if month < 1 or month > 12:
            raise ValueError("Month must be 1-12")
    except ValueError as exc:
        raise click.ClickException(f"Invalid date format: {exc}. Use YYYY-MM.")

    console.print(f"\n[cyan]Fetching and loading {year}-{month:02d} metadata...[/cyan]\n")
    fetch_by_date(year, month, verbose=True)

    with get_db() as db:
        patches = get_patches_by_date(db, year, month)
    if not patches:
        console.print("[yellow]No patches found for that month[/yellow]")
        return

    architecture = Architecture(arch) if arch else None
    console.print(f"[bold]Analyzing {len(patches)} patch(es) for {year}-{month:02d}[/bold]")
    for patch in patches:
        _run_kb_pipeline(patch.kb_number, architecture=architecture, save_db=save_db, report=True)


@analyze.command(name="cve")
@click.argument("cve_id")
@click.option("--arch", "-a", type=click.Choice(["x64", "x86", "arm64"]), help="Catalog architecture filter")
@click.option("--fetch-count", type=int, default=24, show_default=True, help="Fetch this many recent updates if the CVE is missing locally")
@click.option("--save-db", is_flag=True, help="Persist extracted and baseline records to the local DB")
def analyze_cve_simple(cve_id: str, arch: Optional[str], fetch_count: int, save_db: bool) -> None:
    """Resolve a CVE to KBs and analyze each related KB."""
    print_header()
    init_db()
    normalized_cve = cve_id.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", normalized_cve):
        console.print(f"\n[red]Invalid CVE format: {cve_id}[/red]")
        console.print("[dim]Expected format: CVE-YYYY-NNNN[/dim]")
        return
    patches = _resolve_cve_patches(normalized_cve, fetch_count)
    if not patches:
        console.print(f"\n[red]No KB mappings found for {normalized_cve}.[/red]")
        console.print("[dim]Try: ppp fetch -d YYYY-MM[/dim]")
        return
    _render_cve_patch_table(normalized_cve, patches)

    architecture = Architecture(arch) if arch else None
    for patch in patches:
        _run_kb_pipeline(patch.kb_number, architecture=architecture, save_db=save_db, report=True)


@cli.command()
@click.option(
    "--date",
    "-d",
    type=str,
    help="Specific month to fetch (YYYY-MM format)",
)
@click.option(
    "--count",
    "-n",
    type=int,
    default=1,
    help="Number of recent updates to fetch (default: 1)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Show detailed progress",
)
@click.option(
    "--source",
    type=click.Choice(["rss", "api"]),
    default="rss",
    show_default=True,
    help="Update ID source when fetching latest updates",
)
def fetch(date: Optional[str], count: int, verbose: bool, source: str) -> None:
    """
    Fetch Patch Tuesday data from MSRC.
    
    Examples:
    
        ppp fetch                          # Fetch latest update
        
        ppp fetch -n 3                     # Fetch last 3 updates
        
        ppp fetch -d 2024-01               # Fetch January 2024
    """
    print_header()
    init_db()
    
    if date:
        # Parse YYYY-MM format
        try:
            year, month = map(int, date.split("-"))
            if month < 1 or month > 12:
                raise ValueError("Month must be 1-12")
        except ValueError as e:
            console.print(f"[red]Invalid date format: {e}[/red]")
            console.print("[dim]Use YYYY-MM format (e.g., 2024-01)[/dim]")
            return
        
        console.print(f"\n[cyan]Fetching patches for {year}-{month:02d}...[/cyan]\n")
        result = fetch_by_date(year, month, verbose=verbose)
        
        if result:
            console.print(f"\n[green]✓ Fetched {result['patches']} patches, "
                         f"{result['products']} products, {result['cves']} CVEs[/green]")
        else:
            console.print("[yellow]No patches found for that date[/yellow]")
    else:
        console.print(f"\n[cyan]Fetching latest {count} update(s)...[/cyan]\n")
        results = fetch_latest(count, verbose=verbose, prefer_rss=(source == "rss"))
        
        if results:
            total_patches = sum(r['patches'] for r in results)
            total_cves = sum(r['cves'] for r in results)
            console.print(f"\n[green]✓ Fetched {len(results)} update(s): "
                         f"{total_patches} patches, {total_cves} CVEs[/green]")
        else:
            console.print("[yellow]No updates fetched[/yellow]")


@cli.command(name="updates", hidden=True)
@click.option("--year", "-y", type=int, help="Filter by year")
@click.option(
    "--source",
    type=click.Choice(["rss", "api"]),
    default="rss",
    show_default=True,
    help="Update ID source",
)
def list_updates(year: Optional[int], source: str) -> None:
    """List available Patch Tuesday updates from MSRC."""
    print_header()
    
    console.print("\n[cyan]Fetching available updates...[/cyan]\n")
    
    update_ids = get_update_ids(year, prefer_rss=(source == "rss"))
    
    if not update_ids:
        console.print("[yellow]No updates found[/yellow]")
        return
    
    table = Table(title="Available Patch Tuesday Updates")
    table.add_column("Update ID", style="cyan")
    table.add_column("Year", style="green")
    table.add_column("Month", style="yellow")
    
    for update_id in update_ids[:24]:  # Show last 2 years
        parts = update_id.split("-")
        if len(parts) == 2:
            table.add_row(update_id, parts[0], parts[1])
    
    console.print(table)
    console.print(f"\n[dim]Showing {min(24, len(update_ids))} of {len(update_ids)} updates[/dim]")


@cli.command(name="list")
@click.option(
    "--date",
    "-d",
    type=str,
    help="Filter by month (YYYY-MM format)",
)
@click.option(
    "--product",
    "-p",
    type=str,
    help="Filter by product name (partial match)",
)
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["critical", "important", "moderate", "low"]),
    help="Filter by severity",
)
def list_patches(
    date: Optional[str],
    product: Optional[str],
    severity: Optional[str],
) -> None:
    """List patches from the database."""
    print_header()
    init_db()
    
    with get_db() as db:
        # Get patches based on filters
        if product:
            patches = get_patches_by_product(db, product)
        elif date:
            try:
                year, month = map(int, date.split("-"))
                patches = get_patches_by_date(db, year, month)
            except ValueError:
                console.print("[red]Invalid date format. Use YYYY-MM[/red]")
                return
        else:
            patches = get_patches_by_date(db)
        
        # Filter by severity if specified
        if severity:
            sev = Severity(severity.capitalize())
            patches = [p for p in patches if p.severity == sev]
        
        if not patches:
            console.print("\n[yellow]No patches found. Try running 'ppp fetch' first.[/yellow]")
            return
        
        # Group by date
        by_date: dict[str, list] = {}
        for patch in patches:
            date_key = patch.release_date.strftime("%Y-%m")
            if date_key not in by_date:
                by_date[date_key] = []
            by_date[date_key].append(patch)
        
        # Display
        for date_key in sorted(by_date.keys(), reverse=True):
            date_patches = by_date[date_key]
            
            table = Table(title=f"Patches - {date_key}")
            table.add_column("KB", style="cyan", width=12)
            table.add_column("Release Date", style="magenta", width=12)
            table.add_column("Severity", style="yellow", width=12)
            table.add_column("Products", style="green", width=30)
            table.add_column("Title", style="white", max_width=50)
            
            for patch in sorted(date_patches, key=lambda p: p.kb_number):
                sev_style = {
                    Severity.CRITICAL: "red bold",
                    Severity.IMPORTANT: "yellow",
                    Severity.MODERATE: "blue",
                    Severity.LOW: "dim",
                }.get(patch.severity, "white")
                
                # Get products for this patch
                products = get_products_for_patch(db, patch.id)
                products_str = summarize_products(products)
                
                table.add_row(
                    patch.kb_number,
                    patch.release_date.strftime("%Y-%m-%d"),
                    f"[{sev_style}]{patch.severity.value}[/{sev_style}]",
                    products_str,
                    patch.title[:50] + ("..." if len(patch.title) > 50 else ""),
                )
            
            console.print(table)
            console.print()


@cli.command()
@click.argument("kb_number")
def show(kb_number: str) -> None:
    """Show detailed information about a specific patch."""
    print_header()
    init_db()
    
    with get_db() as db:
        patch = get_patch(db, kb_number)
        
        if not patch:
            console.print(f"\n[yellow]Patch {kb_number} not found in database.[/yellow]")
            console.print("[dim]Try running 'ppp fetch' first.[/dim]")
            return
        
        # Main patch info
        console.print(f"\n[bold cyan]{patch.kb_number}[/bold cyan] - {patch.title}\n")
        
        sev_style = {
            Severity.CRITICAL: "red bold",
            Severity.IMPORTANT: "yellow",
            Severity.MODERATE: "blue",
            Severity.LOW: "dim",
        }.get(patch.severity, "white")
        
        console.print(f"[bold]Release Date:[/bold] {patch.release_date.strftime('%Y-%m-%d')}")
        console.print(f"[bold]Severity:[/bold] [{sev_style}]{patch.severity.value}[/{sev_style}]")
        
        if patch.description:
            console.print(f"\n[bold]Description:[/bold]\n{patch.description}")
        
        # Products
        if patch.products:
            console.print(f"\n[bold]Affected Products ({len(patch.products)}):[/bold]")
            tree = Tree("[cyan]Products[/cyan]")
            
            # Group by product family
            families: dict[str, list] = {}
            for product in patch.products:
                family = product.name.split()[0:2]
                family_name = " ".join(family)
                if family_name not in families:
                    families[family_name] = []
                families[family_name].append(product)
            
            for family, products in sorted(families.items()):
                branch = tree.add(f"[green]{family}[/green]")
                for p in products[:5]:  # Limit display
                    branch.add(f"[dim]{p.name}[/dim]")
                if len(products) > 5:
                    branch.add(f"[dim]... and {len(products) - 5} more[/dim]")
            
            console.print(tree)
        
        # CVEs
        if patch.cves:
            console.print(f"\n[bold]CVEs ({len(patch.cves)}):[/bold]")
            
            cve_table = Table(show_header=True, header_style="bold")
            cve_table.add_column("CVE ID", style="cyan", width=16)
            cve_table.add_column("Severity", width=12)
            cve_table.add_column("Title", max_width=50)
            
            for cve in sorted(patch.cves, key=lambda c: c.cve_id)[:20]:
                cve_sev_style = {
                    Severity.CRITICAL: "red bold",
                    Severity.IMPORTANT: "yellow",
                    Severity.MODERATE: "blue",
                    Severity.LOW: "dim",
                }.get(cve.severity, "white")
                
                cve_table.add_row(
                    cve.cve_id,
                    f"[{cve_sev_style}]{cve.severity.value}[/{cve_sev_style}]",
                    cve.title[:50] + ("..." if len(cve.title) > 50 else ""),
                )
            
            console.print(cve_table)
            
            if len(patch.cves) > 20:
                console.print(f"[dim]... and {len(patch.cves) - 20} more CVEs[/dim]")


@cli.command(hidden=True)
def stats() -> None:
    """Show database statistics."""
    print_header()
    init_db()
    
    with get_db() as db:
        s = get_stats(db)
        
        console.print("\n[bold]Database Statistics[/bold]\n")
        
        table = Table(show_header=False)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Patches", str(s["patches"]))
        table.add_row("Total Products", str(s["products"]))
        table.add_row("Total CVEs", str(s["cves"]))
        table.add_row("Downloaded Files", str(s["downloaded_files"]))
        
        if s["latest_patch_date"]:
            table.add_row("Latest Patch Date", s["latest_patch_date"])
        
        console.print(table)


@cli.command(hidden=True)
@click.argument("kb_number")
@click.option("--arch", "-a", type=click.Choice(["x64", "x86", "arm64"]), help="Architecture filter")
@click.option("--list-only", "-l", is_flag=True, help="List available packages without downloading")
def download(kb_number: str, arch: Optional[str], list_only: bool) -> None:
    """Download update packages from Microsoft Update Catalog."""
    print_header()
    
    architecture = Architecture(arch) if arch else None
    
    if list_only:
        console.print(f"\n[cyan]Searching catalog for {kb_number}...[/cyan]\n")
        list_catalog_entries(kb_number)
        return
    
    console.print(f"\n[cyan]Downloading packages for {kb_number}...[/cyan]\n")
    
    downloaded = download_by_kb(kb_number, architecture)
    
    if downloaded:
        console.print(f"\n[green]✓ Downloaded {len(downloaded)} package(s)[/green]")
        for path in downloaded:
            console.print(f"  [dim]{path}[/dim]")
    else:
        console.print("[yellow]No packages downloaded[/yellow]")


@cli.command(hidden=True)
@click.argument("kb_number")
@click.option("--save-db", "-s", is_flag=True, help="Save extracted file info to database")
def extract(kb_number: str, save_db: bool) -> None:
    """Extract binary files from downloaded update packages."""
    print_header()
    init_db()
    
    console.print(f"\n[cyan]Extracting binaries from {kb_number} packages...[/cyan]\n")
    
    extracted = extract_by_kb(kb_number)
    
    if not extracted:
        console.print("[yellow]No files extracted. Make sure packages are downloaded first.[/yellow]")
        console.print(f"[dim]Run: ppp download {kb_number}[/dim]")
        return
    
    # Save to database if requested
    if save_db:
        with get_db() as db:
            for file in extracted:
                add_downloaded_file(db, file)
        console.print(f"[green]✓ Saved {len(extracted)} file records to database[/green]")
    
    # Show stats
    kb = kb_number.upper()
    if not kb.startswith("KB"):
        kb = f"KB{kb}"
    
    stats = get_extraction_stats(kb)
    
    console.print(f"\n[bold]Extraction Summary:[/bold]")
    console.print(f"  Total files: {stats['total']}")
    
    if stats['by_arch']:
        console.print("  By architecture:")
        for arch, count in sorted(stats['by_arch'].items()):
            console.print(f"    {arch}: {count}")
    
    if stats['by_type']:
        console.print("  By type:")
        for ext, count in sorted(stats['by_type'].items()):
            console.print(f"    {ext}: {count}")


@cli.command(name="files", hidden=True)
@click.argument("kb_number")
def list_files(kb_number: str) -> None:
    """List extracted files for a KB."""
    print_header()
    
    files = list_extracted_files(kb_number)
    
    if not files:
        console.print(f"\n[yellow]No extracted files found for {kb_number}[/yellow]")
        console.print("[dim]Run: ppp extract {kb_number}[/dim]")
        return
    
    table = Table(title=f"Extracted Files - {kb_number}")
    table.add_column("Architecture", style="cyan", width=10)
    table.add_column("Filename", style="green")
    table.add_column("Size", style="yellow", justify="right")
    
    for file_path in files:
        arch = file_path.parent.name
        size = file_path.stat().st_size
        size_str = f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / 1024 / 1024:.1f} MB"
        
        table.add_row(arch, file_path.name, size_str)
    
    console.print(table)
    console.print(f"\n[dim]Total: {len(files)} files[/dim]")


@cli.command(hidden=True)
@click.argument("kb_number")
def baseline(kb_number: str) -> None:
    """Fetch pre-patch versions of binaries from WinBIndex."""
    print_header()
    init_db()
    
    # Normalize KB number
    kb = kb_number.upper()
    if not kb.startswith("KB"):
        kb = f"KB{kb}"
    
    extracted_dir = DEFAULT_EXTRACTED_DIR / kb
    
    if not extracted_dir.exists():
        console.print(f"\n[yellow]No extracted files found for {kb}[/yellow]")
        console.print("[dim]Run these commands first:[/dim]")
        console.print(f"  [dim]ppp download {kb}[/dim]")
        console.print(f"  [dim]ppp extract {kb}[/dim]")
        return
    
    console.print(f"\n[cyan]Fetching baseline versions for {kb}...[/cyan]\n")
    
    downloaded = fetch_baseline_for_extracted(extracted_dir, kb)
    
    if downloaded:
        console.print(f"\n[green]✓ Downloaded {len(downloaded)} baseline file(s)[/green]")
        
        # Save to database
        with get_db() as db:
            for file in downloaded:
                add_downloaded_file(db, file)
    else:
        console.print("[yellow]No baseline files could be downloaded[/yellow]")


@cli.command(hidden=True)
@click.argument("filename")
@click.option("--arch", "-a", type=click.Choice(["x64", "x86", "arm64"]), help="Architecture filter")
@click.option("--limit", "-n", type=int, default=20, show_default=True, help="How many Winbindex versions to list")
def versions(filename: str, arch: Optional[str], limit: int) -> None:
    """Show available versions of a Windows binary on WinBIndex."""
    print_header()
    
    architecture = Architecture(arch) if arch else None
    
    console.print(f"\n[cyan]Looking up {filename}...[/cyan]\n")
    
    show_file_versions(filename, architecture, limit=limit)


@cli.command(name="binary-diff", hidden=True)
@click.argument("filename")
@click.option("--arch", "-a", type=click.Choice(["x64", "x86", "arm64"]), default="x64", show_default=True, help="Architecture filter")
@click.option("--kb", type=str, help="Select the newer/patched binary by KB number")
@click.option("--new-version", type=str, help="Exact version string for the newer binary")
@click.option("--old-version", type=str, help="Exact version string for the older binary")
@click.option("--new-build", type=str, help="Substring to match in newer version/build")
@click.option("--old-build", type=str, help="Substring to match in older version/build")
@click.option("--new-date", type=str, help="Release date for newer version (YYYY-MM-DD)")
@click.option("--old-date", type=str, help="Release date for older version (YYYY-MM-DD)")
@click.option("--limit", type=int, default=200, show_default=True, help="How many Winbindex entries to inspect")
@click.option("--list-only", "-l", is_flag=True, help="Only list available versions and selected pair")
@click.option("--report", is_flag=True, help="Generate an HTML report with pseudo-C diffs for non-identical matched functions")
@click.option("--pseudo-c", is_flag=True, help="Alias for report pseudo-C behavior")
@click.option("--overwrite", is_flag=True, help="Regenerate exports/BinDiff/report even if cached artifacts already exist")
def binary_diff(
    filename: str,
    arch: str,
    kb: Optional[str],
    new_version: Optional[str],
    old_version: Optional[str],
    new_build: Optional[str],
    old_build: Optional[str],
    new_date: Optional[str],
    old_date: Optional[str],
    limit: int,
    list_only: bool,
    report: bool,
    pseudo_c: bool,
    overwrite: bool,
) -> None:
    """Download and BinDiff two versions of a binary from Winbindex."""
    _run_binary_diff(
        filename=filename,
        arch=arch,
        kb=kb,
        new_version=new_version,
        old_version=old_version,
        new_build=new_build,
        old_build=old_build,
        new_date=new_date,
        old_date=old_date,
        limit=limit,
        list_only=list_only,
        report=report,
        pseudo_c=pseudo_c,
        overwrite=overwrite,
    )


@cli.command(name="cve", hidden=True)
@click.argument("cve_id")
@click.option("--arch", "-a", type=click.Choice(["x64", "x86", "arm64"]), help="Architecture filter for catalog downloads")
@click.option(
    "--fetch-count",
    type=int,
    default=24,
    show_default=True,
    help="If CVE isn't in DB, fetch this many recent updates before retrying",
)
@click.option("--list-only", "-l", is_flag=True, help="Only resolve and list KBs for the CVE")
@click.option("--run-bindiff", is_flag=True, help="Run BinDiff comparisons after baseline acquisition")
@click.option("--report", is_flag=True, help="Generate HTML reports with pseudo-C diffs for non-identical matched functions")
@click.option("--pseudo-c", is_flag=True, help="Alias for report pseudo-C behavior")
@click.option("--save-db", "-s", is_flag=True, help="Save extracted/baseline file records to database")
def analyze_cve(
    cve_id: str,
    arch: Optional[str],
    fetch_count: int,
    list_only: bool,
    run_bindiff: bool,
    report: bool,
    pseudo_c: bool,
    save_db: bool,
) -> None:
    """Resolve a CVE to KBs and run the patch analysis workflow."""
    print_header()
    init_db()
    if pseudo_c and not report:
        report = True
        console.print("[dim]`--pseudo-c` enabled: generating HTML reports automatically[/dim]")
    if report and run_bindiff and not pseudo_c:
        pseudo_c = True
        console.print("[dim]`--report` enabled: including pseudo-C diffs for non-identical matched functions[/dim]")
    
    normalized_cve = cve_id.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", normalized_cve):
        console.print(f"\n[red]Invalid CVE format: {cve_id}[/red]")
        console.print("[dim]Expected format: CVE-YYYY-NNNN[/dim]")
        return
    
    with get_db() as db:
        patches = get_patches_for_cve(db, normalized_cve)
        patch_products = {
            patch.id: summarize_products(get_products_for_patch(db, patch.id))
            for patch in patches
            if patch.id is not None
        }
    
    if not patches:
        console.print(f"\n[yellow]{normalized_cve} not found in local database.[/yellow]")
        console.print(f"[cyan]Fetching latest {fetch_count} updates via RSS/API and retrying...[/cyan]\n")
        fetch_latest(fetch_count, verbose=True, prefer_rss=True)
        with get_db() as db:
            patches = get_patches_for_cve(db, normalized_cve)
            patch_products = {
                patch.id: summarize_products(get_products_for_patch(db, patch.id))
                for patch in patches
                if patch.id is not None
            }
    
    if not patches:
        console.print(f"\n[red]No KB mappings found for {normalized_cve}.[/red]")
        console.print("[dim]Try: ppp fetch -d YYYY-MM[/dim]")
        return
    
    table = Table(title=f"{normalized_cve} - Related KB Patches")
    table.add_column("KB", style="cyan")
    table.add_column("Release Date", style="green")
    table.add_column("Severity", style="yellow")
    table.add_column("Products", style="green", width=30)
    table.add_column("Title", style="white", max_width=60)
    
    for patch in patches:
        table.add_row(
            patch.kb_number,
            patch.release_date.strftime("%Y-%m-%d"),
            patch.severity.value,
            patch_products.get(patch.id, ""),
            patch.title[:60] + ("..." if len(patch.title) > 60 else ""),
        )
    console.print()
    console.print(table)
    
    if list_only:
        return
    if pseudo_c and not run_bindiff:
        console.print("[yellow]`--pseudo-c` has no effect unless `--run-bindiff` is set[/yellow]")
    
    architecture = Architecture(arch) if arch else None
    if run_bindiff:
        from .bindiff_client import compare_binaries_for_kb, show_comparison_summary
    
    for patch in patches:
        kb = patch.kb_number
        console.print(f"\n[bold cyan]Processing {kb} for {normalized_cve}[/bold cyan]")
        
        downloaded_packages = download_by_kb(kb, architecture)
        if not downloaded_packages:
            console.print("[yellow]No new packages downloaded (continuing with local cache if available).[/yellow]")
        
        extracted = extract_by_kb(kb)
        if not extracted:
            console.print(f"[yellow]Skipping {kb}: no extracted binaries available.[/yellow]")
            continue
        
        if save_db:
            with get_db() as db:
                for file in extracted:
                    add_downloaded_file(db, file)
        
        extracted_dir = DEFAULT_EXTRACTED_DIR / kb
        baseline_files = fetch_baseline_for_extracted(extracted_dir, kb)
        
        if baseline_files and save_db:
            with get_db() as db:
                for file in baseline_files:
                    add_downloaded_file(db, file)
        
        total_extracted = len(list_extracted_files(kb))
        console.print(
            f"[green]✓ {kb}: extracted {total_extracted} files, baseline candidates {len(baseline_files)}[/green]"
        )
        
        if run_bindiff:
            results = compare_binaries_for_kb(
                kb,
                generate_reports=report,
                include_pseudocode=pseudo_c,
            )
            if results:
                console.print(f"[green]✓ Generated {len(results)} BinDiff comparison(s) for {kb}[/green]")
                show_comparison_summary(results)
            else:
                console.print(f"[yellow]No BinDiff outputs generated for {kb}[/yellow]")


@cli.command(hidden=True)
@click.argument("kb_number")
def diff(kb_number: str) -> None:
    """Show files changed in a patch with before/after paths."""
    print_header()
    init_db()
    
    # Normalize KB number
    kb = kb_number.upper()
    if not kb.startswith("KB"):
        kb = f"KB{kb}"
    
    extracted_dir = DEFAULT_EXTRACTED_DIR / kb
    baseline_dir = DEFAULT_BASELINE_DIR / kb
    
    if not extracted_dir.exists():
        console.print(f"\n[yellow]No extracted files found for {kb}[/yellow]")
        return
    
    console.print(f"\n[bold]{kb} - Changed Files Analysis[/bold]\n")
    
    # Get extracted (post-patch) files
    extracted_files = list_extracted_files(kb)
    
    if not extracted_files:
        console.print("[yellow]No extracted files found[/yellow]")
        return
    
    # Check for baseline files
    has_baseline = baseline_dir.exists()
    baseline_files = {}
    
    if has_baseline:
        for f in baseline_dir.rglob("*"):
            if f.is_file():
            # Extract base filename from versioned name (e.g., "wcp_10_0_19041_963.dll" -> "wcp.dll")
                stem = f.stem
                # Remove version info in parentheses first
                if " (" in stem:
                    stem = stem.split(" (")[0]
                # The base name is everything before the first underscore followed by digits
                import re
                match = re.match(r'^([a-zA-Z][a-zA-Z0-9._-]*?)(?:_\d|$)', stem)
                if match:
                    base_name = match.group(1) + f.suffix
                else:
                    base_name = stem.split("_")[0] + f.suffix
                baseline_files[base_name.lower()] = f
    
    import re
    unique_extracted: dict[str, Path] = {}
    for file_path in extracted_files:
        name = file_path.name.lower()
        clean_name = re.sub(r'_[a-f0-9]{8}(\.[a-z]+)$', r'\1', name)
        if clean_name not in unique_extracted:
            unique_extracted[clean_name] = file_path
    
    project_root = Path.cwd()
    
    def rel_path(p: Path) -> str:
        try:
            return str(p.relative_to(project_root))
        except ValueError:
            return str(p)
    
    console.print("\n[bold]Changed Files:[/bold]\n")
    
    matched_count = 0
    for clean_name in sorted(unique_extracted.keys()):
        file_path = unique_extracted[clean_name]
        arch = file_path.parent.name
        post_path = rel_path(file_path)
        baseline_path = baseline_files.get(clean_name)
        if baseline_path:
            pre_path = rel_path(baseline_path)
            matched_count += 1
            status = "[green]✓[/green]"
        else:
            pre_path = None
            status = "[yellow]○[/yellow]"
        
        console.print(f"{status} [cyan bold]{clean_name}[/cyan bold] [dim]({arch})[/dim]")
        console.print(f"    [yellow]Post:[/yellow] {post_path}")
        if pre_path:
            console.print(f"    [blue]Pre: [/blue] {pre_path}")
        else:
            console.print(f"    [dim]Pre:  N/A (no baseline)[/dim]")
        console.print()
    
    console.print(f"[dim]─────────────────────────────────────────[/dim]")
    console.print(f"[dim]Total files: {len(unique_extracted)}[/dim]")
    console.print(f"[dim]With baseline: {matched_count}/{len(unique_extracted)}[/dim]")
    
    if not has_baseline:
        console.print(f"\n[yellow]Tip: Run 'ppp baseline {kb}' to fetch pre-patch versions[/yellow]")


@cli.command(name="bindiff", hidden=True)
@click.argument("kb_number")
@click.option("--check-deps", is_flag=True, help="Check if BinDiff dependencies are installed")
@click.option("--manual", is_flag=True, help="Show instructions for manual BinExport workflow")
@click.option("--run-diff", is_flag=True, help="Run BinDiff on existing .BinExport files")
@click.option("--binary", "-b", type=str, help="Only compare a specific binary (e.g., notepad.exe)")
@click.option("--report", is_flag=True, help="Generate HTML report(s) with pseudo-C diffs for non-identical matched functions")
@click.option("--pseudo-c", is_flag=True, help="Alias for report pseudo-C behavior")
def bindiff_compare(
    kb_number: str,
    check_deps: bool,
    manual: bool,
    run_diff: bool,
    binary: Optional[str],
    report: bool,
    pseudo_c: bool,
) -> None:
    """Compare pre-patch and post-patch binaries using BinDiff."""
    from .bindiff_client import (
        check_dependencies,
        compare_binaries_for_kb,
        show_comparison_summary,
        DEFAULT_BINDIFF_DIR,
    )
    
    print_header()
    if pseudo_c and not report:
        report = True
        console.print("[dim]`--pseudo-c` enabled: generating HTML reports automatically[/dim]")
    if report and not run_diff and not pseudo_c:
        pseudo_c = True
        console.print("[dim]`--report` enabled: including pseudo-C diffs for non-identical matched functions[/dim]")
    
    if check_deps:
        from .bindiff_client import _find_binexport_extension
        
        console.print("\n[bold]Checking BinDiff dependencies...[/bold]\n")
        deps = check_dependencies()
        
        ghidra_found, ghidra_path = deps["ghidra"]
        bindiff_found, bindiff_path = deps["bindiff"]
        binexport_found, binexport_path = deps["binexport"]
        
        binexport_ext = None
        if ghidra_path:
            binexport_ext = _find_binexport_extension(ghidra_path)
        
        table = Table(title="Dependency Status")
        table.add_column("Dependency", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Path", style="dim", max_width=50)
        
        table.add_row(
            "Ghidra",
            "✅ Found" if ghidra_found else "❌ Missing",
            str(ghidra_path) if ghidra_path else "Set GHIDRA_HOME env var",
        )
        table.add_row(
            "BinDiff",
            "✅ Found" if bindiff_found else "❌ Missing",
            str(bindiff_path) if bindiff_path else "github.com/google/bindiff/releases",
        )
        table.add_row(
            "BinExport Ext",
            "✅ Found" if binexport_ext else "❌ Missing",
            str(binexport_ext) if binexport_ext else "github.com/google/binexport/releases",
        )
        
        console.print(table)
        
        all_found = ghidra_found and bindiff_found and binexport_ext is not None
        if all_found:
            console.print("\n[green]✓ All dependencies satisfied![/green]")
        else:
            console.print("\n[yellow]Some dependencies are missing.[/yellow]")
            if not binexport_ext and ghidra_path:
                console.print(f"\n[dim]Install BinExport Ghidra extension:[/dim]")
                console.print(f"[dim]  1. Download BinExport_Ghidra-Java.zip from https://github.com/google/binexport/releases[/dim]")
                console.print(f"[dim]  2. Extract to {ghidra_path}/Ghidra/Extensions/[/dim]")
        return
    
    # Normalize KB number
    kb = kb_number.upper()
    if not kb.startswith("KB"):
        kb = f"KB{kb}"
    
    # Get paths
    from .bindiff_client import (
        DEFAULT_EXTRACTED_DIR,
        DEFAULT_BASELINE_DIR,
        run_bindiff,
        export_bindiff_report,
        BinDiffResult,
    )
    
    kb_extracted = DEFAULT_EXTRACTED_DIR / kb
    kb_baseline = DEFAULT_BASELINE_DIR / kb
    exports_dir = DEFAULT_BINDIFF_DIR / kb / "exports"
    target_base = _normalize_binary_base_name(binary) if binary else None
    
    if manual:
        # Show manual export instructions
        console.print(f"\n[bold cyan]Manual BinExport Workflow for {kb}[/bold cyan]\n")
        
        if not kb_extracted.exists():
            console.print(f"[red]No extracted files found for {kb}[/red]")
            console.print(f"[dim]Run: ppp extract {kb}[/dim]")
            return
        
        if not kb_baseline.exists():
            console.print(f"[red]No baseline files found for {kb}[/red]")
            console.print(f"[dim]Run: ppp baseline {kb}[/dim]")
            return
        
        # Create exports directory
        exports_dir.mkdir(parents=True, exist_ok=True)
        
        console.print("[bold]Step 1:[/bold] Open Ghidra and create a new project\n")
        
        console.print("[bold]Step 2:[/bold] For each file pair, import and export:\n")
        
        # Find pairs
        import re
        baseline_files: dict[str, Path] = {}
        for f in kb_baseline.rglob("*"):
            if f.is_file() and f.suffix.lower() in (".dll", ".exe", ".sys"):
                stem = f.stem
                if " (" in stem:
                    stem = stem.split(" (")[0]
                match = re.match(r'^([a-zA-Z][a-zA-Z0-9._-]*?)(?:_\d|$)', stem)
                base_name = match.group(1).lower() if match else stem.split("_")[0].lower()
                baseline_files[base_name] = f
        
        extracted_files: dict[str, Path] = {}
        for f in kb_extracted.rglob("*"):
            if f.is_file() and f.suffix.lower() in (".dll", ".exe", ".sys"):
                name = f.name.lower()
                clean_name = re.sub(r'_[a-f0-9]{8}(\.[a-z]+)$', r'\1', name)
                base_name = clean_name.rsplit(".", 1)[0]
                if base_name not in extracted_files:
                    extracted_files[base_name] = f
        
        pairs = []
        for n in extracted_files:
            if n not in baseline_files:
                continue
            if target_base and n != target_base:
                continue
            pairs.append((baseline_files[n], extracted_files[n]))
        
        if target_base and not pairs:
            console.print(f"[yellow]No matching baseline/extracted pair found for {target_base}[/yellow]")
            return
        
        for i, (baseline, extracted) in enumerate(pairs, 1):
            base_name = extracted.stem.lower()
            base_name = re.sub(r'_[a-f0-9]{8}$', '', base_name)
            
            console.print(f"  [cyan]{i}. {base_name}[/cyan]")
            console.print(f"     Pre:  {baseline}")
            console.print(f"     Post: {extracted}")
            console.print(f"     Export to:")
            console.print(f"       • {exports_dir / f'{base_name}_baseline.BinExport'}")
            console.print(f"       • {exports_dir / f'{base_name}_patched.BinExport'}")
            console.print()
        
        console.print("[bold]Step 3:[/bold] In Ghidra for each binary:")
        console.print("   a. File → Import File → select binary")
        console.print("   b. Analyze (Yes to all)")
        console.print("   c. File → Export Program")
        console.print("   d. Format: 'Binary BinExport (v2) for BinDiff'")
        console.print("   e. Save to the paths shown above\n")
        
        console.print("[bold]Step 4:[/bold] Run comparison:")
        console.print(f"   [green]ppp bindiff {kb} --run-diff[/green]\n")
        return
    
    if run_diff:
        # Run BinDiff on existing .BinExport files
        console.print(f"\n[cyan]Running BinDiff on exported files for {kb}...[/cyan]\n")
        
        if not exports_dir.exists():
            console.print(f"[red]No exports directory found: {exports_dir}[/red]")
            console.print(f"[dim]Run: ppp bindiff {kb} --manual[/dim]")
            return
        
        # Find pairs of .BinExport files
        baseline_exports = list(exports_dir.glob("*_baseline.BinExport"))
        
        if not baseline_exports:
            console.print("[yellow]No .BinExport files found[/yellow]")
            console.print(f"[dim]Export files to: {exports_dir}[/dim]")
            return
        
        results: list[BinDiffResult] = []
        
        for baseline_export in baseline_exports:
            base_name = baseline_export.stem.replace("_baseline", "")
            if target_base and base_name.lower() != target_base:
                continue
            patched_export = exports_dir / f"{base_name}_patched.BinExport"
            
            if not patched_export.exists():
                console.print(f"[yellow]Missing patched export for {base_name}[/yellow]")
                continue
            
            console.print(f"[cyan]Comparing {base_name}...[/cyan]")
            
            bindiff_file = run_bindiff(baseline_export, patched_export, exports_dir.parent / f"{base_name}.BinDiff")
            
            if bindiff_file:
                if pseudo_c:
                    console.print("[yellow]Pseudo-C diff embedding requires original binaries; skipping for --run-diff mode[/yellow]")
                report_path = export_bindiff_report(bindiff_file, exports_dir.parent / "reports") if report else None
                results.append(BinDiffResult(
                    primary_file=str(baseline_export),
                    secondary_file=str(patched_export),
                    bindiff_file=bindiff_file,
                    similarity=0.0,
                    confidence=0.0,
                    matched_functions=0,
                    unmatched_primary=0,
                    unmatched_secondary=0,
                    report_path=report_path,
                ))
                console.print(f"[green]✓ {base_name}: {bindiff_file}[/green]")
            else:
                console.print(f"[red]✗ {base_name}: BinDiff failed[/red]")
        
        if results:
            console.print(f"\n[green]✓ Generated {len(results)} BinDiff comparison(s)[/green]")
            show_comparison_summary(results)
        else:
            console.print("[yellow]No comparisons were generated[/yellow]")
        return
    
    # Default: automatic comparison
    console.print(f"\n[cyan]Running BinDiff comparison for {kb}...[/cyan]\n")
    
    results = compare_binaries_for_kb(
        kb,
        binary_name=binary,
        generate_reports=report,
        include_pseudocode=pseudo_c,
    )
    
    if results:
        console.print(f"\n[green]✓ Generated {len(results)} BinDiff comparison(s)[/green]")
        show_comparison_summary(results)
        
        output_dir = DEFAULT_BINDIFF_DIR / kb
        console.print(f"\n[dim]Output directory: {output_dir}[/dim]")
        console.print("[dim]Open .BinDiff files in BinDiff GUI for detailed analysis[/dim]")
    else:
        console.print("[yellow]No comparisons were generated[/yellow]")
        console.print(f"\n[dim]If automatic export fails, try manual mode:[/dim]")
        console.print(f"[dim]  ppp bindiff {kb} --manual[/dim]")


@cli.command()
@click.option("--db", is_flag=True, help="Clear the database")
@click.option("--cache", is_flag=True, help="Clear downloaded files (packages, extracted, baseline, bindiff)")
@click.option("--all", "clear_all", is_flag=True, help="Clear both database and cache")
@click.option("--force", "-f", is_flag=True, help="Skip confirmation prompt")
def clean(db: bool, cache: bool, clear_all: bool, force: bool) -> None:
    """Clear local cache and/or database.
    
    Examples:
    
        ppp clean --db                     # Clear only the database
        
        ppp clean --cache                  # Clear only downloaded files
        
        ppp clean --all                    # Clear everything
        
        ppp clean --all -f                 # Clear everything without confirmation
    """
    import shutil
    
    print_header()
    
    if not (db or cache or clear_all):
        console.print("\n[yellow]No action specified. Use --db, --cache, or --all[/yellow]")
        console.print("[dim]Run 'ppp clean --help' for usage[/dim]")
        return
    
    clear_db = db or clear_all
    clear_cache = cache or clear_all
    
    # Show what will be deleted
    console.print("\n[bold]The following will be deleted:[/bold]\n")
    
    items_to_delete = []
    
    if clear_db:
        db_path = get_db_path()
        if db_path.exists():
            size = db_path.stat().st_size
            size_str = f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / 1024 / 1024:.1f} MB"
            console.print(f"  [cyan]Database:[/cyan] {db_path} ({size_str})")
            items_to_delete.append(("db", db_path))
        else:
            console.print(f"  [dim]Database: (not found)[/dim]")
    
    if clear_cache:
        from .bindiff_client import DEFAULT_BINDIFF_DIR
        
        cache_dirs = [
            ("Packages", DEFAULT_PACKAGES_DIR),
            ("Extracted", DEFAULT_EXTRACTED_DIR),
            ("Baseline", DEFAULT_BASELINE_DIR),
            ("BinDiff", DEFAULT_BINDIFF_DIR),
        ]
        
        for name, dir_path in cache_dirs:
            if dir_path.exists():
                # Calculate size
                total_size = sum(f.stat().st_size for f in dir_path.rglob("*") if f.is_file())
                file_count = sum(1 for f in dir_path.rglob("*") if f.is_file())
                size_str = f"{total_size / 1024:.1f} KB" if total_size < 1024 * 1024 else f"{total_size / 1024 / 1024:.1f} MB"
                console.print(f"  [cyan]{name}:[/cyan] {dir_path} ({file_count} files, {size_str})")
                items_to_delete.append(("dir", dir_path))
            else:
                console.print(f"  [dim]{name}: (not found)[/dim]")
    
    if not items_to_delete:
        console.print("\n[yellow]Nothing to delete.[/yellow]")
        return
    
    # Confirm
    if not force:
        console.print()
        if not click.confirm("Are you sure you want to delete these items?"):
            console.print("[dim]Aborted.[/dim]")
            return
    
    # Delete
    console.print()
    for item_type, path in items_to_delete:
        try:
            if item_type == "db":
                path.unlink()
                console.print(f"[green]✓ Deleted database: {path}[/green]")
            else:
                shutil.rmtree(path)
                console.print(f"[green]✓ Deleted directory: {path}[/green]")
        except Exception as e:
            console.print(f"[red]✗ Failed to delete {path}: {e}[/red]")
    
    console.print("\n[green]Done![/green]")


if __name__ == "__main__":
    cli()
