"""CLI for Patch Tuesday Analyzer."""

from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from . import __version__
from .catalog_client import download_by_kb, list_catalog_entries, search_catalog
from .database import (
    get_db,
    get_db_path,
    get_patch,
    get_patches_by_date,
    get_patches_by_product,
    get_products_for_patch,
    get_stats,
    init_db,
    add_downloaded_file,
    get_downloaded_files,
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
    fetch_baseline_for_extracted,
    show_file_versions,
    DEFAULT_BASELINE_DIR,
)

console = Console()


def print_header() -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]Patch Tuesday Analyzer[/bold cyan] v{__version__}\n"
            "[dim]Microsoft Security Update Analysis Tool[/dim]",
            border_style="cyan",
        )
    )


@click.group()
@click.version_option(version=__version__)
def cli() -> None:
    """Patch Tuesday Analyzer - fetch, analyze, and download Windows security patches."""
    pass


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
def fetch(date: Optional[str], count: int, verbose: bool) -> None:
    """
    Fetch Patch Tuesday data from MSRC.
    
    Examples:
    
        patch-tuesday fetch                # Fetch latest update
        
        patch-tuesday fetch -n 3           # Fetch last 3 updates
        
        patch-tuesday fetch -d 2024-01     # Fetch January 2024
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
        result = fetch_by_date(year, month, verbose=True)
        
        if result:
            console.print(f"\n[green]✓ Fetched {result['patches']} patches, "
                         f"{result['products']} products, {result['cves']} CVEs[/green]")
        else:
            console.print("[yellow]No patches found for that date[/yellow]")
    else:
        console.print(f"\n[cyan]Fetching latest {count} update(s)...[/cyan]\n")
        results = fetch_latest(count, verbose=True)
        
        if results:
            total_patches = sum(r['patches'] for r in results)
            total_cves = sum(r['cves'] for r in results)
            console.print(f"\n[green]✓ Fetched {len(results)} update(s): "
                         f"{total_patches} patches, {total_cves} CVEs[/green]")
        else:
            console.print("[yellow]No updates fetched[/yellow]")


@cli.command(name="updates")
@click.option("--year", "-y", type=int, help="Filter by year")
def list_updates(year: Optional[int]) -> None:
    """List available Patch Tuesday updates from MSRC."""
    print_header()
    
    console.print("\n[cyan]Fetching available updates...[/cyan]\n")
    
    update_ids = get_update_ids(year)
    
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
            console.print("\n[yellow]No patches found. Try running 'patch-tuesday fetch' first.[/yellow]")
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
            console.print("[dim]Try running 'patch-tuesday fetch' first.[/dim]")
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


@cli.command()
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


@cli.command()
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


@cli.command()
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
        console.print(f"[dim]Run: patch-tuesday download {kb_number}[/dim]")
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


@cli.command(name="files")
@click.argument("kb_number")
def list_files(kb_number: str) -> None:
    """List extracted files for a KB."""
    print_header()
    
    files = list_extracted_files(kb_number)
    
    if not files:
        console.print(f"\n[yellow]No extracted files found for {kb_number}[/yellow]")
        console.print("[dim]Run: patch-tuesday extract {kb_number}[/dim]")
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


@cli.command()
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
        console.print(f"  [dim]patch-tuesday download {kb}[/dim]")
        console.print(f"  [dim]patch-tuesday extract {kb}[/dim]")
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


@cli.command()
@click.argument("filename")
@click.option("--arch", "-a", type=click.Choice(["x64", "x86", "arm64"]), help="Architecture filter")
def versions(filename: str, arch: Optional[str]) -> None:
    """Show available versions of a Windows binary on WinBIndex."""
    print_header()
    
    architecture = Architecture(arch) if arch else None
    
    console.print(f"\n[cyan]Looking up {filename}...[/cyan]\n")
    
    show_file_versions(filename, architecture)


@cli.command()
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
        console.print(f"\n[yellow]Tip: Run 'patch-tuesday baseline {kb}' to fetch pre-patch versions[/yellow]")


@cli.command(name="bindiff")
@click.argument("kb_number")
@click.option("--check-deps", is_flag=True, help="Check if BinDiff dependencies are installed")
@click.option("--manual", is_flag=True, help="Show instructions for manual BinExport workflow")
@click.option("--run-diff", is_flag=True, help="Run BinDiff on existing .BinExport files")
def bindiff_compare(kb_number: str, check_deps: bool, manual: bool, run_diff: bool) -> None:
    """Compare pre-patch and post-patch binaries using BinDiff."""
    from .bindiff_client import (
        check_dependencies,
        compare_binaries_for_kb,
        show_comparison_summary,
        DEFAULT_BINDIFF_DIR,
    )
    
    print_header()
    
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
    
    if manual:
        # Show manual export instructions
        console.print(f"\n[bold cyan]Manual BinExport Workflow for {kb}[/bold cyan]\n")
        
        if not kb_extracted.exists():
            console.print(f"[red]No extracted files found for {kb}[/red]")
            console.print(f"[dim]Run: patch-tuesday extract {kb}[/dim]")
            return
        
        if not kb_baseline.exists():
            console.print(f"[red]No baseline files found for {kb}[/red]")
            console.print(f"[dim]Run: patch-tuesday baseline {kb}[/dim]")
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
        
        pairs = [(baseline_files[n], extracted_files[n]) for n in extracted_files if n in baseline_files]
        
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
        console.print(f"   [green]patch-tuesday bindiff {kb} --run-diff[/green]\n")
        return
    
    if run_diff:
        # Run BinDiff on existing .BinExport files
        console.print(f"\n[cyan]Running BinDiff on exported files for {kb}...[/cyan]\n")
        
        if not exports_dir.exists():
            console.print(f"[red]No exports directory found: {exports_dir}[/red]")
            console.print(f"[dim]Run: patch-tuesday bindiff {kb} --manual[/dim]")
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
            patched_export = exports_dir / f"{base_name}_patched.BinExport"
            
            if not patched_export.exists():
                console.print(f"[yellow]Missing patched export for {base_name}[/yellow]")
                continue
            
            console.print(f"[cyan]Comparing {base_name}...[/cyan]")
            
            bindiff_file = run_bindiff(baseline_export, patched_export, exports_dir.parent / f"{base_name}.BinDiff")
            
            if bindiff_file:
                report_path = export_bindiff_report(bindiff_file, exports_dir.parent / "reports")
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
    
    results = compare_binaries_for_kb(kb)
    
    if results:
        console.print(f"\n[green]✓ Generated {len(results)} BinDiff comparison(s)[/green]")
        show_comparison_summary(results)
        
        output_dir = DEFAULT_BINDIFF_DIR / kb
        console.print(f"\n[dim]Output directory: {output_dir}[/dim]")
        console.print("[dim]Open .BinDiff files in BinDiff GUI for detailed analysis[/dim]")
    else:
        console.print("[yellow]No comparisons were generated[/yellow]")
        console.print(f"\n[dim]If automatic export fails, try manual mode:[/dim]")
        console.print(f"[dim]  patch-tuesday bindiff {kb} --manual[/dim]")


@cli.command()
@click.option("--db", is_flag=True, help="Clear the database")
@click.option("--cache", is_flag=True, help="Clear downloaded files (packages, extracted, baseline, bindiff)")
@click.option("--all", "clear_all", is_flag=True, help="Clear both database and cache")
@click.option("--force", "-f", is_flag=True, help="Skip confirmation prompt")
def clean(db: bool, cache: bool, clear_all: bool, force: bool) -> None:
    """Clear local cache and/or database.
    
    Examples:
    
        patch-tuesday clean --db           # Clear only the database
        
        patch-tuesday clean --cache        # Clear only downloaded files
        
        patch-tuesday clean --all          # Clear everything
        
        patch-tuesday clean --all -f       # Clear everything without confirmation
    """
    import shutil
    
    print_header()
    
    if not (db or cache or clear_all):
        console.print("\n[yellow]No action specified. Use --db, --cache, or --all[/yellow]")
        console.print("[dim]Run 'patch-tuesday clean --help' for usage[/dim]")
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
