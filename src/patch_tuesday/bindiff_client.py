"""BinDiff integration for comparing pre-patch and post-patch binaries."""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()

DEFAULT_EXTRACTED_DIR = Path(__file__).parent.parent.parent / "downloads" / "extracted"
DEFAULT_BASELINE_DIR = Path(__file__).parent.parent.parent / "downloads" / "baseline"
DEFAULT_BINDIFF_DIR = Path(__file__).parent.parent.parent / "downloads" / "bindiff"


@dataclass
class BinDiffResult:
    primary_file: str
    secondary_file: str
    bindiff_file: Path
    similarity: float
    confidence: float
    matched_functions: int
    unmatched_primary: int
    unmatched_secondary: int
    report_path: Optional[Path] = None


def _find_ghidra() -> Optional[Path]:
    ghidra_home = os.environ.get("GHIDRA_HOME")
    if ghidra_home:
        path = Path(ghidra_home)
        if path.exists():
            return path
    search_bases = [
        Path("/Applications"),  # macOS
        Path("/opt"),
        Path("/usr/local"),
        Path.home(),
        Path.home() / "Applications",
    ]
    for base in search_bases:
        if not base.exists():
            continue
        try:
            for d in base.iterdir():
                if d.is_dir() and d.name.lower().startswith("ghidra"):
                    # Verify it's actually a Ghidra installation
                    if (d / "support" / "analyzeHeadless").exists() or (d / "ghidraRun").exists():
                        return d
        except PermissionError:
            continue
    return None


def _find_bindiff() -> Optional[Path]:
    bindiff_path = shutil.which("bindiff")
    if bindiff_path:
        return Path(bindiff_path)
    bindiff_home = os.environ.get("BINDIFF_HOME")
    if bindiff_home:
        path = Path(bindiff_home) / "bin" / "bindiff"
        if path.exists():
            return path
    common_paths = [
        Path("/opt/bindiff/bin/bindiff"),
        Path("/usr/local/bindiff/bin/bindiff"),
        Path("/usr/bin/bindiff"),
        Path.home() / "bindiff" / "bin" / "bindiff",
        # macOS
        Path("/Applications/BinDiff/bin/bindiff"),
        Path("C:/Program Files/BinDiff/bin/bindiff.exe"),
    ]
    for path in common_paths:
        if path.exists():
            return path
    return None


def _find_binexport() -> Optional[Path]:
    ghidra_home = _find_ghidra()
    if not ghidra_home:
        return None
    extensions_dir = ghidra_home / "Ghidra" / "Extensions"
    if extensions_dir.exists():
        for ext in extensions_dir.iterdir():
            if "binexport" in ext.name.lower():
                return ext
    user_ext = Path.home() / ".ghidra" / ".ghidra_extensions"
    if user_ext.exists():
        for ext in user_ext.iterdir():
            if "binexport" in ext.name.lower():
                return ext
    return None


def check_dependencies() -> dict[str, tuple[bool, Optional[Path]]]:
    ghidra = _find_ghidra()
    bindiff = _find_bindiff()
    binexport = _find_binexport()
    
    return {
        "ghidra": (ghidra is not None, ghidra),
        "bindiff": (bindiff is not None, bindiff),
        "binexport": (binexport is not None, binexport),
    }


def _find_binexport_extension(ghidra_path: Path) -> Optional[Path]:
    search_paths = [
        ghidra_path / "Ghidra" / "Extensions",
        ghidra_path / "Extensions",
    ]
    for ghidra_dir in Path.home().glob(".ghidra/.ghidra_*"):
        search_paths.append(ghidra_dir / "Extensions")
    
    for search_path in search_paths:
        if not search_path.exists():
            continue
        for ext_dir in search_path.iterdir():
            if ext_dir.is_dir() and "binexport" in ext_dir.name.lower():
                lib_dir = ext_dir / "lib"
                if lib_dir.exists():
                    for jar in lib_dir.glob("*.jar"):
                        if "binexport" in jar.name.lower():
                            return ext_dir
    return None


def _create_binexport_script(ghidra_path: Path) -> Path:
    script_content = '''// BinExport automation script
// @category BinExport
// @keybinding
// @menupath
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainFile;
import ghidra.util.classfinder.ClassSearcher;

import java.io.File;
import java.util.List;

public class ExportBinExport extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: ExportBinExport.java <output_path>");
            return;
        }
        
        String outputPath = args[0];
        File outputFile = new File(outputPath);
        
        // Find BinExport exporter
        List<Exporter> exporters = ClassSearcher.getInstances(Exporter.class);
        Exporter binExporter = null;
        
        for (Exporter exp : exporters) {
            String name = exp.getName().toLowerCase();
            if (name.contains("binexport") || name.contains("bindiff")) {
                binExporter = exp;
                break;
            }
        }
        
        if (binExporter == null) {
            printerr("BinExport exporter not found. Is the extension installed?");
            return;
        }
        
        println("Using exporter: " + binExporter.getName());
        
        try {
            binExporter.export(outputFile, currentProgram, null, monitor);
            println("Exported to: " + outputPath);
        } catch (ExporterException e) {
            printerr("Export failed: " + e.getMessage());
        }
    }
}
'''
    scripts_dir = ghidra_path / "Ghidra" / "Features" / "Base" / "ghidra_scripts"
    if not scripts_dir.exists():
        scripts_dir = ghidra_path / "ghidra_scripts"
        scripts_dir.mkdir(exist_ok=True)
    script_path = scripts_dir / "ExportBinExport.java"
    script_path.write_text(script_content)
    return script_path


def export_with_ghidra(
    binary_path: Path,
    output_path: Path,
    ghidra_path: Optional[Path] = None,
    verbose: bool = False,
) -> bool:
    ghidra = ghidra_path or _find_ghidra()
    if not ghidra:
        console.print("[red]Ghidra not found. Set GHIDRA_HOME environment variable.[/red]")
        return False
    analyze_headless = ghidra / "support" / "analyzeHeadless"
    if not analyze_headless.exists():
        analyze_headless = ghidra / "analyzeHeadless"
    if not analyze_headless.exists():
        console.print(f"[red]analyzeHeadless not found in {ghidra}[/red]")
        return False
    output_path.parent.mkdir(parents=True, exist_ok=True)
    export_script = _create_binexport_script(ghidra)
    with tempfile.TemporaryDirectory() as temp_dir:
        project_dir = Path(temp_dir)
        project_name = "binexport_temp"
        try:
            cmd = [
                str(analyze_headless),
                str(project_dir),
                project_name,
                "-import", str(binary_path),
                "-postScript", "ExportBinExport.java", str(output_path),
                "-scriptPath", str(export_script.parent),
                "-deleteProject",
            ]
            if verbose:
                console.print(f"[dim]Running: {' '.join(cmd)}[/dim]")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )
            # Ghidra sometimes returns non-zero even on success
            if output_path.exists():
                return True
            if verbose:
                console.print(f"[dim]Return code: {result.returncode}[/dim]")
            if result.stdout:
                for line in result.stdout.split('\n'):
                    line_lower = line.lower()
                    if 'error' in line_lower or 'exception' in line_lower or 'binexport' in line_lower:
                        console.print(f"[dim]{line}[/dim]")
            if result.stderr and 'java version' not in result.stderr:
                console.print(f"[dim]stderr: {result.stderr[-500:]}[/dim]")
            return False
        except subprocess.TimeoutExpired:
            console.print("[red]Ghidra analysis timed out[/red]")
            return False
        except Exception as e:
            console.print(f"[red]Ghidra export failed: {e}[/red]")
            return False


def run_bindiff(
    primary_export: Path,
    secondary_export: Path,
    output_path: Path,
    bindiff_path: Optional[Path] = None,
) -> Optional[Path]:
    bindiff = bindiff_path or _find_bindiff()
    if not bindiff:
        console.print("[red]BinDiff not found. Install from https://github.com/google/bindiff[/red]")
        return None
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        cmd = [
            str(bindiff),
            "--primary", str(primary_export),
            "--secondary", str(secondary_export),
            "--output_dir", str(output_path.parent),
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode != 0:
            console.print(f"[red]BinDiff failed: {result.stderr}[/red]")
            return None
        for f in output_path.parent.glob("*.BinDiff"):
            return f
        return None
    except subprocess.TimeoutExpired:
        console.print("[red]BinDiff comparison timed out[/red]")
        return None
    except Exception as e:
        console.print(f"[red]BinDiff failed: {e}[/red]")
        return None


def export_bindiff_report(
    bindiff_file: Path,
    output_dir: Path,
    format: str = "html",
) -> Optional[Path]:
    bindiff = _find_bindiff()
    if not bindiff:
        return None
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / f"{bindiff_file.stem}_report.{format}"
    try:
        bindiff_export = bindiff.parent / "bindiff_export"
        if not bindiff_export.exists():
            bindiff_export = shutil.which("bindiff_export")
        if bindiff_export:
            cmd = [
                str(bindiff_export),
                "--input", str(bindiff_file),
                "--output", str(report_path),
                "--format", format,
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0 and report_path.exists():
                return report_path
        return _export_report_from_db(bindiff_file, report_path)
    except Exception as e:
        console.print(f"[yellow]Report export failed: {e}[/yellow]")
        return None


def _export_report_from_db(bindiff_file: Path, output_path: Path) -> Optional[Path]:
    """BinDiff files are SQLite databases with comparison results."""
    import sqlite3
    try:
        conn = sqlite3.connect(str(bindiff_file))
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM metadata")
        metadata = dict(cursor.fetchall())
        cursor.execute("""
            SELECT 
                f1.name as primary_name,
                f2.name as secondary_name,
                fm.similarity,
                fm.confidence,
                f1.address as primary_addr,
                f2.address as secondary_addr
            FROM function_match fm
            JOIN function f1 ON fm.primary_function_id = f1.id
            JOIN function f2 ON fm.secondary_function_id = f2.id
            ORDER BY fm.similarity DESC
        """)
        matches = cursor.fetchall()
        cursor.execute("""
            SELECT name, address, 'primary' as source
            FROM function f1
            WHERE NOT EXISTS (
                SELECT 1 FROM function_match fm WHERE fm.primary_function_id = f1.id
            )
            UNION ALL
            SELECT name, address, 'secondary' as source
            FROM function f2
            WHERE NOT EXISTS (
                SELECT 1 FROM function_match fm WHERE fm.secondary_function_id = f2.id
            )
        """)
        unmatched = cursor.fetchall()
        conn.close()
        html = _generate_html_report(metadata, matches, unmatched)
        output_path.write_text(html)
        return output_path
    except Exception as e:
        console.print(f"[yellow]Could not read BinDiff database: {e}[/yellow]")
        return None


def _generate_html_report(metadata: dict, matches: list, unmatched: list) -> str:
    html = """<!DOCTYPE html>
<html>
<head>
    <title>BinDiff Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }
        h1, h2, h3 { color: #00d4ff; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #333; padding: 8px; text-align: left; }
        th { background: #16213e; color: #00d4ff; }
        tr:nth-child(even) { background: #1f1f3a; }
        tr:hover { background: #2a2a4a; }
        .similarity-high { color: #00ff88; }
        .similarity-medium { color: #ffaa00; }
        .similarity-low { color: #ff4444; }
        .metadata { background: #16213e; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .section { margin: 30px 0; }
        code { background: #2a2a4a; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <h1>🔍 BinDiff Comparison Report</h1>
"""
    html += '<div class="metadata">\n'
    html += '<h2>📊 Summary</h2>\n'
    html += f'<p><strong>Primary:</strong> <code>{metadata.get("primary", "N/A")}</code></p>\n'
    html += f'<p><strong>Secondary:</strong> <code>{metadata.get("secondary", "N/A")}</code></p>\n'
    html += f'<p><strong>Similarity:</strong> {metadata.get("similarity", "N/A")}</p>\n'
    html += f'<p><strong>Matched Functions:</strong> {len(matches)}</p>\n'
    html += f'<p><strong>Unmatched Functions:</strong> {len(unmatched)}</p>\n'
    html += '</div>\n'
    html += '<div class="section">\n'
    html += '<h2>✅ Matched Functions</h2>\n'
    html += '<table>\n'
    html += '<tr><th>Primary Function</th><th>Secondary Function</th><th>Similarity</th><th>Confidence</th><th>Primary Addr</th><th>Secondary Addr</th></tr>\n'
    
    for match in matches[:100]:
        name1, name2, sim, conf, addr1, addr2 = match
        sim_class = "similarity-high" if sim > 0.9 else "similarity-medium" if sim > 0.7 else "similarity-low"
        html += f'<tr><td><code>{name1}</code></td><td><code>{name2}</code></td>'
        html += f'<td class="{sim_class}">{sim:.2%}</td><td>{conf:.2%}</td>'
        html += f'<td><code>0x{addr1:x}</code></td><td><code>0x{addr2:x}</code></td></tr>\n'
    
    if len(matches) > 100:
        html += f'<tr><td colspan="6"><em>... and {len(matches) - 100} more matches</em></td></tr>\n'
    html += '</table>\n'
    html += '</div>\n'
    if unmatched:
        html += '<div class="section">\n'
        html += '<h2>❌ Unmatched Functions</h2>\n'
        html += '<table>\n'
        html += '<tr><th>Function Name</th><th>Address</th><th>Source</th></tr>\n'
        
        for func in unmatched[:50]:
            name, addr, source = func
            html += f'<tr><td><code>{name}</code></td><td><code>0x{addr:x}</code></td><td>{source}</td></tr>\n'
        
        if len(unmatched) > 50:
            html += f'<tr><td colspan="3"><em>... and {len(unmatched) - 50} more unmatched</em></td></tr>\n'
        
        html += '</table>\n'
        html += '</div>\n'
    html += '</body>\n</html>'
    return html


def compare_binaries_for_kb(
    kb_number: str,
    extracted_dir: Optional[Path] = None,
    baseline_dir: Optional[Path] = None,
    output_dir: Optional[Path] = None,
) -> list[BinDiffResult]:
    extracted_dir = extracted_dir or DEFAULT_EXTRACTED_DIR
    baseline_dir = baseline_dir or DEFAULT_BASELINE_DIR
    output_dir = output_dir or DEFAULT_BINDIFF_DIR
    kb = kb_number.upper()
    if not kb.startswith("KB"):
        kb = f"KB{kb}"
    kb_extracted = extracted_dir / kb
    kb_baseline = baseline_dir / kb
    kb_output = output_dir / kb
    if not kb_extracted.exists():
        console.print(f"[yellow]No extracted files found for {kb}[/yellow]")
        return []
    if not kb_baseline.exists():
        console.print(f"[yellow]No baseline files found for {kb}[/yellow]")
        console.print(f"[dim]Run: patch-tuesday baseline {kb}[/dim]")
        return []
    deps = check_dependencies()
    ghidra_found, ghidra_path = deps["ghidra"]
    bindiff_found, bindiff_path = deps["bindiff"]
    binexport_found, binexport_path = deps["binexport"]
    if not ghidra_found:
        console.print("[red]Ghidra not found.[/red]")
        console.print("[dim]Install Ghidra and set GHIDRA_HOME environment variable[/dim]")
        console.print("[dim]Download from: https://ghidra-sre.org/[/dim]")
        return []
    if not bindiff_found:
        console.print("[red]BinDiff not found.[/red]")
        console.print("[dim]Install from: https://github.com/google/bindiff/releases[/dim]")
        return []
    binexport_ext = _find_binexport_extension(ghidra_path)
    if not binexport_ext:
        console.print("[yellow]BinExport extension not found in Ghidra.[/yellow]")
        console.print("[dim]Install BinExport from: https://github.com/google/binexport/releases[/dim]")
        console.print(f"[dim]Copy to: {ghidra_path}/Ghidra/Extensions/[/dim]")
        return []
    console.print(f"[dim]Using Ghidra: {ghidra_path}[/dim]")
    console.print(f"[dim]Using BinExport: {binexport_ext}[/dim]")
    console.print(f"[dim]Using BinDiff: {bindiff_path}[/dim]")
    results: list[BinDiffResult] = []
    import re
    baseline_files: dict[str, Path] = {}
    for f in kb_baseline.rglob("*"):
        if f.is_file() and f.suffix.lower() in (".dll", ".exe", ".sys"):
            stem = f.stem
            if " (" in stem:
                stem = stem.split(" (")[0]
            match = re.match(r'^([a-zA-Z][a-zA-Z0-9._-]*?)(?:_\d|$)', stem)
            if match:
                base_name = match.group(1).lower()
            else:
                base_name = stem.split("_")[0].lower()
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
    for base_name, extracted_path in extracted_files.items():
        if base_name in baseline_files:
            pairs.append((baseline_files[base_name], extracted_path))
    if not pairs:
        console.print("[yellow]No matching file pairs found for comparison[/yellow]")
        return []
    console.print(f"[cyan]Found {len(pairs)} file pairs to compare[/cyan]")
    kb_output.mkdir(parents=True, exist_ok=True)
    exports_dir = kb_output / "exports"
    exports_dir.mkdir(exist_ok=True)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        for baseline_path, extracted_path in pairs:
            base_name = extracted_path.stem.lower()
            task = progress.add_task(f"Processing {base_name}...", total=None)
            progress.update(task, description=f"Exporting {base_name} (baseline)...")
            baseline_export = exports_dir / f"{base_name}_baseline.BinExport"
            if not baseline_export.exists():
                if not export_with_ghidra(baseline_path, baseline_export, ghidra_path):
                    console.print(f"[yellow]Failed to export {baseline_path.name}[/yellow]")
                    progress.remove_task(task)
                    continue
            progress.update(task, description=f"Exporting {base_name} (patched)...")
            extracted_export = exports_dir / f"{base_name}_patched.BinExport"
            if not extracted_export.exists():
                if not export_with_ghidra(extracted_path, extracted_export, ghidra_path):
                    console.print(f"[yellow]Failed to export {extracted_path.name}[/yellow]")
                    continue
            progress.update(task, description=f"Comparing {base_name}...")
            bindiff_output = exports_dir / f"{base_name}.BinDiff"
            bindiff_file = run_bindiff(baseline_export, extracted_export, bindiff_output)
            if bindiff_file:
                progress.update(task, description=f"Generating report for {base_name}...")
                report_path = export_bindiff_report(bindiff_file, kb_output / "reports")
                
                result = BinDiffResult(
                    primary_file=str(baseline_path),
                    secondary_file=str(extracted_path),
                    bindiff_file=bindiff_file,
                    similarity=0.0,  # TODO: read from BinDiff file
                    confidence=0.0,
                    matched_functions=0,
                    unmatched_primary=0,
                    unmatched_secondary=0,
                    report_path=report_path,
                )
                results.append(result)
                console.print(f"[green]✓ {base_name}: {bindiff_file}[/green]")
            progress.remove_task(task)
    return results


def show_comparison_summary(results: list[BinDiffResult]) -> None:
    if not results:
        console.print("[yellow]No comparison results to display[/yellow]")
        return
    table = Table(title="BinDiff Comparison Results")
    table.add_column("Binary", style="cyan")
    table.add_column("BinDiff File", style="green")
    table.add_column("Report", style="blue")
    for r in results:
        binary_name = Path(r.secondary_file).name
        bindiff_name = r.bindiff_file.name if r.bindiff_file else "N/A"
        report_name = r.report_path.name if r.report_path else "N/A"
        table.add_row(binary_name, bindiff_name, report_name)
    console.print(table)
