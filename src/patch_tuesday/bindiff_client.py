"""BinDiff integration for comparing pre-patch and post-patch binaries."""

import base64
import difflib
import html as html_lib
import json
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


def _create_pseudoc_script(ghidra_path: Path) -> Path:
    script_content = '''// Pseudo-C export automation script
// @category BinDiff

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

public class ExportPseudoC extends GhidraScript {
    private static String sanitizeName(String value) {
        if (value == null) {
            return "";
        }
        return value.replace('\\t', ' ').replace('\\n', ' ').replace('\\r', ' ');
    }

    private static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        String escaped = value.replace("\\\\", "\\\\\\\\");
        escaped = escaped.replace("\\\"", "\\\\\\\"");
        return escaped;
    }

    private static String relationsToJson(Set<Function> funcs) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        boolean first = true;
        for (Function f : funcs) {
            if (!first) {
                sb.append(",");
            }
            first = false;
            sb.append("{\\"addr\\":\\"");
            sb.append(Long.toHexString(f.getEntryPoint().getOffset()));
            sb.append("\\",\\"name\\":\\"");
            sb.append(escapeJson(sanitizeName(f.getName())));
            sb.append("\\"}");
        }
        sb.append("]");
        return sb.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: ExportPseudoC.java <output_path> [address_csv]");
            return;
        }

        String outputPath = args[0];
        Set<Long> wanted = new HashSet<Long>();
        if (args.length >= 2 && args[1] != null && !args[1].trim().isEmpty()) {
            for (String raw : args[1].split(",")) {
                String token = raw.trim().toLowerCase();
                if (token.startsWith("0x")) {
                    token = token.substring(2);
                }
                if (token.isEmpty()) {
                    continue;
                }
                try {
                    wanted.add(Long.parseUnsignedLong(token, 16));
                } catch (NumberFormatException ignored) {
                }
            }
        }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(outputPath), StandardCharsets.UTF_8))) {
            FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
            while (funcs.hasNext() && !monitor.isCancelled()) {
                Function function = funcs.next();
                long offset = function.getEntryPoint().getOffset();
                if (!wanted.isEmpty() && !wanted.contains(offset)) {
                    continue;
                }
                DecompileResults res = decomp.decompileFunction(function, 60, monitor);
                String cCode = "";
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    cCode = res.getDecompiledFunction().getC();
                }
                String encoded = Base64.getEncoder().encodeToString(cCode.getBytes(StandardCharsets.UTF_8));
                String callersJson = relationsToJson(function.getCallingFunctions(monitor));
                String calleesJson = relationsToJson(function.getCalledFunctions(monitor));
                String callersEncoded = Base64.getEncoder().encodeToString(callersJson.getBytes(StandardCharsets.UTF_8));
                String calleesEncoded = Base64.getEncoder().encodeToString(calleesJson.getBytes(StandardCharsets.UTF_8));
                writer.write(Long.toHexString(offset));
                writer.write('\\t');
                writer.write(sanitizeName(function.getName()));
                writer.write('\\t');
                writer.write(encoded);
                writer.write('\\t');
                writer.write(callersEncoded);
                writer.write('\\t');
                writer.write(calleesEncoded);
                writer.newLine();
            }
        } finally {
            decomp.dispose();
        }
        println("Exported pseudo-C to: " + outputPath);
    }
}
'''
    scripts_dir = ghidra_path / "Ghidra" / "Features" / "Base" / "ghidra_scripts"
    if not scripts_dir.exists():
        scripts_dir = ghidra_path / "ghidra_scripts"
        scripts_dir.mkdir(exist_ok=True)
    script_path = scripts_dir / "ExportPseudoC.java"
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


def export_pseudocode_with_ghidra(
    binary_path: Path,
    output_path: Path,
    addresses: list[int],
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
    pseudoc_script = _create_pseudoc_script(ghidra)
    address_csv = ",".join(f"{addr:x}" for addr in addresses if int(addr or 0) > 0)
    with tempfile.TemporaryDirectory() as temp_dir:
        project_dir = Path(temp_dir)
        project_name = "pseudoc_temp"
        try:
            cmd = [
                str(analyze_headless),
                str(project_dir),
                project_name,
                "-import",
                str(binary_path),
                "-postScript",
                "ExportPseudoC.java",
                str(output_path),
                address_csv,
                "-scriptPath",
                str(pseudoc_script.parent),
                "-deleteProject",
            ]
            if verbose:
                console.print(f"[dim]Running: {' '.join(cmd)}[/dim]")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1200,
            )
            if output_path.exists():
                return True
            if verbose:
                console.print(f"[dim]Return code: {result.returncode}[/dim]")
                if result.stdout:
                    console.print(f"[dim]stdout: {result.stdout[-500:]}[/dim]")
                if result.stderr and 'java version' not in result.stderr:
                    console.print(f"[dim]stderr: {result.stderr[-500:]}[/dim]")
            return False
        except subprocess.TimeoutExpired:
            console.print("[yellow]Ghidra pseudo-C export timed out[/yellow]")
            return False
        except Exception as e:
            console.print(f"[yellow]Pseudo-C export failed: {e}[/yellow]")
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
        before = {p.resolve() for p in output_path.parent.glob("*.BinDiff")}
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
        after = list(output_path.parent.glob("*.BinDiff"))
        new_files = [p for p in after if p.resolve() not in before]
        if new_files:
            return max(new_files, key=lambda p: p.stat().st_mtime)
        if output_path.exists():
            return output_path
        if after:
            return max(after, key=lambda p: p.stat().st_mtime)
        return None
    except subprocess.TimeoutExpired:
        console.print("[red]BinDiff comparison timed out[/red]")
        return None
    except Exception as e:
        console.print(f"[red]BinDiff failed: {e}[/red]")
        return None


def _decode_relation_payload(encoded: str) -> list[dict]:
    if not encoded:
        return []
    try:
        decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
        raw_items = json.loads(decoded)
    except Exception:
        return []
    if not isinstance(raw_items, list):
        return []
    relations: list[dict] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        addr_raw = str(item.get("addr", "")).strip()
        if not addr_raw:
            continue
        try:
            addr_val = int(addr_raw, 16)
        except ValueError:
            continue
        relations.append(
            {
                "addr": addr_val,
                "name": str(item.get("name", "")),
            }
        )
    return relations


def _parse_pseudocode_map(path: Path) -> dict[int, dict]:
    results: dict[int, dict] = {}
    if not path.exists():
        return results
    for raw_line in path.read_text(errors="ignore").splitlines():
        if not raw_line.strip():
            continue
        parts = raw_line.split("\t")
        if len(parts) < 3:
            continue
        addr_hex, name, encoded = parts[0], parts[1], parts[2]
        callers_encoded = parts[3] if len(parts) > 3 else ""
        callees_encoded = parts[4] if len(parts) > 4 else ""
        try:
            address = int(addr_hex, 16)
        except ValueError:
            continue
        try:
            code = base64.b64decode(encoded).decode("utf-8", errors="replace")
        except Exception:
            code = ""
        results[address] = {
            "name": name,
            "code": code,
            "callers": _decode_relation_payload(callers_encoded),
            "callees": _decode_relation_payload(callees_encoded),
        }
    return results


def _build_pseudocode_diffs(
    matches: list[tuple],
    primary_binary: Path,
    secondary_binary: Path,
    ghidra_path: Optional[Path],
) -> list[dict]:
    if not primary_binary.exists() or not secondary_binary.exists():
        console.print("[yellow]Skipping pseudo-C diff generation: missing binary path(s)[/yellow]")
        return []
    selected: list[tuple] = []
    seen_pairs: set[tuple[int, int]] = set()
    for match in matches:
        if len(match) < 6:
            continue
        name1, name2, sim, conf, addr1, addr2 = match
        addr1_val = int(addr1 or 0)
        addr2_val = int(addr2 or 0)
        if addr1_val <= 0 or addr2_val <= 0:
            continue
        sim_val = float(sim or 0.0)
        # Only generate pseudo-C for non-identical matches (< 100% similarity).
        if sim_val >= 0.999999:
            continue
        key = (addr1_val, addr2_val)
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        selected.append((name1, name2, sim_val, float(conf or 0), addr1_val, addr2_val))
    if not selected:
        return []
    primary_addrs = [item[4] for item in selected]
    secondary_addrs = [item[5] for item in selected]
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir)
        primary_out = temp_root / "primary_pseudoc.tsv"
        secondary_out = temp_root / "secondary_pseudoc.tsv"
        if not export_pseudocode_with_ghidra(primary_binary, primary_out, primary_addrs, ghidra_path=ghidra_path):
            return []
        if not export_pseudocode_with_ghidra(secondary_binary, secondary_out, secondary_addrs, ghidra_path=ghidra_path):
            return []
        primary_map = _parse_pseudocode_map(primary_out)
        secondary_map = _parse_pseudocode_map(secondary_out)
    diffs: list[dict] = []
    for name1, name2, sim, conf, addr1, addr2 in selected:
        old_item = primary_map.get(addr1)
        new_item = secondary_map.get(addr2)
        if not old_item or not new_item:
            continue
        old_code = old_item.get("code", "")
        new_code = new_item.get("code", "")
        old_label = old_item.get("name") or str(name1 or f"sub_{addr1:x}")
        new_label = new_item.get("name") or str(name2 or f"sub_{addr2:x}")
        diff_lines = list(
            difflib.unified_diff(
                old_code.splitlines(),
                new_code.splitlines(),
                fromfile=f"{old_label}@0x{addr1:x}",
                tofile=f"{new_label}@0x{addr2:x}",
                lineterm="",
                n=3,
            )
        )
        truncated = len(diff_lines) > 400
        if truncated:
            diff_lines = diff_lines[:400]
        diff_text = "\n".join(diff_lines)
        if not diff_text:
            diff_text = "(No pseudo-C textual changes in decompiler output)"
        diffs.append(
            {
                "name1": str(name1 or old_label),
                "name2": str(name2 or new_label),
                "addr1": addr1,
                "addr2": addr2,
                "sim": sim,
                "conf": conf,
                "diff_text": diff_text,
                "truncated": truncated,
                "old_callers": old_item.get("callers", []),
                "old_callees": old_item.get("callees", []),
                "new_callers": new_item.get("callers", []),
                "new_callees": new_item.get("callees", []),
            }
        )
    return diffs


def export_bindiff_report(
    bindiff_file: Path,
    output_dir: Path,
    format: str = "html",
    include_pseudocode: bool = False,
    primary_binary: Optional[Path] = None,
    secondary_binary: Optional[Path] = None,
    ghidra_path: Optional[Path] = None,
) -> Optional[Path]:
    bindiff = _find_bindiff()
    if not bindiff:
        return None
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / f"{bindiff_file.stem}_report.{format}"
    try:
        if not include_pseudocode:
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
        return _export_report_from_db(
            bindiff_file,
            report_path,
            include_pseudocode=include_pseudocode,
            primary_binary=primary_binary,
            secondary_binary=secondary_binary,
            ghidra_path=ghidra_path,
        )
    except Exception as e:
        console.print(f"[yellow]Report export failed: {e}[/yellow]")
        return None


def _export_report_from_db(
    bindiff_file: Path,
    output_path: Path,
    include_pseudocode: bool = False,
    primary_binary: Optional[Path] = None,
    secondary_binary: Optional[Path] = None,
    ghidra_path: Optional[Path] = None,
) -> Optional[Path]:
    """BinDiff files are SQLite databases with comparison results."""
    import sqlite3
    
    def _table_exists(cursor: sqlite3.Cursor, table_name: str) -> bool:
        row = cursor.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()
        return row is not None
    
    def _column_names(cursor: sqlite3.Cursor, table_name: str) -> list[str]:
        rows = cursor.execute(f"PRAGMA table_info({table_name})").fetchall()
        return [r[1] for r in rows]
    
    def _load_metadata(cursor: sqlite3.Cursor) -> dict:
        if not _table_exists(cursor, "metadata"):
            return {}
        columns = _column_names(cursor, "metadata")
        rows = cursor.execute("SELECT * FROM metadata").fetchall()
        if not rows:
            return {}
        
        # Legacy schema sometimes stores key/value rows in metadata.
        if len(rows[0]) == 2 and all(len(r) == 2 for r in rows):
            try:
                return {str(k): v for k, v in rows}
            except Exception:
                pass
        
        # BinDiff 8 schema stores a single metadata row with named columns.
        first = rows[0]
        return {
            str(columns[idx]): first[idx]
            for idx in range(min(len(columns), len(first)))
        }
    
    def _enrich_primary_secondary(cursor: sqlite3.Cursor, metadata: dict) -> None:
        if not _table_exists(cursor, "file"):
            return
        file1 = metadata.get("file1")
        file2 = metadata.get("file2")
        if file1 is not None:
            row = cursor.execute(
                "SELECT filename FROM file WHERE id = ? LIMIT 1",
                (file1,),
            ).fetchone()
            if row and row[0]:
                metadata.setdefault("primary", row[0])
        if file2 is not None:
            row = cursor.execute(
                "SELECT filename FROM file WHERE id = ? LIMIT 1",
                (file2,),
            ).fetchone()
            if row and row[0]:
                metadata.setdefault("secondary", row[0])
    
    def _read_matches_unmatched(cursor: sqlite3.Cursor) -> tuple[list[tuple], list[tuple]]:
        if _table_exists(cursor, "function_match"):
            matches = cursor.execute(
                """
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
                """
            ).fetchall()
            unmatched = cursor.execute(
                """
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
                """
            ).fetchall()
            return matches, unmatched
        
        # BinDiff 8 schema has a unified "function" table with paired columns.
        if _table_exists(cursor, "function"):
            columns = set(_column_names(cursor, "function"))
            required = {"name1", "name2", "similarity", "confidence", "address1", "address2"}
            if required.issubset(columns):
                matches = cursor.execute(
                    """
                    SELECT
                        COALESCE(name1, ''),
                        COALESCE(name2, ''),
                        COALESCE(similarity, 0),
                        COALESCE(confidence, 0),
                        COALESCE(address1, 0),
                        COALESCE(address2, 0)
                    FROM function
                    WHERE COALESCE(address1, 0) != 0
                      AND COALESCE(address2, 0) != 0
                    ORDER BY COALESCE(similarity, 0) DESC
                    """
                ).fetchall()
                unmatched = cursor.execute(
                    """
                    SELECT COALESCE(name1, ''), COALESCE(address1, 0), 'primary'
                    FROM function
                    WHERE COALESCE(address1, 0) != 0
                      AND COALESCE(address2, 0) = 0
                    UNION ALL
                    SELECT COALESCE(name2, ''), COALESCE(address2, 0), 'secondary'
                    FROM function
                    WHERE COALESCE(address2, 0) != 0
                      AND COALESCE(address1, 0) = 0
                    """
                ).fetchall()
                return matches, unmatched
        
        return [], []
    
    try:
        conn = sqlite3.connect(str(bindiff_file))
        cursor = conn.cursor()
        metadata = _load_metadata(cursor)
        _enrich_primary_secondary(cursor, metadata)
        matches, unmatched = _read_matches_unmatched(cursor)
        conn.close()
        pseudocode_diffs: list[dict] = []
        if include_pseudocode:
            if primary_binary and secondary_binary:
                console.print("[cyan]Generating pseudo-C diffs with Ghidra...[/cyan]")
                pseudocode_diffs = _build_pseudocode_diffs(
                    matches,
                    primary_binary=primary_binary,
                    secondary_binary=secondary_binary,
                    ghidra_path=ghidra_path,
                )
                if not pseudocode_diffs:
                    console.print("[yellow]No pseudo-C diffs were generated from matched functions[/yellow]")
            else:
                console.print("[yellow]Skipping pseudo-C diffs: binary paths not provided[/yellow]")
        html = _generate_html_report(metadata, matches, unmatched, pseudocode_diffs=pseudocode_diffs)
        output_path.write_text(html)
        return output_path
    except Exception as e:
        console.print(f"[yellow]Could not read BinDiff database: {e}[/yellow]")
        return None


def _generate_html_report(
    metadata: dict,
    matches: list,
    unmatched: list,
    pseudocode_diffs: Optional[list[dict]] = None,
) -> str:
    report_html = """<!DOCTYPE html>
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
        .metadata { background: #16213e; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .section { margin: 30px 0; }
        code { background: #2a2a4a; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <h1>BinDiff Comparison Report</h1>
"""
    report_html += '<div class="metadata">\n'
    report_html += '<h2>Summary</h2>\n'
    report_html += f'<p><strong>Primary:</strong> <code>{metadata.get("primary", "N/A")}</code></p>\n'
    report_html += f'<p><strong>Secondary:</strong> <code>{metadata.get("secondary", "N/A")}</code></p>\n'
    report_html += f'<p><strong>Similarity:</strong> {metadata.get("similarity", "N/A")}</p>\n'
    report_html += f'<p><strong>Matched Functions:</strong> {len(matches)}</p>\n'
    report_html += f'<p><strong>Unmatched Functions:</strong> {len(unmatched)}</p>\n'
    report_html += '</div>\n'

    matched_rows: list[dict] = []
    for name1, name2, sim, conf, addr1, addr2 in matches:
        matched_rows.append(
            {
                "name1": str(name1 or ""),
                "name2": str(name2 or ""),
                "sim": float(sim or 0.0),
                "conf": float(conf or 0.0),
                "addr1": int(addr1 or 0),
                "addr2": int(addr2 or 0),
            }
        )
    matched_rows_b64 = base64.b64encode(json.dumps(matched_rows).encode("utf-8")).decode("ascii")

    pseudocode_map: dict[str, dict] = {}
    for item in (pseudocode_diffs or []):
        addr1 = int(item.get("addr1", 0) or 0)
        addr2 = int(item.get("addr2", 0) or 0)
        key = f"{addr1}:{addr2}"
        pseudocode_map[key] = {
            "name1": str(item.get("name1", "")),
            "name2": str(item.get("name2", "")),
            "addr1": addr1,
            "addr2": addr2,
            "diff_text": str(item.get("diff_text", "")),
            "truncated": bool(item.get("truncated", False)),
            "old_callers": [
                {"addr": int(x.get("addr", 0) or 0), "name": str(x.get("name", ""))}
                for x in item.get("old_callers", [])
                if isinstance(x, dict)
            ],
            "old_callees": [
                {"addr": int(x.get("addr", 0) or 0), "name": str(x.get("name", ""))}
                for x in item.get("old_callees", [])
                if isinstance(x, dict)
            ],
            "new_callers": [
                {"addr": int(x.get("addr", 0) or 0), "name": str(x.get("name", ""))}
                for x in item.get("new_callers", [])
                if isinstance(x, dict)
            ],
            "new_callees": [
                {"addr": int(x.get("addr", 0) or 0), "name": str(x.get("name", ""))}
                for x in item.get("new_callees", [])
                if isinstance(x, dict)
            ],
        }
    pseudocode_map_b64 = base64.b64encode(json.dumps(pseudocode_map).encode("utf-8")).decode("ascii")

    report_html += '<div class="section">\n'
    report_html += '<h2>Matched Functions</h2>\n'
    report_html += '<matched-functions-table id="matched-functions-table"></matched-functions-table>\n'
    report_html += f'<div id="matched-functions-data" data-b64="{matched_rows_b64}"></div>\n'
    report_html += f'<div id="pseudocode-diffs-data" data-b64="{pseudocode_map_b64}"></div>\n'
    report_html += '</div>\n'

    if unmatched:
        report_html += '<div class="section">\n'
        report_html += '<h2>Unmatched Functions</h2>\n'
        report_html += '<table>\n'
        report_html += '<tr><th>Function Name</th><th>Address</th><th>Source</th></tr>\n'
        for name, addr, source in unmatched[:50]:
            name_html = html_lib.escape(str(name or ""))
            source_html = html_lib.escape(str(source or ""))
            addr_val = int(addr or 0)
            report_html += f'<tr><td><code>{name_html}</code></td><td><code>0x{addr_val:x}</code></td><td>{source_html}</td></tr>\n'
        if len(unmatched) > 50:
            report_html += f'<tr><td colspan="3"><em>... and {len(unmatched) - 50} more unmatched</em></td></tr>\n'
        report_html += '</table>\n'
        report_html += '</div>\n'

    report_html += """
<script>
(function() {
  const dataNode = document.getElementById('matched-functions-data');
  const pseudoNode = document.getElementById('pseudocode-diffs-data');
  const host = document.getElementById('matched-functions-table');
  if (!dataNode || !pseudoNode || !host) return;

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  class MatchedFunctionsTable extends HTMLElement {
    constructor() {
      super();
      this.attachShadow({ mode: 'open' });
      this.rows = [];
      this.pseudoMap = {};
      this.byPair = new Map();
      this.byAddr1 = new Map();
      this.byAddr2 = new Map();
      this.activePair = null;
      this.sortKey = 'sim';
      this.ascending = false;
      this.page = 1;
      this.pageSize = 30;
      this.columns = [
        { key: 'name1', label: 'Primary Function', type: 'text' },
        { key: 'name2', label: 'Secondary Function', type: 'text' },
        { key: 'sim', label: 'Similarity', type: 'num' },
        { key: 'conf', label: 'Confidence', type: 'num' },
        { key: 'addr1', label: 'Primary Addr', type: 'num' },
        { key: 'addr2', label: 'Secondary Addr', type: 'num' },
      ];
    }

    connectedCallback() {
      try {
        this.rows = JSON.parse(atob(dataNode.dataset.b64 || ''));
      } catch (_) {
        this.rows = [];
      }
      try {
        this.pseudoMap = JSON.parse(atob(pseudoNode.dataset.b64 || ''));
      } catch (_) {
        this.pseudoMap = {};
      }
      this.rebuildIndex();
      this.render();
    }

    rebuildIndex() {
      this.byPair = new Map();
      this.byAddr1 = new Map();
      this.byAddr2 = new Map();
      this.rows.forEach((row) => {
        const addr1 = Number(row.addr1) || 0;
        const addr2 = Number(row.addr2) || 0;
        const key = `${addr1}:${addr2}`;
        if (!this.byPair.has(key)) this.byPair.set(key, row);
        if (!this.byAddr1.has(addr1)) this.byAddr1.set(addr1, row);
        if (!this.byAddr2.has(addr2)) this.byAddr2.set(addr2, row);
      });
    }

    getSortedRows() {
      const column = this.columns.find((c) => c.key === this.sortKey) || this.columns[2];
      const rows = [...this.rows];
      rows.sort((a, b) => {
        const av = a[column.key];
        const bv = b[column.key];
        if (column.type === 'num') {
          const an = Number(av);
          const bn = Number(bv);
          if (an < bn) return this.ascending ? -1 : 1;
          if (an > bn) return this.ascending ? 1 : -1;
          return 0;
        }
        const as = String(av || '').toLowerCase();
        const bs = String(bv || '').toLowerCase();
        return this.ascending ? as.localeCompare(bs) : bs.localeCompare(as);
      });
      return rows;
    }

    formatDiff(diffText) {
      return String(diffText || '')
        .split('\\n')
        .map((line) => {
          let cls = 'diff-line';
          if (line.startsWith('+') && !line.startsWith('+++')) cls += ' diff-add';
          else if (line.startsWith('-') && !line.startsWith('---')) cls += ' diff-del';
          else if (line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++')) cls += ' diff-hdr';
          return `<span class="${cls}">${escapeHtml(line)}</span>`;
        })
        .join('');
    }

    relationList(relations, side) {
      if (!Array.isArray(relations) || relations.length === 0) {
        return '<li><em>No entries</em></li>';
      }
      return relations
        .map((rel) => {
          const addr = Number(rel.addr) || 0;
          const name = String(rel.name || '').trim() || `sub_${addr.toString(16)}`;
          const related = side === 'old' ? this.byAddr1.get(addr) : this.byAddr2.get(addr);
          let jumpButton = '';
          if (related) {
            const pairKey = `${Number(related.addr1) || 0}:${Number(related.addr2) || 0}`;
            const hasDiff = !!this.pseudoMap[pairKey];
            jumpButton = `<button class="jump-btn" data-pair="${pairKey}" data-open="${hasDiff ? 'diff' : 'row'}">${hasDiff ? 'Open Diff' : 'Open Row'}</button>`;
          }
          return `<li><code>${escapeHtml(name)} @ 0x${addr.toString(16)}</code>${jumpButton}</li>`;
        })
        .join('');
    }

    openModal(pairKey) {
      this.activePair = pairKey;
      this.render();
    }

    closeModal() {
      this.activePair = null;
      this.render();
    }

    goToPair(pairKey, openDiff) {
      const sorted = this.getSortedRows();
      const idx = sorted.findIndex((row) => `${Number(row.addr1) || 0}:${Number(row.addr2) || 0}` === pairKey);
      if (idx >= 0) {
        this.page = Math.floor(idx / this.pageSize) + 1;
      }
      this.activePair = openDiff ? pairKey : null;
      this.render();
    }

    render() {
      const sorted = this.getSortedRows();
      const total = sorted.length;
      const totalPages = Math.max(1, Math.ceil(total / this.pageSize));
      if (this.page > totalPages) this.page = totalPages;
      const start = (this.page - 1) * this.pageSize;
      const end = Math.min(start + this.pageSize, total);
      const pageRows = sorted.slice(start, end);

      const headersHtml = this.columns
        .map((c) => {
          const dir = this.sortKey === c.key ? (this.ascending ? 'asc' : 'desc') : '';
          const icon = dir === 'asc' ? ' ↑' : dir === 'desc' ? ' ↓' : ' ⇅';
          return `<th class="sortable" data-key="${c.key}" data-dir="${dir}">${escapeHtml(c.label)}${icon}</th>`;
        })
        .join('');

      const rowsHtml = pageRows
        .map((r) => {
          const simClass = r.sim > 0.9 ? 'similarity-high' : (r.sim > 0.7 ? 'similarity-medium' : 'similarity-low');
          const simText = (Number(r.sim) || 0).toLocaleString(undefined, { style: 'percent', minimumFractionDigits: 2, maximumFractionDigits: 2 });
          const confText = (Number(r.conf) || 0).toLocaleString(undefined, { style: 'percent', minimumFractionDigits: 2, maximumFractionDigits: 2 });
          const pairKey = `${Number(r.addr1) || 0}:${Number(r.addr2) || 0}`;
          return `
            <tr>
              <td><code>${escapeHtml(r.name1 || '')}</code></td>
              <td><code>${escapeHtml(r.name2 || '')}</code></td>
              <td class="${simClass}">${simText}</td>
              <td>${confText}</td>
              <td><code>0x${(Number(r.addr1) || 0).toString(16)}</code></td>
              <td><code>0x${(Number(r.addr2) || 0).toString(16)}</code></td>
              <td><button class="view-btn" data-pair="${pairKey}">View</button></td>
            </tr>
          `;
        })
        .join('');

      this.shadowRoot.innerHTML = `
        <style>
          :host { display: block; }
          table { border-collapse: collapse; width: 100%; margin: 8px 0 10px 0; }
          th, td { border: 1px solid #333; padding: 8px; text-align: left; }
          th { background: #16213e; color: #00d4ff; }
          tr:nth-child(even) { background: #1f1f3a; }
          tr:hover { background: #2a2a4a; }
          code { background: #2a2a4a; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
          .similarity-high { color: #00ff88; }
          .similarity-medium { color: #ffaa00; }
          .similarity-low { color: #ff4444; }
          th.sortable { cursor: pointer; user-select: none; }
          .view-btn, .jump-btn {
            background: #16213e;
            color: #00d4ff;
            border: 1px solid #2f3a5a;
            border-radius: 4px;
            padding: 3px 8px;
            cursor: pointer;
            font-size: 0.85rem;
            margin-left: 8px;
          }
          .pager { display: flex; gap: 8px; align-items: center; justify-content: flex-end; font-size: 0.95rem; }
          .pager button {
            background: #16213e;
            color: #00d4ff;
            border: 1px solid #2f3a5a;
            border-radius: 4px;
            padding: 4px 10px;
            cursor: pointer;
          }
          .pager button:disabled { opacity: 0.45; cursor: default; }
          .pager .meta { margin-right: auto; color: #b8c5e0; }
          .modal-backdrop {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
          }
          .modal-backdrop.hidden { display: none; }
          .modal {
            width: min(1200px, 95vw);
            max-height: 88vh;
            overflow: auto;
            background: #0f1628;
            border: 1px solid #2f3a5a;
            border-radius: 8px;
            padding: 14px;
          }
          .modal-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 8px;
          }
          .modal-title { color: #9ee9ff; font-weight: 600; }
          .close-btn {
            background: #16213e;
            color: #00d4ff;
            border: 1px solid #2f3a5a;
            border-radius: 4px;
            padding: 4px 10px;
            cursor: pointer;
          }
          .modal-body { display: grid; grid-template-columns: 1.4fr 1fr; gap: 12px; }
          .panel {
            border: 1px solid #2f3a5a;
            border-radius: 6px;
            padding: 10px;
            background: #16213e;
          }
          .panel h3 { margin-top: 0; margin-bottom: 8px; font-size: 1rem; }
          .diff-block {
            margin: 0;
            padding: 10px;
            background: #0b1222;
            border: 1px solid #24314f;
            border-radius: 4px;
            overflow-x: auto;
            min-height: 120px;
          }
          .diff-line { display: block; white-space: pre; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
          .diff-add { background: rgba(31, 125, 79, 0.25); color: #77f0b0; }
          .diff-del { background: rgba(160, 43, 43, 0.25); color: #ff9a9a; }
          .diff-hdr { color: #9ec6ff; }
          .context-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
          .context-list { margin: 0; padding-left: 18px; }
          .context-list li { margin: 6px 0; }
          .meta-note { color: #b8c5e0; margin: 0 0 8px 0; font-size: 0.9rem; }
        </style>
        <table>
          <thead><tr>${headersHtml}<th>Code</th></tr></thead>
          <tbody>${rowsHtml}</tbody>
        </table>
        <div class="pager">
          <span class="meta">Showing ${total === 0 ? 0 : start + 1}-${end} of ${total}</span>
          <button data-action="prev" ${this.page <= 1 ? 'disabled' : ''}>Prev</button>
          <span>Page ${this.page} / ${totalPages}</span>
          <button data-action="next" ${this.page >= totalPages ? 'disabled' : ''}>Next</button>
        </div>
        <div class="modal-backdrop ${this.activePair ? '' : 'hidden'}">
          <div class="modal">
            <div class="modal-header">
              <div class="modal-title" id="modal-title"></div>
              <button class="close-btn" data-action="close-modal">Close</button>
            </div>
            <div class="modal-body">
              <div class="panel">
                <h3>Function Diff</h3>
                <p class="meta-note" id="modal-meta"></p>
                <pre class="diff-block" id="modal-diff"></pre>
                <p class="meta-note" id="modal-truncated"></p>
              </div>
              <div class="panel">
                <h3>Call Graph Context (One Hop)</h3>
                <p class="meta-note">Callers are incoming edges. Callees are outgoing edges.</p>
                <div class="context-grid">
                  <div>
                    <h3>Primary Callers</h3>
                    <ul class="context-list" id="old-callers"></ul>
                    <h3>Primary Callees</h3>
                    <ul class="context-list" id="old-callees"></ul>
                  </div>
                  <div>
                    <h3>Secondary Callers</h3>
                    <ul class="context-list" id="new-callers"></ul>
                    <h3>Secondary Callees</h3>
                    <ul class="context-list" id="new-callees"></ul>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      `;

      this.shadowRoot.querySelectorAll('th.sortable').forEach((th) => {
        th.addEventListener('click', () => {
          const key = th.getAttribute('data-key');
          if (!key) return;
          if (this.sortKey === key) this.ascending = !this.ascending;
          else {
            this.sortKey = key;
            this.ascending = true;
          }
          this.page = 1;
          this.render();
        });
      });

      this.shadowRoot.querySelectorAll('button.view-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
          const pair = btn.getAttribute('data-pair');
          if (pair) this.openModal(pair);
        });
      });

      const prev = this.shadowRoot.querySelector('button[data-action="prev"]');
      const next = this.shadowRoot.querySelector('button[data-action="next"]');
      const close = this.shadowRoot.querySelector('button[data-action="close-modal"]');
      const modal = this.shadowRoot.querySelector('.modal-backdrop');
      if (prev) {
        prev.addEventListener('click', () => {
          if (this.page > 1) {
            this.page -= 1;
            this.render();
          }
        });
      }
      if (next) {
        next.addEventListener('click', () => {
          const pages = Math.max(1, Math.ceil(this.rows.length / this.pageSize));
          if (this.page < pages) {
            this.page += 1;
            this.render();
          }
        });
      }
      if (close) close.addEventListener('click', () => this.closeModal());
      if (modal) {
        modal.addEventListener('click', (event) => {
          if (event.target === modal) this.closeModal();
        });
      }

      if (this.activePair) {
        const row = this.byPair.get(this.activePair);
        const info = this.pseudoMap[this.activePair] || null;
        const title = this.shadowRoot.getElementById('modal-title');
        const meta = this.shadowRoot.getElementById('modal-meta');
        const diff = this.shadowRoot.getElementById('modal-diff');
        const truncated = this.shadowRoot.getElementById('modal-truncated');
        const oldCallers = this.shadowRoot.getElementById('old-callers');
        const oldCallees = this.shadowRoot.getElementById('old-callees');
        const newCallers = this.shadowRoot.getElementById('new-callers');
        const newCallees = this.shadowRoot.getElementById('new-callees');
        if (row && title && meta && diff && truncated && oldCallers && oldCallees && newCallers && newCallees) {
          const name1 = String(row.name1 || '');
          const name2 = String(row.name2 || '');
          const addr1 = Number(row.addr1) || 0;
          const addr2 = Number(row.addr2) || 0;
          title.innerHTML = `<code>${escapeHtml(name1)}</code> vs <code>${escapeHtml(name2)}</code>`;
          meta.innerHTML = `Primary: <code>0x${addr1.toString(16)}</code> | Secondary: <code>0x${addr2.toString(16)}</code> | Similarity: ${(Number(row.sim) || 0).toLocaleString(undefined, { style: 'percent', minimumFractionDigits: 2, maximumFractionDigits: 2 })} | Confidence: ${(Number(row.conf) || 0).toLocaleString(undefined, { style: 'percent', minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
          if (info && info.diff_text) {
            diff.innerHTML = this.formatDiff(info.diff_text);
            truncated.textContent = info.truncated ? 'Diff truncated to first 400 lines.' : '';
          } else {
            diff.innerHTML = '<span class="diff-line">Pseudo-C diff not generated for this row.</span>';
            truncated.textContent = '';
          }
          oldCallers.innerHTML = this.relationList(info ? info.old_callers : [], 'old');
          oldCallees.innerHTML = this.relationList(info ? info.old_callees : [], 'old');
          newCallers.innerHTML = this.relationList(info ? info.new_callers : [], 'new');
          newCallees.innerHTML = this.relationList(info ? info.new_callees : [], 'new');
          this.shadowRoot.querySelectorAll('button.jump-btn').forEach((btn) => {
            btn.addEventListener('click', () => {
              const pair = btn.getAttribute('data-pair');
              const mode = btn.getAttribute('data-open');
              if (!pair) return;
              this.goToPair(pair, mode === 'diff');
            });
          });
        }
      }
    }
  }

  if (!customElements.get('matched-functions-table')) {
    customElements.define('matched-functions-table', MatchedFunctionsTable);
  }
  dataNode.remove();
  pseudoNode.remove();
})();
</script>
"""
    report_html += '</body>\n</html>'
    return report_html


def compare_binaries_for_kb(
    kb_number: str,
    extracted_dir: Optional[Path] = None,
    baseline_dir: Optional[Path] = None,
    output_dir: Optional[Path] = None,
    binary_name: Optional[str] = None,
    generate_reports: bool = False,
    include_pseudocode: bool = False,
) -> list[BinDiffResult]:
    extracted_dir = extracted_dir or DEFAULT_EXTRACTED_DIR
    baseline_dir = baseline_dir or DEFAULT_BASELINE_DIR
    output_dir = output_dir or DEFAULT_BINDIFF_DIR
    if include_pseudocode and not generate_reports:
        generate_reports = True
    if generate_reports and not include_pseudocode:
        include_pseudocode = True
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
    target_base: Optional[str] = None
    if binary_name:
        target = Path(binary_name.lower()).name
        if "." in target:
            target_base = target.rsplit(".", 1)[0]
        else:
            target_base = target
    for base_name, extracted_path in extracted_files.items():
        if base_name in baseline_files:
            if target_base and base_name != target_base:
                continue
            pairs.append((baseline_files[base_name], extracted_path))
    if not pairs:
        if target_base:
            console.print(f"[yellow]No matching file pair found for {target_base}[/yellow]")
        else:
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
                report_path = None
                if generate_reports:
                    progress.update(task, description=f"Generating report for {base_name}...")
                    report_path = export_bindiff_report(
                        bindiff_file,
                        kb_output / "reports",
                        include_pseudocode=include_pseudocode,
                        primary_binary=baseline_path if include_pseudocode else None,
                        secondary_binary=extracted_path if include_pseudocode else None,
                        ghidra_path=ghidra_path if include_pseudocode else None,
                    )
                
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
