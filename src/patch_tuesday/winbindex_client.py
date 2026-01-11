"""WinBIndex client for fetching pre-patch versions of Windows binaries."""

import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx
from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from rich.table import Table

from .models import Architecture, DownloadedFile, WinBIndexFile

console = Console()

WINBINDEX_BASE = "https://winbindex.m417z.com"
WINBINDEX_API = f"{WINBINDEX_BASE}/api"
DEFAULT_BASELINE_DIR = Path(__file__).parent.parent.parent / "downloads" / "baseline"
HEADERS = {"User-Agent": "PatchTuesdayAnalyzer/1.0", "Accept": "application/json"}


def _parse_architecture(arch_value) -> Optional[Architecture]:
    """machineType: 332 (x86), 34404 (x64), 43620 (ARM64), or string like 'amd64'."""
    if isinstance(arch_value, int):
        if arch_value == 332:  # IMAGE_FILE_MACHINE_I386
            return Architecture.X86
        elif arch_value == 34404:  # IMAGE_FILE_MACHINE_AMD64
            return Architecture.X64
        elif arch_value == 43620:
            return Architecture.ARM64
        return None
    if isinstance(arch_value, str):
        arch_lower = arch_value.lower()
        if "arm64" in arch_lower or "aarch64" in arch_lower:
            return Architecture.ARM64
        elif "amd64" in arch_lower or "x64" in arch_lower:
            return Architecture.X64
        elif "x86" in arch_lower or "i386" in arch_lower:
            return Architecture.X86
    return None


def _parse_version(version_str: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version_str)
    return tuple(int(p) for p in parts)


def get_file_info(filename: str) -> Optional[dict]:
    import gzip
    import json
    filename = filename.lower()
    data_url = f"{WINBINDEX_BASE}/data/by_filename_compressed/{filename}.json.gz"
    try:
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            response = client.get(data_url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "*/*",
            })
            
            if response.status_code == 404:
                return None
            response.raise_for_status()
            try:
                decompressed = gzip.decompress(response.content)
                data = json.loads(decompressed)
                return {"fileInfo": data}
            except Exception:
                return {"fileInfo": response.json()}
    except httpx.HTTPStatusError as e:
        if e.response.status_code != 404:
            console.print(f"[yellow]WinBIndex API returned {e.response.status_code}[/yellow]")
        return None
    except Exception as e:
        console.print(f"[yellow]WinBIndex lookup failed: {e}[/yellow]")
        console.print("[dim]Note: WinBIndex API may be temporarily unavailable[/dim]")
        return None


def list_file_versions(
    filename: str,
    architecture: Optional[Architecture] = None,
    limit: int = 20,
) -> list[WinBIndexFile]:
    info = get_file_info(filename)
    if not info:
        return []
    versions: list[WinBIndexFile] = []
    file_data = info.get("fileInfo", {})
    
    for hash_key, entry in file_data.items():
        if not isinstance(entry, dict):
            continue
        file_info = entry.get("fileInfo", {})
        if not file_info:
            continue
        
        version = file_info.get("version", "")
        machine_type = file_info.get("machineType")
        arch = _parse_architecture(machine_type)
        sha256 = file_info.get("sha256", hash_key)
        if architecture and arch and arch != architecture:
            continue
        
        # Symbol server URL: {filename}/{timestamp:08X}{virtualSize:x}/{filename}
        timestamp = file_info.get("timestamp", 0)
        virtual_size = file_info.get("virtualSize", 0)
        
        if timestamp and virtual_size:
            download_url = f"https://msdl.microsoft.com/download/symbols/{filename}/{timestamp:08X}{virtual_size:x}/{filename}"
        else:
            download_url = f"https://msdl.microsoft.com/download/symbols/{filename}/{hash_key}/{filename}"
        
        file_entry = WinBIndexFile(
            filename=filename,
            version=version,
            architecture=arch or Architecture.X64,
            sha256=sha256,
            download_url=download_url,
            timestamp=None,
        )
        versions.append(file_entry)
        
        if len(versions) >= limit:
            break
    versions.sort(key=lambda x: _parse_version(x.version), reverse=True)
    return versions


def find_previous_version(
    filename: str,
    current_version: str,
    architecture: Optional[Architecture] = None,
) -> Optional[WinBIndexFile]:
    versions = list_file_versions(filename, architecture, limit=50)
    if not versions:
        return None
    current_tuple = _parse_version(current_version)
    for version in versions:
        version_tuple = _parse_version(version.version)
        if version_tuple < current_tuple:
            return version
    return None


def _calculate_sha256(file_path: Path) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def download_file_version(
    file_info: WinBIndexFile,
    output_dir: Optional[Path] = None,
    kb_number: Optional[str] = None,
    show_progress: bool = True,
) -> Optional[Path]:
    output_dir = output_dir or DEFAULT_BASELINE_DIR
    if kb_number:
        kb = kb_number.upper()
        if not kb.startswith("KB"):
            kb = f"KB{kb}"
        output_dir = output_dir / kb
    arch_dir = output_dir / file_info.architecture.value
    arch_dir.mkdir(parents=True, exist_ok=True)
    base_name = Path(file_info.filename).stem
    extension = Path(file_info.filename).suffix
    versioned_name = f"{base_name}_{file_info.version.replace('.', '_')}{extension}"
    output_path = arch_dir / versioned_name
    if output_path.exists():
        console.print(f"[yellow]Already downloaded: {versioned_name}[/yellow]")
        return output_path
    download_urls = [
        file_info.download_url,
        f"https://msdl.microsoft.com/download/symbols/{file_info.filename}/{file_info.sha256[:32]}/{file_info.filename}",
        f"https://symbols.nuget.org/download/symbols/{file_info.filename}/{file_info.sha256[:32]}/{file_info.filename}",
    ]
    for url in download_urls:
        if not url:
            continue
        try:
            with httpx.Client(timeout=120.0, follow_redirects=True) as client:
                head_response = client.head(url, headers=HEADERS)
                if head_response.status_code != 200:
                    continue
                with client.stream("GET", url, headers=HEADERS) as response:
                    if response.status_code != 200:
                        continue
                    total = int(response.headers.get("content-length", 0))
                    if show_progress and total > 0:
                        with Progress(
                            TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
                            BarColumn(bar_width=40),
                            "[progress.percentage]{task.percentage:>3.1f}%",
                            "•",
                            DownloadColumn(),
                            "•",
                            TransferSpeedColumn(),
                            "•",
                            TimeRemainingColumn(),
                            console=console,
                        ) as progress:
                            task = progress.add_task(
                                "download",
                                total=total,
                                filename=versioned_name,
                            )
                            
                            with open(output_path, "wb") as f:
                                for chunk in response.iter_bytes(chunk_size=8192):
                                    f.write(chunk)
                                    progress.update(task, advance=len(chunk))
                    else:
                        with open(output_path, "wb") as f:
                            for chunk in response.iter_bytes(chunk_size=8192):
                                f.write(chunk)
                    console.print(f"[green]Downloaded: {output_path}[/green]")
                    return output_path
        except Exception as e:
            console.print(f"[dim]Failed to download from {url[:50]}...: {e}[/dim]")
            continue
    
    console.print(f"[red]Could not download {file_info.filename} v{file_info.version}[/red]")
    return None


def _clean_filename(filename: str) -> str:
    """Remove hash suffixes added during extraction (e.g., gdiplus_12345678.dll -> gdiplus.dll)."""
    import re
    pattern = r'^(.+)_[a-fA-F0-9]{8}(\.[a-zA-Z0-9]+)$'
    match = re.match(pattern, filename)
    if match:
        return match.group(1) + match.group(2)
    return filename


def fetch_baseline_for_extracted(
    extracted_dir: Path,
    kb_number: str,
    output_dir: Optional[Path] = None,
) -> list[DownloadedFile]:
    output_dir = output_dir or DEFAULT_BASELINE_DIR
    kb = kb_number.upper()
    if not kb.startswith("KB"):
        kb = f"KB{kb}"
    downloaded: list[DownloadedFile] = []
    binary_files = []
    for ext in [".dll", ".exe", ".sys"]:
        binary_files.extend(extracted_dir.rglob(f"*{ext}"))
    if not binary_files:
        console.print(f"[yellow]No binary files found in {extracted_dir}[/yellow]")
        return []
    unique_files: dict[str, Path] = {}
    for binary_path in binary_files:
        raw_name = binary_path.name.lower()
        clean_name = _clean_filename(raw_name)
        # Skip Windows SxS assembly files not in WinBIndex
        if clean_name.startswith(('msil_', 'amd64_', 'x86_', 'wow64_', 'arm64_')):
            continue
        if clean_name not in unique_files:
            unique_files[clean_name] = binary_path
    console.print(f"[cyan]Found {len(unique_files)} unique binary files to fetch baselines for[/cyan]")
    seen_files: set[str] = set()
    for clean_name, binary_path in unique_files.items():
        if clean_name in seen_files:
            continue
        seen_files.add(clean_name)
        console.print(f"\n[cyan]Looking up: {clean_name}[/cyan]")
        arch = None
        if "arm64" in str(binary_path).lower():
            arch = Architecture.ARM64
        elif "x64" in str(binary_path).lower() or "amd64" in str(binary_path).lower():
            arch = Architecture.X64
        elif "x86" in str(binary_path).lower():
            arch = Architecture.X86
        versions = list_file_versions(clean_name, arch, limit=10)
        if not versions:
            console.print(f"  [yellow]No versions found on WinBIndex[/yellow]")
            continue
        file_info = versions[0]
        console.print(f"  [dim]Found version: {file_info.version} ({file_info.architecture.value})[/dim]")
        path = download_file_version(file_info, output_dir, kb)
        if path:
            record = DownloadedFile(
                kb_number=kb,
                filename=path.name,
                file_path=str(path),
                file_type="baseline",
                architecture=file_info.architecture,
                version=file_info.version,
                sha256=_calculate_sha256(path),
            )
            downloaded.append(record)
    return downloaded


def show_file_versions(filename: str, architecture: Optional[Architecture] = None) -> None:
    versions = list_file_versions(filename, architecture, limit=20)
    if not versions:
        console.print(f"[yellow]No versions found for {filename}[/yellow]")
        return
    table = Table(title=f"Available versions of {filename}")
    table.add_column("Version", style="cyan")
    table.add_column("Architecture", style="green")
    table.add_column("SHA256", style="dim", max_width=16)
    
    for v in versions:
        table.add_row(
            v.version,
            v.architecture.value,
            v.sha256[:16] + "..." if len(v.sha256) > 16 else v.sha256,
        )
    
    console.print(table)
