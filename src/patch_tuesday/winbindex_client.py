"""WinBIndex client for fetching pre-patch versions of Windows binaries."""

import hashlib
import html as html_lib
import re
from datetime import datetime, timezone
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

from .models import Architecture, DownloadedFile, WinBIndexFile, WinBIndexUpdate

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


def _datetime_to_timestamp(dt: Optional[datetime]) -> float:
    if not dt:
        return float("-inf")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _parse_datetime(value) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    if value is None:
        return None
    if isinstance(value, (int, float)):
        # Heuristic: values > 1e11 are probably milliseconds.
        ts = float(value)
        if ts > 100_000_000_000:
            ts /= 1000.0
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        
        # Try integer-like timestamps first.
        try:
            if text.isdigit():
                return _parse_datetime(int(text))
        except ValueError:
            pass
        
        # ISO-like date/time parsing with UTC handling.
        iso_text = text.replace("Z", "+00:00")
        for candidate in (iso_text, text):
            try:
                return datetime.fromisoformat(candidate)
            except ValueError:
                continue
        
        # Date-only fallback.
        for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%m/%d/%Y"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
    return None


def _collect_datetimes(obj, keys_of_interest: set[str], out: list[datetime]) -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_lower = str(key).lower()
            if key_lower in keys_of_interest:
                dt = _parse_datetime(value)
                if dt:
                    out.append(dt)
            _collect_datetimes(value, keys_of_interest, out)
    elif isinstance(obj, list):
        for item in obj:
            _collect_datetimes(item, keys_of_interest, out)


def _extract_release_date(entry: dict, file_info: dict) -> Optional[datetime]:
    # Prefer explicit release/update dates from windowsVersions metadata.
    windows_versions = entry.get("windowsVersions", {})
    candidates: list[datetime] = []
    date_keys = {
        "releasedate",
        "release_date",
        "release",
        "released",
        "date",
        "created",
        "creationdate",
        "updated",
        "updatedat",
        "lastupdated",
        "builddate",
    }
    _collect_datetimes(windows_versions, date_keys, candidates)
    if candidates:
        return min(candidates)
    
    # Fallback to PE timestamp if present.
    return _parse_datetime(file_info.get("timestamp"))


def _extract_update_refs(entry: dict) -> list[WinBIndexUpdate]:
    windows_versions = entry.get("windowsVersions", {})
    updates: list[WinBIndexUpdate] = []

    def walk(node, current_windows: Optional[str] = None) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                key_text = str(key)
                if re.match(r"^KB\d{6,8}$", key_text, flags=re.IGNORECASE) and isinstance(value, dict):
                    update_info = value.get("updateInfo", {}) if isinstance(value.get("updateInfo", {}), dict) else {}
                    updates.append(
                        WinBIndexUpdate(
                            kb_number=key_text.upper(),
                            windows_version=current_windows,
                            release_date=_parse_datetime(update_info.get("releaseDate")),
                            release_version=update_info.get("releaseVersion"),
                            update_url=update_info.get("updateUrl"),
                            heading=html_lib.unescape(str(update_info.get("heading", ""))).strip() or None,
                        )
                    )
                    continue

                next_windows = current_windows
                if current_windows is None and not key_text.lower().startswith("kb"):
                    next_windows = key_text
                walk(value, next_windows)
        elif isinstance(node, list):
            for item in node:
                walk(item, current_windows)

    walk(windows_versions)

    deduped: list[WinBIndexUpdate] = []
    seen: set[tuple] = set()
    for item in updates:
        key = (
            item.kb_number,
            item.windows_version,
            item.release_date.isoformat() if item.release_date else None,
            item.release_version,
            item.update_url,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _parse_int(value) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            return None
    return None


def _make_symbol_server_url(filename: str, timestamp, size_of_image) -> Optional[str]:
    ts = _parse_int(timestamp)
    soi = _parse_int(size_of_image)
    if ts is None or soi is None:
        return None
    return f"https://msdl.microsoft.com/download/symbols/{filename}/{ts:08X}{soi:x}/{filename}"


def _build_symbol_server_urls(filename: str, file_info: dict, hash_key: str) -> list[str]:
    """Mirror WinBindex URL generation for downloadable binaries."""
    candidates: list[str] = []
    
    timestamp = file_info.get("timestamp")
    virtual_size = file_info.get("virtualSize")
    primary = _make_symbol_server_url(filename, timestamp, virtual_size)
    if primary:
        candidates.append(primary)
    else:
        size = _parse_int(file_info.get("size"))
        last_ptr = _parse_int(file_info.get("lastSectionPointerToRawData"))
        last_va = _parse_int(file_info.get("lastSectionVirtualAddress"))
        ts = _parse_int(timestamp)
        
        # WinBindex fallback: try multiple possible SizeOfImage values.
        if ts is not None and size and last_ptr is not None and last_va is not None:
            start = max(last_va + last_ptr, size)
            end = size + 2 * 1024 * 1024
            for size_of_image in range(start, end + 1, 0x1000):
                url = _make_symbol_server_url(filename, ts, size_of_image)
                if url:
                    candidates.append(url)
    
    if hash_key:
        candidates.append(
            f"https://msdl.microsoft.com/download/symbols/{filename}/{hash_key}/{filename}"
        )
    
    deduped: list[str] = []
    seen: set[str] = set()
    for url in candidates:
        if url and url not in seen:
            deduped.append(url)
            seen.add(url)
    return deduped


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
        
        download_urls = _build_symbol_server_urls(filename, file_info, hash_key)
        if not download_urls:
            continue
        download_url = download_urls[0]
        
        file_entry = WinBIndexFile(
            filename=filename,
            version=version,
            architecture=arch or Architecture.X64,
            sha256=sha256,
            download_url=download_url,
            download_urls=download_urls,
            release_date=_extract_release_date(entry, file_info),
            timestamp=_parse_datetime(file_info.get("timestamp")),
            size=_parse_int(file_info.get("size")),
            updates=_extract_update_refs(entry),
        )
        versions.append(file_entry)
    versions.sort(
        key=lambda x: (_datetime_to_timestamp(x.release_date), _parse_version(x.version)),
        reverse=True,
    )
    return versions[:limit]


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
    download_urls = list(file_info.download_urls)
    if file_info.download_url:
        download_urls.insert(0, file_info.download_url)
    download_urls.extend([
        f"https://msdl.microsoft.com/download/symbols/{file_info.filename}/{file_info.sha256[:32]}/{file_info.filename}",
        f"https://symbols.nuget.org/download/symbols/{file_info.filename}/{file_info.sha256[:32]}/{file_info.filename}",
    ])
    
    deduped_urls: list[str] = []
    seen_urls: set[str] = set()
    for url in download_urls:
        if url and url not in seen_urls:
            deduped_urls.append(url)
            seen_urls.add(url)
    
    for url in deduped_urls:
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


def _get_pe_version(file_path: Path) -> Optional[str]:
    """Extract version info from a PE file using pefile."""
    try:
        import pefile
    except ImportError:
        return None
    
    try:
        pe = pefile.PE(str(file_path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )
        
        if not hasattr(pe, "VS_FIXEDFILEINFO"):
            pe.close()
            return None
        
        # Extract version from VS_FIXEDFILEINFO
        version_info = pe.VS_FIXEDFILEINFO[0] if pe.VS_FIXEDFILEINFO else None
        if version_info:
            ms = version_info.FileVersionMS
            ls = version_info.FileVersionLS
            version = f"{(ms >> 16) & 0xFFFF}.{ms & 0xFFFF}.{(ls >> 16) & 0xFFFF}.{ls & 0xFFFF}"
            pe.close()
            return version
        
        pe.close()
        return None
    except Exception:
        return None


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
        
        # Get the version of the patched binary so we can find the previous version
        patched_version = _get_pe_version(binary_path)
        
        if patched_version:
            console.print(f"  [dim]Patched binary version: {patched_version}[/dim]")
            # Find the version immediately before the patched version
            file_info = find_previous_version(clean_name, patched_version, arch)
            if file_info:
                console.print(f"  [green]Found baseline version: {file_info.version} (previous to {patched_version})[/green]")
            else:
                console.print(f"  [yellow]No previous version found for {patched_version}, trying latest available[/yellow]")
                versions = list_file_versions(clean_name, arch, limit=10)
                if versions:
                    # Filter out versions >= patched version
                    patched_tuple = _parse_version(patched_version)
                    older_versions = [v for v in versions if _parse_version(v.version) < patched_tuple]
                    if older_versions:
                        file_info = older_versions[0]
                        console.print(f"  [dim]Using version: {file_info.version}[/dim]")
                    else:
                        console.print(f"  [yellow]All available versions are >= {patched_version}, skipping[/yellow]")
                        continue
                else:
                    console.print(f"  [yellow]No versions found on WinBIndex[/yellow]")
                    continue
        else:
            # Fallback: if we can't read the version, take the second-newest version
            # (assuming the newest might be the same as the patched one)
            console.print(f"  [yellow]Could not read version from patched binary, using heuristic[/yellow]")
            versions = list_file_versions(clean_name, arch, limit=10)
            if not versions:
                console.print(f"  [yellow]No versions found on WinBIndex[/yellow]")
                continue
            # Use second version if available, otherwise first
            # This is a heuristic - the patched version might already be on WinBIndex
            if len(versions) >= 2:
                file_info = versions[1]
                console.print(f"  [dim]Using second-newest version: {file_info.version} (heuristic)[/dim]")
            else:
                file_info = versions[0]
                console.print(f"  [dim]Only one version available: {file_info.version}[/dim]")
        
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


def show_file_versions(
    filename: str,
    architecture: Optional[Architecture] = None,
    limit: int = 20,
) -> None:
    versions = list_file_versions(filename, architecture, limit=limit)
    if not versions:
        console.print(f"[yellow]No versions found for {filename}[/yellow]")
        return
    table = Table(title=f"Available versions of {filename}")
    table.add_column("KBs", style="yellow", max_width=14)
    table.add_column("Version", style="cyan")
    table.add_column("Release Date", style="magenta", width=12)
    table.add_column("Windows", style="blue", max_width=16)
    table.add_column("Architecture", style="green")
    table.add_column("Size", style="white", justify="right")
    table.add_column("SHA256", style="dim", max_width=16)
    
    for v in versions:
        release_date = v.release_date.strftime("%Y-%m-%d") if v.release_date else "N/A"
        kb_values = sorted({item.kb_number for item in v.updates if item.kb_number})
        kb_text = ", ".join(kb_values[:2]) if kb_values else "N/A"
        if len(kb_values) > 2:
            kb_text += f" +{len(kb_values) - 2}"
        windows_values = sorted({item.windows_version for item in v.updates if item.windows_version})
        windows_text = ", ".join(windows_values[:2]) if windows_values else "N/A"
        if len(windows_values) > 2:
            windows_text += f" +{len(windows_values) - 2}"
        size_value = v.size or 0
        size_text = "N/A"
        if size_value > 0:
            size_text = f"{size_value / 1024:.1f} KB" if size_value < 1024 * 1024 else f"{size_value / 1024 / 1024:.2f} MB"
        table.add_row(
            kb_text,
            v.version,
            release_date,
            windows_text,
            v.architecture.value,
            size_text,
            v.sha256[:16] + "..." if len(v.sha256) > 16 else v.sha256,
        )
    
    console.print(table)
