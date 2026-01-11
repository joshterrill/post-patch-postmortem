"""Microsoft Update Catalog client."""

import hashlib
import re
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

from .models import Architecture, CatalogEntry

console = Console()

CATALOG_BASE = "https://www.catalog.update.microsoft.com"
CATALOG_SEARCH = f"{CATALOG_BASE}/Search.aspx"
CATALOG_DOWNLOAD = f"{CATALOG_BASE}/DownloadDialog.aspx"
DEFAULT_DOWNLOAD_DIR = Path(__file__).parent.parent.parent / "downloads" / "packages"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


def _detect_architecture(title: str) -> Optional[Architecture]:
    title_lower = title.lower()
    if "arm64" in title_lower:
        return Architecture.ARM64
    elif "x64" in title_lower or "64-bit" in title_lower:
        return Architecture.X64
    elif "x86" in title_lower or "32-bit" in title_lower:
        return Architecture.X86
    return None


def search_catalog(
    kb_number: str,
    architecture: Optional[Architecture] = None,
) -> list[CatalogEntry]:
    kb = kb_number.upper()
    if not kb.startswith("KB"):
        kb = f"KB{kb}"
    entries: list[CatalogEntry] = []
    with httpx.Client(timeout=60.0, follow_redirects=True) as client:
        response = client.get(
            CATALOG_SEARCH,
            params={"q": kb},
            headers=HEADERS,
        )
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, "lxml")
        table = soup.find("table", id="ctl00_catalogBody_updateMatches")
        if not table:
            return entries
        rows = table.find_all("tr")
        for row in rows:
            cells = row.find_all("td")
            if len(cells) < 6:
                continue
            input_elem = row.find("input", {"class": "flatBlueButtonDownload"})
            if not input_elem:
                continue
            
            update_id = input_elem.get("id", "").replace("_", "-")
            if not update_id:
                continue
            title_cell = cells[1]
            title_link = title_cell.find("a")
            title = title_link.get_text(strip=True) if title_link else ""
            products = cells[2].get_text(strip=True) if len(cells) > 2 else ""
            classification = cells[3].get_text(strip=True) if len(cells) > 3 else ""
            size = cells[4].get_text(strip=True) if len(cells) > 4 else ""
            arch = _detect_architecture(title)
            if architecture and arch and arch != architecture:
                continue
            
            entry = CatalogEntry(
                update_id=update_id,
                kb_number=kb,
                title=title,
                products=products,
                classification=classification,
                size=size,
            )
            entries.append(entry)
    
    return entries


def get_download_url(update_id: str) -> Optional[str]:
    """The catalog uses JS-based download dialog, so we POST to get the actual link."""
    clean_id = update_id.replace("-", "_")
    with httpx.Client(timeout=60.0, follow_redirects=True) as client:
        client.get(CATALOG_BASE, headers=HEADERS)
        post_data = {
            "updateIDs": f'[{{"uidInfo":"{update_id}","updateID":"{update_id}"}}]',
        }
        
        response = client.post(
            CATALOG_DOWNLOAD,
            data=post_data,
            headers={
                **HEADERS,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        response.raise_for_status()
        html = response.text
        patterns = [
            r"https?://[^'\"]+\.msu",
            r"https?://[^'\"]+\.cab",
            r"https?://download\.windowsupdate\.com/[^'\"]+",
            r"https?://catalog\.s\.download\.windowsupdate\.com/[^'\"]+",
        ]
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                return match.group(0)
    
    return None


def _calculate_sha256(file_path: Path) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def download_update(
    entry: CatalogEntry,
    download_dir: Optional[Path] = None,
    show_progress: bool = True,
) -> Optional[Path]:
    download_dir = download_dir or DEFAULT_DOWNLOAD_DIR
    download_dir.mkdir(parents=True, exist_ok=True)
    if not entry.download_url:
        url = get_download_url(entry.update_id)
        if not url:
            console.print(f"[red]Could not get download URL for {entry.title}[/red]")
            return None
        entry.download_url = url
    url = entry.download_url
    filename = url.split("/")[-1].split("?")[0]
    if not filename.endswith((".msu", ".cab")):
        filename = f"{entry.kb_number}_{entry.update_id[:8]}.msu"
    arch = _detect_architecture(entry.title)
    if arch:
        base, ext = filename.rsplit(".", 1)
        filename = f"{base}_{arch.value}.{ext}"
    file_path = download_dir / filename
    if file_path.exists():
        console.print(f"[yellow]Already downloaded: {filename}[/yellow]")
        return file_path
    with httpx.Client(timeout=300.0, follow_redirects=True) as client:
        with client.stream("GET", url, headers=HEADERS) as response:
            response.raise_for_status()
            
            total = int(response.headers.get("content-length", 0))
            
            if show_progress:
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
                        filename=filename,
                    )
                    
                    with open(file_path, "wb") as f:
                        for chunk in response.iter_bytes(chunk_size=8192):
                            f.write(chunk)
                            progress.update(task, advance=len(chunk))
            else:
                with open(file_path, "wb") as f:
                    for chunk in response.iter_bytes(chunk_size=8192):
                        f.write(chunk)
    
    console.print(f"[green]Downloaded: {file_path}[/green]")
    return file_path


def download_by_kb(
    kb_number: str,
    architecture: Optional[Architecture] = None,
    download_dir: Optional[Path] = None,
    show_progress: bool = True,
) -> list[Path]:
    console.print(f"[cyan]Searching catalog for {kb_number}...[/cyan]")
    entries = search_catalog(kb_number, architecture)
    if not entries:
        console.print(f"[yellow]No entries found for {kb_number}[/yellow]")
        return []
    console.print(f"[green]Found {len(entries)} entries[/green]")
    downloaded: list[Path] = []
    for entry in entries:
        console.print(f"[cyan]Downloading: {entry.title}[/cyan]")
        time.sleep(1)
        path = download_update(entry, download_dir, show_progress)
        if path:
            downloaded.append(path)
    
    return downloaded


def list_catalog_entries(kb_number: str) -> None:
    from rich.table import Table
    entries = search_catalog(kb_number)
    if not entries:
        console.print(f"[yellow]No entries found for {kb_number}[/yellow]")
        return
    
    table = Table(title=f"Update Catalog Results for {kb_number}")
    table.add_column("Title", style="cyan", max_width=60)
    table.add_column("Products", style="green", max_width=30)
    table.add_column("Classification", style="yellow")
    table.add_column("Size", style="magenta")
    
    for entry in entries:
        arch = _detect_architecture(entry.title)
        arch_str = f" [{arch.value}]" if arch else ""
        table.add_row(
            entry.title[:60] + ("..." if len(entry.title) > 60 else "") + arch_str,
            entry.products[:30] + ("..." if len(entry.products) > 30 else ""),
            entry.classification,
            entry.size,
        )
    
    console.print(table)
