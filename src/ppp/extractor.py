"""Binary extraction from MSU/CAB update packages."""

import hashlib
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .models import Architecture, DownloadedFile

console = Console()

DEFAULT_PACKAGES_DIR = Path(__file__).parent.parent.parent / "downloads" / "packages"
DEFAULT_EXTRACTED_DIR = Path(__file__).parent.parent.parent / "downloads" / "extracted"

BINARY_EXTENSIONS = {
    ".dll",
    ".exe",
    ".sys",  # Drivers
    ".ocx",  # ActiveX controls
    ".cpl",  # Control panel applets
    ".drv",  # Drivers
    ".scr",
}

IGNORE_PATTERNS = {
    "*.cat",  # Catalog files
    "*.mum",  # Manifest files (unless needed)
    "*.manifest",
    "*.txt",
    "update.mum",
}


def _get_cab_extractor() -> tuple[str, list[str]]:
    system = platform.system().lower()
    if system == "windows":
        return "expand", ["-F:*"]
    else:
        if shutil.which("cabextract"):
            return "cabextract", ["-q"]
        else:
            raise RuntimeError(
                "cabextract not found. Please install it:\n"
                "  macOS: brew install cabextract\n"
                "  Ubuntu/Debian: sudo apt install cabextract\n"
                "  Fedora: sudo dnf install cabextract"
            )


def _calculate_sha256(file_path: Path) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def _detect_architecture_from_path(path: Path, package_name: str = "") -> Optional[Architecture]:
    path_str = str(path).lower()
    if "arm64" in path_str or "aarch64" in path_str:
        return Architecture.ARM64
    elif "amd64" in path_str or "x64" in path_str or "wow64" in path_str:
        return Architecture.X64
    elif "x86" in path_str or "i386" in path_str:
        return Architecture.X86
    if package_name:
        pkg_lower = package_name.lower()
        if "_arm64" in pkg_lower or "-arm64" in pkg_lower:
            return Architecture.ARM64
        elif "_x64" in pkg_lower or "-x64" in pkg_lower:
            return Architecture.X64
        elif "_x86" in pkg_lower or "-x86" in pkg_lower:
            return Architecture.X86
    return None


def _extract_cab(cab_path: Path, output_dir: Path) -> bool:
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        cmd, base_args = _get_cab_extractor()
        if cmd == "expand":
            result = subprocess.run(
                [cmd] + base_args + [str(cab_path), str(output_dir)],
                capture_output=True,
                text=True,
            )
        else:
            result = subprocess.run(
                [cmd] + base_args + ["-d", str(output_dir), str(cab_path)],
                capture_output=True,
                text=True,
            )
        return result.returncode == 0
    except Exception as e:
        console.print(f"[red]Extraction error: {e}[/red]")
        return False


def _find_nested_cabs(directory: Path) -> list[Path]:
    cabs = []
    for path in directory.rglob("*.cab"):
        cabs.append(path)
    return cabs


def _extract_all_nested_cabs(directory: Path, max_depth: int = 5) -> None:
    """MSU packages often have multiple nesting levels: MSU -> CAB -> CAB -> PSFX.cab -> files."""
    if max_depth <= 0:
        return
    cabs = _find_nested_cabs(directory)
    for cab in cabs:
        extract_marker = cab.parent / f".extracted_{cab.name}"
        if extract_marker.exists():
            continue
        cab_output = cab.parent / f"_extracted_{cab.stem}"
        if _extract_cab(cab, cab_output):
            extract_marker.touch()
            _extract_all_nested_cabs(cab_output, max_depth - 1)


def _is_binary_file(path: Path) -> bool:
    return path.suffix.lower() in BINARY_EXTENSIONS


def _get_file_version(file_path: Path) -> Optional[str]:
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
        
        # Try to get version from StringFileInfo
        if hasattr(pe, "FileInfo"):
            for file_info in pe.FileInfo:
                for info in file_info:
                    if hasattr(info, "StringTable"):
                        for st in info.StringTable:
                            for entry in st.entries.items():
                                if entry[0] == b"FileVersion" or entry[0] == "FileVersion":
                                    pe.close()
                                    version_str = entry[1]
                                    if isinstance(version_str, bytes):
                                        version_str = version_str.decode("utf-8", errors="ignore")
                                    # Clean up version string (remove extra spaces, etc.)
                                    version_str = version_str.strip().replace(" ", "")
                                    return version_str
        
        pe.close()
        return None
    except Exception:
        return None


def extract_package(
    package_path: Path,
    output_dir: Optional[Path] = None,
    kb_number: Optional[str] = None,
) -> list[DownloadedFile]:
    if not package_path.exists():
        raise FileNotFoundError(f"Package not found: {package_path}")
    if not kb_number:
        import re
        match = re.search(r"(KB\d+)", package_path.name, re.IGNORECASE)
        kb_number = match.group(1).upper() if match else package_path.stem
    if output_dir is None:
        output_dir = DEFAULT_EXTRACTED_DIR / kb_number
    output_dir.mkdir(parents=True, exist_ok=True)
    extracted_files: list[DownloadedFile] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Extracting package...", total=None)
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            progress.update(task, description="Extracting outer package...")
            if not _extract_cab(package_path, temp_path):
                console.print(f"[red]Failed to extract {package_path.name}[/red]")
                return []
            progress.update(task, description="Extracting nested packages...")
            _extract_all_nested_cabs(temp_path, max_depth=5)
            progress.update(task, description="Collecting binaries...")
            for file_path in temp_path.rglob("*"):
                if not file_path.is_file():
                    continue
                
                if not _is_binary_file(file_path):
                    continue
                arch = _detect_architecture_from_path(file_path, package_path.name)
                if arch:
                    dest_dir = output_dir / arch.value
                else:
                    dest_dir = output_dir / "unknown"
                dest_dir.mkdir(parents=True, exist_ok=True)
                dest_path = dest_dir / file_path.name
                if dest_path.exists():
                    file_hash = _calculate_sha256(file_path)[:8]
                    dest_path = dest_dir / f"{file_path.stem}_{file_hash}{file_path.suffix}"
                shutil.copy2(file_path, dest_path)
                sha256 = _calculate_sha256(dest_path)
                version = _get_file_version(dest_path)
                
                record = DownloadedFile(
                    kb_number=kb_number,
                    filename=dest_path.name,
                    file_path=str(dest_path),
                    file_type="extracted",
                    architecture=arch,
                    version=version,
                    sha256=sha256,
                )
                extracted_files.append(record)
    console.print(f"[green]Extracted {len(extracted_files)} binary files to {output_dir}[/green]")
    return extracted_files


def extract_by_kb(kb_number: str, packages_dir: Optional[Path] = None) -> list[DownloadedFile]:
    packages_dir = packages_dir or DEFAULT_PACKAGES_DIR
    kb = kb_number.upper()
    if not kb.startswith("KB"):
        kb = f"KB{kb}"
    packages = list(packages_dir.glob(f"*{kb}*")) + list(packages_dir.glob(f"*{kb.lower()}*"))
    packages = [p for p in packages if p.suffix.lower() in (".msu", ".cab")]
    if not packages:
        console.print(f"[yellow]No packages found for {kb} in {packages_dir}[/yellow]")
        return []
    console.print(f"[cyan]Found {len(packages)} package(s) for {kb}[/cyan]")
    all_extracted: list[DownloadedFile] = []
    for package in packages:
        console.print(f"\n[cyan]Processing: {package.name}[/cyan]")
        extracted = extract_package(package, kb_number=kb)
        all_extracted.extend(extracted)
    return all_extracted


def list_extracted_files(kb_number: str, extracted_dir: Optional[Path] = None) -> list[Path]:
    extracted_dir = extracted_dir or DEFAULT_EXTRACTED_DIR
    kb = kb_number.upper()
    if not kb.startswith("KB"):
        kb = f"KB{kb}"
    kb_dir = extracted_dir / kb
    if not kb_dir.exists():
        return []
    files = []
    for path in kb_dir.rglob("*"):
        if path.is_file() and _is_binary_file(path):
            files.append(path)
    return sorted(files)


def get_extraction_stats(kb_number: str, extracted_dir: Optional[Path] = None) -> dict:
    files = list_extracted_files(kb_number, extracted_dir)
    if not files:
        return {"total": 0, "by_arch": {}, "by_type": {}}
    by_arch: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for file in files:
        arch = file.parent.name
        by_arch[arch] = by_arch.get(arch, 0) + 1
        ext = file.suffix.lower()
        by_type[ext] = by_type.get(ext, 0) + 1
    return {
        "total": len(files),
        "by_arch": by_arch,
        "by_type": by_type,
    }
