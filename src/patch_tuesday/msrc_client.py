"""MSRC API client for fetching Patch Tuesday data."""

import re
from datetime import datetime
from typing import Optional

import httpx
from rich.console import Console

from .database import (
    get_db,
    init_db,
    link_patch_cve,
    link_patch_product,
    upsert_cve,
    upsert_patch,
    upsert_product,
)
from .models import CVE, Patch, Product, Severity

console = Console()

MSRC_API_BASE = "https://api.msrc.microsoft.com/cvrf/v2.0"
HEADERS = {"Accept": "application/json", "User-Agent": "PatchTuesdayAnalyzer/1.0"}


def get_update_ids(year: Optional[int] = None) -> list[str]:
    """Returns IDs like '2024-Jan', '2024-Feb', etc."""
    url = f"{MSRC_API_BASE}/updates"
    with httpx.Client(timeout=30.0) as client:
        response = client.get(url, headers=HEADERS)
        response.raise_for_status()
        data = response.json()
    
    update_ids = []
    for update in data.get("value", []):
        update_id = update.get("ID", "")
        if update_id:
            # Filter by year if specified
            if year:
                if update_id.startswith(str(year)):
                    update_ids.append(update_id)
            else:
                update_ids.append(update_id)
    
    return sorted(update_ids, reverse=True)


def _parse_severity(severity_str: Optional[str]) -> Severity:
    if not severity_str:
        return Severity.UNKNOWN
    severity_map = {
        "critical": Severity.CRITICAL,
        "important": Severity.IMPORTANT,
        "moderate": Severity.MODERATE,
        "low": Severity.LOW,
    }
    return severity_map.get(severity_str.lower(), Severity.UNKNOWN)


def _extract_kb_numbers(text: str) -> list[str]:
    pattern = r"KB\d{6,8}"
    matches = re.findall(pattern, text, re.IGNORECASE)
    return [kb.upper() for kb in set(matches)]


def _parse_release_date(date_str: str) -> datetime:
    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_str.split(".")[0], fmt)
        except ValueError:
            continue
    return datetime.now()


def fetch_cvrf_document(update_id: str) -> dict:
    url = f"{MSRC_API_BASE}/cvrf/{update_id}"
    with httpx.Client(timeout=60.0) as client:
        response = client.get(url, headers=HEADERS)
        response.raise_for_status()
        return response.json()


def parse_cvrf_document(cvrf: dict, update_id: str) -> tuple[
    list[Patch],
    list[Product],
    list[CVE],
    dict[str, set[str]],
    dict[str, set[str]],
    dict[str, Product],
]:
    cves: list[CVE] = []
    kb_patches: dict[str, Patch] = {}
    cve_kb_map: dict[str, set[str]] = {}
    product_kb_map: dict[str, set[str]] = {}
    
    # Use InitialReleaseDate (actual Patch Tuesday date), not CurrentReleaseDate
    doc_tracking = cvrf.get("DocumentTracking", {})
    release_date_str = doc_tracking.get("InitialReleaseDate", "") or doc_tracking.get("CurrentReleaseDate", "")
    release_date = _parse_release_date(release_date_str) if release_date_str else datetime.now()
    
    product_tree = cvrf.get("ProductTree", {})
    product_map: dict[str, Product] = {}
    full_product_names = product_tree.get("FullProductName", [])
    for item in full_product_names:
        product_id = item.get("ProductID", "")
        product_name = item.get("Value", "")
        
        if product_id and _is_windows_product(product_name):
            product = Product(
                product_id=product_id,
                name=product_name,
                version=_extract_version(product_name),
            )
            product_map[product_id] = product
    
    products = list(product_map.values())
    vulnerabilities = cvrf.get("Vulnerability", [])
    
    for vuln in vulnerabilities:
        cve_id = vuln.get("CVE", "")
        if not cve_id:
            continue
        
        title = vuln.get("Title", {}).get("Value", cve_id)
        severity = Severity.UNKNOWN
        threats = vuln.get("Threats", [])
        for threat in threats:
            if threat.get("Type") == 3:  # Severity type
                desc = threat.get("Description", {}).get("Value", "")
                severity = _parse_severity(desc)
                break
        
        description = ""
        notes = vuln.get("Notes", [])
        for note in notes:
            if note.get("Type") == 1:  # Description type
                description = note.get("Value", "")
                break
        cve = CVE(
            cve_id=cve_id,
            title=title,
            severity=severity,
            description=description,
        )
        cves.append(cve)
        remediations = vuln.get("Remediations", [])
        for remediation in remediations:
            rem_type = remediation.get("Type", 0)
            if rem_type != 2:  # Vendor Fix
                continue
            
            description = remediation.get("Description", {}).get("Value", "")
            kb_numbers = _extract_kb_numbers(description)
            url = remediation.get("URL", "")
            kb_numbers.extend(_extract_kb_numbers(url))
            product_ids = remediation.get("ProductID", [])
            if isinstance(product_ids, str):
                product_ids = [product_ids]
            
            for kb in set(kb_numbers):
                if cve_id not in cve_kb_map:
                    cve_kb_map[cve_id] = set()
                cve_kb_map[cve_id].add(kb)
                for pid in product_ids:
                    if pid in product_map:
                        if pid not in product_kb_map:
                            product_kb_map[pid] = set()
                        product_kb_map[pid].add(kb)
                if kb not in kb_patches:
                    patch = Patch(
                        kb_number=kb,
                        title=f"Security Update {kb}",
                        release_date=release_date,
                        description=f"Security update from {update_id}",
                        severity=severity,
                    )
                    kb_patches[kb] = patch
                else:
                    existing = kb_patches[kb]
                    if _severity_rank(severity) > _severity_rank(existing.severity):
                        existing.severity = severity
    
    patches = list(kb_patches.values())
    products = list(product_map.values())
    
    return patches, products, cves, cve_kb_map, product_kb_map, product_map


def _is_windows_product(name: str) -> bool:
    name_lower = name.lower()
    keywords = [
        "windows 10",
        "windows 11",
        "windows server",
        "microsoft edge",
        "windows defender",
        ".net framework",
    ]
    return any(kw in name_lower for kw in keywords)


def _extract_version(name: str) -> Optional[str]:
    patterns = [r"(\d{2}H\d)", r"Version (\d+)", r"(\d{4})"]
    for pattern in patterns:
        match = re.search(pattern, name)
        if match:
            return match.group(1)
    return None


def _severity_rank(severity: Severity) -> int:
    ranks = {
        Severity.CRITICAL: 4,
        Severity.IMPORTANT: 3,
        Severity.MODERATE: 2,
        Severity.LOW: 1,
        Severity.UNKNOWN: 0,
    }
    return ranks.get(severity, 0)


def fetch_and_store_update(update_id: str, verbose: bool = False) -> dict:
    init_db()
    if verbose:
        console.print(f"[cyan]Fetching CVRF document for {update_id}...[/cyan]")
    
    cvrf = fetch_cvrf_document(update_id)
    
    if verbose:
        console.print("[cyan]Parsing document...[/cyan]")
    
    result = parse_cvrf_document(cvrf, update_id)
    patches, products, cves, cve_kb_map, product_kb_map, product_map = result
    
    if verbose:
        console.print(f"[green]Found {len(patches)} patches, {len(products)} products, {len(cves)} CVEs[/green]")
    
    with get_db() as db:
        product_db_ids: dict[str, int] = {}
        for product in products:
            db_id = upsert_product(db, product)
            product_db_ids[product.product_id] = db_id
        cve_db_ids: dict[str, int] = {}
        for cve in cves:
            db_id = upsert_cve(db, cve)
            cve_db_ids[cve.cve_id] = db_id
        patch_db_ids: dict[str, int] = {}
        for patch in patches:
            db_id = upsert_patch(db, patch)
            patch_db_ids[patch.kb_number] = db_id
        for cve_id, kb_numbers in cve_kb_map.items():
            if cve_id in cve_db_ids:
                cve_db_id = cve_db_ids[cve_id]
                for kb in kb_numbers:
                    if kb in patch_db_ids:
                        link_patch_cve(db, patch_db_ids[kb], cve_db_id)
        for product_id, kb_numbers in product_kb_map.items():
            if product_id in product_db_ids:
                product_db_id = product_db_ids[product_id]
                for kb in kb_numbers:
                    if kb in patch_db_ids:
                        link_patch_product(db, patch_db_ids[kb], product_db_id)
    
    return {
        "update_id": update_id,
        "patches": len(patches),
        "products": len(products),
        "cves": len(cves),
    }


def fetch_latest(count: int = 1, verbose: bool = False) -> list[dict]:
    if verbose:
        console.print("[cyan]Getting available updates...[/cyan]")
    
    update_ids = get_update_ids()
    update_ids = update_ids[:count]
    
    results = []
    for update_id in update_ids:
        try:
            result = fetch_and_store_update(update_id, verbose)
            results.append(result)
        except Exception as e:
            if verbose:
                console.print(f"[red]Error fetching {update_id}: {e}[/red]")
    
    return results


def fetch_by_date(year: int, month: int, verbose: bool = False) -> Optional[dict]:
    month_names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    ]
    
    update_id = f"{year}-{month_names[month - 1]}"
    
    try:
        return fetch_and_store_update(update_id, verbose)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            if verbose:
                console.print(f"[yellow]No update found for {update_id}[/yellow]")
            return None
        raise
