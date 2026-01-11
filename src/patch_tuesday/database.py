"""SQLite database operations."""

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from sqlite_utils import Database

from .models import (
    Architecture,
    CVE,
    DownloadedFile,
    Patch,
    Product,
    Severity,
)

DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "data" / "patches.db"


def get_db_path() -> Path:
    db_path = DEFAULT_DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return db_path


@contextmanager
def get_db(db_path: Optional[Path] = None) -> Iterator[Database]:
    path = db_path or get_db_path()
    db = Database(path)
    try:
        yield db
    finally:
        db.close()


def init_db(db_path: Optional[Path] = None) -> None:
    with get_db(db_path) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                version TEXT
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                severity TEXT DEFAULT 'Unknown',
                description TEXT,
                impact TEXT
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS patches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kb_number TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                release_date TEXT NOT NULL,
                description TEXT,
                severity TEXT DEFAULT 'Unknown'
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS patch_products (
                patch_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                PRIMARY KEY (patch_id, product_id),
                FOREIGN KEY (patch_id) REFERENCES patches(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS patch_cves (
                patch_id INTEGER NOT NULL,
                cve_id INTEGER NOT NULL,
                PRIMARY KEY (patch_id, cve_id),
                FOREIGN KEY (patch_id) REFERENCES patches(id) ON DELETE CASCADE,
                FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS downloaded_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kb_number TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_type TEXT NOT NULL,
                architecture TEXT,
                version TEXT,
                sha256 TEXT,
                downloaded_at TEXT NOT NULL,
                FOREIGN KEY (kb_number) REFERENCES patches(kb_number) ON DELETE CASCADE
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_patches_release_date ON patches(release_date)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_patches_kb ON patches(kb_number)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_products_name ON products(name)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_downloaded_kb ON downloaded_files(kb_number)")


def upsert_product(db: Database, product: Product) -> int:
    conn = db.conn
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM products WHERE product_id = ?", [product.product_id])
    existing = cursor.fetchone()
    if existing:
        cursor.execute(
            "UPDATE products SET name = ?, version = ? WHERE product_id = ?",
            [product.name, product.version, product.product_id],
        )
        conn.commit()
        return existing[0]
    cursor.execute(
        "INSERT INTO products (product_id, name, version) VALUES (?, ?, ?)",
        [product.product_id, product.name, product.version],
    )
    conn.commit()
    return cursor.lastrowid or -1


def get_product_by_id(db: Database, product_id: str) -> Optional[Product]:
    row = db.execute(
        "SELECT id, product_id, name, version FROM products WHERE product_id = ?",
        [product_id],
    ).fetchone()
    if row:
        return Product(id=row[0], product_id=row[1], name=row[2], version=row[3])
    return None


def get_all_products(db: Database) -> list[Product]:
    rows = db.execute("SELECT id, product_id, name, version FROM products").fetchall()
    return [Product(id=r[0], product_id=r[1], name=r[2], version=r[3]) for r in rows]


def get_products_for_patch(db: Database, patch_id: int) -> list[Product]:
    rows = db.execute(
        """
        SELECT p.id, p.product_id, p.name, p.version
        FROM products p
        JOIN patch_products pp ON p.id = pp.product_id
        WHERE pp.patch_id = ?
        ORDER BY p.name
        """,
        [patch_id],
    ).fetchall()
    return [Product(id=r[0], product_id=r[1], name=r[2], version=r[3]) for r in rows]


def summarize_products(products: list[Product]) -> str:
    """Summarize products into a compact display string (e.g., 'Win11, Win10, Server 2022')."""
    if not products:
        return ""
    families: set[str] = set()
    for p in products:
        name = p.name
        # Extract the main product name
        if "Windows 11" in name:
            families.add("Win11")
        elif "Windows 10" in name:
            families.add("Win10")
        elif "Windows Server 2022" in name:
            families.add("Server 2022")
        elif "Windows Server 2019" in name:
            families.add("Server 2019")
        elif "Windows Server 2016" in name:
            families.add("Server 2016")
        elif "Windows Server" in name:
            families.add("Server")
        elif "Microsoft Office" in name:
            families.add("Office")
        elif "Microsoft Edge" in name:
            families.add("Edge")
        elif "Visual Studio" in name:
            families.add("VS")
        elif "Azure" in name:
            families.add("Azure")
        elif ".NET" in name:
            families.add(".NET")
        else:
            parts = name.split()[:2]
            if parts:
                families.add(" ".join(parts))
    sorted_families = sorted(families)
    if len(sorted_families) > 3:
        return ", ".join(sorted_families[:3]) + f" +{len(sorted_families) - 3}"
    return ", ".join(sorted_families)


def upsert_cve(db: Database, cve: CVE) -> int:
    conn = db.conn
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM cves WHERE cve_id = ?", [cve.cve_id])
    existing = cursor.fetchone()
    if existing:
        cursor.execute(
            "UPDATE cves SET title = ?, severity = ?, description = ?, impact = ? WHERE cve_id = ?",
            [cve.title, cve.severity.value, cve.description, cve.impact, cve.cve_id],
        )
        conn.commit()
        return existing[0]
    cursor.execute(
        "INSERT INTO cves (cve_id, title, severity, description, impact) VALUES (?, ?, ?, ?, ?)",
        [cve.cve_id, cve.title, cve.severity.value, cve.description, cve.impact],
    )
    conn.commit()
    return cursor.lastrowid or -1


def get_cve(db: Database, cve_id: str) -> Optional[CVE]:
    row = db.execute(
        "SELECT id, cve_id, title, severity, description, impact FROM cves WHERE cve_id = ?",
        [cve_id],
    ).fetchone()
    if row:
        return CVE(
            id=row[0],
            cve_id=row[1],
            title=row[2],
            severity=Severity(row[3]) if row[3] else Severity.UNKNOWN,
            description=row[4],
            impact=row[5],
        )
    return None


def upsert_patch(db: Database, patch: Patch) -> int:
    conn = db.conn
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM patches WHERE kb_number = ?", [patch.kb_number])
    existing = cursor.fetchone()
    if existing:
        cursor.execute(
            "UPDATE patches SET title = ?, release_date = ?, description = ?, severity = ? WHERE kb_number = ?",
            [patch.title, patch.release_date.isoformat(), patch.description, patch.severity.value, patch.kb_number],
        )
        conn.commit()
        return existing[0]
    cursor.execute(
        "INSERT INTO patches (kb_number, title, release_date, description, severity) VALUES (?, ?, ?, ?, ?)",
        [patch.kb_number, patch.title, patch.release_date.isoformat(), patch.description, patch.severity.value],
    )
    conn.commit()
    return cursor.lastrowid or -1


def get_patch(db: Database, kb_number: str) -> Optional[Patch]:
    kb = kb_number.upper()
    if not kb.startswith("KB"):
        kb = f"KB{kb}"
    
    row = db.execute(
        "SELECT id, kb_number, title, release_date, description, severity FROM patches WHERE kb_number = ?",
        [kb],
    ).fetchone()
    
    if not row:
        return None
    
    patch_id = row[0]
    patch = Patch(
        id=patch_id,
        kb_number=row[1],
        title=row[2],
        release_date=datetime.fromisoformat(row[3]),
        description=row[4],
        severity=Severity(row[5]) if row[5] else Severity.UNKNOWN,
    )
    product_rows = db.execute(
        """
        SELECT p.id, p.product_id, p.name, p.version
        FROM products p
        JOIN patch_products pp ON p.id = pp.product_id
        WHERE pp.patch_id = ?
        """,
        [patch_id],
    ).fetchall()
    patch.products = [
        Product(id=r[0], product_id=r[1], name=r[2], version=r[3]) for r in product_rows
    ]
    cve_rows = db.execute(
        """
        SELECT c.id, c.cve_id, c.title, c.severity, c.description, c.impact
        FROM cves c
        JOIN patch_cves pc ON c.id = pc.cve_id
        WHERE pc.patch_id = ?
        """,
        [patch_id],
    ).fetchall()
    patch.cves = [
        CVE(
            id=r[0],
            cve_id=r[1],
            title=r[2],
            severity=Severity(r[3]) if r[3] else Severity.UNKNOWN,
            description=r[4],
            impact=r[5],
        )
        for r in cve_rows
    ]
    
    return patch


def get_patches_by_date(
    db: Database,
    year: Optional[int] = None,
    month: Optional[int] = None,
) -> list[Patch]:
    query = "SELECT id, kb_number, title, release_date, description, severity FROM patches"
    params: list = []
    if year and month:
        start_date = f"{year:04d}-{month:02d}-01"
        if month == 12:
            end_date = f"{year + 1:04d}-01-01"
        else:
            end_date = f"{year:04d}-{month + 1:02d}-01"
        query += " WHERE release_date >= ? AND release_date < ?"
        params = [start_date, end_date]
    elif year:
        start_date = f"{year:04d}-01-01"
        end_date = f"{year + 1:04d}-01-01"
        query += " WHERE release_date >= ? AND release_date < ?"
        params = [start_date, end_date]
    
    query += " ORDER BY release_date DESC"
    
    rows = db.execute(query, params).fetchall()
    patches = []
    
    for row in rows:
        patch = Patch(
            id=row[0],
            kb_number=row[1],
            title=row[2],
            release_date=datetime.fromisoformat(row[3]),
            description=row[4],
            severity=Severity(row[5]) if row[5] else Severity.UNKNOWN,
        )
        patches.append(patch)
    
    return patches


def get_patches_by_product(db: Database, product_name: str) -> list[Patch]:
    rows = db.execute(
        """
        SELECT DISTINCT pa.id, pa.kb_number, pa.title, pa.release_date, pa.description, pa.severity
        FROM patches pa
        JOIN patch_products pp ON pa.id = pp.patch_id
        JOIN products pr ON pp.product_id = pr.id
        WHERE pr.name LIKE ?
        ORDER BY pa.release_date DESC
        """,
        [f"%{product_name}%"],
    ).fetchall()
    
    return [
        Patch(
            id=r[0],
            kb_number=r[1],
            title=r[2],
            release_date=datetime.fromisoformat(r[3]),
            description=r[4],
            severity=Severity(r[5]) if r[5] else Severity.UNKNOWN,
        )
        for r in rows
    ]


def link_patch_product(db: Database, patch_id: int, product_id: int) -> None:
    conn = db.conn
    try:
        conn.execute(
            "INSERT OR IGNORE INTO patch_products (patch_id, product_id) VALUES (?, ?)",
            [patch_id, product_id],
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass


def link_patch_cve(db: Database, patch_id: int, cve_id: int) -> None:
    conn = db.conn
    try:
        conn.execute(
            "INSERT OR IGNORE INTO patch_cves (patch_id, cve_id) VALUES (?, ?)",
            [patch_id, cve_id],
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass


def add_downloaded_file(db: Database, file: DownloadedFile) -> int:
    conn = db.conn
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO downloaded_files 
           (kb_number, filename, file_path, file_type, architecture, version, sha256, downloaded_at) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            file.kb_number,
            file.filename,
            file.file_path,
            file.file_type,
            file.architecture.value if file.architecture else None,
            file.version,
            file.sha256,
            file.downloaded_at.isoformat(),
        ],
    )
    conn.commit()
    return cursor.lastrowid or -1


def get_downloaded_files(db: Database, kb_number: str) -> list[DownloadedFile]:
    rows = db.execute(
        """
        SELECT id, kb_number, filename, file_path, file_type, architecture, version, sha256, downloaded_at
        FROM downloaded_files
        WHERE kb_number = ?
        """,
        [kb_number],
    ).fetchall()
    
    return [
        DownloadedFile(
            id=r[0],
            kb_number=r[1],
            filename=r[2],
            file_path=r[3],
            file_type=r[4],
            architecture=Architecture(r[5]) if r[5] else None,
            version=r[6],
            sha256=r[7],
            downloaded_at=datetime.fromisoformat(r[8]),
        )
        for r in rows
    ]


def get_downloaded_files_by_type(
    db: Database, kb_number: str, file_type: str
) -> list[DownloadedFile]:
    rows = db.execute(
        """
        SELECT id, kb_number, filename, file_path, file_type, architecture, version, sha256, downloaded_at
        FROM downloaded_files
        WHERE kb_number = ? AND file_type = ?
        """,
        [kb_number, file_type],
    ).fetchall()
    
    return [
        DownloadedFile(
            id=r[0],
            kb_number=r[1],
            filename=r[2],
            file_path=r[3],
            file_type=r[4],
            architecture=Architecture(r[5]) if r[5] else None,
            version=r[6],
            sha256=r[7],
            downloaded_at=datetime.fromisoformat(r[8]),
        )
        for r in rows
    ]


def get_stats(db: Database) -> dict:
    patch_count = db.execute("SELECT COUNT(*) FROM patches").fetchone()[0]
    product_count = db.execute("SELECT COUNT(*) FROM products").fetchone()[0]
    cve_count = db.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    file_count = db.execute("SELECT COUNT(*) FROM downloaded_files").fetchone()[0]
    
    latest_row = db.execute(
        "SELECT release_date FROM patches ORDER BY release_date DESC LIMIT 1"
    ).fetchone()
    latest_date = latest_row[0] if latest_row else None
    
    return {
        "patches": patch_count,
        "products": product_count,
        "cves": cve_count,
        "downloaded_files": file_count,
        "latest_patch_date": latest_date,
    }
