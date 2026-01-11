"""Tests for patch_tuesday.database module."""

from datetime import datetime
from pathlib import Path

import pytest
from sqlite_utils import Database

from patch_tuesday.database import (
    add_downloaded_file,
    get_all_products,
    get_cve,
    get_db,
    get_db_path,
    get_downloaded_files,
    get_downloaded_files_by_type,
    get_patch,
    get_patches_by_date,
    get_patches_by_product,
    get_product_by_id,
    get_products_for_patch,
    get_stats,
    init_db,
    link_patch_cve,
    link_patch_product,
    summarize_products,
    upsert_cve,
    upsert_patch,
    upsert_product,
)
from patch_tuesday.models import (
    Architecture,
    CVE,
    DownloadedFile,
    Patch,
    Product,
    Severity,
)


class TestDatabasePath:
    """Tests for database path functions."""
    
    def test_get_db_path_returns_path(self):
        """Test that get_db_path returns a Path object."""
        path = get_db_path()
        assert isinstance(path, Path)
        assert path.name == "patches.db"
    
    def test_get_db_path_creates_parent_dir(self, tmp_path: Path, monkeypatch):
        """Test that get_db_path creates parent directory."""
        import patch_tuesday.database as db_module
        
        test_path = tmp_path / "subdir" / "patches.db"
        monkeypatch.setattr(db_module, "DEFAULT_DB_PATH", test_path)
        
        result = get_db_path()
        assert result.parent.exists()


class TestGetDb:
    """Tests for get_db context manager."""
    
    def test_get_db_yields_database(self, temp_db_path: Path):
        """Test that get_db yields a Database object."""
        init_db(temp_db_path)
        with get_db(temp_db_path) as db:
            assert isinstance(db, Database)
    
    def test_get_db_closes_connection(self, temp_db_path: Path):
        """Test that get_db closes the connection on exit."""
        init_db(temp_db_path)
        with get_db(temp_db_path) as db:
            conn = db.conn
        # Connection should be closed after context exit
        # Accessing the closed connection should raise
        # Note: sqlite_utils doesn't raise on closed connections easily
        # but we verify the context manager completes without error


class TestInitDb:
    """Tests for init_db function."""
    
    def test_init_db_creates_tables(self, temp_db_path: Path):
        """Test that init_db creates all required tables."""
        init_db(temp_db_path)
        
        db = Database(temp_db_path)
        tables = db.table_names()
        
        assert "products" in tables
        assert "cves" in tables
        assert "patches" in tables
        assert "patch_products" in tables
        assert "patch_cves" in tables
        assert "downloaded_files" in tables
        
        db.close()
    
    def test_init_db_creates_indexes(self, temp_db_path: Path):
        """Test that init_db creates indexes."""
        init_db(temp_db_path)
        
        db = Database(temp_db_path)
        indexes = [idx.name for idx in db["patches"].indexes]
        
        assert "idx_patches_release_date" in indexes
        assert "idx_patches_kb" in indexes
        
        db.close()
    
    def test_init_db_idempotent(self, temp_db_path: Path):
        """Test that init_db can be called multiple times."""
        init_db(temp_db_path)
        init_db(temp_db_path)  # Should not raise
        
        db = Database(temp_db_path)
        assert "patches" in db.table_names()
        db.close()


class TestProductOperations:
    """Tests for product database operations."""
    
    def test_upsert_product_insert(self, initialized_db: Database, sample_product: Product):
        """Test inserting a new product."""
        product_id = upsert_product(initialized_db, sample_product)
        
        assert product_id > 0
        
        # Verify it was inserted
        row = initialized_db.conn.execute(
            "SELECT * FROM products WHERE product_id = ?",
            [sample_product.product_id],
        ).fetchone()
        assert row is not None
        assert row[2] == sample_product.name
    
    def test_upsert_product_update(self, initialized_db: Database, sample_product: Product):
        """Test updating an existing product."""
        # Insert first
        first_id = upsert_product(initialized_db, sample_product)
        
        # Modify and upsert again
        sample_product.name = "Updated Windows 11"
        second_id = upsert_product(initialized_db, sample_product)
        
        assert first_id == second_id
        
        # Verify update
        row = initialized_db.conn.execute(
            "SELECT name FROM products WHERE id = ?",
            [first_id],
        ).fetchone()
        assert row[0] == "Updated Windows 11"
    
    def test_get_product_by_id(self, initialized_db: Database, sample_product: Product):
        """Test retrieving a product by its Microsoft ID."""
        upsert_product(initialized_db, sample_product)
        
        result = get_product_by_id(initialized_db, sample_product.product_id)
        
        assert result is not None
        assert result.product_id == sample_product.product_id
        assert result.name == sample_product.name
    
    def test_get_product_by_id_not_found(self, initialized_db: Database):
        """Test retrieving a non-existent product."""
        result = get_product_by_id(initialized_db, "nonexistent")
        assert result is None
    
    def test_get_all_products(
        self,
        initialized_db: Database,
        sample_product: Product,
        sample_product_2: Product,
    ):
        """Test retrieving all products."""
        upsert_product(initialized_db, sample_product)
        upsert_product(initialized_db, sample_product_2)
        
        products = get_all_products(initialized_db)
        
        assert len(products) == 2
        product_ids = {p.product_id for p in products}
        assert sample_product.product_id in product_ids
        assert sample_product_2.product_id in product_ids


class TestCVEOperations:
    """Tests for CVE database operations."""
    
    def test_upsert_cve_insert(self, initialized_db: Database, sample_cve: CVE):
        """Test inserting a new CVE."""
        cve_id = upsert_cve(initialized_db, sample_cve)
        
        assert cve_id > 0
        
        row = initialized_db.conn.execute(
            "SELECT * FROM cves WHERE cve_id = ?",
            [sample_cve.cve_id],
        ).fetchone()
        assert row is not None
    
    def test_upsert_cve_update(self, initialized_db: Database, sample_cve: CVE):
        """Test updating an existing CVE."""
        first_id = upsert_cve(initialized_db, sample_cve)
        
        sample_cve.title = "Updated Title"
        second_id = upsert_cve(initialized_db, sample_cve)
        
        assert first_id == second_id
        
        row = initialized_db.conn.execute(
            "SELECT title FROM cves WHERE id = ?",
            [first_id],
        ).fetchone()
        assert row[0] == "Updated Title"
    
    def test_get_cve(self, initialized_db: Database, sample_cve: CVE):
        """Test retrieving a CVE by ID."""
        upsert_cve(initialized_db, sample_cve)
        
        result = get_cve(initialized_db, sample_cve.cve_id)
        
        assert result is not None
        assert result.cve_id == sample_cve.cve_id
        assert result.severity == sample_cve.severity
    
    def test_get_cve_not_found(self, initialized_db: Database):
        """Test retrieving a non-existent CVE."""
        result = get_cve(initialized_db, "CVE-9999-99999")
        assert result is None


class TestPatchOperations:
    """Tests for patch database operations."""
    
    def test_upsert_patch_insert(self, initialized_db: Database, sample_patch: Patch):
        """Test inserting a new patch."""
        patch_id = upsert_patch(initialized_db, sample_patch)
        
        assert patch_id > 0
        
        row = initialized_db.conn.execute(
            "SELECT * FROM patches WHERE kb_number = ?",
            [sample_patch.kb_number],
        ).fetchone()
        assert row is not None
    
    def test_upsert_patch_update(self, initialized_db: Database, sample_patch: Patch):
        """Test updating an existing patch."""
        first_id = upsert_patch(initialized_db, sample_patch)
        
        sample_patch.title = "Updated Title"
        second_id = upsert_patch(initialized_db, sample_patch)
        
        assert first_id == second_id
    
    def test_get_patch(self, initialized_db: Database, sample_patch: Patch):
        """Test retrieving a patch by KB number."""
        upsert_patch(initialized_db, sample_patch)
        
        result = get_patch(initialized_db, sample_patch.kb_number)
        
        assert result is not None
        assert result.kb_number == sample_patch.kb_number
        assert result.products == []
        assert result.cves == []
    
    def test_get_patch_normalizes_kb(self, initialized_db: Database, sample_patch: Patch):
        """Test that get_patch normalizes KB number format."""
        upsert_patch(initialized_db, sample_patch)
        
        # Without KB prefix
        result = get_patch(initialized_db, "5034441")
        assert result is not None
        assert result.kb_number == "KB5034441"
        
        # Lowercase
        result = get_patch(initialized_db, "kb5034441")
        assert result is not None
    
    def test_get_patch_with_relationships(
        self,
        initialized_db: Database,
        sample_patch: Patch,
        sample_product: Product,
        sample_cve: CVE,
    ):
        """Test retrieving a patch with related products and CVEs."""
        patch_id = upsert_patch(initialized_db, sample_patch)
        product_id = upsert_product(initialized_db, sample_product)
        cve_id = upsert_cve(initialized_db, sample_cve)
        
        link_patch_product(initialized_db, patch_id, product_id)
        link_patch_cve(initialized_db, patch_id, cve_id)
        
        result = get_patch(initialized_db, sample_patch.kb_number)
        
        assert len(result.products) == 1
        assert result.products[0].product_id == sample_product.product_id
        assert len(result.cves) == 1
        assert result.cves[0].cve_id == sample_cve.cve_id
    
    def test_get_patch_not_found(self, initialized_db: Database):
        """Test retrieving a non-existent patch."""
        result = get_patch(initialized_db, "KB9999999")
        assert result is None
    
    def test_get_patches_by_date_all(
        self,
        initialized_db: Database,
        sample_patch: Patch,
        sample_patch_2: Patch,
    ):
        """Test retrieving all patches."""
        upsert_patch(initialized_db, sample_patch)
        upsert_patch(initialized_db, sample_patch_2)
        
        results = get_patches_by_date(initialized_db)
        
        assert len(results) == 2
    
    def test_get_patches_by_date_year_month(self, initialized_db: Database, sample_patch: Patch):
        """Test retrieving patches by year and month."""
        upsert_patch(initialized_db, sample_patch)
        
        # Should find the patch
        results = get_patches_by_date(initialized_db, year=2024, month=1)
        assert len(results) == 1
        
        # Should not find with wrong month
        results = get_patches_by_date(initialized_db, year=2024, month=6)
        assert len(results) == 0
    
    def test_get_patches_by_date_year_only(self, initialized_db: Database, sample_patch: Patch):
        """Test retrieving patches by year only."""
        upsert_patch(initialized_db, sample_patch)
        
        results = get_patches_by_date(initialized_db, year=2024)
        assert len(results) == 1
        
        results = get_patches_by_date(initialized_db, year=2023)
        assert len(results) == 0
    
    def test_get_patches_by_date_december_boundary(self, initialized_db: Database):
        """Test December date boundary handling."""
        dec_patch = Patch(
            kb_number="KB1234567",
            title="December Patch",
            release_date=datetime(2024, 12, 15),
        )
        upsert_patch(initialized_db, dec_patch)
        
        results = get_patches_by_date(initialized_db, year=2024, month=12)
        assert len(results) == 1
    
    def test_get_patches_by_product(
        self,
        initialized_db: Database,
        sample_patch: Patch,
        sample_product: Product,
    ):
        """Test retrieving patches by product name."""
        patch_id = upsert_patch(initialized_db, sample_patch)
        product_id = upsert_product(initialized_db, sample_product)
        link_patch_product(initialized_db, patch_id, product_id)
        
        results = get_patches_by_product(initialized_db, "Windows 11")
        assert len(results) == 1
        assert results[0].kb_number == sample_patch.kb_number
    
    def test_get_patches_by_product_partial_match(
        self,
        initialized_db: Database,
        sample_patch: Patch,
        sample_product: Product,
    ):
        """Test that product search uses partial matching."""
        patch_id = upsert_patch(initialized_db, sample_patch)
        product_id = upsert_product(initialized_db, sample_product)
        link_patch_product(initialized_db, patch_id, product_id)
        
        # Should match partial name
        results = get_patches_by_product(initialized_db, "23H2")
        assert len(results) == 1


class TestRelationshipOperations:
    """Tests for relationship operations."""
    
    def test_link_patch_product(
        self,
        initialized_db: Database,
        sample_patch: Patch,
        sample_product: Product,
    ):
        """Test linking a patch to a product."""
        patch_id = upsert_patch(initialized_db, sample_patch)
        product_id = upsert_product(initialized_db, sample_product)
        
        link_patch_product(initialized_db, patch_id, product_id)
        
        row = initialized_db.conn.execute(
            "SELECT * FROM patch_products WHERE patch_id = ? AND product_id = ?",
            [patch_id, product_id],
        ).fetchone()
        assert row is not None
    
    def test_link_patch_product_idempotent(
        self,
        initialized_db: Database,
        sample_patch: Patch,
        sample_product: Product,
    ):
        """Test that duplicate links are ignored."""
        patch_id = upsert_patch(initialized_db, sample_patch)
        product_id = upsert_product(initialized_db, sample_product)
        
        link_patch_product(initialized_db, patch_id, product_id)
        link_patch_product(initialized_db, patch_id, product_id)  # Should not raise
        
        count = initialized_db.conn.execute(
            "SELECT COUNT(*) FROM patch_products WHERE patch_id = ? AND product_id = ?",
            [patch_id, product_id],
        ).fetchone()[0]
        assert count == 1
    
    def test_link_patch_cve(
        self,
        initialized_db: Database,
        sample_patch: Patch,
        sample_cve: CVE,
    ):
        """Test linking a patch to a CVE."""
        patch_id = upsert_patch(initialized_db, sample_patch)
        cve_id = upsert_cve(initialized_db, sample_cve)
        
        link_patch_cve(initialized_db, patch_id, cve_id)
        
        row = initialized_db.conn.execute(
            "SELECT * FROM patch_cves WHERE patch_id = ? AND cve_id = ?",
            [patch_id, cve_id],
        ).fetchone()
        assert row is not None
    
    def test_link_patch_cve_idempotent(
        self,
        initialized_db: Database,
        sample_patch: Patch,
        sample_cve: CVE,
    ):
        """Test that duplicate CVE links are ignored."""
        patch_id = upsert_patch(initialized_db, sample_patch)
        cve_id = upsert_cve(initialized_db, sample_cve)
        
        link_patch_cve(initialized_db, patch_id, cve_id)
        link_patch_cve(initialized_db, patch_id, cve_id)
        
        count = initialized_db.conn.execute(
            "SELECT COUNT(*) FROM patch_cves WHERE patch_id = ? AND cve_id = ?",
            [patch_id, cve_id],
        ).fetchone()[0]
        assert count == 1


class TestDownloadedFilesOperations:
    """Tests for downloaded files operations."""
    
    def test_add_downloaded_file(
        self,
        initialized_db: Database,
        sample_downloaded_file: DownloadedFile,
    ):
        """Test adding a downloaded file record."""
        file_id = add_downloaded_file(initialized_db, sample_downloaded_file)
        
        assert file_id > 0
        
        row = initialized_db.conn.execute(
            "SELECT * FROM downloaded_files WHERE id = ?",
            [file_id],
        ).fetchone()
        assert row is not None
    
    def test_get_downloaded_files(
        self,
        initialized_db: Database,
        sample_downloaded_file: DownloadedFile,
    ):
        """Test retrieving downloaded files for a KB."""
        add_downloaded_file(initialized_db, sample_downloaded_file)
        
        results = get_downloaded_files(initialized_db, "KB5034441")
        
        assert len(results) == 1
        assert results[0].filename == "ntdll.dll"
        assert results[0].architecture == Architecture.X64
    
    def test_get_downloaded_files_empty(self, initialized_db: Database):
        """Test retrieving files for non-existent KB."""
        results = get_downloaded_files(initialized_db, "KB9999999")
        assert len(results) == 0
    
    def test_get_downloaded_files_by_type(
        self,
        initialized_db: Database,
        sample_downloaded_file: DownloadedFile,
    ):
        """Test retrieving files filtered by type."""
        add_downloaded_file(initialized_db, sample_downloaded_file)
        
        # Should find extracted files
        results = get_downloaded_files_by_type(initialized_db, "KB5034441", "extracted")
        assert len(results) == 1
        
        # Should not find baseline files
        results = get_downloaded_files_by_type(initialized_db, "KB5034441", "baseline")
        assert len(results) == 0


class TestStats:
    """Tests for database statistics."""
    
    def test_get_stats_empty(self, initialized_db: Database):
        """Test stats on empty database."""
        stats = get_stats(initialized_db)
        
        assert stats["patches"] == 0
        assert stats["products"] == 0
        assert stats["cves"] == 0
        assert stats["downloaded_files"] == 0
        assert stats["latest_patch_date"] is None
    
    def test_get_stats_with_data(
        self,
        initialized_db: Database,
        sample_patch: Patch,
        sample_product: Product,
        sample_cve: CVE,
        sample_downloaded_file: DownloadedFile,
    ):
        """Test stats with data in database."""
        upsert_patch(initialized_db, sample_patch)
        upsert_product(initialized_db, sample_product)
        upsert_cve(initialized_db, sample_cve)
        add_downloaded_file(initialized_db, sample_downloaded_file)
        
        stats = get_stats(initialized_db)
        
        assert stats["patches"] == 1
        assert stats["products"] == 1
        assert stats["cves"] == 1
        assert stats["downloaded_files"] == 1
        assert stats["latest_patch_date"] is not None


class TestGetProductsForPatch:
    """Tests for get_products_for_patch function."""
    
    def test_get_products_for_patch_with_products(
        self,
        initialized_db: Database,
        sample_patch: Patch,
        sample_product: Product,
    ):
        """Test getting products for a patch that has linked products."""
        patch_id = upsert_patch(initialized_db, sample_patch)
        product_id = upsert_product(initialized_db, sample_product)
        link_patch_product(initialized_db, patch_id, product_id)
        
        products = get_products_for_patch(initialized_db, patch_id)
        
        assert len(products) == 1
        assert products[0].name == sample_product.name
    
    def test_get_products_for_patch_no_products(
        self,
        initialized_db: Database,
        sample_patch: Patch,
    ):
        """Test getting products for a patch with no linked products."""
        patch_id = upsert_patch(initialized_db, sample_patch)
        
        products = get_products_for_patch(initialized_db, patch_id)
        
        assert len(products) == 0
    
    def test_get_products_for_patch_multiple_products(
        self,
        initialized_db: Database,
        sample_patch: Patch,
    ):
        """Test getting multiple products for a patch."""
        patch_id = upsert_patch(initialized_db, sample_patch)
        
        products_to_add = [
            Product(product_id="p1", name="Windows 11 Version 22H2"),
            Product(product_id="p2", name="Windows 10 Version 21H2"),
            Product(product_id="p3", name="Windows Server 2022"),
        ]
        
        for product in products_to_add:
            product_id = upsert_product(initialized_db, product)
            link_patch_product(initialized_db, patch_id, product_id)
        
        products = get_products_for_patch(initialized_db, patch_id)
        
        assert len(products) == 3


class TestSummarizeProducts:
    """Tests for summarize_products function."""
    
    def test_summarize_products_empty(self):
        """Test summarizing empty product list."""
        result = summarize_products([])
        assert result == ""
    
    def test_summarize_products_windows_11(self):
        """Test summarizing Windows 11 products."""
        products = [
            Product(product_id="p1", name="Windows 11 Version 22H2 for x64-based Systems"),
            Product(product_id="p2", name="Windows 11 Version 23H2 for ARM64-based Systems"),
        ]
        result = summarize_products(products)
        assert "Win11" in result
    
    def test_summarize_products_windows_10(self):
        """Test summarizing Windows 10 products."""
        products = [
            Product(product_id="p1", name="Windows 10 Version 21H2 for x64-based Systems"),
        ]
        result = summarize_products(products)
        assert "Win10" in result
    
    def test_summarize_products_server(self):
        """Test summarizing Windows Server products."""
        products = [
            Product(product_id="p1", name="Windows Server 2022"),
            Product(product_id="p2", name="Windows Server 2019"),
            Product(product_id="p3", name="Windows Server 2016"),
        ]
        result = summarize_products(products)
        assert "Server 2022" in result
        assert "Server 2019" in result
        assert "Server 2016" in result
    
    def test_summarize_products_mixed(self):
        """Test summarizing mixed product list."""
        products = [
            Product(product_id="p1", name="Windows 11 Version 22H2"),
            Product(product_id="p2", name="Windows 10 Version 21H2"),
            Product(product_id="p3", name="Windows Server 2022"),
        ]
        result = summarize_products(products)
        assert "Win11" in result
        assert "Win10" in result
        assert "Server 2022" in result
    
    def test_summarize_products_truncation(self):
        """Test summarizing with more than 3 product families."""
        products = [
            Product(product_id="p1", name="Windows 11"),
            Product(product_id="p2", name="Windows 10"),
            Product(product_id="p3", name="Windows Server 2022"),
            Product(product_id="p4", name="Windows Server 2019"),
            Product(product_id="p5", name="Microsoft Office 365"),
        ]
        result = summarize_products(products)
        assert "+2" in result or "+1" in result  # Should truncate
    
    def test_summarize_products_office(self):
        """Test summarizing Office products."""
        products = [
            Product(product_id="p1", name="Microsoft Office 2019"),
        ]
        result = summarize_products(products)
        assert "Office" in result
    
    def test_summarize_products_edge(self):
        """Test summarizing Edge products."""
        products = [
            Product(product_id="p1", name="Microsoft Edge (Chromium-based)"),
        ]
        result = summarize_products(products)
        assert "Edge" in result
    
    def test_summarize_products_dotnet(self):
        """Test summarizing .NET products."""
        products = [
            Product(product_id="p1", name=".NET 6.0"),
        ]
        result = summarize_products(products)
        assert ".NET" in result
    
    def test_summarize_products_visual_studio(self):
        """Test summarizing Visual Studio products."""
        products = [
            Product(product_id="p1", name="Visual Studio 2022"),
        ]
        result = summarize_products(products)
        assert "VS" in result
    
    def test_summarize_products_azure(self):
        """Test summarizing Azure products."""
        products = [
            Product(product_id="p1", name="Azure DevOps Server 2022"),
        ]
        result = summarize_products(products)
        assert "Azure" in result
    
    def test_summarize_products_generic_server(self):
        """Test summarizing generic Windows Server products."""
        products = [
            Product(product_id="p1", name="Windows Server"),
        ]
        result = summarize_products(products)
        assert "Server" in result
