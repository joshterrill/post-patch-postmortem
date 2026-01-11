"""Tests for patch_tuesday.models module."""

from datetime import datetime

import pytest
from pydantic import ValidationError

from patch_tuesday.models import (
    Architecture,
    CatalogEntry,
    CVE,
    DownloadedFile,
    Patch,
    PatchCVE,
    PatchProduct,
    Product,
    Severity,
    WinBIndexFile,
)


class TestSeverityEnum:
    """Tests for Severity enum."""
    
    def test_severity_values(self):
        """Test all severity values exist."""
        assert Severity.CRITICAL == "Critical"
        assert Severity.IMPORTANT == "Important"
        assert Severity.MODERATE == "Moderate"
        assert Severity.LOW == "Low"
        assert Severity.UNKNOWN == "Unknown"
    
    def test_severity_is_string(self):
        """Test that severity values are strings."""
        assert isinstance(Severity.CRITICAL.value, str)


class TestArchitectureEnum:
    """Tests for Architecture enum."""
    
    def test_architecture_values(self):
        """Test all architecture values exist."""
        assert Architecture.X86 == "x86"
        assert Architecture.X64 == "x64"
        assert Architecture.ARM64 == "arm64"


class TestProductModel:
    """Tests for Product model."""
    
    def test_product_creation(self, sample_product: Product):
        """Test creating a product with all fields."""
        assert sample_product.product_id == "11926"
        assert sample_product.name == "Windows 11 Version 23H2 for x64-based Systems"
        assert sample_product.version == "23H2"
        assert sample_product.id is None
    
    def test_product_with_id(self):
        """Test creating a product with ID."""
        product = Product(
            id=1,
            product_id="11926",
            name="Windows 11",
        )
        assert product.id == 1
    
    def test_product_minimal(self):
        """Test creating a product with minimal fields."""
        product = Product(
            product_id="12345",
            name="Windows 10",
        )
        assert product.version is None
        assert product.id is None
    
    def test_product_from_attributes(self):
        """Test that from_attributes config works."""
        # This tests the Config.from_attributes setting
        product = Product(product_id="123", name="Test")
        assert product.model_config.get("from_attributes") is True


class TestCVEModel:
    """Tests for CVE model."""
    
    def test_cve_creation(self, sample_cve: CVE):
        """Test creating a CVE with all fields."""
        assert sample_cve.cve_id == "CVE-2024-12345"
        assert sample_cve.title == "Windows Kernel Elevation of Privilege Vulnerability"
        assert sample_cve.severity == Severity.CRITICAL
        assert sample_cve.description is not None
        assert sample_cve.impact == "Elevation of Privilege"
    
    def test_cve_minimal(self):
        """Test creating a CVE with minimal fields."""
        cve = CVE(
            cve_id="CVE-2024-99999",
            title="Test Vulnerability",
        )
        assert cve.severity == Severity.UNKNOWN
        assert cve.description is None
        assert cve.impact is None
    
    def test_cve_with_id(self):
        """Test creating a CVE with database ID."""
        cve = CVE(
            id=42,
            cve_id="CVE-2024-99999",
            title="Test",
        )
        assert cve.id == 42


class TestPatchModel:
    """Tests for Patch model."""
    
    def test_patch_creation(self, sample_patch: Patch):
        """Test creating a patch with all fields."""
        assert sample_patch.kb_number == "KB5034441"
        assert sample_patch.title == "2024-01 Cumulative Update for Windows 11"
        assert sample_patch.release_date == datetime(2024, 1, 9, 10, 0, 0)
        assert sample_patch.severity == Severity.CRITICAL
        assert sample_patch.products == []
        assert sample_patch.cves == []
    
    def test_patch_with_relationships(self, sample_product: Product, sample_cve: CVE):
        """Test patch with related products and CVEs."""
        patch = Patch(
            kb_number="KB5034441",
            title="Test Patch",
            release_date=datetime.now(),
            products=[sample_product],
            cves=[sample_cve],
        )
        assert len(patch.products) == 1
        assert len(patch.cves) == 1
        assert patch.products[0].product_id == "11926"
        assert patch.cves[0].cve_id == "CVE-2024-12345"
    
    def test_patch_minimal(self):
        """Test creating a patch with minimal fields."""
        patch = Patch(
            kb_number="KB1234567",
            title="Test",
            release_date=datetime(2024, 1, 1),
        )
        assert patch.severity == Severity.UNKNOWN
        assert patch.description is None


class TestPatchProductModel:
    """Tests for PatchProduct model."""
    
    def test_patch_product_creation(self):
        """Test creating a patch-product relationship."""
        rel = PatchProduct(patch_id=1, product_id=2)
        assert rel.patch_id == 1
        assert rel.product_id == 2


class TestPatchCVEModel:
    """Tests for PatchCVE model."""
    
    def test_patch_cve_creation(self):
        """Test creating a patch-CVE relationship."""
        rel = PatchCVE(patch_id=1, cve_id=3)
        assert rel.patch_id == 1
        assert rel.cve_id == 3


class TestDownloadedFileModel:
    """Tests for DownloadedFile model."""
    
    def test_downloaded_file_creation(self, sample_downloaded_file: DownloadedFile):
        """Test creating a downloaded file record."""
        assert sample_downloaded_file.kb_number == "KB5034441"
        assert sample_downloaded_file.filename == "ntdll.dll"
        assert sample_downloaded_file.file_type == "extracted"
        assert sample_downloaded_file.architecture == Architecture.X64
        assert sample_downloaded_file.version == "10.0.22621.3007"
    
    def test_downloaded_file_minimal(self):
        """Test creating a downloaded file with minimal fields."""
        f = DownloadedFile(
            kb_number="KB1234567",
            filename="test.dll",
            file_path="/path/to/file",
            file_type="package",
        )
        assert f.architecture is None
        assert f.version is None
        assert f.sha256 is None
        # downloaded_at should have a default
        assert f.downloaded_at is not None
    
    def test_downloaded_file_types(self):
        """Test different file types."""
        for file_type in ["package", "extracted", "baseline"]:
            f = DownloadedFile(
                kb_number="KB123",
                filename="test.dll",
                file_path="/path",
                file_type=file_type,
            )
            assert f.file_type == file_type


class TestCatalogEntryModel:
    """Tests for CatalogEntry model."""
    
    def test_catalog_entry_creation(self, sample_catalog_entry: CatalogEntry):
        """Test creating a catalog entry."""
        assert sample_catalog_entry.update_id == "12345678-1234-1234-1234-123456789abc"
        assert sample_catalog_entry.kb_number == "KB5034441"
        assert sample_catalog_entry.classification == "Security Updates"
        assert sample_catalog_entry.download_url is not None
    
    def test_catalog_entry_minimal(self):
        """Test creating a catalog entry with minimal fields."""
        entry = CatalogEntry(
            update_id="abc123",
            kb_number="KB123",
            title="Test Update",
            products="Windows 11",
            classification="Updates",
        )
        assert entry.size is None
        assert entry.download_url is None


class TestWinBIndexFileModel:
    """Tests for WinBIndexFile model."""
    
    def test_winbindex_file_creation(self, sample_winbindex_file: WinBIndexFile):
        """Test creating a WinBIndex file entry."""
        assert sample_winbindex_file.filename == "ntdll.dll"
        assert sample_winbindex_file.version == "10.0.22621.3000"
        assert sample_winbindex_file.architecture == Architecture.X64
        assert sample_winbindex_file.sha256 == "def456abc123"
        assert sample_winbindex_file.download_url is not None
    
    def test_winbindex_file_no_timestamp(self):
        """Test creating a WinBIndex file without timestamp."""
        f = WinBIndexFile(
            filename="kernel32.dll",
            version="10.0.22621.1",
            architecture=Architecture.X64,
            sha256="abc123",
            download_url="https://example.com/file",
        )
        assert f.timestamp is None
