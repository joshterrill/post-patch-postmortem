"""Data models."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    IMPORTANT = "Important"
    MODERATE = "Moderate"
    LOW = "Low"
    UNKNOWN = "Unknown"


class Architecture(str, Enum):
    X86 = "x86"
    X64 = "x64"
    ARM64 = "arm64"


class Product(BaseModel):
    id: Optional[int] = None
    product_id: str
    name: str
    version: Optional[str] = None
    
    class Config:
        from_attributes = True


class CVE(BaseModel):
    id: Optional[int] = None
    cve_id: str
    title: str
    severity: Severity = Severity.UNKNOWN
    description: Optional[str] = None
    impact: Optional[str] = None
    
    class Config:
        from_attributes = True


class Patch(BaseModel):
    id: Optional[int] = None
    kb_number: str
    title: str
    release_date: datetime
    description: Optional[str] = None
    severity: Severity = Severity.UNKNOWN
    products: list[Product] = Field(default_factory=list)
    cves: list[CVE] = Field(default_factory=list)
    
    class Config:
        from_attributes = True


class PatchProduct(BaseModel):
    patch_id: int
    product_id: int


class PatchCVE(BaseModel):
    patch_id: int
    cve_id: int


class DownloadedFile(BaseModel):
    id: Optional[int] = None
    kb_number: str
    filename: str
    file_path: str
    file_type: str  # package, extracted, baseline
    architecture: Optional[Architecture] = None
    version: Optional[str] = None
    sha256: Optional[str] = None
    downloaded_at: datetime = Field(default_factory=datetime.now)
    
    class Config:
        from_attributes = True


class CatalogEntry(BaseModel):
    update_id: str
    kb_number: str
    title: str
    products: str
    classification: str
    size: Optional[str] = None
    download_url: Optional[str] = None


class WinBIndexFile(BaseModel):
    filename: str
    version: str
    architecture: Architecture
    sha256: str
    download_url: str
    timestamp: Optional[datetime] = None
