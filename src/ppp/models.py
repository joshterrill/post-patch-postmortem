"""Data models for the supported list/diff workflows."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class Architecture(str, Enum):
    X86 = "x86"
    X64 = "x64"
    ARM64 = "arm64"


class DownloadedFile(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    kb_number: str
    filename: str
    file_path: str
    file_type: str
    architecture: Optional[Architecture] = None
    version: Optional[str] = None
    sha256: Optional[str] = None
    downloaded_at: datetime = Field(default_factory=datetime.now)


class CatalogEntry(BaseModel):
    update_id: str
    kb_number: str
    title: str
    products: str
    classification: str
    size: Optional[str] = None
    download_url: Optional[str] = None


class WinBIndexUpdate(BaseModel):
    kb_number: str
    windows_version: Optional[str] = None
    release_date: Optional[datetime] = None
    release_version: Optional[str] = None
    update_url: Optional[str] = None
    heading: Optional[str] = None


class WinBIndexFile(BaseModel):
    filename: str
    version: str
    architecture: Architecture
    sha256: str
    download_url: str
    download_urls: list[str] = Field(default_factory=list)
    release_date: Optional[datetime] = None
    timestamp: Optional[datetime] = None
    size: Optional[int] = None
    updates: list[WinBIndexUpdate] = Field(default_factory=list)
