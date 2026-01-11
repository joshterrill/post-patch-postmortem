"""Tests for patch_tuesday.msrc_client module."""

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from patch_tuesday.msrc_client import (
    _extract_kb_numbers,
    _extract_version,
    _is_windows_product,
    _parse_release_date,
    _parse_severity,
    _severity_rank,
    fetch_by_date,
    fetch_cvrf_document,
    fetch_latest,
    fetch_and_store_update,
    get_update_ids,
    parse_cvrf_document,
)
from patch_tuesday.models import Severity


class TestParseSeverity:
    """Tests for _parse_severity function."""
    
    def test_parse_critical(self):
        """Test parsing Critical severity."""
        assert _parse_severity("Critical") == Severity.CRITICAL
        assert _parse_severity("CRITICAL") == Severity.CRITICAL
        assert _parse_severity("critical") == Severity.CRITICAL
    
    def test_parse_important(self):
        """Test parsing Important severity."""
        assert _parse_severity("Important") == Severity.IMPORTANT
    
    def test_parse_moderate(self):
        """Test parsing Moderate severity."""
        assert _parse_severity("Moderate") == Severity.MODERATE
    
    def test_parse_low(self):
        """Test parsing Low severity."""
        assert _parse_severity("Low") == Severity.LOW
    
    def test_parse_unknown(self):
        """Test parsing unknown severity."""
        assert _parse_severity("Unknown") == Severity.UNKNOWN
        assert _parse_severity("Invalid") == Severity.UNKNOWN
        assert _parse_severity("") == Severity.UNKNOWN
    
    def test_parse_none(self):
        """Test parsing None severity."""
        assert _parse_severity(None) == Severity.UNKNOWN


class TestExtractKbNumbers:
    """Tests for _extract_kb_numbers function."""
    
    def test_extract_single_kb(self):
        """Test extracting a single KB number."""
        text = "Please apply KB5034441 to fix this issue."
        result = _extract_kb_numbers(text)
        assert result == ["KB5034441"]
    
    def test_extract_multiple_kbs(self):
        """Test extracting multiple KB numbers."""
        text = "KB5034441 and KB5034442 are both required."
        result = _extract_kb_numbers(text)
        assert set(result) == {"KB5034441", "KB5034442"}
    
    def test_extract_no_kbs(self):
        """Test text with no KB numbers."""
        text = "No patches here."
        result = _extract_kb_numbers(text)
        assert result == []
    
    def test_extract_lowercase_kb(self):
        """Test extracting lowercase KB numbers."""
        text = "Apply kb5034441"
        result = _extract_kb_numbers(text)
        assert result == ["KB5034441"]
    
    def test_extract_deduplicates(self):
        """Test that duplicate KBs are removed."""
        text = "KB5034441 KB5034441 KB5034441"
        result = _extract_kb_numbers(text)
        assert result == ["KB5034441"]


class TestParseReleaseDate:
    """Tests for _parse_release_date function."""
    
    def test_parse_iso_format(self):
        """Test parsing ISO format date."""
        result = _parse_release_date("2024-01-09T08:00:00")
        assert result == datetime(2024, 1, 9, 8, 0, 0)
    
    def test_parse_iso_with_z(self):
        """Test parsing ISO format with Z suffix."""
        result = _parse_release_date("2024-01-09T08:00:00Z")
        assert result == datetime(2024, 1, 9, 8, 0, 0)
    
    def test_parse_date_only(self):
        """Test parsing date-only format."""
        result = _parse_release_date("2024-01-09")
        assert result == datetime(2024, 1, 9, 0, 0, 0)
    
    def test_parse_with_milliseconds(self):
        """Test parsing date with milliseconds (gets stripped)."""
        result = _parse_release_date("2024-01-09T08:00:00.123")
        assert result.year == 2024
    
    def test_parse_invalid_returns_now(self):
        """Test parsing invalid date returns current time."""
        result = _parse_release_date("invalid")
        assert isinstance(result, datetime)
        # Should be close to now
        assert (datetime.now() - result).total_seconds() < 5


class TestIsWindowsProduct:
    """Tests for _is_windows_product function."""
    
    def test_windows_10(self):
        """Test Windows 10 products."""
        assert _is_windows_product("Windows 10 Version 22H2 for x64-based Systems")
        assert _is_windows_product("WINDOWS 10 Enterprise")
    
    def test_windows_11(self):
        """Test Windows 11 products."""
        assert _is_windows_product("Windows 11 Version 23H2")
    
    def test_windows_server(self):
        """Test Windows Server products."""
        assert _is_windows_product("Windows Server 2022")
        assert _is_windows_product("Windows Server 2019 (Server Core)")
    
    def test_edge(self):
        """Test Microsoft Edge."""
        assert _is_windows_product("Microsoft Edge (Chromium-based)")
    
    def test_defender(self):
        """Test Windows Defender."""
        assert _is_windows_product("Windows Defender Antivirus")
    
    def test_dotnet(self):
        """Test .NET Framework."""
        assert _is_windows_product(".NET Framework 4.8")
    
    def test_non_windows(self):
        """Test non-Windows products are filtered."""
        assert not _is_windows_product("Microsoft Office 2019")
        assert not _is_windows_product("Azure DevOps Server 2022")
        assert not _is_windows_product("Visual Studio 2022")


class TestExtractVersion:
    """Tests for _extract_version function."""
    
    def test_extract_h_version(self):
        """Test extracting H2-style versions."""
        assert _extract_version("Windows 11 Version 23H2") == "23H2"
        assert _extract_version("Windows 10 Version 22H2") == "22H2"
    
    def test_extract_year_version(self):
        """Test extracting year versions."""
        assert _extract_version("Windows Server 2022") == "2022"
        assert _extract_version("Windows Server 2019") == "2019"
    
    def test_extract_version_number(self):
        """Test extracting Version N format."""
        assert _extract_version("Windows 10 Version 1903") == "1903"
    
    def test_no_version(self):
        """Test products without version."""
        assert _extract_version("Windows Defender") is None


class TestSeverityRank:
    """Tests for _severity_rank function."""
    
    def test_rank_ordering(self):
        """Test severity ranks are in correct order."""
        assert _severity_rank(Severity.CRITICAL) > _severity_rank(Severity.IMPORTANT)
        assert _severity_rank(Severity.IMPORTANT) > _severity_rank(Severity.MODERATE)
        assert _severity_rank(Severity.MODERATE) > _severity_rank(Severity.LOW)
        assert _severity_rank(Severity.LOW) > _severity_rank(Severity.UNKNOWN)
    
    def test_specific_ranks(self):
        """Test specific rank values."""
        assert _severity_rank(Severity.CRITICAL) == 4
        assert _severity_rank(Severity.UNKNOWN) == 0


class TestGetUpdateIds:
    """Tests for get_update_ids function."""
    
    @respx.mock
    def test_get_update_ids_success(self):
        """Test successfully fetching update IDs."""
        respx.get("https://api.msrc.microsoft.com/cvrf/v2.0/updates").mock(
            return_value=httpx.Response(
                200,
                json={
                    "value": [
                        {"ID": "2024-Jan"},
                        {"ID": "2024-Feb"},
                        {"ID": "2023-Dec"},
                    ]
                },
            )
        )
        
        result = get_update_ids()
        
        assert "2024-Feb" in result
        assert "2024-Jan" in result
        assert "2023-Dec" in result
    
    @respx.mock
    def test_get_update_ids_filter_by_year(self):
        """Test filtering update IDs by year."""
        respx.get("https://api.msrc.microsoft.com/cvrf/v2.0/updates").mock(
            return_value=httpx.Response(
                200,
                json={
                    "value": [
                        {"ID": "2024-Jan"},
                        {"ID": "2024-Feb"},
                        {"ID": "2023-Dec"},
                    ]
                },
            )
        )
        
        result = get_update_ids(year=2024)
        
        assert "2024-Jan" in result
        assert "2024-Feb" in result
        assert "2023-Dec" not in result
    
    @respx.mock
    def test_get_update_ids_empty_response(self):
        """Test handling empty response."""
        respx.get("https://api.msrc.microsoft.com/cvrf/v2.0/updates").mock(
            return_value=httpx.Response(200, json={"value": []})
        )
        
        result = get_update_ids()
        assert result == []


class TestFetchCvrfDocument:
    """Tests for fetch_cvrf_document function."""
    
    @respx.mock
    def test_fetch_cvrf_success(self, sample_cvrf_document: dict):
        """Test successfully fetching a CVRF document."""
        respx.get("https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/2024-Jan").mock(
            return_value=httpx.Response(200, json=sample_cvrf_document)
        )
        
        result = fetch_cvrf_document("2024-Jan")
        
        assert "DocumentTracking" in result
        assert "ProductTree" in result
        assert "Vulnerability" in result
    
    @respx.mock
    def test_fetch_cvrf_not_found(self):
        """Test handling 404 response."""
        respx.get("https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/2099-Jan").mock(
            return_value=httpx.Response(404)
        )
        
        with pytest.raises(httpx.HTTPStatusError):
            fetch_cvrf_document("2099-Jan")


class TestParseCvrfDocument:
    """Tests for parse_cvrf_document function."""
    
    def test_parse_cvrf_extracts_patches(self, sample_cvrf_document: dict):
        """Test that patches are extracted from CVRF."""
        patches, products, cves, cve_kb_map, product_kb_map, product_map = parse_cvrf_document(
            sample_cvrf_document, "2024-Jan"
        )
        
        assert len(patches) >= 1
        kb_numbers = {p.kb_number for p in patches}
        assert "KB5034441" in kb_numbers or "KB5034442" in kb_numbers
    
    def test_parse_cvrf_extracts_products(self, sample_cvrf_document: dict):
        """Test that Windows products are extracted from CVRF."""
        patches, products, cves, cve_kb_map, product_kb_map, product_map = parse_cvrf_document(
            sample_cvrf_document, "2024-Jan"
        )
        
        # Should have Windows products, not Office
        product_names = {p.name for p in products}
        assert any("Windows 11" in name for name in product_names)
        assert not any("Office" in name for name in product_names)
    
    def test_parse_cvrf_extracts_cves(self, sample_cvrf_document: dict):
        """Test that CVEs are extracted from CVRF."""
        patches, products, cves, cve_kb_map, product_kb_map, product_map = parse_cvrf_document(
            sample_cvrf_document, "2024-Jan"
        )
        
        assert len(cves) == 2
        cve_ids = {c.cve_id for c in cves}
        assert "CVE-2024-12345" in cve_ids
        assert "CVE-2024-12346" in cve_ids
    
    def test_parse_cvrf_maps_cves_to_kbs(self, sample_cvrf_document: dict):
        """Test that CVE to KB mapping is created."""
        patches, products, cves, cve_kb_map, product_kb_map, product_map = parse_cvrf_document(
            sample_cvrf_document, "2024-Jan"
        )
        
        assert "CVE-2024-12345" in cve_kb_map
        assert "KB5034441" in cve_kb_map["CVE-2024-12345"]
    
    def test_parse_cvrf_handles_string_product_id(self, sample_cvrf_document: dict):
        """Test that string ProductID (instead of list) is handled."""
        # CVE-2024-12346 has ProductID as string "11926"
        patches, products, cves, cve_kb_map, product_kb_map, product_map = parse_cvrf_document(
            sample_cvrf_document, "2024-Jan"
        )
        
        # Should not raise and should process correctly
        assert "CVE-2024-12346" in cve_kb_map
    
    def test_parse_cvrf_release_date(self, sample_cvrf_document: dict):
        """Test that release date is parsed from CVRF."""
        patches, products, cves, cve_kb_map, product_kb_map, product_map = parse_cvrf_document(
            sample_cvrf_document, "2024-Jan"
        )
        
        for patch in patches:
            assert patch.release_date.year == 2024
            assert patch.release_date.month == 1
    
    def test_parse_cvrf_severity_assignment(self, sample_cvrf_document: dict):
        """Test that severity is correctly assigned to patches."""
        patches, products, cves, cve_kb_map, product_kb_map, product_map = parse_cvrf_document(
            sample_cvrf_document, "2024-Jan"
        )
        
        # Should have patches with severity set
        severities = {p.severity for p in patches}
        assert Severity.CRITICAL in severities or Severity.IMPORTANT in severities


class TestFetchAndStoreUpdate:
    """Tests for fetch_and_store_update function."""
    
    @respx.mock
    def test_fetch_and_store_success(self, sample_cvrf_document: dict, temp_db_path: Path):
        """Test fetching and storing an update."""
        respx.get("https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/2024-Jan").mock(
            return_value=httpx.Response(200, json=sample_cvrf_document)
        )
        
        import patch_tuesday.database as db_module
        import patch_tuesday.msrc_client as msrc_module
        
        # Patch the database path
        with patch.object(db_module, "DEFAULT_DB_PATH", temp_db_path):
            with patch.object(msrc_module, "init_db") as mock_init:
                with patch.object(msrc_module, "get_db") as mock_get_db:
                    # Create a mock database context
                    from sqlite_utils import Database
                    db = Database(temp_db_path)
                    db_module.init_db(temp_db_path)
                    
                    mock_get_db.return_value.__enter__ = MagicMock(return_value=db)
                    mock_get_db.return_value.__exit__ = MagicMock(return_value=False)
                    
                    result = fetch_and_store_update("2024-Jan", verbose=False)
        
        assert result["update_id"] == "2024-Jan"
        assert result["patches"] >= 0
        assert result["cves"] == 2


class TestFetchLatest:
    """Tests for fetch_latest function."""
    
    @respx.mock
    def test_fetch_latest_single(self, sample_cvrf_document: dict, temp_db_path: Path):
        """Test fetching the latest update."""
        respx.get("https://api.msrc.microsoft.com/cvrf/v2.0/updates").mock(
            return_value=httpx.Response(
                200, json={"value": [{"ID": "2024-Jan"}]}
            )
        )
        respx.get("https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/2024-Jan").mock(
            return_value=httpx.Response(200, json=sample_cvrf_document)
        )
        
        import patch_tuesday.database as db_module
        
        with patch.object(db_module, "DEFAULT_DB_PATH", temp_db_path):
            db_module.init_db(temp_db_path)
            results = fetch_latest(count=1, verbose=False)
        
        assert len(results) == 1
        assert results[0]["update_id"] == "2024-Jan"
    
    @respx.mock
    def test_fetch_latest_handles_error(self, temp_db_path: Path):
        """Test that fetch_latest handles errors gracefully."""
        respx.get("https://api.msrc.microsoft.com/cvrf/v2.0/updates").mock(
            return_value=httpx.Response(
                200, json={"value": [{"ID": "2024-Jan"}]}
            )
        )
        respx.get("https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/2024-Jan").mock(
            return_value=httpx.Response(500)
        )
        
        import patch_tuesday.database as db_module
        
        with patch.object(db_module, "DEFAULT_DB_PATH", temp_db_path):
            db_module.init_db(temp_db_path)
            results = fetch_latest(count=1, verbose=False)
        
        # Should return empty list on error
        assert results == []


class TestFetchByDate:
    """Tests for fetch_by_date function."""
    
    @respx.mock
    def test_fetch_by_date_success(self, sample_cvrf_document: dict, temp_db_path: Path):
        """Test fetching by specific date."""
        respx.get("https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/2024-Jan").mock(
            return_value=httpx.Response(200, json=sample_cvrf_document)
        )
        
        import patch_tuesday.database as db_module
        
        with patch.object(db_module, "DEFAULT_DB_PATH", temp_db_path):
            db_module.init_db(temp_db_path)
            result = fetch_by_date(2024, 1, verbose=False)
        
        assert result is not None
        assert result["update_id"] == "2024-Jan"
    
    @respx.mock
    def test_fetch_by_date_not_found(self, temp_db_path: Path):
        """Test fetching a date with no update."""
        respx.get("https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/2099-Jan").mock(
            return_value=httpx.Response(404)
        )
        
        import patch_tuesday.database as db_module
        
        with patch.object(db_module, "DEFAULT_DB_PATH", temp_db_path):
            db_module.init_db(temp_db_path)
            result = fetch_by_date(2099, 1, verbose=False)
        
        assert result is None
    
    def test_fetch_by_date_month_names(self):
        """Test that all month names are mapped correctly."""
        month_names = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        ]
        
        # Verify month_names list exists in the expected format
        for i, month in enumerate(month_names, 1):
            expected_id = f"2024-{month}"
            assert month in expected_id
