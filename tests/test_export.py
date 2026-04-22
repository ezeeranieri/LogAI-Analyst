"""Tests for report export functionality."""
import pytest
import os
import json
import csv
from src.utils import ReportExporter
from src.config import ABS_DATA_DIR


@pytest.fixture
def sample_threats():
    """Sample threat data for export tests."""
    return [
        {
            "ip_origen": "192.0.2.1",
            "usuario": "admin",
            "reason": "Brute Force",
            "datetime": "2026-10-11T10:00:00",
            "status": "FAIL"
        },
        {
            "ip_origen": "192.0.2.2",
            "usuario": "root",
            "reason": "User Probing",
            "datetime": "2026-10-11T10:05:00",
            "status": "FAIL"
        }
    ]


def test_export_json_creates_file(sample_threats, tmp_path):
    """
    Verifies that export_json creates a valid JSON file.
    """
    file_path = ReportExporter.export_json(sample_threats, str(tmp_path), "test_report")

    assert os.path.exists(file_path)
    assert file_path.endswith(".json")

    # Verify content
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "export_metadata" in data
    assert "threats" in data
    assert len(data["threats"]) == 2
    assert data["export_metadata"]["format"] == "json"
    assert data["export_metadata"]["record_count"] == 2


def test_export_csv_creates_file(sample_threats, tmp_path):
    """
    Verifies that export_csv creates a valid CSV file.
    """
    file_path = ReportExporter.export_csv(sample_threats, str(tmp_path), "test_csv")

    assert os.path.exists(file_path)
    assert file_path.endswith(".csv")

    # Verify content
    with open(file_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == 2
    assert "ip_origen" in rows[0]
    assert "reason" in rows[0]


def test_export_generic_dispatches_to_correct_format(sample_threats, tmp_path):
    """
    Verifies that export() method dispatches to correct format handler.
    """
    # Test JSON
    json_path = ReportExporter.export(sample_threats, "json", str(tmp_path), "generic_json")
    assert json_path.endswith(".json")

    # Test CSV
    csv_path = ReportExporter.export(sample_threats, "csv", str(tmp_path), "generic_csv")
    assert csv_path.endswith(".csv")


def test_export_raises_on_empty_data(tmp_path):
    """
    Verifies that export raises ValueError on empty data.
    """
    with pytest.raises(ValueError, match="Cannot export empty data"):
        ReportExporter.export_json([], str(tmp_path))


def test_export_raises_on_invalid_format(sample_threats, tmp_path):
    """
    Verifies that export raises ValueError on invalid format.
    """
    with pytest.raises(ValueError, match="Unsupported format"):
        ReportExporter.export(sample_threats, "xml", str(tmp_path))


def test_get_report_info_returns_metadata(sample_threats, tmp_path):
    """
    Verifies that get_report_info returns correct file metadata.
    """
    file_path = ReportExporter.export_json(sample_threats, str(tmp_path), "info_test")

    info = ReportExporter.get_report_info(file_path)

    assert info["filename"] == "info_test.json"
    assert info["format"] == "json"
    assert info["path"] == file_path
    assert "size_bytes" in info
    assert info["size_bytes"] > 0
    assert "created" in info


def test_get_report_info_raises_on_missing_file():
    """
    Verifies that get_report_info raises FileNotFoundError for missing files.
    """
    with pytest.raises(FileNotFoundError):
        ReportExporter.get_report_info("/nonexistent/path/report.json")


def test_auto_generated_filename(sample_threats, tmp_path):
    """
    Verifies that auto-generated filenames include timestamp and unique ID.
    """
    file_path = ReportExporter.export_json(sample_threats, str(tmp_path))
    filename = os.path.basename(file_path)

    # Format: report_YYYYMMDD_HHMMSS_<uuid>.json
    assert filename.startswith("report_")
    assert filename.endswith(".json")
    # Should have 4 parts: report, date, time, uuid
    parts = filename.replace(".json", "").split("_")
    assert len(parts) == 4  # report, date, time, uuid
    assert len(parts[1]) == 8  # YYYYMMDD
    assert len(parts[2]) == 6  # HHMMSS
    assert len(parts[3]) == 8  # UUID prefix


def test_csv_flatten_nested_dicts(tmp_path):
    """
    Verifies that CSV export flattens nested dictionaries.
    """
    data_with_nested = [
        {
            "ip_origen": "192.0.2.1",
            "nested": {"key1": "value1", "key2": "value2"},
            "list_field": ["a", "b", "c"]
        }
    ]

    file_path = ReportExporter.export_csv(data_with_nested, str(tmp_path), "nested")

    with open(file_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # Nested keys should be flattened
    assert "nested_key1" in rows[0]
    assert "nested_key2" in rows[0]
    # Lists should be converted to comma-separated string
    assert rows[0]["list_field"] == "a, b, c"


def test_reports_directory_created(tmp_path):
    """
    Verifies that reports subdirectory is created automatically.
    """
    base_dir = str(tmp_path)
    data = [{"test": "value"}]

    ReportExporter.export_json(data, base_dir, "subdir_test")

    reports_dir = os.path.join(base_dir, "reports")
    assert os.path.exists(reports_dir)
    assert os.path.isdir(reports_dir)
