"""Tests for the GCS client."""

import pytest
from datetime import datetime, timezone

from pathmon_analyzer.gcs_client import MtrLogFile, GcsClient


class TestMtrLogFile:
    """Tests for MtrLogFile dataclass."""

    def test_from_blob_name_pass(self):
        blob_name = "my-pathmon/2024-01-15/14:30:45:123456.log-Pass"
        log_file = MtrLogFile.from_blob_name(blob_name)

        assert log_file.pathmon_name == "my-pathmon"
        assert log_file.passed is True
        assert log_file.blob_name == blob_name
        assert log_file.timestamp.year == 2024
        assert log_file.timestamp.month == 1
        assert log_file.timestamp.day == 15
        assert log_file.timestamp.hour == 14
        assert log_file.timestamp.minute == 30
        assert log_file.timestamp.second == 45
        assert log_file.timestamp.tzinfo == timezone.utc

    def test_from_blob_name_fail(self):
        blob_name = "my-pathmon/2024-01-15/14:30:45:123456.log-Fail"
        log_file = MtrLogFile.from_blob_name(blob_name)

        assert log_file.pathmon_name == "my-pathmon"
        assert log_file.passed is False

    def test_from_blob_name_with_underscores(self):
        blob_name = "dc1_to_provider_pop/2024-01-15/14:30:45:123456.log-Pass"
        log_file = MtrLogFile.from_blob_name(blob_name)

        assert log_file.pathmon_name == "dc1_to_provider_pop"

    def test_from_blob_name_invalid_format(self):
        with pytest.raises(ValueError):
            MtrLogFile.from_blob_name("invalid-blob-name")

    def test_from_blob_name_missing_parts(self):
        with pytest.raises(ValueError):
            MtrLogFile.from_blob_name("only-one-part")


class TestGcsClientValidation:
    """Tests for GcsClient validation."""

    def test_raises_error_when_no_bucket(self):
        """Should raise ValueError when bucket is not specified."""
        with pytest.raises(ValueError) as exc_info:
            GcsClient(None)
        assert "GCS bucket name is required" in str(exc_info.value)
        assert "PATHMON_GCS_BUCKET" in str(exc_info.value)
