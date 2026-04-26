"""Tests for the CLI."""

import pytest
from click.testing import CliRunner

from pathmon_analyzer.cli import main, parse_datetime


class TestParseDatetime:
    """Tests for datetime parsing."""

    def test_parse_full_datetime(self):
        dt = parse_datetime("2024-01-15 14:30:45")
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 15
        assert dt.hour == 14
        assert dt.minute == 30
        assert dt.second == 45

    def test_parse_datetime_no_seconds(self):
        dt = parse_datetime("2024-01-15 14:30")
        assert dt.hour == 14
        assert dt.minute == 30
        assert dt.second == 0

    def test_parse_iso_format(self):
        dt = parse_datetime("2024-01-15T14:30:45")
        assert dt.hour == 14
        assert dt.minute == 30
        assert dt.second == 45

    def test_parse_date_only(self):
        dt = parse_datetime("2024-01-15")
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 15
        assert dt.hour == 0
        assert dt.minute == 0

    def test_parse_invalid_format(self):
        with pytest.raises(Exception):  # click.BadParameter
            parse_datetime("not-a-date")


class TestCliHelp:
    """Tests for CLI help commands."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_main_help(self, runner):
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Pathmon Analyzer" in result.output
        assert "--bucket" in result.output

    def test_investigate_help(self, runner):
        result = runner.invoke(main, ["investigate", "--help"])
        assert result.exit_code == 0
        assert "PATHMON_NAME" in result.output
        assert "--alert-time" in result.output
        assert "--before" in result.output
        assert "--after" in result.output

    def test_analyze_help(self, runner):
        result = runner.invoke(main, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "PATHMON_NAME" in result.output
        assert "--start" in result.output
        assert "--end" in result.output
        assert "--failures-only" in result.output

    def test_recent_help(self, runner):
        result = runner.invoke(main, ["recent", "--help"])
        assert result.exit_code == 0
        assert "PATHMON_NAME" in result.output
        assert "--hours" in result.output

    def test_list_pathmons_help(self, runner):
        result = runner.invoke(main, ["list-pathmons", "--help"])
        assert result.exit_code == 0

    def test_login_help(self, runner):
        result = runner.invoke(main, ["login", "--help"])
        assert result.exit_code == 0
        assert "Authenticate" in result.output
