# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-04-26

### Added
- Initial release
- `pathmon investigate` - Investigate alerts around a specific time
- `pathmon analyze` - Analyze pathmon over a time range (defaults to today)
- `pathmon recent` - Check recent status for a pathmon
- `pathmon list-pathmons` - List available pathmons in GCS bucket
- `pathmon login` - Authenticate with Google Cloud
- Support for parsing MTR (My Traceroute) output
- Support for parsing httpstat HTTP timing output
- Support for parsing sipping.py SIP ping output
- Automatic provider detection (Colt, Level3, Telia, etc.) in issue summaries
- One-line PagerDuty summary generation for easy copy/paste
- Rich terminal output with tables and color
- HTML report generation with interactive Plotly charts
- Configurable GCS bucket via `--bucket` flag or `PATHMON_GCS_BUCKET` env var
