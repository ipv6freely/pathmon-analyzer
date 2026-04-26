# Pathmon Analyzer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Claude](https://img.shields.io/badge/Claude-Opus%204.5-6B5CE7?logo=anthropic)](https://www.anthropic.com/claude)

CLI tool to analyze pathmon logs from GCS when investigating PagerDuty alerts for severe latency or packet loss.

Supports parsing of:
- **MTR** (My Traceroute) - hop-by-hop network diagnostics
- **httpstat** - HTTP timing breakdown (DNS, TCP, TLS, server response)
- **sipping** - SIP ping packet loss and latency

## Installation

```bash
# Install with pip (editable mode for development)
pip install -e .

# Or install dependencies directly
pip install google-cloud-storage click rich plotly pandas
```

## Configuration

### GCS Bucket (Required)

You must specify your GCS bucket name via environment variable or CLI option:

```bash
# Environment variable (recommended)
export PATHMON_GCS_BUCKET=my-pathmon-bucket

# Or CLI option (works with any command)
pathmon --bucket my-pathmon-bucket list-pathmons
```

If not set, you'll see:
```
Error: GCS bucket name is required.

Set it via:
  • Environment variable: export PATHMON_GCS_BUCKET=your-bucket-name
  • CLI option: pathmon --bucket your-bucket-name <command>
```

### Authentication

```bash
# Easy way: use the built-in login command
pathmon login

# Or manually with gcloud
gcloud auth application-default login

# Or set service account key
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
```

## Usage

### List Available Pathmons

```bash
pathmon list-pathmons
```

### Investigate an Alert

When you receive a PagerDuty alert, use the `investigate` command with the alert time:

```bash
# Investigate around a specific alert time
pathmon investigate my-pathmon -t "2024-01-15 14:30:00"

# Customize the time window (default: 30 min before, 10 min after)
pathmon investigate my-pathmon -t "2024-01-15 14:30:00" -b 60 -a 15

# Generate an HTML report
pathmon investigate my-pathmon -t "2024-01-15 14:30:00" -o report.html

# Show detailed hop tables for each sample
pathmon investigate my-pathmon -t "2024-01-15 14:30:00" --show-all-hops
```

### Analyze a Time Range

```bash
# Analyze today (default)
pathmon analyze my-pathmon

# Analyze a specific day
pathmon analyze my-pathmon -s "2024-01-15 00:00" -e "2024-01-15 23:59"

# Show only failures
pathmon analyze my-pathmon -f

# Generate HTML report
pathmon analyze my-pathmon -o daily-report.html
```

### Check Recent Status

```bash
# Last hour (default)
pathmon recent my-pathmon

# Last 4 hours
pathmon recent my-pathmon -h 4
```

## Output

### Terminal Output

The tool provides rich terminal output including:

- **Summary table**: Total samples, failures, avg/max latency and loss
  - MTR metrics (network latency/loss)
  - HTTP metrics (total time, breakdown)
  - SIP metrics (packet loss, latency)
- **Timeline**: Visual pass/fail indicator over time
- **Path change detection**: Identifies when routing changes occur between samples
- **Problematic hops**: Analysis of which hops consistently show issues
- **Failure details**: Detailed breakdown of each failure including:
  - HTTP timing table (DNS, TCP connect, TLS handshake, server processing)
  - SIP ping results (packets sent/received, loss %, latency)
  - MTR hop-by-hop trace
- **PagerDuty summary**: One-line issue summary ready to copy/paste, with automatic provider detection (Colt, Level3, Telia, etc.)

### Example PagerDuty Summary

```
Issue: SIP latency elevated (476ms); network issues at Colt (ae1.3115.edge7.lon1.neo.colt.net) to 212.23.246.79.
```

```
Issue: TCP connect time elevated (1034ms, total 1190ms) to app.example.com.
```

### HTML Reports

Use `-o report.html` to generate interactive HTML reports with:

- Combined latency/loss chart over time
- Packet loss heatmap by hop
- Latency heatmap by hop

## GCS Bucket Structure

Logs are expected in your configured GCS bucket with the format:

```
<pathmon_name>/yyyy-mm-dd/hh:mm:ss:ms.log-<Pass|Fail>
```

Each log file may contain:
- MTR output with hop-by-hop statistics
- httpstat output with HTTP timing breakdown
- sipping.py output with SIP ping results

## Development

```bash
# Install with dev/test dependencies
pip install -e ".[dev]"
# or
pip install -e ".[test]"

# Format code with black
black src/ tests/

# Check formatting
black --check src/ tests/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed development guidelines.

## Testing

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=pathmon_analyzer --cov-report=term-missing

# Run specific test file
pytest tests/test_parser.py
```

Tests cover:
- **Parser**: MTR, httpstat, and sipping.py log parsing
- **Visualizer**: Provider detection, issue summary generation
- **GCS Client**: Blob name parsing, timestamp extraction
- **CLI**: Datetime parsing, command help

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Acknowledgments

This project was developed with assistance from [Claude](https://www.anthropic.com/claude) (Anthropic's AI assistant, Claude Opus 4.5 via Windsurf/Cascade). See [AI.md](AI.md) for full disclosure.
