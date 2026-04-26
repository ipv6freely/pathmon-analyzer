# Contributing to Pathmon Analyzer

Thank you for your interest in contributing to Pathmon Analyzer!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/ipv6freely/pathmon-analyzer.git
   cd pathmon-analyzer
   ```

2. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install in development mode with all dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

## Code Style

This project uses [Black](https://black.readthedocs.io/) for code formatting.

```bash
# Format all code
black src/ tests/

# Check formatting without making changes
black --check src/ tests/
```

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=pathmon_analyzer --cov-report=term-missing

# Run specific test file
pytest tests/test_parser.py -v
```

## Pull Request Process

1. Fork the repository and create a feature branch
2. Make your changes
3. Ensure all tests pass: `pytest`
4. Ensure code is formatted: `black src/ tests/`
5. Update documentation if needed
6. Submit a pull request

## Adding New Features

### Adding a new log format parser

1. Add a new dataclass in `src/pathmon_analyzer/parser.py`
2. Add regex patterns to `PathmonParser`
3. Update the `parse()` method to extract the new data
4. Add the field to `PathmonResult`
5. Update `TerminalVisualizer` to display the new data
6. Add tests in `tests/test_parser.py`

### Adding a new provider for detection

Add the provider to the `providers` dict in `TerminalVisualizer._extract_provider()`:

```python
providers = {
    "newprovider": "New Provider Name",
    # ...
}
```

## Reporting Issues

When reporting issues, please include:
- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant log output (sanitized of sensitive data)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
