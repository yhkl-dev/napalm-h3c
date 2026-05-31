# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A NAPALM driver for H3C Comware network devices. Extends NAPALM's `NetworkDriver` to provide standardized network automation interfaces for H3C Comware switches.

## Build & Test Commands

```bash
# Install dependencies
poetry install

# Run all tests
poetry run pytest

# Run a single test file
poetry run pytest tests/test_parse_time.py

# Run a single test function
poetry run pytest tests/test_parse_time.py::TestTimeParser::test_empty_string

# Run with verbose output
poetry run pytest -v

# Lint
poetry run flake8 napalm_h3c_comware/

# Type check
poetry run mypy napalm_h3c_comware/

# Format
poetry run black --line-length=120 napalm_h3c_comware/ tests/
poetry run isort --profile=black napalm_h3c_comware/ tests/

# Pre-commit (runs all checks)
poetry run pre-commit run --all-files
```

## Architecture

### Core Pattern: CLI → TextFSM → TypedDict

The driver follows a consistent three-phase data pipeline for every NAPALM method:

1. **Send CLI command** via netmiko's `HPComwareBase` SSH transport
2. **Parse raw output** using a TextFSM template (templates live in `napalm_h3c_comware/utils/textfsm_templates/`)
3. **Transform** the parsed list-of-lists into strongly-typed dicts (defined in `types.py`)

### Key Files

| File | Purpose |
|------|---------|
| `napalm_h3c_comware/comware.py` | `ComwareDriver(NetworkDriver)` — the main driver class with all NAPALM interface methods |
| `napalm_h3c_comware/types.py` | All `TypedDict`, `TypeAlias`, and `NewType` definitions for structured data |
| `napalm_h3c_comware/utils/helpers.py` | Pure utility functions: time parsing (`parse_time`), Comware interface name canonicalization |
| `napalm_h3c_comware/utils/textfsm_templates/*.tpl` | 15 TextFSM templates — one per CLI command |

### Critical Internal Method

`_get_structured_output(command, template_name=None)` is the central dispatch for all data collection. It:
1. Sends the given command via SSH
2. Resolves the TextFSM template (auto-derives template name by replacing spaces with underscores in the command string)
3. Returns parsed list-of-dicts

Every `get_*()` or `_get_*()` method in the driver ultimately calls this method.

### Environment Data Collection

`get_environment()` collects CPU, memory, power, fans, and temperature **in parallel** using `ThreadPoolExecutor(max_workers=5)`. Results are cached for 30 seconds (`_cache_ttl = 30`). Call `clear_cache()` to force a fresh collection.

### Connection Transport

The driver uses `device_type = "hp_comware"` with netmiko's `HPComwareBase` class. The `open()` method delegates to `_netmiko_open()` (inherited from NAPALM base), passing `netmiko_optional_args` derived from the constructor's `optional_args` dict.

## Tests

Tests are in `tests/`. The `conftest.py` provides a `device` fixture — a `ComwareDriver` instance with `_get_structured_output` mocked via `MagicMock()`. Use this fixture for testing any method that calls `_get_structured_output()`.

Test patterns:
- **TextFSM template tests** (`test_lldp_parser.py`, `test_display_memory.py`): Load `.tpl` files directly with `textfsm.TextFSM()`, feed sample CLI output, assert parsed fields
- **Method tests** (`test_get_interfaces_ip.py`): Mock `_get_structured_output` return value, call the public method, assert the transformed output
- **Pure function tests** (`test_parse_time.py`): Standard parametrized pytest on `utils/helpers.py` functions
