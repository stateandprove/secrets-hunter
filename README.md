# Secrets Hunter

[![PyPI](badges/pypi.svg)](https://pypi.org/project/secrets-hunter/)
[![Python](badges/python.svg)](https://python.org/)

**Secrets Hunter** is a lightweight, fully autonomous, and dependency-free scanner that detects secrets and sensitive information in your codebase.

The scanner provides a **command-line interface** (CLI) and is designed for use both locally (as a linter) and in security pipelines (as a security gate).

## Features

Findings are detected using a combined **regex** and **entropy** approach:

- **Pattern-based detection**: Identifies predefined secret formats (API keys, tokens, etc.)
- **Entropy-based detection**: Finds high-entropy strings

Each high-entropy finding gets a **confidence boost** if it is detected in the context of an assignment or key/value pair with keywords, 
assuming a secret (e.g., `API_KEY=...`, `"secret_token": "..."`, etc.). 

All of these patterns are fully configurable via TOML config overlays (see [Configuration](#configuration)).

**Secrets Hunter** supports parallel scanning with configurable workers. Output findings can be displayed in console output or exported to a JSON file.

## Installation

> **Requirements:** Python 3.11+

Secrets Hunter can be installed via PyPI, from source, or using Docker. For a quick start, install directly from PyPI:
```bash
pip install secrets-hunter
```

For installation from source or Docker, see the [Installation docs](https://docs.fvlcn.dev/secrets-hunter/installation/).

## Quick start

Scan the current directory:

```bash
secrets-hunter .
```

Findings are masked by default. To reveal them, use the `--reveal-findings` flag:

```bash
secrets-hunter . --reveal-findings
```

Scan a specific file:

```bash
secrets-hunter path/to/file.py
```

Export results to JSON:

```bash
secrets-hunter . --json results.json
```

See the [Usage docs](https://docs.fvlcn.dev/secrets-hunter/usage/) for all flags and more examples.

## Configuration

Secrets Hunter ships with built-in packaged defaults. You can display them using CLI:
```bash
secrets-hunter showconfig
```

Configuration can be customized using overlay config files. Example (team baseline overlay):
```bash
secrets-hunter . --config team.toml
```

Multiple overlays are applied **in the order provided**:
```bash
secrets-hunter . --config ci.toml --config local.toml
```

A full description and usage examples are available in [Configuration docs](https://docs.fvlcn.dev/secrets-hunter/config/).

## License

Secrets Hunter is released under the MIT License, meaning you are free to use, modify, and distribute it for both personal and commercial purposes.

## Acknowledgment

This project was made possible by [whitespots.io](https://whitespots.io)
