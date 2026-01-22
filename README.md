# Secrets Hunter

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

### From PyPI

```bash
pip install secrets-hunter
```

### From source

1) Clone this repository

```bash
git clone https://github.com/FVLCN/secrets-hunter.git secrets-hunter
cd secrets-hunter
```

2) Activate virtual environment (macOS and Linux)

```bash
python -m venv venv
source venv/bin/activate
```

3) Build and install package

```bash
pip install -e .
```

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

See the [usage docs](docs/usage.md) for all flags and more examples.

## Configuration

Secrets Hunter ships with built-in packaged defaults and supports **overlay configs**.

Example (team baseline overlay):

```bash
secrets-hunter . --config team.toml
```

Multiple overlays are applied **in the order provided**:

```bash
secrets-hunter . --config ci.toml --config local.toml
```

A full description and usage examples of the configuration are available in [Configuration docs](docs/config.md).

## License

MIT

## Acknowledgment

This project was made possible by [whitespots.io](https://whitespots.io)
