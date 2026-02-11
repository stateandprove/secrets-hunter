# Usage

**Secrets Hunter** scans a **file** or a **directory**:

```bash
secrets-hunter [OPTIONS] [target]
```

- **target**: file or directory to scan (default: current directory `.`)

## Table of Contents
- [Options](#options)
- [Usage examples](#usage-examples)
- [Exit codes](#exit-codes)
- [Logging](#logging)

---

## Options

| Flag                   |    Type | Default | Description                                                         |
|------------------------|--------:|--------:|---------------------------------------------------------------------|
| `-h`, `--help`         |         |         | Show help and exit.                                                 |
| `--reveal-findings`    |    bool | `False` | Print raw matches in output.                                        |
| `--config FILE`        |  path[] |         | Path to a TOML overlay config. Can be used multiple times.          |
| `--json FILE`          |    path |         | Export results to a JSON file.                                      |
| `--sarif FILE`         |    path |         | Export results to a SARIF file.                                     |
| `--hex-entropy FLOAT`  |   float |   `3.0` | Hex entropy threshold. Lower = more sensitive / more noise.         |
| `--b64-entropy FLOAT`  |   float |   `4.3` | Base64 entropy threshold. Lower = more sensitive / more noise.      |
| `--min-length INT`     |     int |    `10` | Minimum candidate string length to consider.                        |
| `--workers INT`        |     int |     `4` | Number of parallel workers when scanning directories.               |
| `--log-level LEVEL`    |    enum |  `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `--min-confidence INT` |     int |     `0` | Only report findings with confidence **>=** this value (0–100).     |

---

## Usage examples

### Scan the current directory

```bash
secrets-hunter .
```

Example output:

```bash
========================================================================================
[1] AWS Access Key found at app.py:6
    Severity:   CRITICAL (confidence: 100%, reasoning: Pattern Match)
    Variable:   aws_access_key
    Match:      ***MASKED***
    Context:    ***MASKED***
----------------------------------------------------------------------------------------
[2] High Entropy Base64 String found at app.py:7
    Severity:   CRITICAL (confidence: 100%, reasoning: High Entropy in context of secret key/variable assignment - secret)
    Variable:   aws_secret_access_key
    Match:      ***MASKED***
    Context:    ***MASKED***
----------------------------------------------------------------------------------------
```

### Scan a single file

```bash
secrets-hunter path/to/file.py
```

### Reveal findings (unmasked)
Findings are masked by default. To show raw values, use the `--reveal-findings` flag:

```bash
secrets-hunter . --reveal-findings
```

Example output:

```bash
========================================================================================
[1] AWS Access Key found at app.py:6
    Severity:   CRITICAL (confidence: 100%, reasoning: Pattern Match)
    Variable:   aws_access_key
    Match:      AKIAxxxxxxxxxxxxxxxx
    Context:    AWS_ACCESS_KEY = "AKIAxxxxxxxxxxxxxxxx"
----------------------------------------------------------------------------------------
[2] High Entropy Base64 String found at app.py:7
    Severity:   CRITICAL (confidence: 100%, reasoning: High Entropy in context of secret key/variable assignment - secret)
    Variable:   aws_secret_access_key
    Match:      xxxxxxxxxxxxx/xxxxxxx/xxxxxxxxxxxxxxxxxx
    Context:    AWS_SECRET_ACCESS_KEY = "xxxxxxxxxxxxx/xxxxxxx/xxxxxxxxxxxxxxxxxx"
----------------------------------------------------------------------------------------
```

### Export as JSON

```bash
secrets-hunter . --json results.json
```

Example output:

```json
[
    {
        "file": "app.py",
        "line": 6,
        "type": "AWS Access Key",
        "match": "***MASKED***",
        "context": "***MASKED***",
        "severity": "CRITICAL",
        "confidence_reasoning": "Pattern Match",
        "detection_method": "pattern",
        "confidence": 100,
        "context_var": "aws_access_key"
    },
    {
        "file": "app.py",
        "line": 7,
        "type": "High Entropy Base64 String",
        "match": "***MASKED***",
        "context": "***MASKED***",
        "severity": "CRITICAL",
        "confidence_reasoning": "High Entropy in context of secret key/variable assignment - secret",
        "detection_method": "entropy",
        "confidence": 100,
        "context_var": "aws_secret_access_key"
    }
]
```

### Export as JSON and reveal findings

```bash
secrets-hunter . --reveal-findings --json results.json
```

### Export as JSON, reveal findings and filter out low-confidence findings

```bash
secrets-hunter . --reveal-findings --json results.json --min-confidence 75
```

### Export as SARIF

```bash
secrets-hunter . --sarif results.sarif
```

### Use overlay config
Apply custom configuration using an overlay file:

```bash
secrets-hunter . --config team.toml
```

### Stack multiple overlays
Apply multiple configuration files in sequence:

```bash
secrets-hunter . --config ci.toml --config local.toml
```

Learn more about configuration in the [Configuration docs](config.md).

---

## Exit codes

Always returns `0` unless scan fails.

---

## Logging

### Debug output

```bash
secrets-hunter . --log-level DEBUG
```

---
