# Usage

**Secrets Hunter** scans a **file** or a **directory**:

```bash
secrets-hunter [OPTIONS] [target]
```

- **target**: file or directory to scan (default: current directory `.`)

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
| `--b64-entropy FLOAT`  |   float |   `4.5` | Base64 entropy threshold. Lower = more sensitive / more noise.      |
| `--min-length INT`     |     int |    `10` | Minimum candidate string length to consider.                        |
| `--workers INT`        |     int |     `4` | Number of parallel workers when scanning directories.               |
| `--log-level LEVEL`    |    enum |  `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `--min-confidence INT` |     int |    `75` | Only report findings with confidence **>=** this value (0–100).     |

---

## Usage examples

### Scan the current directory

```bash
secrets-hunter .
```

Example output:

```bash
========================================================================================
[1] Stripe API Key found at app.py:11
    Severity:   CRITICAL (confidence: 100%)
    Match:      ***MASKED***
    Context:    ***MASKED***
----------------------------------------------------------------------------------------
```

### Scan a single file

```bash
secrets-hunter path/to/file.py
```

### Reveal findings (unmasked)

```bash
secrets-hunter . --reveal-findings
```

Example output:

```bash
========================================================================================
[1] Stripe API Key found at app.py:11
    Severity:   CRITICAL (confidence: 100%)
    Match:      sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    Context:    STRIPE_API_KEY = "sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
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
        "line": 11,
        "type": "Stripe API Key",
        "match": "***MASKED***",
        "context": "***MASKED***",
        "severity": "CRITICAL",
        "detection_method": "pattern",
        "confidence": 100,
        "context_var": "stripe_api_key"
    }
]
```

### Export as JSON and reveal findings

```bash
secrets-hunter . --reveal-findings --json results.json
```

### Export as JSON, reveal findings and filter out low-confidence findings

```bash
secrets-hunter . --reveal-findings --json results.json --min-confidence 90
```

### Export as SARIF

```bash
secrets-hunter . --sarif results.sarif
```

### Use overlay config (team baseline)

```bash
secrets-hunter . --config team.toml
```

### Stack multiple overlays

```bash
secrets-hunter . --config ci.toml --config local.toml
```

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
