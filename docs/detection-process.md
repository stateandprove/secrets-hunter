# Detection Process

The detection process handles three kinds of candidates:

- PEM keys
- generic string candidates
- database connection strings

Secrets Hunter handles different candidate types differently. PEM keys and database connection strings have recognizable structure, while generic string candidates are usually detected through entropy and assignment context.

## Process Overview

The detection flow can be described by the following diagram:

```text
Text content from scan mode
        |
        v
Extract candidate fragments
        |
        +--> PEM keys
        |
        +--> Database connection strings
        |
        +--> Generic string candidates
        |
        v
Run entropy detector and pattern detector
        |
        v
Merge findings and prefer pattern matches
        |
        v
Process context, rejection, and confidence
        |
        +--> check value false-positive rules
        +--> find assignment and key/value context
        |
        +--> without assignment context:
        |       +--> mark value-based false positives
        |
        +--> with assignment context:
        |       +--> give entropy findings an assignment-context confidence boost
        |       +--> mark keyword-based false positives
        |       +--> mark value-based false positives unless secret-like context permits them
        |       +--> give entropy findings a secret-keyword confidence boost
        |
        v
Prepare findings for output
        |
        +--> confidence filtering
        +--> truncation
        +--> masking
```

For each collected text target, Secrets Hunter:

1. Extracts candidate fragments.
2. Runs entropy-based detection.
3. Runs pattern and structure-aware detection.
4. Merges findings and prefers pattern matches over duplicate entropy matches.
5. Processes assignment context, false-positive checks, severity, and confidence together.
6. Prepares findings for output.

## PEM Keys

PEM blocks are detected by header/footer patterns. When Secrets Hunter sees a supported PEM header, it collects the whole block up to the matching footer and treats that block as one candidate.

> The body lines are not reported as separate findings.

A key is treated as actionable when it looks like private key material: it has a supported private-key header, a matching footer, and a base64 body that can be decoded.

Example:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAJqRw7USOB2KRO3K1faJP5X2raZhHitmFBIjjnfAxivAAAAKgpZj7/KWY+
/wAAAAtzc2gtZWQyNTUxOQAAACAJqRw7USOB2KRO3K1faJP5X2raZhHitmFBIjjnfAxivA
AAAEDYfn9ZgXwunqZCBla+H8+F5hggplLpxqgprYTFwfv0MAmpHDtRI4HYpE7crV9ok/lf
atpmEeK2YUEiOOd8DGK8AAAAIXN0YXRlYW5kcHJvdmVATWFjQm9vay1BaXItMi5sb2NhbA
ECAwQ=
-----END OPENSSH PRIVATE KEY-----
```

Inline PEM blocks are also detected when the supported header and matching footer appear on the same line.

Example inline private key:

```text
-----BEGIN OPENSSH PRIVATE KEY-----b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACAJqRw7USOB2KRO3K1faJP5X2raZhHitmFBIjjnfAxivAAAAKgpZj7/KWY+/wAAAAtzc2gtZWQyNTUxOQAAACAJqRw7USOB2KRO3K1faJP5X2raZhHitmFBIjjnfAxivAAAAEDYfn9ZgXwunqZCBla+H8+F5hggplLpxqgprYTFwfv0MAmpHDtRI4HYpE7crV9ok/lfatpmEeK2YUEiOOd8DGK8AAAAIXN0YXRlYW5kcHJvdmVATWFjQm9vay1BaXItMi5sb2NhbAECAwQ=-----END OPENSSH PRIVATE KEY-----
```

### Rejection

Some PEM blocks are rejected instead of treated as actionable secrets:

- Public keys and certificates are public material.
- Blocks without a matching footer are malformed.
- Blocks with an invalid base64 body, or a decoded body that is too short, are malformed.

Example inline missing footer:

```text
PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----MIICXQIBAAKBgQDAwmJKDNZadDYMkkLRFL6B1/ZJ3fN3AqNiXy0N7YTa8Qaozu..."
```

Example invalid base64 body:

```text
-----BEGIN RSA PRIVATE KEY-----your_key_goes_here-----END RSA PRIVATE KEY-----
```

### Missing or mismatched footers

When a multi-line PEM block has no matching footer, Secrets Hunter rejects the PEM candidate as malformed. The same applies when the footer exists but does not match the header type.

Example missing footer:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAgEA37a60AuK/dgXtxyVgnvrE7LGs9zX/bJuy0eBuKpn03m3cMZFhPWI
Xz+q6CU9cR1H5wqvtHoOqLKajo9iB6XYjPlpw8b2mvc66UPGFCUEMoWxzf3QdFXfU/veaG
```

Example mismatched footer:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAgEA37a60AuK/dgXtxyVgnvrE7LGs9zX/bJuy0eBuKpn03m3cMZFhPWI
Xz+q6CU9cR1H5wqvtHoOqLKajo9iB6XYjPlpw8b2mvc66UPGFCUEMoWxzf3QdFXfU/veaG
-----END RSA PRIVATE KEY-----
```

> Malformed PEM blocks do not stop scanning; later secrets can still be found.

After rejecting a malformed PEM candidate, Secrets Hunter returns the remaining lines to the normal scanning flow. Body-like lines from the malformed block are then scanned as generic strings and can still produce low-confidence entropy findings.

## Generic Secrets

Generic secrets are ordinary string values that are not PEM blocks or database connection strings. They are detected with regex patterns or entropy checks. The surrounding assignment or key/value context is then used to adjust confidence and reject false positives.

Consider this text block:

```text
api_key = "qF7xN2pL9vR4sT8mK3zY6dH1wC5bJ0uA"
value = "qF7xN2pL9vR4sT8mK3zY6dH1wC5bJ0uA"
asset_integrity = "qF7xN2pL9vR4sT8mK3zY6dH1wC5bJ0uA"
```

Even though the assigned value is the same, the assignment context changes its meaning completely:

- `api_key` identifies the value as a secret, so it becomes a high-confidence finding.
- `value` is only an assignment of a high-entropy string. It becomes a medium-confidence finding that requires further investigation.
- `asset_integrity` identifies the value as integrity-related context, so it is treated as a false positive rather than an actionable secret.

A value can also be rejected because of the detected value itself, not only because of the variable name. For example:

```text
value = "c12ddf3bfeeda5a2f7dd28feee62e1d3afaf097c"
```

The assigned string has high entropy and assignment context, but it also matches the shape of a SHA1 hash.

> Secrets Hunter treats known hash formats as false positives unless the surrounding context identifies the value as a secret.

Regex matches are treated as high-confidence findings, but false-positive rules still apply. Consider this line:

```text
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
```

This AWS-shaped value matches a built-in secret pattern, but it is rejected because it contains an example placeholder.

## Database Connection Strings

Database connection strings are detected structurally. Secrets Hunter looks for supported URI schemes with an embedded username and password, then treats the full URI as one candidate.

Example:

```text
DATABASE_URL="postgres://app_user:S3cr3tPassw0rd!@db.example.com:5432/app"
```

A connection URI is treated as actionable only when it contains an embedded password before the host.

### Rejection

Connection strings with placeholder or template passwords are rejected instead of treated as actionable secrets.

Example placeholder password:

```text
DATABASE_URL="postgresql://%s:%s@%s:%s/%s"
```

Example template password:

```text
DATABASE_URL="postgres://app_user:{password}@db.example.com:5432/app"
```

Example non-actionable password:

```text
DATABASE_URL="postgres://app_user:example@db.example.com:5432/app"
```

## Confidence

Findings are assigned confidence based on detection method, assignment context, secret-like keywords, and false-positive checks.

> Confidence is used for prioritization and filtering; it does not mean the scanner has validated that a credential is live.

| Confidence | Meaning                                                    |
|------------|------------------------------------------------------------|
| `0`        | Rejected / false positive                                  |
| `5`        | High entropy without assignment context                    |
| `75`       | High entropy with assignment context                       |
| `100`      | Pattern match or high-entropy value in secret-like context |


## Output

Before findings are reported, Secrets Hunter prepares them for output. This includes confidence filtering, optional truncation, and masking.

### Filtering

`--min-confidence` controls which findings are included in the report. By default, the threshold is `0`, so rejected findings are still shown. Raising the threshold hides lower-confidence findings.

```bash
secrets-hunter . --min-confidence 75
```

### Masking

> Findings are masked by default so scan results can be used safely in terminals, logs, and CI systems.

Use `--reveal-findings` only when raw values are needed.

```bash
secrets-hunter . --reveal-findings
```

### Truncation

Long findings can be truncated with `--truncate-long-matches`. PEM keys are truncated in a structure-aware way: Secrets Hunter keeps the header, the first body lines, the last body lines, and the footer.

```bash
secrets-hunter . --reveal-findings --truncate-long-matches
```

Example truncated PEM output:

```text
-----BEGIN RSA PRIVATE KEY-----
MIIJKQIBAAKCAgEAvbjpw9ZFgc8ZvCWCpGMCoCsDCNbRAsj5Sh0csCCeV4mswDMD
dDf7ObMeK7F/Rp4+TgUoWFeBHEzc5E2tE1akxqNglf4pdsyDhfKeYdJ0ByHiSCni
TGbEwz2RacjJ6gDMZZLHt9iGYpmFYnlOG5+RZLCEK9TABJrJwbtrNTs+izB+VqQs
dzh3XJ/u2U30+/rX3PImF9vMQKYKyJE2w5N0M5N44fXloPMgRpcUpFv4HhViRd7s
(... truncated 41 lines ...)
2R7RDfWXuZ0jwGv1W3pxFYMqnnnits0ltwbxBmvFw2su+TJWIIYBoXiHl4vihVK5
GtUw9sNoVCTKnA404W8lJxfOTtqQvk2imSBr5QgV34t4AnuSaB6sMfKeai35Y5Ha
srBoLatunmWKxgSU9OHz85Dmj+Vvb48zMT1jsw8luifDSZ7u3Y3eRmVTtpti9DAa
CVidWgYbN/hJrTdYJpdxSFmetosh6wTSXAdmk/XkaVAuzmKvfnsWEpf5eUz+
-----END RSA PRIVATE KEY-----
```

After this step, each finding has its final confidence, rejection state, and display-safe value. The scanner can then report the same prepared finding consistently across supported output formats.
