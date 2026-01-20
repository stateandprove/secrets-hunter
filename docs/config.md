# Configuration (TOML)

Secrets Hunter loads two **packaged** config files:

- `patterns.toml` (regex patterns, keywords, assignment patterns, excludes)
- `ignore.toml` (ignored extensions and directories)

You can then apply **one or more overlay TOML files** via CLI:

```bash
secrets-hunter . --config team-overrides.toml
```

Overlays are applied **in the order provided**.

---

## How overlays work

### `secret_patterns` (by name)
`[[secret_patterns]]` entries are merged **by `name`**:

- If an overlay defines a pattern with an existing `name`, it **replaces** the previous pattern (and flags).
- If it uses a new `name`, it **adds** a new pattern.
- You can remove existing patterns using `remove_secret_patterns`.

### Lists
These keys are treated as lists and are:

1. **extended** (appended) from each file in load order
2. **de-duplicated** (first occurrence kept)

Applies to:
- `exclude_patterns`
- `secret_keywords`
- `assignment_patterns`
- `ignore.extensions`
- `ignore.dirs`

### Removals
If you need to remove a previously-added item, use the corresponding `remove_*` key.

Supported removal keys:

- `remove_secret_patterns`
- `remove_exclude_patterns`
- `remove_secret_keywords`
- `remove_assignment_patterns`
- `remove_ignore_extensions`
- `remove_ignore_dirs`

---

## Full schema

### Secret patterns

```toml
[[secret_patterns]]
name = "GitHub Token"
pattern = '''\bgh[pousr]_[A-Za-z0-9]{36,}\b'''
# Optional (list of strings):
# flags = ["IGNORECASE", "MULTILINE", "DOTALL", "VERBOSE", "ASCII"]
```

Notes:
- `name` must be a **non-empty string**
- `pattern` must be a **non-empty string**
- `flags` (if present) must be a **list of strings**, each one of:
  - `IGNORECASE`, `MULTILINE`, `DOTALL`, `VERBOSE`, `ASCII`

### Exclude patterns (false positives)

```toml
exclude_patterns = [
  '''^[0-9a-f]{32}$''',  # MD5 hashes
  "example",
  "dummy",
]
```

Each entry is compiled as a regex. Plain strings like `"example"` will match anywhere.

### Secret keywords
Used to boost confidence when a match is associated with a variable name suggesting a secret.

```toml
secret_keywords = [
  "secret",
  "token",
  "api_key",
  "password",
]
```

### Assignment patterns
Used to extract candidate values from code lines (e.g. `API_KEY="..."`).

```toml
assignment_patterns = [
  '''([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*["']([^"']+)["']''',
  '''export\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*["']([^"']+)["']''',
]
```

### Ignore rules
Ignore rules live under the `[ignore]` table:

```toml
[ignore]
extensions = [".pdf", ".png", ".zip"]
dirs = ["node_modules", ".git", "dist", "build"]
```

---

## Removal keys

### Remove secret patterns by name
```toml
remove_secret_patterns = ["Private Key", "JWT Token"]
```

### Remove exclude patterns / keywords / assignment patterns
These remove by **exact string match**:

```toml
remove_exclude_patterns = ["dummy", "example"]
remove_secret_keywords = ["key"]
remove_assignment_patterns = [
  '''set\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*["']([^"']+)["']''',
]
```

### Remove ignore items
```toml
remove_ignore_extensions = [".pdf", ".svg"]
remove_ignore_dirs = ["dist"]
```

---

## Practical examples

### 1) Minimal overlay: add one pattern + ignore a dir

```toml
[[secret_patterns]]
name = "My Service Token"
pattern = '''\bmytok_[A-Za-z0-9]{32,}\b'''

[ignore]
dirs = ["vendor"]
```

### 2) Override an existing pattern by name

```toml
[[secret_patterns]]
name = "GitHub Token" # same name => overrides packaged one
pattern = '''\bghp_[A-Za-z0-9]{36}\b'''
flags = ["ASCII"]
```

### 3) Remove a built-in pattern (e.g. PEM/private keys)

```toml
remove_secret_patterns = ["Private Key"]
```

### 4) Make CI stricter but local dev more permissive

**ci.toml**
```toml
exclude_patterns = [
  "example",
  "test",
]
```

**local.toml**
```toml
remove_exclude_patterns = ["test"] # let local show “test” matches
```

Run:

```bash
secrets-hunter . --config ci.toml --config local.toml
```

---

## Keep things clean

- Prefer **specific patterns** over broad ones (broad regex = noisy scans).
- Keep `exclude_patterns` tight; avoid excluding generic words unless you really need it.
- Name of your pattern will be shown in a report, so give it a clear `name`.

---
