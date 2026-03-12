import re
import tomllib

from hashlib import sha256
from importlib.resources import files as res_files
from pathlib import Path
from typing import Any

from secrets_hunter.models.config import ExcludePattern, RuntimeConfig

FLAG_MAP: dict[str, int] = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "VERBOSE": re.VERBOSE,
    "ASCII": re.ASCII,
}


def require_table(value: Any, key: str, file: Path) -> dict[str, Any]:
    if value is None:
        return {}

    if not isinstance(value, dict):
        raise ValueError(f"'{key}' must be a table in {file}")

    return value


def require_list(data: dict[str, Any], key: str, file: Path) -> list[Any]:
    v = data.get(key) or []

    if not isinstance(v, list):
        raise ValueError(f"'{key}' must be a list in {file}")

    return v


def require_string_list(data: dict[str, Any], key: str, file: Path) -> list[str]:
    v = require_list(data, key, file)

    for i, item in enumerate(v):
        if not isinstance(item, str):
            raise ValueError(f"'{key}[{i}]' must be a string in {file}, got {type(item).__name__}")

    return v


def require_pattern_item(item: Any, key: str, required_fields: set[str], file: Path) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError(f"'{key}' items must be tables in {file}: {item!r}")

    missing = required_fields - item.keys()

    if missing:
        raise ValueError(f"'{key}' item in {file} missing fields {missing}: {item!r}")

    flags = item.get("flags") or []

    if not isinstance(flags, list) or any(not isinstance(x, str) for x in flags):
        raise ValueError(f"'{key}' item in {file} 'flags' must be a list of strings: {item!r}")

    item["flags"] = flags
    return item


def remove_from_list(lst: list[str], names: list[str]) -> list[str]:
    names_set = set(names)
    return [x for x in lst if x not in names_set]


def read_toml(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as e:
        raise FileNotFoundError(f"Config file not found: {path}") from e
    except OSError as e:
        raise type(e)(f"Cannot read {path}: {e}") from e

    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"Invalid TOML in {path}: {e}") from e


def deduplicate_keep_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []

    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)

    return out


def re_compile(pattern: str, flags: list[str] | None = None, *, source: str = "") -> re.Pattern:
    f = 0

    for name in (flags or []):
        if name not in FLAG_MAP:
            where = f" in {source}" if source else ""
            raise ValueError(f"Unknown regex flag '{name}'{where}")

        f |= FLAG_MAP[name]

    try:
        return re.compile(pattern, f)
    except re.error as e:
        where = f" in {source}" if source else ""
        raise ValueError(f"Invalid regex pattern{where}: {e}") from e


def load_runtime_config(user_configs: list[str | Path] | None = None) -> RuntimeConfig:
    """
    Loads packaged TOML config and applies user overlays.
    Overlays are applied in the order provided.
    """
    base_dir = res_files("secrets_hunter.config")
    base_files = [
        Path(str(base_dir / "patterns.toml")),
        Path(str(base_dir / "ignore.toml")),
    ]

    for bf in base_files:
        if not bf.exists():
            raise FileNotFoundError(f"Missing packaged config file: {bf}")

    overlay_files = [Path(p).expanduser().resolve() for p in (user_configs or [])]
    files = base_files + overlay_files

    # aggregated (raw)
    secret_patterns_by_name: dict[str, dict[str, Any]] = {}
    exclude_patterns_by_name: dict[str, dict[str, Any]] = {}
    exclude_keywords: list[str] = []
    secret_keywords: list[str] = []
    assignment_patterns: list[str] = []
    ignore_files: list[str] = []
    ignore_ext: list[str] = []
    ignore_dirs: list[str] = []

    for f in files:
        data = read_toml(f)

        # removals
        for name in require_string_list(data, "remove_secret_patterns", f):
            secret_patterns_by_name.pop(name, None)

        for name in require_string_list(data, "remove_exclude_patterns", f):
            exclude_patterns_by_name.pop(name, None)

        ignore_files = remove_from_list(
            ignore_files, require_string_list(data, "remove_ignore_files", f)
        )
        ignore_ext = remove_from_list(
            ignore_ext, require_string_list(data, "remove_ignore_extensions", f)
        )
        ignore_dirs = remove_from_list(
            ignore_dirs, require_string_list(data, "remove_ignore_dirs", f)
        )
        exclude_keywords = remove_from_list(
            exclude_keywords, require_string_list(data, "remove_exclude_keywords", f)
        )
        secret_keywords = remove_from_list(
            secret_keywords, require_string_list(data, "remove_secret_keywords", f)
        )
        assignment_patterns = remove_from_list(
            assignment_patterns, require_string_list(data, "remove_assignment_patterns", f)
        )

        # patterns
        for item in require_list(data, "secret_patterns", f):
            item = require_pattern_item(item, "secret_patterns", {"name", "pattern"}, f)
            secret_patterns_by_name[item["name"]] = {"pattern": item["pattern"], "flags": item["flags"]}

        for item in require_list(data, "exclude_patterns", f):
            item = require_pattern_item(item, "exclude_patterns", {"name", "pattern", "category"}, f)
            exclude_patterns_by_name[item["name"]] = item

        # lists
        exclude_keywords.extend(require_string_list(data, "exclude_keywords", f))
        secret_keywords.extend(require_string_list(data, "secret_keywords", f))
        assignment_patterns.extend(require_string_list(data, "assignment_patterns", f))

        # ignore
        ig = require_table(data.get("ignore"), "ignore", f)
        ignore_files.extend(require_string_list(ig, "files", f))
        ignore_ext.extend(require_string_list(ig, "extensions", f))
        ignore_dirs.extend(require_string_list(ig, "dirs", f))

    # deduplication
    exclude_keywords = deduplicate_keep_order(exclude_keywords)
    secret_keywords = deduplicate_keep_order(secret_keywords)
    assignment_patterns = deduplicate_keep_order(assignment_patterns)
    ignore_files = deduplicate_keep_order(ignore_files)
    ignore_ext = deduplicate_keep_order(ignore_ext)
    ignore_dirs = deduplicate_keep_order(ignore_dirs)

    # compile
    compiled_secret_patterns = {
        name: re_compile(v["pattern"], v.get("flags"), source=f"secret_patterns[{name}]")
        for name, v in secret_patterns_by_name.items()
    }

    compiled_exclude_patterns = [
        ExcludePattern(
            pattern=re_compile(ep["pattern"], ep.get("flags"), source=f"exclude_patterns[{ep['name']}]"),
            name=ep["name"],
            category=ep["category"]
        )
        for ep in exclude_patterns_by_name.values()
    ]

    compiled_assignment = [
        re_compile(p, source=f"assignment_patterns[{i}]")
        for i, p in enumerate(assignment_patterns)
    ]

    return RuntimeConfig(
        secret_patterns=compiled_secret_patterns,
        exclude_patterns=compiled_exclude_patterns,
        exclude_keywords=exclude_keywords,
        secret_keywords=secret_keywords,
        assignment_patterns=compiled_assignment,
        ignore_files=tuple(ignore_files),
        ignore_extensions=tuple(ignore_ext),
        ignore_dirs=tuple(ignore_dirs),
    )


CONFIG_CACHE: dict[str, RuntimeConfig] = {}


def _config_key(user_configs: list[str | Path] | None) -> str:
    if not user_configs:
        return ""

    paths = [str(Path(p).expanduser().resolve()) for p in user_configs]  # normalize
    return sha256("\n".join(paths).encode("utf-8")).hexdigest()


def get_runtime_config(user_configs: list[str | Path] | None = None, *, reload: bool = False) -> RuntimeConfig:
    """
    Cached accessor. Pass reload=True to force reloading.
    """
    key = _config_key(user_configs)

    if key not in CONFIG_CACHE or reload:
        CONFIG_CACHE[key] = load_runtime_config(user_configs=user_configs)

    return CONFIG_CACHE[key]
