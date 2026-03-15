import re

from dataclasses import dataclass


@dataclass(frozen=True)
class ExcludePattern:
    pattern: re.Pattern
    name: str
    category: str


@dataclass(frozen=True)
class RuntimeConfig:
    secret_patterns:     dict[str, re.Pattern]
    exclude_patterns:    list[ExcludePattern]
    exclude_keywords:    list[str]
    secret_keywords:     list[str]
    assignment_patterns: list[re.Pattern]
    ignore_files:        tuple[str, ...]
    ignore_extensions:   tuple[str, ...]
    ignore_dirs:         tuple[str, ...]
