import re

from typing import Any, Iterable, Mapping

from secrets_hunter.reporters.console_base import BaseConsoleReporter
from secrets_hunter.config.loader import FLAG_MAP
from secrets_hunter.config import RuntimeConfig


class RuntimeConfigReporter(BaseConsoleReporter):
    SECTIONS = {
        "secret_patterns": ("dict", None),
        "exclude_patterns": ("list", None),
        "secret_keywords": ("simple_list", None),
        "exclude_keywords": ("simple_list", None),
        "assignment_patterns": ("list", None),
        "ignore_extensions": ("compact_list", 6),
        "ignore_dirs": ("compact_list", 4),
    }

    @staticmethod
    def should_show(k: str, sections) -> bool:
        return not sections or k in sections

    @staticmethod
    def add_section(lines: list, title: str) -> None:
        lines.append(f"\n{title}")
        lines.append("-" * RuntimeConfigReporter.WIDTH)

    @staticmethod
    def re_to_str(p: re.Pattern) -> str:
        names = [name for name, bit in FLAG_MAP.items() if p.flags & bit]

        if names:
            return f"/{p.pattern}/  flags={'|'.join(names)}"

        return f"/{p.pattern}/"

    @staticmethod
    def as_mapping(obj: Any) -> Mapping[str, Any]:
        if isinstance(obj, Mapping):
            return obj

        d = getattr(obj, "__dict__", None)

        if isinstance(d, dict):
            return d

        return {"value": obj}

    @staticmethod
    def pretty_runtime_cfg(runtime_cfg: RuntimeConfig, sections: list[str] | None = None) -> None:
        cfg = RuntimeConfigReporter.as_mapping(runtime_cfg)
        lines = ["Scanner Runtime Configuration", "─" * RuntimeConfigReporter.WIDTH]

        for key, (fmt_type, cols) in RuntimeConfigReporter.SECTIONS.items():
            if not RuntimeConfigReporter.should_show(key, sections):
                continue

            val = cfg.get(key)

            if val is None:
                continue

            if fmt_type == "dict" and isinstance(val, Mapping):
                RuntimeConfigReporter.add_section(lines, f"{key} ({len(val)})")

                for name in sorted(val.keys(), key=lambda x: x.lower()):
                    pat = val[name]

                    if isinstance(pat, re.Pattern):
                        lines.append(f"  - {name}: {RuntimeConfigReporter.re_to_str(pat)}")
                    else:
                        lines.append(f"  - {name}: {pat!r}")

            elif fmt_type == "list" and isinstance(val, Iterable) and not isinstance(val, (str, bytes, Mapping)):
                items = list(val)
                RuntimeConfigReporter.add_section(lines, f"{key} ({len(items)})")

                for item in items:
                    lines.append(
                        f"  - {RuntimeConfigReporter.re_to_str(item) if isinstance(item, re.Pattern) else item!r}"
                    )

            elif fmt_type == "simple_list" and isinstance(val, Iterable) and not isinstance(val, (str, bytes, Mapping)):
                items = sorted([str(x) for x in val], key=lambda x: x.lower())
                RuntimeConfigReporter.add_section(lines, f"{key} ({len(items)})")

                for x in items:
                    lines.append(f"  - {x}")

            elif fmt_type == "compact_list" and isinstance(val, (set, frozenset, list, tuple)):
                items = sorted([str(x) for x in val], key=lambda x: x.lower())
                RuntimeConfigReporter.add_section(lines, f"{key} ({len(items)})")

                for i in range(0, len(items), cols):
                    chunk = ", ".join(items[i: i + cols])
                    lines.append(f"  - {chunk}")

        print("\n".join(lines) + "\n")
