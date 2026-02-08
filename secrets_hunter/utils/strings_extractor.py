import re

from typing import List

from secrets_hunter.config import STRIP

class StringsExtractor:
    def __init__(self, assignment_patterns, min_token_length):
        self.assignment_patterns = assignment_patterns
        self.min_token_length = min_token_length

        # quoted strings (handles escapes)
        self._quoted_re = re.compile(r'"((?:\\.|[^"\\]){5,})"|\'((?:\\.|[^\'\\]){5,})\'|`((?:\\.|[^`\\]){5,})`')

        # any non-whitespace chunk with length >= min_token_length
        self._chunk_re = re.compile(rf'\S{{{min_token_length},}}')

    def assignment_map(self, line: str) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}

        for pattern in self.assignment_patterns:
            for match in pattern.finditer(line):
                var = match.group(1).lower()
                val = match.group(2).strip().strip(STRIP)
                out.setdefault(val, set()).add(var)

        return out

    def extract(self, line: str) -> List[str]:
        """Extract all potential strings from a line"""
        strings = []

        # 1) collect quoted strings + blank them out
        line_wo_quotes = line
        for m in self._quoted_re.finditer(line):
            s = m.group(1) or m.group(2) or m.group(3)
            if s:
                strings.append(s)
            # remove whole quoted span to avoid extracting them twice
            start, end = m.span()
            line_wo_quotes = line_wo_quotes[:start] + " " * (end - start) + line_wo_quotes[end:]

        # 2) collect other long chunks (unquoted)
        for chunk in self._chunk_re.findall(line_wo_quotes):
            cleaned = chunk.strip(STRIP)

            # If it's key=value or key:value, keep only RHS (value) when it's long enough
            extracted_value = None
            for sep in ("=", ":"):
                if sep in cleaned:
                    _, rhs = cleaned.split(sep, 1)
                    rhs = rhs.strip(STRIP)
                    rhs = rhs.lstrip("=")
                    if len(rhs) >= self.min_token_length:
                        extracted_value = rhs
                        break

            if extracted_value:
                strings.append(extracted_value)
            else:
                if len(cleaned) >= self.min_token_length:
                    strings.append(cleaned)

        seen = set()
        unique_strings = []
        for s in strings:
            if s not in seen:
                seen.add(s)
                unique_strings.append(s)

        return unique_strings
