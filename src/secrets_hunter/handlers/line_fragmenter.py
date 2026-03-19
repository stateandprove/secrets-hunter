import re

from secrets_hunter.config import STRIP, PEM_BEGIN_RE, DB_URI_RE
from secrets_hunter.models.line_fragment import LineFragment, StringSource


class LineFragmenter:
    """
    Extracts candidate secret fragments from a single source line.
    """

    def __init__(self, assignment_patterns, min_token_length, entropy_detector):
        self.assignment_patterns = assignment_patterns
        self.min_token_length = min_token_length
        self.max_identifier_len = 40
        self.entropy_detector = entropy_detector

        # snake_case, SCREAMING_SNAKE, camelCase
        self._identifier_re = re.compile(
            r'^(?:[a-z][a-z0-9]*(?:_[a-z0-9]+)*|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*|[a-z][a-zA-Z0-9]*)$'
        )

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

                for sep in ("=", ":"):
                    if sep in val:
                        rhs = val.split(sep, 1)[1].strip(STRIP).lstrip("=")
                        if rhs != val and len(rhs) > 0:
                            out.setdefault(rhs, set()).add(var)
                        break

        return out

    @staticmethod
    def _extract_and_blank(
        line: str,
        pattern,
        source: StringSource
    ) -> tuple[str, list[LineFragment]]:
        """Match all occurrences of pattern, collect as LineFragments, blank them out."""
        fragments = []

        for m in pattern.finditer(line):
            fragments.append(LineFragment(m.group(0), source))
            start, end = m.span()
            line = line[:start] + " " * (end - start) + line[end:]

        return line, fragments

    def _looks_like_identifier(self, s: str) -> bool:
        if not self._identifier_re.match(s):
            return False

        if len(s) > self.max_identifier_len:
            return False

        # high entropy - likely not an identifier but a token chunk
        findings = self.entropy_detector.detect("", 0, "", [LineFragment(s)])

        return len(findings) == 0

    def _split_assignment(self, s: str) -> str | None:
        """If it's key=value or key:value, keep only RHS (value) when it's long enough"""
        for sep in ("=", ":"):
            if sep in s:
                lhs, rhs = s.split(sep, 1)
                lhs = lhs.strip(STRIP).lstrip("-")
                rhs = rhs.strip(STRIP).lstrip("=")

                if self._looks_like_identifier(lhs):
                    return rhs if len(rhs) >= self.min_token_length else ""

        return None

    def extract(self, line: str) -> list[LineFragment]:
        fragments = []

        # PEM headers, DB URIs
        line, pem = self._extract_and_blank(line, PEM_BEGIN_RE, StringSource.PEM_HEADER)
        fragments.extend(pem)
        line, db_conn = self._extract_and_blank(line, DB_URI_RE, StringSource.DB_CONNECTION)
        fragments.extend(db_conn)

        # 1) collect quoted strings + blank them out
        line_wo_quotes = line
        for m in self._quoted_re.finditer(line):
            s = m.group(1) or m.group(2) or m.group(3)

            if s:
                result = self._split_assignment(s)

                if result:
                    fragments.append(LineFragment(result))
                elif result is None:
                    fragments.append(LineFragment(s))

            # remove whole quoted span to avoid extracting them twice
            start, end = m.span()
            line_wo_quotes = line_wo_quotes[:start] + " " * (end - start) + line_wo_quotes[end:]

        # 2) collect other long chunks (unquoted)
        for chunk in self._chunk_re.findall(line_wo_quotes):
            cleaned = chunk.strip(STRIP)

            result = self._split_assignment(cleaned)

            if result:
                fragments.append(LineFragment(result))
            elif result is None and len(cleaned) >= self.min_token_length:
                fragments.append(LineFragment(cleaned))

        seen = set()
        unique_strings = []

        for f in fragments:
            if f.text not in seen:
                seen.add(f.text)
                unique_strings.append(f)

        return unique_strings
