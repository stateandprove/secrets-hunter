import re

from secrets_hunter.models import Finding, StringSource
from secrets_hunter.models.config import ExcludePattern

# Special patterns
PUBLIC_PEM = ExcludePattern(name="Public", category="Key", pattern=re.compile("PUBLIC"))
CERT = ExcludePattern(name="Public", category="Certificate", pattern=re.compile("CERTIFICATE"))
SEMANTICS = ExcludePattern(name="Semantics -", category="string with English-like words", pattern=re.compile(''))


class FalsePositiveFindingsValidator:
    def __init__(self, exclude_patterns, exclude_keywords, string_semantics_classifier):
        self.exclude_patterns = exclude_patterns
        self.exclude_keywords = exclude_keywords
        self.string_classifier = string_semantics_classifier

    @staticmethod
    def check_rejection_for_pem_header(pem_header: str) -> tuple[bool, ExcludePattern | None]:
        if re.search(PUBLIC_PEM.pattern, pem_header):
            return True, PUBLIC_PEM

        if re.search(CERT.pattern, pem_header):
            return True, CERT

        return False, None

    @staticmethod
    def check_rejection_for_db_conn_string(db_conn_string: str) -> tuple[bool, ExcludePattern | None]:
        return False, None

    def check_rejection_for_generic_string(self, finding: Finding) -> tuple[bool, ExcludePattern | None]:
        string = finding.match
        string_lower = string.lower()

        for exclude_pattern in self.exclude_patterns:
            pattern = exclude_pattern.pattern

            if re.search(pattern, string_lower):
                if pattern.pattern == "test" and "sk_test" in string_lower:
                    continue

                return True, exclude_pattern

        string_semantics_classification = self.string_classifier.classify(string)

        if string_semantics_classification.structured:
            return True, SEMANTICS

        return False, None

    def check_rejection_for_finding_value(self, finding: Finding) -> tuple[bool, ExcludePattern | None]:
        match = finding.match

        if finding.source is StringSource.PEM_HEADER:
            return self.check_rejection_for_pem_header(match)
        elif finding.source is StringSource.DB_CONNECTION:
            return self.check_rejection_for_db_conn_string(match)

        return self.check_rejection_for_generic_string(finding)

    def check_rejection_for_keywords(self, kws: list[str]) -> tuple[bool, str]:
        exclude = [k.lower() for k in self.exclude_keywords if k]

        for kw in kws:
            kw_lower = (kw or "").lower()

            for ex in exclude:
                if ex in kw_lower:
                    return True, ex

        return False, ""
