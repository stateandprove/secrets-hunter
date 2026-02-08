import re

from typing import Tuple, List


class FalsePositiveValidator:
    def __init__(self, exclude_patterns, exclude_keywords):
        self.exclude_patterns = exclude_patterns
        self.exclude_keywords = exclude_keywords

    def check_rejection_for_value(self, string: str) -> Tuple[bool, str]:
        string_lower = string.lower()

        for pattern in self.exclude_patterns:
            if re.search(pattern, string_lower):
                rejected_by = pattern.pattern
                return True, rejected_by

        return False, ""

    def check_rejection_for_keywords(self, kws: List[str]) -> Tuple[bool, str]:
        exclude = [k.lower() for k in self.exclude_keywords if k]

        for kw in kws:
            kw_lower = (kw or "").lower()

            for ex in exclude:
                if ex in kw_lower:
                    return True, ex

        return False, ""
