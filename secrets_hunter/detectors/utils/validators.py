import re

from typing import Tuple


class FalsePositiveValidator:
    def __init__(self, exclude_patterns):
        self.exclude_patterns = exclude_patterns

    def is_valid(self, string: str) -> Tuple[bool, str]:
        """Check if string matches common false positive patterns"""
        string_lower = string.lower()
        rejected_by = ""

        for pattern in self.exclude_patterns:
            if re.search(pattern, string_lower):
                rejected_by = pattern.pattern
                return False, rejected_by

        return True, rejected_by
