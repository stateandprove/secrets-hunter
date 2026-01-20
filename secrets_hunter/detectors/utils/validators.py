import re


class FalsePositiveValidator:
    def __init__(self, exclude_patterns):
        self.exclude_patterns = exclude_patterns

    def is_valid(self, string: str) -> bool:
        """Check if string matches common false positive patterns"""
        string_lower = string.lower()

        for pattern in self.exclude_patterns:
            if re.search(pattern, string_lower):
                return False

        return True


class MinLengthValidator:
    def __init__(self, min_string_length):
        self.min_string_length = min_string_length

    def is_valid(self, string: str) -> bool:
        return len(string) >= self.min_string_length
