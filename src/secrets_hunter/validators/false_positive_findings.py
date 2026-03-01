import re


class FalsePositiveFindingsValidator:
    def __init__(self, exclude_patterns, exclude_keywords, string_classifier):
        self.exclude_patterns = exclude_patterns
        self.exclude_keywords = exclude_keywords
        self.string_classifier = string_classifier

    def check_rejection_for_value(self, string: str) -> tuple[bool, str]:
        string_lower = string.lower()

        for pattern in self.exclude_patterns:
            if re.search(pattern, string_lower):
                rejected_by = pattern.pattern
                return True, rejected_by

        string_classification = self.string_classifier.classify(string)

        if string_classification.structured:
            return True, "String with English-like words"

        return False, ""

    def check_rejection_for_keywords(self, kws: list[str]) -> tuple[bool, str]:
        exclude = [k.lower() for k in self.exclude_keywords if k]

        for kw in kws:
            kw_lower = (kw or "").lower()

            for ex in exclude:
                if ex in kw_lower:
                    return True, ex

        return False, ""
