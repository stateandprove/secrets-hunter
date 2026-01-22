import math
import string

from collections import Counter
from typing import Set

HEX_CHARS: Set[str] = set(string.hexdigits)
BASE64_CHARS: Set[str] = set(string.ascii_letters + string.digits) | {"+", "/", "="}


def calculate_shannon_entropy(input_string: str) -> float:
    entropy = 0.0

    if not input_string:
        return entropy

    counts = Counter(input_string)
    length = len(input_string)

    for count in counts.values():
        probability = count / length

        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy

def is_hex_string(s: str) -> bool:
    return bool(s) and all(c in HEX_CHARS for c in s)

def is_base64_string(s: str) -> bool:
    return bool(s) and all(c in BASE64_CHARS for c in s)
