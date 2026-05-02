import math
import re

from collections import Counter

HEX_RE = re.compile(r'^[0-9A-Fa-f]+$')
BASE64_RE = re.compile(r'^[A-Za-z0-9+/=]+$')
BASE64URL_RE = re.compile(r'^[A-Za-z0-9+/=_-]+$')

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
    return bool(s) and bool(HEX_RE.match(s))

def is_base64_string(s: str) -> bool:
    return bool(s) and bool(BASE64_RE.match(s))

def is_base64url_string(s: str) -> bool:
    return bool(s) and bool(BASE64URL_RE.match(s))
