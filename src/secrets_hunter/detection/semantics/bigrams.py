import math
import string

# Character bigram counts
# Sourced from Peter Norvig's analysis of the Google Books corpus.
# https://norvig.com/mayzner.html

BIGRAM_COUNTS: dict[str, int] = {
    "th": 1003, "he": 867, "in": 686, "er": 578, "an": 560, "re": 523,
    "on": 496, "at": 419, "en": 410, "nd": 381, "ti": 379, "es": 378,
    "or": 360, "te": 340, "of": 331, "ed": 329, "is": 318, "it": 317,
    "al": 307, "ar": 303, "st": 297, "to": 294, "nt": 294, "ng": 269,
    "se": 263, "ha": 261, "as": 246, "ou": 245, "io": 235, "le": 234,
    "ve": 233, "co": 224, "me": 224, "de": 216, "hi": 215, "ri": 205,
    "ro": 205, "ic": 197, "ne": 195, "ea": 194, "ra": 193, "ce": 184,
    "li": 176, "ch": 169, "ll": 163, "be": 162, "ma": 159, "si": 155,
    "om": 154, "ur": 153
}


def _build_bigram_model() -> dict[tuple[str, str], float]:
    """Return a log-probability table for all 676 lowercase letter pairs."""
    n = len(string.ascii_lowercase)
    total = sum(BIGRAM_COUNTS.values()) + n ** 2
    table: dict[tuple[str, str], float] = {}
    log_total = math.log(total)

    for a in string.ascii_lowercase:
        for b in string.ascii_lowercase:
            c = BIGRAM_COUNTS.get(a + b, 0) + 1
            table[(a, b)] = math.log(c) - log_total

    return table


BIGRAM_MODEL: dict[tuple[str, str], float] = _build_bigram_model()
