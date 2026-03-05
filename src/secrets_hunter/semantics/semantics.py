import re

from .bigrams import BIGRAM_MODEL
from .corpus import CORPUS

from secrets_hunter.models import StringClassification, StringKind


class StringClassifier:
    """
    Classifies a string as structured or random using two signals:

    1. Word match ratio — fraction of tokens found in the corpus
    2. Bigram score — how English-like the character transitions are
    """

    _RANDOM_BASELINE: float = sum(BIGRAM_MODEL.values()) / len(BIGRAM_MODEL)
    _BEST_BASELINE: float = max(BIGRAM_MODEL.values())

    def __init__(
        self,
        word_weight:   float = 0.6,
        bigram_weight: float = 0.4,
        threshold:     float = 0.43,
    ) -> None:
        self.word_weight   = word_weight
        self.bigram_weight = bigram_weight
        self.threshold     = threshold

    @staticmethod
    def split_tokens(s: str) -> list[str]:
        parts = re.split(r"[_\-./\s]+", s)
        tokens: list[str] = []

        for part in parts:
            if not part:
                continue

            p = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", part)
            p = re.sub(r"([a-z\d])([A-Z])", r"\1 \2", p)

            tokens.extend(t for t in p.split() if t)

        return tokens

    @staticmethod
    def word_match_ratio(s: str) -> float:
        tokens = StringClassifier.split_tokens(s)

        if not tokens:
            return 0.0

        return sum(1 for t in tokens if t.lower() in CORPUS) / len(tokens)

    @classmethod
    def bigram_score(cls, s: str) -> float:
        cleaned = re.sub(r"[^a-z]", "", s.lower())

        if len(cleaned) < 2:
            return 0.0

        pairs = [(cleaned[i], cleaned[i + 1]) for i in range(len(cleaned) - 1)]
        avg_log_prob = sum(BIGRAM_MODEL[pair] for pair in pairs) / len(pairs)
        score = (avg_log_prob - cls._RANDOM_BASELINE) / (cls._BEST_BASELINE - cls._RANDOM_BASELINE)

        return max(0.0, min(1.0, score))

    def classify(self, s: str) -> StringClassification:
        wmr = self.word_match_ratio(s)
        bgs = self.bigram_score(s)
        combined = self.word_weight * wmr + self.bigram_weight * bgs

        return StringClassification(
            string=s,
            tokens=self.split_tokens(s),
            word_match_ratio=round(wmr, 3),
            bigram_score=round(bgs, 3),
            combined_score=round(combined, 3),
            kind=StringKind.STRUCTURED if combined >= self.threshold else StringKind.RANDOM
        )
