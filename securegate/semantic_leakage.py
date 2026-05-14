import math
import os
import re
from typing import Iterable, List

from .config import load_policy


class SemanticLeakageDetector:
    def __init__(self) -> None:
        self.enabled = self._env_bool("SECUREGATE_SEMANTIC_LEAKAGE_ENABLED", True)
        self.threshold = self._env_float("SECUREGATE_SEMANTIC_LEAKAGE_THRESHOLD", 0.55)
        policy = load_policy()
        refs = policy.get("semantic_leakage_reference_texts", [])
        self.references: List[str] = refs if isinstance(refs, list) else []
        self._sbert_model = None
        self._sbert_available = False
        if self._env_bool("SECUREGATE_SBERT_ENABLED", False):
            self._try_init_sbert()

    def score(self, text: str) -> float:
        if not self.enabled or not text:
            return 0.0
        if self._sbert_available:
            return self._score_sbert(text)
        return self._score_jaccard(text, self.references)

    def is_high_risk(self, text: str) -> bool:
        return self.score(text) >= self.threshold

    def _score_sbert(self, text: str) -> float:
        # Optional higher quality mode when sentence-transformers is installed.
        if not self._sbert_model or not self.references:
            return 0.0
        vectors = self._sbert_model.encode([text, *self.references], normalize_embeddings=True)
        source = vectors[0]
        best = max(float(source @ ref_vec) for ref_vec in vectors[1:])
        return round(max(0.0, min(best, 1.0)), 3)

    @staticmethod
    def _score_jaccard(text: str, refs: Iterable[str]) -> float:
        source_tokens = set(re.findall(r"[a-z0-9]+", text.lower()))
        if not source_tokens:
            return 0.0
        best = 0.0
        for ref in refs:
            ref_tokens = set(re.findall(r"[a-z0-9]+", ref.lower()))
            if not ref_tokens:
                continue
            overlap = len(source_tokens.intersection(ref_tokens))
            union = len(source_tokens.union(ref_tokens))
            similarity = overlap / union if union else 0.0
            best = max(best, similarity)
        return round(best, 3)

    def _try_init_sbert(self) -> None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            return
        model_name = os.getenv("SECUREGATE_SBERT_MODEL", "all-MiniLM-L6-v2")
        try:
            self._sbert_model = SentenceTransformer(model_name)
            self._sbert_available = True
        except Exception:
            self._sbert_model = None
            self._sbert_available = False

    @staticmethod
    def _env_bool(name: str, default: bool) -> bool:
        raw = os.getenv(name)
        if raw is None:
            return default
        return raw.strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def _env_float(name: str, default: float) -> float:
        raw = os.getenv(name)
        if not raw:
            return default
        try:
            value = float(raw)
        except ValueError:
            return default
        if math.isnan(value):
            return default
        return value
