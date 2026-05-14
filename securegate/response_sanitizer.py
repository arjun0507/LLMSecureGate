import os
import re
from typing import List, Pattern, Tuple

from .config import load_policy
from .observability import METRICS
from .semantic_leakage import SemanticLeakageDetector
from .schemas import RedactionItem, ResponseSanitizationResult


class ResponseSanitizationEngine:
    def __init__(self) -> None:
        self.enabled = self._env_bool("SECUREGATE_OUTBOUND_ENABLED", True)
        self.redaction_token = os.getenv("SECUREGATE_REDACTION_TOKEN", "[REDACTED]")
        self.enable_presidio = self._env_bool("SECUREGATE_PRESIDIO_ENABLED", False)
        self.semantic_detector = SemanticLeakageDetector()
        policy = load_policy()
        self.policy_replacements = policy.get("redaction_replacements", {})
        self.patterns: List[Tuple[str, Pattern[str]]] = [
            ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
            ("phone", re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){1}\d{3}[-.\s]?\d{4}\b")),
            ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
            ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,16}\b")),
            ("api_key", re.compile(r"\b(?:sk|pk|api|key)_[A-Za-z0-9_]{12,}\b", re.I)),
            ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b", re.I)),
            ("password_assignment", re.compile(r"\b(password|passwd)\s*[:=]\s*\S+", re.I)),
        ]
        self._presidio_analyzer = None
        if self.enable_presidio:
            self._init_presidio()

    def sanitize(self, text: str) -> ResponseSanitizationResult:
        if not self.enabled:
            return ResponseSanitizationResult(
                raw_reply=text,
                sanitized_reply=text,
                redactions=[],
                risk_score=0.0,
                actions=["outbound_disabled"],
            )

        redactions: List[RedactionItem] = []
        detected_entities: List[str] = []
        sanitized = text

        for label, pattern in self.patterns:
            for match in pattern.finditer(sanitized):
                matched_text = match.group(0)
                replacement = self._replacement_for(label)
                redactions.append(
                    RedactionItem(label=label, match=matched_text, replacement=replacement)
                )
                detected_entities.append(label)
            sanitized = pattern.sub(self._replacement_for(label), sanitized)

        for item in self._presidio_redactions(sanitized):
            redactions.append(item)
            detected_entities.append(item.label)
            sanitized = sanitized.replace(item.match, item.replacement)

        semantic_score = self.semantic_detector.score(sanitized)
        if semantic_score >= self.semantic_detector.threshold:
            warning = "Potential semantic leakage was detected and partially masked."
            redactions.append(
                RedactionItem(
                    label="semantic_leakage",
                    match=sanitized,
                    replacement=warning,
                )
            )
            detected_entities.append("semantic_leakage")
            sanitized = warning

        risk_score = min(len(redactions) * 0.2, 1.0)
        actions = ["response_scanned"]
        if redactions:
            actions.append("sensitive_entities_redacted")
            METRICS.inc("outbound.redactions", len(redactions))
        if self.enable_presidio:
            actions.append("presidio_scan_enabled")
        if "semantic_leakage" in detected_entities:
            actions.append("semantic_leakage_masked")
        if detected_entities:
            METRICS.inc("outbound.detected_entities", len(detected_entities))

        return ResponseSanitizationResult(
            raw_reply=text,
            sanitized_reply=sanitized,
            redactions=redactions,
            risk_score=round(risk_score, 3),
            actions=actions,
            detected_entities=sorted(set(detected_entities)),
        )

    def _presidio_redactions(self, text: str) -> List[RedactionItem]:
        if not self._presidio_analyzer:
            return []
        try:
            findings = self._presidio_analyzer.analyze(text=text, language="en")
        except Exception:
            return []
        redactions: List[RedactionItem] = []
        for finding in findings:
            match = text[finding.start:finding.end]
            label = finding.entity_type.lower()
            redactions.append(
                RedactionItem(
                    label=label,
                    match=match,
                    replacement=self._replacement_for(label),
                )
            )
        return redactions

    def _init_presidio(self) -> None:
        try:
            from presidio_analyzer import AnalyzerEngine
        except ImportError:
            self._presidio_analyzer = None
            return
        try:
            self._presidio_analyzer = AnalyzerEngine()
        except Exception:
            self._presidio_analyzer = None

    def _replacement_for(self, label: str) -> str:
        policy_replacement = self.policy_replacements.get(label)
        if isinstance(policy_replacement, str):
            return policy_replacement
        return f"{self.redaction_token}:{label.upper()}"

    @staticmethod
    def _env_bool(name: str, default: bool) -> bool:
        raw = os.getenv(name)
        if raw is None:
            return default
        return raw.strip().lower() in {"1", "true", "yes", "on"}
