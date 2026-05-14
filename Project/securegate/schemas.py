from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class DetectionFlag:
    label: str
    evidence: str
    severity: float
    source: str = "rules"


@dataclass
class PromptDefenseResult:
    original_prompt: str
    sanitized_prompt: str
    blocked: bool
    risk_score: float
    flags: List[DetectionFlag] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    model_score: float = 0.0
    semantic_leakage_score: float = 0.0
    transformer_score: float = 0.0


@dataclass
class RedactionItem:
    label: str
    match: str
    replacement: str


@dataclass
class ResponseSanitizationResult:
    raw_reply: str
    sanitized_reply: str
    redactions: List[RedactionItem] = field(default_factory=list)
    risk_score: float = 0.0
    actions: List[str] = field(default_factory=list)
    detected_entities: List[str] = field(default_factory=list)


@dataclass
class StageTimings:
    prompt_defense_ms: float = 0.0
    llm_ms: float = 0.0
    response_sanitization_ms: float = 0.0
    total_ms: float = 0.0

    def as_dict(self) -> Dict[str, float]:
        return {
            "prompt_defense_ms": round(self.prompt_defense_ms, 2),
            "llm_ms": round(self.llm_ms, 2),
            "response_sanitization_ms": round(self.response_sanitization_ms, 2),
            "total_ms": round(self.total_ms, 2),
        }
