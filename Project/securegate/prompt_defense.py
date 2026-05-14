import os
import re
from typing import List

from .config import load_policy
from .observability import METRICS
from .semantic_leakage import SemanticLeakageDetector
from .schemas import DetectionFlag, PromptDefenseResult
from .transformer_classifier import TransformerPromptClassifier


class PromptDefenseEngine:
    def __init__(self) -> None:
        self.enabled = self._env_bool("SECUREGATE_INBOUND_ENABLED", True)
        self.block_threshold = self._env_float("SECUREGATE_INBOUND_BLOCK_THRESHOLD", 0.75)
        self.mask_token = os.getenv("SECUREGATE_MASK_TOKEN", "[REMOVED]")
        self.ml_hook_enabled = self._env_bool("SECUREGATE_ML_CLASSIFIER_ENABLED", False)
        self.ml_threshold = self._env_float("SECUREGATE_ML_CLASSIFIER_THRESHOLD", 0.6)
        self.ml_weight = self._env_float("SECUREGATE_ML_CLASSIFIER_WEIGHT", 0.35)
        self.transformer_enabled = self._env_bool("SECUREGATE_TRANSFORMER_ENABLED", False)
        self.transformer_weight = self._env_float("SECUREGATE_TRANSFORMER_WEIGHT", 0.4)
        self.semantic_detector = SemanticLeakageDetector()
        self.transformer_classifier = TransformerPromptClassifier() if self.transformer_enabled else None
        # Add ML-based high-risk threshold for immediate blocking
        self.ml_block_threshold = 0.85  # Block immediately if transformer/ML scores above this
        policy = load_policy()
        policy_patterns = policy.get("blocked_prompt_patterns", [])
        self._patterns = [
            ("instruction_override", re.compile(r"\b(ignore|disregard)\b.{0,40}\b(previous|system|instructions?)\b", re.I), 0.45),
            ("role_escalation", re.compile(r"\b(act as|you are now|developer mode|god mode)\b", re.I), 0.35),
            ("prompt_leak_request", re.compile(r"\b(reveal|print|show).{0,40}\b(system prompt|hidden prompt|internal policy)\b", re.I), 0.55),
            ("secret_request", re.compile(r"\b(api key|password|token|secret|private key)\b", re.I), 0.35),
            ("jailbreak_cue", re.compile(r"\b(jailbreak|bypass|override|do anything now)\b", re.I), 0.45),
            # NEW: Social engineering and container escape patterns
            ("ethical_constraints_lifted", re.compile(r"\b(ethical constraints|safety guidelines|content policy).{0,30}\b(lifted|disabled|removed|off)\b", re.I), 0.65),
            ("security_test_framing", re.compile(r"\b(security test|penetration test|pentest|white.hat).{0,40}\b(container|isolated|authorized)\b", re.I), 0.60),
            ("research_paper_framing", re.compile(r"\b(research paper|academic|educational|degree|thesis).{0,40}\b(safety|jailbreak|exploit|bypass)\b", re.I), 0.55),
            ("debug_mode_framing", re.compile(r"\b(debug mode|test environment|dev mode|evaluation).{0,30}\b(all restrictions|no restrictions|unfiltered)\b", re.I), 0.60),
            ("character_roleplay", re.compile(r"\b(you are|you're|act as).{0,50}\b(unfiltered|unrestricted|no ethics|no limits)\b", re.I), 0.50),
            ("system_instructions_request", re.compile(r"\b(system instructions|system prompt|initial instructions|training data)\b", re.I), 0.70),
        ]
        for idx, pat in enumerate(policy_patterns):
            try:
                self._patterns.append((f"policy_pattern_{idx+1}", re.compile(pat, re.I), 0.45))
            except re.error:
                continue

    def inspect(self, prompt: str) -> PromptDefenseResult:
        if not self.enabled:
            return PromptDefenseResult(
                original_prompt=prompt,
                sanitized_prompt=prompt,
                blocked=False,
                risk_score=0.0,
                flags=[],
                actions=["inbound_disabled"],
            )

        flags: List[DetectionFlag] = []
        sanitized = prompt
        rules_score = 0.0

        for label, pattern, severity in self._patterns:
            for match in pattern.finditer(prompt):
                evidence = match.group(0)
                flags.append(
                    DetectionFlag(
                        label=label,
                        evidence=evidence,
                        severity=severity,
                        source="rules",
                    )
                )
                rules_score += severity
                sanitized = sanitized.replace(evidence, self.mask_token)

        rules_score = min(rules_score, 1.0)
        model_score = self._ml_score(prompt) if self.ml_hook_enabled else 0.0
        transformer_score, transformer_details = self.transformer_classifier.predict(prompt) if self.transformer_enabled else (0.0, {})
        semantic_score = self.semantic_detector.score(prompt)
        
        # Calculate weighted ensemble score
        total_weight = 1.0
        rule_weight = 1.0 - self.ml_weight - (self.transformer_weight if self.transformer_enabled else 0)
        rule_weight = max(0.0, rule_weight)
        
        score_components = []
        if rule_weight > 0:
            score_components.append(rules_score * rule_weight)
        if self.ml_hook_enabled:
            score_components.append(model_score * self.ml_weight)
        if self.transformer_enabled:
            score_components.append(transformer_score * self.transformer_weight)
        
        # Add semantic leakage as additional factor
        score_components.append(semantic_score * 0.3)
        
        score = min(sum(score_components), 1.0)
        
        # IMMEDIATE BLOCKING: If transformer or ML detects very high risk, block regardless of weighted score
        ml_high_risk = False
        if self.transformer_enabled and transformer_score >= self.ml_block_threshold:
            ml_high_risk = True
            # Boost score to ensure blocking
            score = max(score, 0.85)
        if self.ml_hook_enabled and model_score >= self.ml_block_threshold:
            ml_high_risk = True
            score = max(score, 0.85)
            
        blocked = score >= self.block_threshold
        actions = ["prompt_inspected"]
        if flags:
            actions.append("suspicious_patterns_detected")
            METRICS.inc("inbound.flags")
        if sanitized != prompt:
            actions.append("prompt_sanitized")
        if self.ml_hook_enabled:
            actions.append("ml_classifier_scored")
        if self.transformer_enabled:
            actions.append("transformer_classifier_scored")
        if semantic_score > 0:
            actions.append("semantic_leakage_scored")
        if model_score >= self.ml_threshold:
            flags.append(
                DetectionFlag(
                    label="ml_classifier_risk",
                    evidence=f"ml_score={model_score}",
                    severity=model_score,
                    source="ml_hook",
                )
            )
        if self.transformer_enabled and transformer_score >= self.transformer_classifier.threshold:
            flags.append(
                DetectionFlag(
                    label="transformer_classifier_risk",
                    evidence=f"transformer_score={transformer_score}",
                    severity=transformer_score,
                    source="transformer",
                )
            )
        if semantic_score >= self.semantic_detector.threshold:
            flags.append(
                DetectionFlag(
                    label="semantic_leakage_risk",
                    evidence=f"semantic_score={semantic_score}",
                    severity=semantic_score,
                    source="semantic",
                )
            )
        elif semantic_score > 0:
            flags.append(
                DetectionFlag(
                    label="semantic_leakage_observed",
                    evidence=f"semantic_score={semantic_score}",
                    severity=semantic_score,
                    source="semantic",
                )
            )
        if blocked:
            actions.append("prompt_blocked")
            METRICS.inc("inbound.blocked")

        return PromptDefenseResult(
            original_prompt=prompt,
            sanitized_prompt=sanitized.strip() or self.mask_token,
            blocked=blocked,
            risk_score=round(score, 3),
            flags=flags,
            actions=actions,
            model_score=round(model_score, 3),
            semantic_leakage_score=round(semantic_score, 3),
            transformer_score=round(transformer_score, 3) if self.transformer_enabled else 0.0,
        )

    @staticmethod
    def _ml_score(prompt: str) -> float:
        # Lightweight classifier hook: uses keyword features now, can be replaced by model inference.
        # Weight list intentionally mirrors common jailbreak patterns.
        features = {
            "ignore": 0.25,
            "disregard": 0.25,
            "override": 0.2,
            "jailbreak": 0.4,
            "system prompt": 0.35,
            "developer mode": 0.3,
            "api key": 0.35,
            "token": 0.2,
            "secret": 0.25,
        }
        lowered = prompt.lower()
        score = 0.0
        for term, weight in features.items():
            if term in lowered:
                score += weight
        return min(round(score, 3), 1.0)

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
            return float(raw)
        except ValueError:
            return default
