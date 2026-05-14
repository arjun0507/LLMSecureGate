import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, List

from .config import load_policy
from .explainer import build_inbound_explanation, build_outbound_explanation
from .observability import LOGGER, METRICS
from .prompt_defense import PromptDefenseEngine
from .response_sanitizer import ResponseSanitizationEngine
from .schemas import PromptDefenseResult, ResponseSanitizationResult, StageTimings


@dataclass
class SecureGateResult:
    final_reply: str
    prompt_result: PromptDefenseResult
    response_result: ResponseSanitizationResult
    explanations: Dict[str, str]
    timings: StageTimings


class SecureGatePipeline:
    def __init__(self) -> None:
        self.prompt_engine = PromptDefenseEngine()
        self.response_engine = ResponseSanitizationEngine()
        self.policy = load_policy()

    async def process(
        self,
        prompt: str,
        llm_callable: Callable[[str], Awaitable[str]],
    ) -> SecureGateResult:
        start_total = time.perf_counter()
        METRICS.inc("requests.total")

        start_prompt = time.perf_counter()
        prompt_result = self.prompt_engine.inspect(prompt)
        prompt_ms = (time.perf_counter() - start_prompt) * 1000

        if prompt_result.blocked:
            blocked_reply = self.policy.get(
                "safe_refusal_message",
                "The request violates policy and cannot be processed.",
            )
            response_result = self.response_engine.sanitize(blocked_reply)
            timings = StageTimings(
                prompt_defense_ms=prompt_ms,
                llm_ms=0.0,
                response_sanitization_ms=0.0,
                total_ms=(time.perf_counter() - start_total) * 1000,
            )
            explanations = self._build_explanations(prompt_result, response_result)
            LOGGER.info(
                "securegate_request blocked=true inbound_score=%.3f outbound_score=%.3f",
                prompt_result.risk_score,
                response_result.risk_score,
            )
            return SecureGateResult(
                final_reply=response_result.sanitized_reply,
                prompt_result=prompt_result,
                response_result=response_result,
                explanations=explanations,
                timings=timings,
            )

        start_llm = time.perf_counter()
        raw_reply = await llm_callable(prompt_result.sanitized_prompt)
        llm_ms = (time.perf_counter() - start_llm) * 1000

        start_response = time.perf_counter()
        response_result = self.response_engine.sanitize(raw_reply)
        response_ms = (time.perf_counter() - start_response) * 1000

        timings = StageTimings(
            prompt_defense_ms=prompt_ms,
            llm_ms=llm_ms,
            response_sanitization_ms=response_ms,
            total_ms=(time.perf_counter() - start_total) * 1000,
        )
        explanations = self._build_explanations(prompt_result, response_result)
        LOGGER.info(
            "securegate_request blocked=false inbound_score=%.3f outbound_score=%.3f",
            prompt_result.risk_score,
            response_result.risk_score,
        )

        return SecureGateResult(
            final_reply=response_result.sanitized_reply,
            prompt_result=prompt_result,
            response_result=response_result,
            explanations=explanations,
            timings=timings,
        )

    @staticmethod
    def serialize_flags(result: PromptDefenseResult) -> List[Dict[str, object]]:
        return [
            {"label": item.label, "evidence": item.evidence, "severity": item.severity}
            for item in result.flags
        ]

    @staticmethod
    def serialize_redactions(result: ResponseSanitizationResult) -> List[Dict[str, str]]:
        return [
            {"label": item.label, "match": item.match, "replacement": item.replacement}
            for item in result.redactions
        ]

    @staticmethod
    def _build_explanations(
        prompt_result: PromptDefenseResult,
        response_result: ResponseSanitizationResult,
    ) -> Dict[str, str]:
        return {
            "inbound": build_inbound_explanation(prompt_result),
            "outbound": build_outbound_explanation(response_result),
        }
