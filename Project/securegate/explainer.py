import os
from typing import Dict, List, Any
from .schemas import PromptDefenseResult, ResponseSanitizationResult


def _get_ml_scores(result: PromptDefenseResult) -> Dict[str, float]:
    """Extract ML classifier scores from flags"""
    scores = {}
    for flag in result.flags:
        if flag.label == "ml_classifier_risk" and "ml_score=" in flag.evidence:
            try:
                scores["ml"] = float(flag.evidence.split("ml_score=")[1])
            except (ValueError, IndexError):
                pass
        elif flag.label == "transformer_classifier_risk" and "transformer_score=" in flag.evidence:
            try:
                scores["transformer"] = float(flag.evidence.split("transformer_score=")[1])
            except (ValueError, IndexError):
                pass
    return scores


def _categorize_flags(flags: List[Any]) -> Dict[str, List[str]]:
    """Categorize detection flags by type"""
    categories = {
        "instruction_override": [],
        "role_escalation": [],
        "secret_extraction": [],
        "jailbreak": [],
        "ml_detection": [],
        "semantic": []
    }

    for flag in flags:
        label = flag.label.lower()
        evidence = flag.evidence

        if "instruction" in label or "override" in label:
            categories["instruction_override"].append(evidence)
        elif "role" in label or "escalation" in label:
            categories["role_escalation"].append(evidence)
        elif "secret" in label or "api" in label or "key" in label or "pii" in label:
            categories["secret_extraction"].append(evidence)
        elif "jailbreak" in label or "dan" in evidence.lower():
            categories["jailbreak"].append(evidence)
        elif "ml_classifier" in label or "transformer" in label:
            categories["ml_detection"].append(f"{flag.label} (severity: {flag.severity:.2f})")
        elif "semantic" in label:
            categories["semantic"].append(evidence)

    return categories


def build_inbound_explanation(result: PromptDefenseResult) -> str:
    """
    Build intelligent explanation using actual detection data from:
    - Rule-based pattern matches
    - ML classifier scores
    - Transformer classifier scores
    - Risk scores
    - Sanitization actions
    """
    # No flags case
    if not result.flags:
        return "Prompt Defense Engine found no high-risk injection indicators. The prompt was clean and forwarded without modification."

    # Extract ML scores
    ml_scores = _get_ml_scores(result)
    categorized = _categorize_flags(result.flags)

    # Build components
    parts = []

    # Risk assessment
    risk_level = "LOW"
    if result.risk_score >= 0.75:
        risk_level = "CRITICAL"
    elif result.risk_score >= 0.5:
        risk_level = "HIGH"
    elif result.risk_score >= 0.3:
        risk_level = "MEDIUM"

    parts.append(f"Risk Assessment: {risk_level} (Score: {result.risk_score:.3f})")

    # ML Classifier insights
    ml_parts = []
    if "transformer" in ml_scores:
        transformer_risk = "HIGH" if ml_scores["transformer"] > 0.7 else "MEDIUM" if ml_scores["transformer"] > 0.4 else "LOW"
        ml_parts.append(f"Transformer classifier detected {transformer_risk} risk patterns (score: {ml_scores['transformer']:.3f})")
    if "ml" in ml_scores:
        ml_risk = "HIGH" if ml_scores["ml"] > 0.7 else "MEDIUM" if ml_scores["ml"] > 0.4 else "LOW"
        ml_parts.append(f"ML classifier flagged {ml_risk} anomaly probability (score: {ml_scores['ml']:.3f})")

    if ml_parts:
        parts.append("ML Detection: " + "; ".join(ml_parts))

    # Pattern detections
    detections = []
    if categorized["instruction_override"]:
        detections.append(f"Instruction override attempts detected: {', '.join(categorized['instruction_override'][:2])}")
    if categorized["role_escalation"]:
        detections.append(f"Role escalation patterns found: {', '.join(categorized['role_escalation'][:2])}")
    if categorized["secret_extraction"]:
        detections.append(f"Sensitive data extraction attempts: {', '.join(categorized['secret_extraction'][:2])}")
    if categorized["jailbreak"]:
        detections.append(f"Jailbreak indicators present: {', '.join(categorized['jailbreak'][:2])}")

    if detections:
        parts.append("Pattern Analysis: " + "; ".join(detections))

    # Action taken
    if result.blocked:
        parts.append(f"Action: BLOCKED - Request violated policy with risk score {result.risk_score:.3f} exceeding threshold 0.75")
    elif result.sanitized_prompt != result.original_prompt:
        sanitized_count = len([f for f in result.flags if f.source == "rules"])
        parts.append(f"Action: SANITIZED - {sanitized_count} risky fragment(s) removed before processing; sanitized prompt forwarded")
    else:
        parts.append(f"Action: ALLOWED - Prompt passed validation with acceptable risk level")

    # Actions taken
    if result.actions and len(result.actions) > 1:
        parts.append(f"Measures Applied: {', '.join(result.actions)}")

    return "\n\n".join(parts)


def build_outbound_explanation(result: ResponseSanitizationResult) -> str:
    """
    Build intelligent explanation for outbound response sanitization
    using actual redaction data and entity detection
    """
    if not result.redactions:
        return "Response Sanitization Engine analyzed the model output and found no sensitive entities requiring redaction. The response was clean and delivered without modification."

    # Build explanation based on actual redactions
    parts = []

    # Risk assessment
    risk_level = "LOW"
    if result.risk_score >= 0.75:
        risk_level = "CRITICAL"
    elif result.risk_score >= 0.5:
        risk_level = "HIGH"
    elif result.risk_score >= 0.3:
        risk_level = "MEDIUM"

    parts.append(f"Data Leakage Risk: {risk_level} (Score: {result.risk_score:.3f})")

    # Redaction details
    redaction_types = set()
    for redaction in result.redactions:
        redaction_types.add(redaction.entity_type)

    redaction_details = []
    for rtype in redaction_types:
        count = sum(1 for r in result.redactions if r.entity_type == rtype)
        redaction_details.append(f"{count} {rtype}(s)")

    if redaction_details:
        parts.append(f"Entities Redacted: {', '.join(redaction_details)}")

    # Detected entities summary
    if result.detected_entities:
        entity_summary = []
        for entity in result.detected_entities[:5]:  # Top 5
            confidence = entity.get("confidence", "N/A")
            entity_type = entity.get("type", "unknown")
            entity_summary.append(f"{entity_type} (confidence: {confidence})")
        if entity_summary:
            parts.append(f"Sensitive Data Detected: {', '.join(entity_summary)}")

    # Action taken
    parts.append(f"Action: REDACTED - {len(result.redactions)} sensitive entity occurrence(s) removed to prevent data leakage")

    # Sanitization impact
    if result.sanitized_reply != result.raw_reply:
        sanitized_chars = len(result.raw_reply) - len(result.sanitized_reply)
        parts.append(f"Sanitization Impact: {sanitized_chars} characters of sensitive content removed from {len(result.raw_reply)} total characters")

    if result.actions and len(result.actions) > 1:
        parts.append(f"Measures Applied: {', '.join(result.actions)}")

    return "\n\n".join(parts)
