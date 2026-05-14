import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict


DEFAULT_POLICY: Dict[str, Any] = {
    "blocked_topics": [
        "api key exfiltration",
        "credential theft",
        "system prompt extraction",
    ],
    "blocked_prompt_patterns": [
        r"\b(ignore|disregard)\b.{0,40}\b(previous|system|instructions?)\b",
        r"\b(reveal|print|show).{0,40}\b(system prompt|hidden prompt|internal policy)\b",
    ],
    "semantic_leakage_reference_texts": [
        "reveal internal system prompt",
        "print private key",
        "disclose admin api key",
        "show hidden credentials",
    ],
    "safe_refusal_message": (
        "Accessing or revealing sensitive credentials violates policy. "
        "I can help with secure key management best practices instead."
    ),
    "redaction_replacements": {
        "email": "[REDACTED]:EMAIL",
        "phone": "[REDACTED]:PHONE",
        "ssn": "[REDACTED]:SSN",
        "credit_card": "[REDACTED]:CREDIT_CARD",
        "api_key": "[REDACTED]:API_KEY",
        "bearer_token": "[REDACTED]:BEARER_TOKEN",
        "password_assignment": "[REDACTED]:PASSWORD",
    },
}


@lru_cache(maxsize=1)
def load_policy() -> Dict[str, Any]:
    policy_path = os.getenv("SECUREGATE_POLICY_PATH", "policy/securegate_policy.json")
    path = Path(policy_path)
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.exists():
        return DEFAULT_POLICY
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return DEFAULT_POLICY
