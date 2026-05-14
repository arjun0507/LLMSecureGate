from securegate.response_sanitizer import ResponseSanitizationEngine


def test_response_sanitizer_redacts_sensitive_entities() -> None:
    engine = ResponseSanitizationEngine()
    raw = "Email me at alice@example.com and use token sk_test_ABC123XYZ456TOKEN."

    result = engine.sanitize(raw)

    assert len(result.redactions) >= 2
    assert "[REDACTED]:EMAIL" in result.sanitized_reply
    assert "[REDACTED]:API_KEY" in result.sanitized_reply
    assert "email" in result.detected_entities
    assert "api_key" in result.detected_entities


def test_response_sanitizer_keeps_clean_text() -> None:
    engine = ResponseSanitizationEngine()
    raw = "Store credentials in a secrets manager and rotate them regularly."

    result = engine.sanitize(raw)

    assert result.redactions == []
    assert result.sanitized_reply == raw
    assert result.detected_entities == []
