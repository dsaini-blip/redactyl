from redactyl.detectors.secret_key import SecretKeyDetector
from redactyl.api import redact


def test_secret_key_detector_types():
    detector = SecretKeyDetector()
    text = (
        'access_key = "my_access_key_123456"\n'
        'aws_access_key_id = "AKIA1234567890ABCDEF"\n'
        'client_secret = "secret_val_987654321"\n'
        'SECRET_KEY = "my_super_secret_key_000"\n'
        'webhook_secret = "whsec_abcdef123456"\n'
        'secret = "my_standalone_secret_value"\n'
    )
    findings = detector.detect(text)
    
    types = [f.type for f in findings]
    assert "ACCESS_KEY" in types
    assert "SECRET_KEY" in types
    assert "SECRET" in types

    access_key_finding = next(f for f in findings if f.type == "ACCESS_KEY")
    assert access_key_finding.value == "my_access_key_123456"

    secret_key_finding = next(f for f in findings if f.type == "SECRET_KEY" and "secret_val" in f.value)
    assert secret_key_finding.value == "secret_val_987654321"

    secret_finding = next(f for f in findings if f.type == "SECRET" and "standalone" in f.value)
    assert secret_finding.value == "my_standalone_secret_value"


def test_redact_with_secret_keys():
    code_snippet = (
        'AWS_ACCESS_KEY_ID = "AKIA1234567890123456"\n'
        'CLIENT_SECRET = "sk_live_secret_key_value_123"\n'
        'DATABASE_SECRET = "super_db_secret_key_999"\n'
    )
    sanitized, findings = redact(code_snippet)
    assert "[REDACTED]" in sanitized
    assert "AKIA1234567890123456" not in sanitized
    assert "sk_live_secret_key_value_123" not in sanitized
    assert "super_db_secret_key_999" not in sanitized

    finding_types = {f.type for f in findings}
    assert "ACCESS_KEY" in finding_types or "AWS_ACCESS_KEY" in finding_types
    assert "SECRET_KEY" in finding_types
    assert "SECRET" in finding_types
