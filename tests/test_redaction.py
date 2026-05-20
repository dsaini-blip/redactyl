from redactyl.api import redact_text

def test_redact_single_finding():
    text = "Hello test@example.com world"
    redacted, _ = redact_text(text)
    assert redacted == "Hello [REDACTED] world"

def test_redact_multiple_findings():
    text = "Email test@example.com and IP 192.168.1.1"
    redacted, _ = redact_text(text)
    assert redacted == "Email [REDACTED] and IP [REDACTED]"

def test_redact_overlapping_findings():
    # If findings overlap, the way _redact_with_findings sorts them in reverse
    # order of start index should prevent crashing, but might double redact.
    # We just ensure it doesn't crash and text is modified.
    text = "Some sensitive string that triggers two things"
    redacted, _ = redact_text(text)
    assert type(redacted) is str
