from redactyl.api import redact_text, scan_text, sanitize_message, sanitize_json_payload, redact

def test_scan_text():
    text = "Contact test@example.com."
    findings = scan_text(text)
    assert len(findings) == 2
    email_finding = next(f for f in findings if f.type == "EMAIL")
    assert email_finding.value == "test@example.com"

def test_redact_text():
    text = "Contact test@example.com."
    redacted, findings = redact_text(text, replacement="***")
    assert redacted == "Contact ***."
    assert len(findings) == 2

def test_sanitize_message():
    message = {"user": "admin", "content": "My email is admin@foo.bar."}
    sanitized, findings = sanitize_message(message, replacement="[CENSORED]")
    assert sanitized["user"] == "admin"
    assert sanitized["content"] == "My email is [CENSORED]."
    assert len(findings) == 2

def test_sanitize_json_payload():
    payload = {
        "user_id": 123,
        "is_active": True,
        "profile": {
            "contact": "Email admin@foo.bar",
            "phones": ["+1-555-123-4567", "No phone"]
        }
    }
    
    sanitized, findings = sanitize_json_payload(payload)
    
    assert sanitized["user_id"] == 123
    assert sanitized["is_active"] is True
    assert sanitized["profile"]["contact"] == "Email [REDACTED]"
    assert "admin@foo.bar" not in sanitized["profile"]["contact"]
    
    assert len(findings) == 3 # EMAIL + DOMAIN + PHONE
    
    json_paths = [f.metadata.get("json_path") for f in findings]
    assert "profile.contact" in json_paths

def test_universal_redact_string():
    text = "User IP is 192.168.1.50."
    sanitized, findings = redact(text)
    assert sanitized == "User IP is [REDACTED]."
    assert len(findings) == 1

def test_universal_redact_dict():
    payload = {"ip": "192.168.1.50"}
    sanitized, findings = redact(payload)
    assert sanitized["ip"] == "[REDACTED]"
    assert len(findings) == 1

def test_universal_redact_file(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("My email is admin@foo.bar")
    
    redacted_f, report_f, findings = redact(str(f))
    assert redacted_f.exists()
    assert report_f.exists()
    assert len(findings) == 2 # EMAIL + DOMAIN

def test_universal_redact_directory(tmp_path):
    d = tmp_path / "logs"
    d.mkdir()
    (d / "log1.txt").write_text("admin@foo.bar")
    (d / "log2.txt").write_text("192.168.1.50")
    
    out_d = tmp_path / "clean_logs"
    processed, findings = redact(str(d), output_dir=str(out_d))
    
    assert len(processed) == 2
    assert len(findings) == 3 # EMAIL + DOMAIN + IP
