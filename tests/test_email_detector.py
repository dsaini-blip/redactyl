from redactyl.detectors.email import EmailDetector

def test_email_detector():
    detector = EmailDetector()
    text = "Contact me at test@example.com or admin@foo.bar."
    findings = detector.detect(text)
    
    assert len(findings) == 2
    assert findings[0].type == "EMAIL"
    assert findings[0].value == "test@example.com"
    assert findings[1].type == "EMAIL"
    assert findings[1].value == "admin@foo.bar"

def test_email_detector_invalid():
    detector = EmailDetector()
    text = "This is not an email test@example or @example.com"
    findings = detector.detect(text)
    assert len(findings) == 0
