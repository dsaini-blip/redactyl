from redactyl.detectors.jwt import JWTDetector

def test_jwt_detector():
    detector = JWTDetector()
    text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI.eyJzdWIiOiIxMjM0NTY3ODkwIiw.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].type == "JWT"
    assert "eyJhbGci" in findings[0].value

def test_jwt_detector_invalid():
    detector = JWTDetector()
    text = "This is not a jwt. Just some words."
    findings = detector.detect(text)
    assert len(findings) == 0
