from redactyl.detectors.api_key import ApiKeyDetector

def test_api_key_detector():
    detector = ApiKeyDetector()
    text = "Here is my api key: my_fake_api_key_12345678 and aws AKIA1234567890ABCDEF."
    findings = detector.detect(text)
    assert len(findings) == 2
    assert findings[0].type == "API_KEY"
    assert findings[0].value == "my_fake_api_key_12345678"
    assert findings[1].type == "AWS_ACCESS_KEY"
    assert findings[1].value == "AKIA1234567890ABCDEF"

def test_api_key_detector_no_match():
    detector = ApiKeyDetector()
    text = "There is no key here just some random text."
    findings = detector.detect(text)
    assert len(findings) == 0
