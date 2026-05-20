from redactyl.detectors.credit_card import CreditCardDetector

def test_credit_card_detector_valid():
    detector = CreditCardDetector()
    # Visa test card (Luhn valid)
    text = "My card is 4111 1111 1111 1111."
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].type == "CREDIT_CARD"
    assert findings[0].value == "4111 1111 1111 1111"

def test_credit_card_detector_invalid_luhn():
    detector = CreditCardDetector()
    # Invalid Luhn
    text = "My card is 4111 1111 1111 1112."
    findings = detector.detect(text)
    assert len(findings) == 0

def test_credit_card_detector_too_short():
    detector = CreditCardDetector()
    text = "My card is 4111 1111 1111."
    findings = detector.detect(text)
    assert len(findings) == 0
