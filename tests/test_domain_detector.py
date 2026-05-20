from redactyl.detectors.domain import DomainDetector

def test_domain_detector():
    detector = DomainDetector(internal_domains=["internal.corp.com"])
    text = "Visit google.com or our intranet at internal.corp.com. Don't look at script.py or README.md."
    findings = detector.detect(text)
    
    # script.py and README.md shouldn't match due to EXCLUDED_SUFFIXES
    assert len(findings) == 2
    
    assert findings[0].type == "PUBLIC_DOMAIN"
    assert findings[0].value == "google.com"
    
    assert findings[1].type == "INTERNAL_DOMAIN"
    assert findings[1].value == "internal.corp.com"

def test_domain_detector_no_match():
    detector = DomainDetector()
    text = "Just regular sentences. No domains here."
    findings = detector.detect(text)
    assert len(findings) == 0
