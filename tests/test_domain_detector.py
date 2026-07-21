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


def test_domain_detector_false_positives():
    detector = DomainDetector(internal_domains=["internal.corp.com"])
    code_text = (
        "currentBuild.result = 'SUCCESS'\n"
        "echo env.WORKSPACE\n"
        "dirs.getName\n"
        "dirs.getName()\n"
        "groovy.io.FileType\n"
        "import groovy.io.FileType\n"
        "import java.util.List;\n"
        "package com.example.service;\n"
        "regionList.add\n"
        "regionList.add(item)\n"
        "localRegionList.size\n"
        "accountList.add\n"
        "accountList.sort\n"
    )
    findings = detector.detect(code_text)
    assert len(findings) == 0, f"Expected 0 findings but got: {[f.value for f in findings]}"


def test_domain_detector_valid_domains():
    detector = DomainDetector(internal_domains=["internal.corp.com", "service.internal"])
    text = (
        "Check out https://google.com or visit example.org and api.github.com. "
        "Intranet is at internal.corp.com or service.internal. "
        "Also test.co.uk is valid."
    )
    findings = detector.detect(text)
    found_values = [f.value for f in findings]
    assert "google.com" in found_values
    assert "example.org" in found_values
    assert "api.github.com" in found_values
    assert "internal.corp.com" in found_values
    assert "service.internal" in found_values
    assert "test.co.uk" in found_values

