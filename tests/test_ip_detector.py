from redactyl.detectors.ip import IPDetector

def test_ip_detector():
    detector = IPDetector()
    text = "My local IP is 192.168.1.1 and my public IP is 8.8.8.8. Also invalid IP 999.999.999.999"
    findings = detector.detect(text)
    
    # Should only find valid IPs
    assert len(findings) == 2
    
    assert findings[0].type == "PRIVATE_IP"
    assert findings[0].value == "192.168.1.1"
    
    assert findings[1].type == "PUBLIC_IP"
    assert findings[1].value == "8.8.8.8"

def test_ip_detector_no_match():
    detector = IPDetector()
    text = "No IPs here. 1.2.3 is not an IP."
    findings = detector.detect(text)
    assert len(findings) == 0
