import ipaddress
import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


class IPDetector(BaseDetector):
    name = "ip"
    supported_types = ("IP_ADDRESS", "PRIVATE_IP", "PUBLIC_IP")

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []

        for match in IP_RE.finditer(text):
            ip_text = match.group(0)
            try:
                addr = ipaddress.ip_address(ip_text)
            except ValueError:
                continue

            finding_type = "PRIVATE_IP" if addr.is_private else "PUBLIC_IP"
            findings.append(
                Finding(
                    type=finding_type,
                    start=match.start(),
                    end=match.end(),
                    value=ip_text,
                    detector=self.name,
                    confidence=0.97,
                    metadata={"ip_version": addr.version, "is_global": addr.is_global},
                )
            )

        return findings