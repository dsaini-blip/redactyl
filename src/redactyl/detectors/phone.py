import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

PHONE_RE = re.compile(
    r"(?<!\w)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\w)"
)


class PhoneDetector(BaseDetector):
    name = "phone"
    supported_types = ("PHONE_NUMBER",)

    def detect(self, text: str) -> list[Finding]:
        findings = []
        for match in PHONE_RE.finditer(text):
            findings.append(
                Finding(
                    type="PHONE_NUMBER",
                    start=match.start(),
                    end=match.end(),
                    value=match.group(0),
                    detector=self.name,
                    confidence=0.93,
                )
            )
        return findings