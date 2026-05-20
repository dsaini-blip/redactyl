import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")


class SSNDetector(BaseDetector):
    name = "ssn"
    supported_types = ("SSN",)

    def detect(self, text: str) -> list[Finding]:
        findings = []
        for match in SSN_RE.finditer(text):
            findings.append(
                Finding(
                    type="SSN",
                    start=match.start(),
                    end=match.end(),
                    value=match.group(0),
                    detector=self.name,
                    confidence=0.98,
                )
            )
        return findings