import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b")


class EmailDetector(BaseDetector):
    name = "email"
    supported_types = ("EMAIL",)

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in EMAIL_RE.finditer(text):
            findings.append(
                Finding(
                    type="EMAIL",
                    start=match.start(),
                    end=match.end(),
                    value=match.group(0),
                    detector=self.name,
                    confidence=0.99,
                )
            )
        return findings