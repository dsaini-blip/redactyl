import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

URL_RE = re.compile(r"\bhttps?://[^\s<>\"]+|www\.[^\s<>\"]+\b", re.IGNORECASE)


class URLDetector(BaseDetector):
    name = "url"
    supported_types = ("URL",)

    def detect(self, text: str) -> list[Finding]:
        findings = []
        for match in URL_RE.finditer(text):
            findings.append(
                Finding(
                    type="URL",
                    start=match.start(),
                    end=match.end(),
                    value=match.group(0),
                    detector=self.name,
                    confidence=0.95,
                )
            )
        return findings