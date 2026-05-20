import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

BEARER_RE = re.compile(r"\bBearer\s+([A-Za-z0-9\-._~+/]+=*)\b", re.IGNORECASE)


class BearerTokenDetector(BaseDetector):
    name = "bearer"
    supported_types = ("BEARER_TOKEN",)

    def detect(self, text: str) -> list[Finding]:
        findings = []
        for match in BEARER_RE.finditer(text):
            token = match.group(1)
            findings.append(
                Finding(
                    type="BEARER_TOKEN",
                    start=match.start(1),
                    end=match.end(1),
                    value=token,
                    detector=self.name,
                    confidence=0.94,
                )
            )
        return findings