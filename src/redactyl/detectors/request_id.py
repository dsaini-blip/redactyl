import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

UUID_RE = re.compile(
    r"\b[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[1-5a-fA-F0-9]{4}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}\b"
)

KEYED_REQUEST_ID_RE = re.compile(
    r"(?i)\b(?:request[_-]?id|req[_-]?id|correlation[_-]?id|trace[_-]?id)\b\s*[:=]\s*([A-Za-z0-9._\-]{6,128})"
)


class RequestIDDetector(BaseDetector):
    name = "request_id"
    supported_types = ("REQUEST_ID",)

    def detect(self, text: str) -> list[Finding]:
        findings = []

        for match in UUID_RE.finditer(text):
            findings.append(
                Finding(
                    type="REQUEST_ID",
                    start=match.start(),
                    end=match.end(),
                    value=match.group(0),
                    detector=self.name,
                    confidence=0.95,
                )
            )

        for match in KEYED_REQUEST_ID_RE.finditer(text):
            findings.append(
                Finding(
                    type="REQUEST_ID",
                    start=match.start(1),
                    end=match.end(1),
                    value=match.group(1),
                    detector=self.name,
                    confidence=0.98,
                )
            )

        return findings