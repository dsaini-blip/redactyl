import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

PASSWORD_RE = re.compile(
    r"(?i)\b(?:password|passwd|pwd|db_password|secret)\b\s*[:=]\s*[\"']?([^\s\"']{4,})[\"']?"
)


class PasswordDetector(BaseDetector):
    name = "password"
    supported_types = ("PASSWORD",)

    def detect(self, text: str) -> list[Finding]:
        findings = []
        for match in PASSWORD_RE.finditer(text):
            value = match.group(1)
            findings.append(
                Finding(
                    type="PASSWORD",
                    start=match.start(1),
                    end=match.end(1),
                    value=value,
                    detector=self.name,
                    confidence=0.92,
                )
            )
        return findings