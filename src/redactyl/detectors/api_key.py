import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

API_KEY_PATTERNS = [
    re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bsk_test_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\b(?:api[_-]?key|apikey|access[_-]?key)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})[\"']?"),
]


class ApiKeyDetector(BaseDetector):
    name = "api_key"
    supported_types = ("API_KEY", "AWS_ACCESS_KEY")

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []

        for pattern in API_KEY_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(1) if match.lastindex else match.group(0)
                start = match.start(1) if match.lastindex else match.start()
                end = match.end(1) if match.lastindex else match.end()

                finding_type = "AWS_ACCESS_KEY" if value.startswith(("AKIA", "ASIA")) else "API_KEY"

                findings.append(
                    Finding(
                        type=finding_type,
                        start=start,
                        end=end,
                        value=value,
                        detector=self.name,
                        confidence=0.96,
                    )
                )

        return findings