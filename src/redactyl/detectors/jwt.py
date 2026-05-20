import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

JWT_RE = re.compile(r"\b[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b")


class JWTDetector(BaseDetector):
    name = "jwt"
    supported_types = ("JWT",)

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in JWT_RE.finditer(text):
            token = match.group(0)
            parts = token.split(".")
            if len(parts) == 3 and all(parts):
                findings.append(
                    Finding(
                        type="JWT",
                        start=match.start(),
                        end=match.end(),
                        value=token,
                        detector=self.name,
                        confidence=0.97,
                    )
                )
        return findings