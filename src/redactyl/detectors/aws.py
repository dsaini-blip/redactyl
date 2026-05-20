import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA|ABIA)[A-Z0-9]{16}\b")
AWS_SECRET_KEY_RE = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")


class AWSDetector(BaseDetector):
    name = "aws"
    supported_types = ("AWS_ACCESS_KEY", "AWS_SECRET_KEY")

    def detect(self, text: str) -> list[Finding]:
        findings = []

        for match in AWS_ACCESS_KEY_RE.finditer(text):
            findings.append(
                Finding(
                    type="AWS_ACCESS_KEY",
                    start=match.start(),
                    end=match.end(),
                    value=match.group(0),
                    detector=self.name,
                    confidence=0.98,
                )
            )

        for match in AWS_SECRET_KEY_RE.finditer(text):
            findings.append(
                Finding(
                    type="AWS_SECRET_KEY",
                    start=match.start(),
                    end=match.end(),
                    value=match.group(0),
                    detector=self.name,
                    confidence=0.85,
                )
            )

        return findings