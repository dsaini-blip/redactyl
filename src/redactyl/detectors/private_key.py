import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |)?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |)?PRIVATE KEY-----",
    re.DOTALL,
)


class PrivateKeyDetector(BaseDetector):
    name = "private_key"
    supported_types = ("PRIVATE_KEY",)

    def detect(self, text: str) -> list[Finding]:
        findings = []
        for match in PRIVATE_KEY_RE.finditer(text):
            findings.append(
                Finding(
                    type="PRIVATE_KEY",
                    start=match.start(),
                    end=match.end(),
                    value=match.group(0),
                    detector=self.name,
                    confidence=0.99,
                )
            )
        return findings