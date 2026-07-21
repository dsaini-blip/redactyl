import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

ACCESS_KEY_RE = re.compile(
    r"(?i)\b(?:[A-Za-z0-9_\-]*access[_\s-]?key(?:[_\s-]?id)?|aws[_\s-]?access[_\s-]?key(?:[_\s-]?id)?|azure[_\s-]?access[_\s-]?key|gcp[_\s-]?access[_\s-]?key)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=]{8,})[\"']?"
)

SECRET_KEY_RE = re.compile(
    r"(?i)\b(?:[A-Za-z0-9_\-]*secret[_\s-]?key(?:[_\s-]?id)?|client[_\s-]?secret|app[_\s-]?secret|api[_\s-]?secret|signing[_\s-]?secret|aws[_\s-]?secret[_\s-]?access[_\s-]?key|jwt[_\s-]?secret|master[_\s-]?secret[_\s-]?key)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=]{8,})[\"']?"
)

SECRET_RE = re.compile(
    r"(?i)\b(?:secret|[A-Za-z0-9_\-]*secret[A-Za-z0-9_\-]*)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=]{8,})[\"']?"
)


class SecretKeyDetector(BaseDetector):
    name = "secret_key"
    supported_types = ("ACCESS_KEY", "SECRET_KEY", "SECRET")

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []

        for match in ACCESS_KEY_RE.finditer(text):
            value = match.group(1)
            findings.append(
                Finding(
                    type="ACCESS_KEY",
                    start=match.start(1),
                    end=match.end(1),
                    value=value,
                    detector=self.name,
                    confidence=0.95,
                )
            )

        for match in SECRET_KEY_RE.finditer(text):
            value = match.group(1)
            findings.append(
                Finding(
                    type="SECRET_KEY",
                    start=match.start(1),
                    end=match.end(1),
                    value=value,
                    detector=self.name,
                    confidence=0.95,
                )
            )

        for match in SECRET_RE.finditer(text):
            value = match.group(1)
            # Avoid duplicate if already captured as ACCESS_KEY or SECRET_KEY
            if any(f.start == match.start(1) and f.end == match.end(1) for f in findings):
                continue
            findings.append(
                Finding(
                    type="SECRET",
                    start=match.start(1),
                    end=match.end(1),
                    value=value,
                    detector=self.name,
                    confidence=0.92,
                )
            )

        return sorted(findings, key=lambda f: (f.start, f.end))
