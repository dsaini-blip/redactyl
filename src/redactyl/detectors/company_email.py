import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@([a-zA-Z0-9.\-]+\.[A-Za-z]{2,})\b")


class CompanyEmailDetector(BaseDetector):
    name = "company_email"
    supported_types = ("COMPANY_EMAIL",)

    def __init__(self, internal_domains: list[str] | None = None):
        self.internal_domains = {d.lower() for d in (internal_domains or [])}

    def detect(self, text: str) -> list[Finding]:
        findings = []
        for match in EMAIL_RE.finditer(text):
            full = match.group(0)
            domain = match.group(1).lower()
            if domain in self.internal_domains:
                findings.append(
                    Finding(
                        type="COMPANY_EMAIL",
                        start=match.start(),
                        end=match.end(),
                        value=full,
                        detector=self.name,
                        confidence=0.99,
                        metadata={"domain": domain},
                    )
                )
        return findings