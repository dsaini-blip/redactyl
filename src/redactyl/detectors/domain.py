import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

DOMAIN_RE = re.compile(
    r"\b(?=.{1,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b"
)

EXCLUDED_SUFFIXES = {
    "txt",
    "log",
    "json",
    "yaml",
    "yml",
    "env",
    "py",
    "md",
    "csv",
}


class DomainDetector(BaseDetector):
    name = "domain"
    supported_types = ("DOMAIN", "INTERNAL_DOMAIN", "PUBLIC_DOMAIN")

    def __init__(self, internal_domains: list[str] | None = None):
        self.internal_domains = {d.lower() for d in (internal_domains or [])}

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []

        for match in DOMAIN_RE.finditer(text):
            domain = match.group(0).lower()
            suffix = domain.rsplit(".", 1)[-1]
            if suffix in EXCLUDED_SUFFIXES:
                continue

            finding_type = "INTERNAL_DOMAIN" if domain in self.internal_domains else "PUBLIC_DOMAIN"
            findings.append(
                Finding(
                    type=finding_type,
                    start=match.start(),
                    end=match.end(),
                    value=match.group(0),
                    detector=self.name,
                    confidence=0.95,
                )
            )

        return findings