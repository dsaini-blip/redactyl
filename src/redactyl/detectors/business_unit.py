import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding


class BusinessUnitDetector(BaseDetector):
    name = "business_unit"
    supported_types = ("BUSINESS_UNIT",)

    def __init__(self, business_units=None):
        self.business_units = [b.strip() for b in (business_units or []) if b and b.strip()]
        escaped = sorted((re.escape(b) for b in self.business_units), key=len, reverse=True)
        self.pattern = re.compile(r"\b(?:%s)\b" % "|".join(escaped), re.IGNORECASE) if escaped else None

    def detect(self, text: str) -> list[Finding]:
        if not self.pattern:
            return []

        findings = []
        for match in self.pattern.finditer(text):
            findings.append(
                Finding(
                    type="BUSINESS_UNIT",
                    start=match.start(),
                    end=match.end(),
                    value=match.group(0),
                    detector=self.name,
                    confidence=0.99,
                )
            )
        return findings