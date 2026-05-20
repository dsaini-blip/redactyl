import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def luhn_valid(number: str) -> bool:
    digits = [int(ch) for ch in number if ch.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False

    total = 0
    reverse_digits = digits[::-1]
    for index, digit in enumerate(reverse_digits):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


class CreditCardDetector(BaseDetector):
    name = "credit_card"
    supported_types = ("CREDIT_CARD",)

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in CARD_CANDIDATE_RE.finditer(text):
            raw = match.group(0)
            normalized = "".join(ch for ch in raw if ch.isdigit())
            if luhn_valid(normalized):
                findings.append(
                    Finding(
                        type="CREDIT_CARD",
                        start=match.start(),
                        end=match.end(),
                        value=raw,
                        detector=self.name,
                        confidence=0.98,
                    )
                )
        return findings