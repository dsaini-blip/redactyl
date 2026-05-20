import re
from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

class CustomKeywordDetector(BaseDetector):
    name = "custom_keyword"

    def __init__(self, keywords: list[str]):
        self.keywords = [k for k in keywords if isinstance(k, str) and k.strip()]
        if self.keywords:
            # Escape keywords to prevent regex injection and join with OR
            pattern_str = "|".join(re.escape(k) for k in self.keywords)
            self.pattern = re.compile(rf"\b({pattern_str})\b", re.IGNORECASE)
        else:
            self.pattern = None

    def detect(self, text: str) -> list[Finding]:
        if not self.pattern or not text:
            return []
            
        findings = []
        for match in self.pattern.finditer(text):
            findings.append(
                Finding(
                    type="CUSTOM_KEYWORD",
                    start=match.start(),
                    end=match.end(),
                    value=match.group(),
                    detector=self.name,
                    confidence=1.0,
                )
            )
        return findings
