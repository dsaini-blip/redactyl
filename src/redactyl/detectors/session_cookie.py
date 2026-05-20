import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

SESSION_COOKIE_RE = re.compile(
    r"(?i)\b(?:sessionid|connect\.sid|jsessionid|phpsessid|sid)\b\s*[:=]\s*([^\s;]+)"
)


class SessionCookieDetector(BaseDetector):
    name = "session_cookie"
    supported_types = ("SESSION_COOKIE",)

    def detect(self, text: str) -> list[Finding]:
        findings = []
        for match in SESSION_COOKIE_RE.finditer(text):
            value = match.group(1)
            findings.append(
                Finding(
                    type="SESSION_COOKIE",
                    start=match.start(1),
                    end=match.end(1),
                    value=value,
                    detector=self.name,
                    confidence=0.93,
                )
            )
        return findings