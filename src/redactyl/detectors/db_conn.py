import re

from redactyl.detectors.base import BaseDetector
from redactyl.models import Finding

DB_CONN_RE = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|sqlite|oracle)://[^\s]+",
    re.IGNORECASE,
)


class DBConnectionStringDetector(BaseDetector):
    name = "db_conn"
    supported_types = ("DB_CONNECTION_STRING",)

    def detect(self, text: str) -> list[Finding]:
        findings = []
        for match in DB_CONN_RE.finditer(text):
            findings.append(
                Finding(
                    type="DB_CONNECTION_STRING",
                    start=match.start(),
                    end=match.end(),
                    value=match.group(0),
                    detector=self.name,
                    confidence=0.97,
                )
            )
        return findings