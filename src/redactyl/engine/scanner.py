from redactyl.models import Finding, ScanResult


class Scanner:
    def __init__(self, detectors: list):
        self.detectors = detectors

    def scan(self, text: str, source: str | None = None) -> ScanResult:
        findings: list[Finding] = []
        for detector in self.detectors:
            findings.extend(detector.detect(text))

        findings = self._resolve_overlaps(findings)
        return ScanResult(source=source, text_length=len(text), findings=findings)

    def _resolve_overlaps(self, findings: list[Finding]) -> list[Finding]:
        ordered = sorted(
            findings,
            key=lambda f: (f.start, -(f.end - f.start), -f.confidence, f.type),
        )

        resolved: list[Finding] = []
        for candidate in ordered:
            overlaps = False
            for existing in resolved:
                if not (candidate.end <= existing.start or candidate.start >= existing.end):
                    overlaps = True
                    break
            if not overlaps:
                resolved.append(candidate)

        return sorted(resolved, key=lambda f: f.start)