from redactyl.models import Finding, ScanResult


def mask_value(value: str, mask_char: str = "*", style: str = "block") -> str:
    if style == "stars":
        return "".join(mask_char if not ch.isspace() else ch for ch in value)
    return "[REDACTED]"


def redact_text(
    text: str,
    findings: list[Finding],
    mask_char: str = "*",
    style: str = "block",
) -> str:
    for finding in sorted(findings, key=lambda f: f.start, reverse=True):
        replacement = mask_value(
            finding.value,
            mask_char=mask_char,
            style=style,
        )
        text = text[:finding.start] + replacement + text[finding.end:]
    return text


def findings_to_dicts(findings: list[Finding]) -> list[dict]:
    return [finding.model_dump() for finding in findings]


def scan_result_to_report(result: ScanResult) -> dict:
    has_sensitive_info = len(result.findings) > 0
    return {
        "warning": "Possible sensitive information detected" if has_sensitive_info else "No sensitive information detected",
        "has_sensitive_info": has_sensitive_info,
        "source": result.source,
        "text_length": result.text_length,
        "total_findings": len(result.findings),
        "findings": findings_to_dicts(result.findings),
    }