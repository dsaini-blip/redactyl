from redactyl.api import scan_text
from redactyl.redaction import redact_text


def safe_print(text: str) -> None:
    result = scan_text(text)
    print(redact_text(text, result.findings))


def safe_prompt(prompt: str = "Enter text: ") -> str:
    text = input(prompt)
    result = scan_text(text)
    return redact_text(text, result.findings)