# src/redactyl/models.py
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Any

class Finding(BaseModel):
    type: str
    start: int
    end: int
    value: str
    confidence: float = 1.0
    detector: str
    metadata: dict[str, Any] = Field(default_factory=dict)

class ScanResult(BaseModel):
    source: str | None = None
    text_length: int
    findings: list[Finding] = Field(default_factory=list)

class Summary(BaseModel):
    total_findings: int
    by_type: dict[str, int]
    files_scanned: int = 0
    matches_redacted: int = 0