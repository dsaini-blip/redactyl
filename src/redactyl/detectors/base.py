# src/redactyl/detectors/base.py
from __future__ import annotations
from abc import ABC, abstractmethod
from redactyl.models import Finding

class BaseDetector(ABC):
    name: str = "base"
    supported_types: tuple[str, ...] = ()

    @abstractmethod
    def detect(self, text: str) -> list[Finding]:
        raise NotImplementedError
    