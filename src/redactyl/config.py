from pathlib import Path
import yaml


DEFAULT_CONFIG = {
    "internal_domains": [],
    "business_units": [],
    "enabled_detectors": [],
    "disabled_detectors": [],
    "include_extensions": None,
    "exclude_dirs": [".git", ".venv", "node_modules", "__pycache__"],
    "redaction_style": "block",
}


def load_config(path: str | None = None) -> dict:
    candidates = [path] if path else ["redactyl.yml", ".redactyl.yml"]

    for candidate in candidates:
        if candidate and Path(candidate).exists():
            data = yaml.safe_load(Path(candidate).read_text(encoding="utf-8")) or {}
            config = DEFAULT_CONFIG.copy()
            config.update(data)
            return config

    return DEFAULT_CONFIG.copy()