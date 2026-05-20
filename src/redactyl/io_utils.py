from pathlib import Path
from collections.abc import Iterator


def read_text_file(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8", errors="ignore")


def iter_text_files(root: str | Path, include_extensions: list[str], exclude_dirs: list[str]) -> Iterator[Path]:
    root = Path(root)
    exclude = set(exclude_dirs)
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in exclude for part in path.parts):
            continue
        if path.suffix.lower() in include_extensions:
            yield path