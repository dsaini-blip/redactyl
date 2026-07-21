from pathlib import Path
from collections.abc import Iterator


def read_text_file(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8", errors="ignore")


def iter_files(
    root: str | Path,
    include_extensions: list[str] | None = None,
    exclude_dirs: list[str] | None = None,
) -> Iterator[Path]:
    root = Path(root)
    exclude = set(exclude_dirs) if exclude_dirs else set()
    
    # Process all extensions if None, empty, or contains '*'
    filter_ext = False
    allowed_exts = set()
    if include_extensions and "*" not in include_extensions:
        filter_ext = True
        allowed_exts = {ext.lower() for ext in include_extensions}

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        try:
            rel_parts = path.relative_to(root).parts[:-1]
        except ValueError:
            rel_parts = path.parts[:-1]

        if any(part in exclude for part in rel_parts):
            continue

        if filter_ext and path.suffix.lower() not in allowed_exts:
            continue

        yield path


def iter_text_files(
    root: str | Path,
    include_extensions: list[str] | None = None,
    exclude_dirs: list[str] | None = None,
) -> Iterator[Path]:
    yield from iter_files(root, include_extensions, exclude_dirs)