"""Scan Markdown files for relative links whose target does not exist."""

import re
from pathlib import Path
from typing import List

_INLINE_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
_HAS_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")

# Directories holding third-party or generated Markdown. .tox alone carries a
# site-packages tree of it. Named rather than matched on a leading dot, so that
# .cursor/ - repository documentation that happens to live in a tool directory -
# is still checked.
_UNCHECKED_DIRECTORIES = frozenset({
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    "node_modules",
    "venv",
})


def find_broken_links(root: Path) -> List[str]:
    """
    Report every relative Markdown link under root whose target is missing.

    Args:
        root: Directory to scan recursively for Markdown files

    Returns:
        Sorted "<path relative to root> -> <link target>" strings, one per
        broken link
    """
    broken: List[str] = []

    for markdown_file in root.rglob("*.md"):
        if not _UNCHECKED_DIRECTORIES.isdisjoint(markdown_file.relative_to(root).parts):
            continue

        targets: List[str] = _INLINE_LINK.findall(markdown_file.read_text())
        for target in targets:
            if _HAS_SCHEME.match(target):
                continue

            path = target.split("#", 1)[0]
            if not path:
                continue

            if not (markdown_file.parent / path).exists():
                broken.append(f"{markdown_file.relative_to(root)} -> {target}")

    return sorted(broken)
