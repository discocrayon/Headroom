"""Scan Markdown files for relative links whose target does not exist."""

import re
from pathlib import Path
from typing import Dict, List, Set

_INLINE_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
_HAS_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_HEADING = re.compile(r"^#{1,6}[ \t]+(.+?)[ \t]*#*$", re.MULTILINE)
_FENCE = re.compile(r"^(?:```|~~~).*?^(?:```|~~~)", re.MULTILINE | re.DOTALL)
_NOT_SLUG = re.compile(r"[^\w\- ]", re.UNICODE)

_MARKDOWN_SUFFIX = ".md"

# Directories holding third-party or generated Markdown. .tox alone carries a
# site-packages tree of it. Named rather than matched on a leading dot, so that
# a dot directory holding repository documentation - `.github/`, for one - is
# still checked.
_UNCHECKED_DIRECTORIES = frozenset({
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    "node_modules",
    "venv",
})


def _slug(heading: str) -> str:
    """
    Convert a heading to the fragment identifier a renderer derives from it.

    Args:
        heading: Heading text with the leading hashes already stripped

    Returns:
        The anchor slug: lowercased, punctuation dropped, spaces hyphenated
    """
    return _NOT_SLUG.sub("", heading.strip().lower()).replace(" ", "-")


def _anchors(path: Path, cache: Dict[Path, Set[str]]) -> Set[str]:
    """
    Collect every anchor the headings in one document define.

    Args:
        path: Markdown file to read
        cache: Per-scan memo, since one document is linked to many times

    Returns:
        Set of anchor slugs, empty for a file that cannot be read as text
    """
    if path not in cache:
        body = _FENCE.sub("", path.read_text())
        cache[path] = {_slug(heading) for heading in _HEADING.findall(body)}
    return cache[path]


def find_broken_links(root: Path) -> List[str]:
    """
    Report every relative Markdown link under root whose target is missing.

    A link is broken when its file does not exist, or when it carries an anchor
    that no heading in the target document defines.

    Args:
        root: Directory to scan recursively for Markdown files

    Returns:
        Sorted "<path relative to root> -> <link target>" strings, one per
        broken link
    """
    broken: List[str] = []
    anchor_cache: Dict[Path, Set[str]] = {}

    for markdown_file in sorted(root.rglob("*")):
        if markdown_file.suffix != _MARKDOWN_SUFFIX:
            continue

        if not _UNCHECKED_DIRECTORIES.isdisjoint(markdown_file.relative_to(root).parts):
            continue

        targets: List[str] = _INLINE_LINK.findall(markdown_file.read_text())
        for target in targets:
            if _HAS_SCHEME.match(target):
                continue

            path, _, anchor = target.partition("#")
            resolved = markdown_file if not path else markdown_file.parent / path

            if not resolved.exists():
                broken.append(f"{markdown_file.relative_to(root)} -> {target}")
                continue

            if not anchor or resolved.suffix != _MARKDOWN_SUFFIX:
                continue

            if _slug(anchor) not in _anchors(resolved, anchor_cache):
                broken.append(f"{markdown_file.relative_to(root)} -> {target}")

    return sorted(broken)
