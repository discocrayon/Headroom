"""
The one place Headroom mutates Terraform output.

Applying is preflight-then-mutate. Preflight reads the filesystem and decides
every write, every unchanged file, the symlink, and every stale deletion
without changing anything; a conflict anywhere aborts the whole run before the
first mkdir. What it proves is ownership: Headroom writes over a file only
when that file's first line is GENERATED_MARKER, and deletes only a regular
.tf file carrying the same line.

This is not a transaction. Nothing before the mutation phase changes the
filesystem, but an OS failure partway through the mutation phase can still
leave a partial apply.
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from .plan import TerraformPlan
from ..constants import GENERATED_MARKER

logger = logging.getLogger(__name__)

__all__ = ["apply_terraform_plan"]


@dataclass
class _Preflight:
    """What the read-only pass decided, before any of it is carried out."""
    to_write: Dict[Path, str] = field(default_factory=dict)
    unchanged: Set[Path] = field(default_factory=set)
    link_destination: Optional[Path] = None
    link_target: Optional[str] = None
    link_replaces: Optional[Path] = None
    to_delete: Set[Path] = field(default_factory=set)
    conflicts: List[str] = field(default_factory=list)


def _first_line(path: Path) -> Optional[str]:
    """
    Return a file's first line, or None if it cannot be read as text.

    Args:
        path: An existing regular file

    Returns:
        The first line without its newline, or None if unreadable/undecodable
    """
    try:
        with open(path, 'r') as handle:
            return handle.readline().rstrip("\n")
    except (OSError, UnicodeDecodeError):
        return None


def _is_marked_regular_file(path: Path) -> bool:
    """
    Report whether Headroom wrote this file and may therefore delete it.

    A symlink is rejected before anything else: rcps/grab_org_info.tf points
    at the real file in scps/, so reading through the link finds the marker
    and would delete a link Headroom maintains rather than removes.

    A file we cannot read is a file we cannot prove is ours, so it is not a
    deletion candidate. Note that a planned *destination* we cannot read is
    handled the other way round -- see `_preflight_file` -- because there we
    are about to overwrite it. The two must not be unified.

    Args:
        path: Candidate file, already known to end in .tf

    Returns:
        True if the file's first line is exactly GENERATED_MARKER
    """
    if path.is_symlink() or not path.is_file():
        return False
    return _first_line(path) == GENERATED_MARKER


def _preflight_file(destination: Path, content: str, result: _Preflight) -> None:
    """
    Decide what to do with one planned regular-file destination.

    Args:
        destination: Where the file belongs
        content: What it should hold
        result: Accumulator for decisions and conflicts
    """
    if destination.is_symlink():
        result.conflicts.append(f"{destination}: is a symlink, not a file Headroom wrote")
        return

    if not destination.exists():
        result.to_write[destination] = content
        return

    if not destination.is_file():
        result.conflicts.append(f"{destination}: is a directory or other non-file")
        return

    if _first_line(destination) != GENERATED_MARKER:
        result.conflicts.append(
            f"{destination}: first line is not {GENERATED_MARKER!r}"
        )
        return

    try:
        if destination.read_text() == content:
            result.unchanged.add(destination)
            return
    except (OSError, UnicodeDecodeError):
        result.conflicts.append(f"{destination}: cannot be read to compare")
        return

    result.to_write[destination] = content


def _preflight_symlink(destination: Path, target: str, result: _Preflight) -> None:
    """
    Decide what to do with the one reserved symlink.

    A correct link is left exactly as it is, so an unchanged run preserves its
    lstat metadata. A marked regular file at the path is a previous Headroom
    layout and may migrate; an unmarked one is somebody else's and aborts.

    Args:
        destination: rcps/grab_org_info.tf
        target: The exact relative link text it must hold
        result: Accumulator for decisions and conflicts
    """
    if destination.is_symlink():
        if os.readlink(destination) == target:
            return
        result.link_destination = destination
        result.link_target = target
        result.link_replaces = destination
        return

    if not destination.exists():
        result.link_destination = destination
        result.link_target = target
        return

    if not destination.is_file():
        result.conflicts.append(
            f"{destination}: is a directory where the shared org-info link belongs"
        )
        return

    if _first_line(destination) != GENERATED_MARKER:
        result.conflicts.append(
            f"{destination}: first line is not {GENERATED_MARKER!r}"
        )
        return

    result.link_destination = destination
    result.link_target = target
    result.link_replaces = destination


def _preflight(plan: TerraformPlan) -> _Preflight:
    """
    Decide everything, change nothing.

    Args:
        plan: The validated whole-run plan

    Returns:
        Every write, unchanged entry, symlink change, and stale deletion

    Raises:
        RuntimeError: If any destination is not Headroom's to touch. Every
            conflict is reported, not just the first: these are hand-edited
            files, and an operator commonly has several.
    """
    result = _Preflight()

    for destination, content in sorted(plan.files.items()):
        _preflight_file(destination, content, result)

    for destination, target in sorted(plan.symlinks.items()):
        _preflight_symlink(destination, target, result)

    planned = set(plan.files) | set(plan.symlinks)
    for directory in plan.managed_directories:
        if not directory.is_dir():
            continue
        for candidate in directory.glob("*.tf"):
            if candidate not in planned and _is_marked_regular_file(candidate):
                result.to_delete.add(candidate)

    if result.conflicts:
        listing = "\n  ".join(sorted(result.conflicts))
        raise RuntimeError(
            f"Refusing to write {len(result.conflicts)} destination(s) Headroom "
            f"does not own:\n  {listing}\n"
            "Ownership is the marker on a file's first line. Move these files "
            "aside or rename them. Nothing was changed."
        )

    return result


def apply_terraform_plan(plan: TerraformPlan) -> None:
    """
    Carry out a compiled plan. The only Terraform filesystem mutation there is.

    Order is deliberate: directories, then the changed files, then the link,
    then the stale deletions. Deleting last is what makes a stale file's
    removal conditional on the desired writes having succeeded.

    Unchanged files are never opened for write and a correct link is never
    recreated, so two identical applications preserve file mtimes and symlink
    lstat metadata.

    Args:
        plan: A validated whole-run plan

    Raises:
        RuntimeError: If preflight finds any destination Headroom does not own
    """
    decided = _preflight(plan)

    for directory in plan.managed_directories:
        directory.mkdir(parents=True, exist_ok=True)

    for destination in sorted(decided.to_write):
        with open(destination, 'w') as handle:
            handle.write(decided.to_write[destination])
        logger.info(f"Generated Terraform file: {destination}")

    for destination in decided.unchanged:
        logger.debug(f"Unchanged Terraform file: {destination}")

    if decided.link_destination is not None and decided.link_target is not None:
        if decided.link_replaces is not None:
            decided.link_replaces.unlink()
        os.symlink(decided.link_target, decided.link_destination)
        logger.info(
            f"Created symlink: {decided.link_destination} -> {decided.link_target}"
        )

    for destination in sorted(decided.to_delete):
        destination.unlink()
        logger.info(f"Deleted stale generated Terraform file: {destination}")
