"""
The one place Headroom mutates Terraform output.

Applying is preflight-then-mutate. Preflight reads the filesystem and decides
every write, every unchanged file, the symlink, and every stale deletion
without changing anything; a conflict anywhere aborts the whole run before the
first mkdir. What it proves is ownership: Headroom writes over a file only
when that file's first line is GENERATED_MARKER, and deletes only a regular
.tf file carrying the same line.

Two things cannot be decided by reading alone, and both are settled here
rather than at compile time, which reads nothing on purpose. Whether the two
output directories are really one directory is invisible while neither
exists, so it is checked again once they do -- still ahead of the first
write, link, or unlink. And the reserved symlink's target is a relative path
from where the link really lives to the file it really points at, which
depends on whether either directory is itself a symlink.

This is not a transaction. Nothing before the mutation phase changes the
filesystem, and each individual file is replaced atomically rather than
truncated and refilled, but an OS failure partway through the mutation phase
can still leave a partial apply: some files replaced and others not.
"""

import logging
import os
from dataclasses import dataclass, field
from itertools import combinations
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .plan import TerraformPlan, validate_plan
from ..constants import GENERATED_MARKER, ORG_INFO_FILENAME

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

    A symlink is rejected before anything else. The reserved
    rcps/grab_org_info.tf is never a candidate here -- it is always in the
    plan -- so what this protects is an operator's own symlink in a managed
    directory: reading through one that points at a marked file finds the
    marker and deletes a link Headroom never wrote.

    A file we cannot read is a file we cannot prove is ours, so it is not a
    deletion candidate: the run carries on and leaves it alone. A planned
    *destination* we cannot read ends the whole run instead -- see
    `_preflight_file` -- because there we are about to replace its contents.
    Both are conservative; they differ in what they cost, and unifying them
    would either delete a file nobody proved was ours or abandon a run over
    one Headroom was never going to touch.

    Args:
        path: Candidate file, already known to end in .tf

    Returns:
        True if the file's first line is exactly GENERATED_MARKER
    """
    if path.is_symlink() or not path.is_file():
        return False
    return _first_line(path) == GENERATED_MARKER


def _filesystem_identity(path: Path) -> Optional[Tuple[int, int]]:
    """
    A path's (device, inode) pair, or None if it cannot be stat'd right now.

    Path equality is a string comparison and does not see filesystem
    aliasing: a case-insensitive or Unicode-normalization-insensitive
    filesystem (APFS, the common case on macOS) can resolve a planned
    destination and a differently-spelled on-disk entry to the same inode.
    Symlinks are not followed -- what matters is the identity of the
    directory entry itself, not of whatever it points to.

    Args:
        path: Any path, possibly gone by the time this runs

    Returns:
        (st_dev, st_ino), or None if the path is not there, which cannot be
        aliased to anything. Any other stat failure is raised, not swallowed:
        a candidate we cannot look at is not a candidate we may rule safe.
    """
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    return (info.st_dev, info.st_ino)


def _directory_identity(path: Path) -> Optional[Tuple[int, int]]:
    """
    An output directory's (device, inode) pair, or None if it is not there.

    Symlinks are followed, the opposite of `_filesystem_identity`: what
    matters about an output directory is which directory the writes land in,
    and rcps_dir spelled as a symlink to scps_dir is one of the aliases this
    exists to catch. For a directory entry about to be deleted the opposite
    holds, which is why the two are separate.

    Args:
        path: A managed directory, which need not exist yet

    Returns:
        (st_dev, st_ino), or None if the directory is not there yet, which
        cannot be aliased to anything. Any other stat failure is raised: this
        is the check that stops one directory under two names from generating
        every RCP file over an SCP file, and it must not pass by default.
    """
    try:
        info = path.stat()
    except FileNotFoundError:
        return None
    return (info.st_dev, info.st_ino)


def _directory_aliases(directories: Tuple[Path, ...]) -> List[str]:
    """
    Report every pair of managed directories that is really one directory.

    `plan.compile_terraform_plan` compares the output directories lexically,
    deliberately: compilation reads nothing, so the same plan validates
    identically on every machine. A lexical comparison cannot see two
    spellings that reach one inode -- a symlink, or a case variant on a
    case-insensitive filesystem -- so the collision it names has to be caught
    again here, where reading the filesystem is allowed.

    Args:
        directories: The plan's managed directories, existing or not

    Returns:
        One message per aliased pair; empty when the directories are distinct
        or do not exist yet
    """
    aliased: List[str] = []
    for first, second in combinations(directories, 2):
        identity = _directory_identity(first)
        if identity is None or identity != _directory_identity(second):
            continue
        aliased.append(
            f"{first} and {second} resolve to the same directory. Every RCP "
            "file would be generated over an SCP file of the same name, and "
            f"{ORG_INFO_FILENAME} would be a symlink to itself. Set scps_dir "
            "and rcps_dir to different directories."
        )
    return aliased


def _protected_identities(result: _Preflight) -> Set[Tuple[int, int]]:
    """
    Filesystem identities of every destination this run must not delete.

    A stale-deletion candidate is found by listing a directory and comparing
    paths to what the plan spells, so a candidate that is really a planned
    write, an unchanged file, or the reserved link's own destination under
    another name would otherwise slip past that string comparison and be
    deleted right back out.

    Args:
        result: Preflight decisions so far

    Returns:
        Every (st_dev, st_ino) this run is about to write, leave unchanged,
        or route the reserved symlink through
    """
    destinations: List[Path] = list(result.to_write) + list(result.unchanged)
    if result.link_destination is not None:
        destinations.append(result.link_destination)
    return {
        identity for identity in map(_filesystem_identity, destinations)
        if identity is not None
    }


def _write_file(destination: Path, content: str) -> None:
    """
    Put content at a destination without ever truncating what is there.

    Opening the destination for write truncates it before a single byte
    arrives. A write that dies in between leaves a 0-byte file carrying no
    marker, which every later run then refuses as a file Headroom does not
    own -- a wedge the run inflicted on itself and cannot undo. Renaming a
    fully written sibling over the destination makes the replacement atomic:
    the destination holds the old content or the new one, never neither.

    Replacing also splits any inode the destination shares, so a hardlinked
    sibling keeps the content it had rather than silently acquiring this
    file's.

    The temp file is a sibling, so the rename stays inside one filesystem,
    and is deliberately not named `*.tf`: an orphan left behind by a failed
    write is then invisible to Terraform and to the stale-file scan alike.

    Args:
        destination: Where the file belongs
        content: What it should hold
    """
    temporary = destination.with_name(f".{destination.name}.headroom-tmp")
    with open(temporary, 'w') as handle:
        handle.write(content)
    os.replace(temporary, destination)


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

    first_line = _first_line(destination)
    if first_line is None:
        result.conflicts.append(f"{destination}: cannot be read to compare")
        return
    if first_line != GENERATED_MARKER:
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


def _preflight_symlink(destination: Path, source: Path, result: _Preflight) -> None:
    """
    Decide what to do with the one reserved symlink.

    The link text is computed here, not carried in the plan, because it is the
    one value in a run that cannot be known without reading the filesystem: a
    relative path is relative to where the link really lives, and either
    output directory may be spelled as a symlink to somewhere else. Computing
    it lexically at compile time produces a link that dangles from the moment
    it is created, and that every later run reads back, agrees with, and
    leaves.

    A correct link is left exactly as it is, so an unchanged run preserves its
    lstat metadata. A marked regular file at the path is a previous Headroom
    layout and may migrate; an unmarked one is somebody else's and aborts.

    Args:
        destination: rcps/grab_org_info.tf
        source: The file the link must point at, absolute
        result: Accumulator for decisions and conflicts
    """
    target = os.path.relpath(
        os.path.realpath(source), os.path.realpath(destination.parent)
    )

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

    first_line = _first_line(destination)
    if first_line is None:
        result.conflicts.append(f"{destination}: cannot be read to compare")
        return
    if first_line != GENERATED_MARKER:
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
        RuntimeError: If any destination is not Headroom's to touch, or the
            output directories are one directory under two names. Every
            conflict is reported, not just the first: these are hand-edited
            files, and an operator commonly has several.
    """
    result = _Preflight()
    result.conflicts.extend(_directory_aliases(plan.managed_directories))

    for destination, content in sorted(plan.files.items()):
        _preflight_file(destination, content, result)

    for destination, source in sorted(plan.symlinks.items()):
        _preflight_symlink(destination, source, result)

    # The name check below is deliberately redundant with the identity filter
    # that follows it, and deleting it leaves every test green. It stays
    # because it is the check that says what the rule is -- do not delete a
    # file this run is writing -- while the identity filter exists only to
    # catch the same file reached under a spelling this one cannot see. Read
    # in the other order, the rule is an inference from inode arithmetic.
    planned = set(plan.files) | set(plan.symlinks)
    for directory in plan.managed_directories:
        if not directory.is_dir():
            continue
        for candidate in directory.glob("*.tf"):
            if candidate not in planned and _is_marked_regular_file(candidate):
                result.to_delete.add(candidate)

    protected = _protected_identities(result)
    result.to_delete = {
        candidate for candidate in result.to_delete
        if _filesystem_identity(candidate) not in protected
    }

    if result.conflicts:
        listing = "\n  ".join(sorted(result.conflicts))
        raise RuntimeError(
            f"Refusing to apply: {len(result.conflicts)} destination(s) or "
            f"output directory(ies) are not this run's to write:\n  {listing}\n"
            "Ownership of a file is the marker on its first line. A file "
            "Headroom does not own must be moved aside or renamed; output "
            "from a Headroom old enough to predate the marker is not "
            "recognizable as ours, and has to be deleted so this run can "
            "write it again. Nothing was changed."
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
        plan: A whole-run plan, revalidated here rather than trusted: the
            compiler is the only thing that builds one, but nothing in the
            type stops a caller from assembling a `TerraformPlan` by hand and
            handing it straight to the one function that mutates the disk.

    Raises:
        RuntimeError: If the plan does not validate, if preflight finds any
            destination Headroom does not own, or if the output directories
            turn out to be one directory
    """
    validate_plan(plan)
    decided = _preflight(plan)

    for directory in plan.managed_directories:
        directory.mkdir(parents=True, exist_ok=True)

    # Preflight saw neither directory, so the alias only exists once mkdir has
    # made it. Creating a directory destroys nothing, so checking here is
    # still ahead of everything that does.
    created_as_one = _directory_aliases(plan.managed_directories)
    if created_as_one:
        listing = "\n  ".join(sorted(created_as_one))
        raise RuntimeError(
            "Refusing to apply: creating the output directories produced one "
            f"directory under two names:\n  {listing}\n"
            "No file was written, linked, or deleted."
        )

    for destination in sorted(decided.to_write):
        _write_file(destination, decided.to_write[destination])
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
