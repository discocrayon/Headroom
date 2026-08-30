"""
Reconciliation of the Terraform directory against a run's recommendations.

Generation is a desired-state compilation, not an append: a target that drops
out of the recommendations must lose its file, or Terraform keeps deploying
last run's decision. Every generated file carries GENERATED_MARKER on its first
line, and that marker - not the filename, not a manifest - is what makes a file
Headroom's to delete.
"""

import logging
from pathlib import Path
from typing import Iterable, List, Set

from ..constants import GENERATED_MARKER

logger = logging.getLogger(__name__)

__all__ = [
    "find_managed_files",
    "reconcile_generated_terraform",
]


def _is_managed(path: Path) -> bool:
    """
    Report whether Headroom wrote this file and may therefore delete it.

    Args:
        path: Candidate file, already known to end in .tf

    Returns:
        True if the file's first line is exactly GENERATED_MARKER
    """
    # A symlink is checked before anything else. rcps/grab_org_info.tf points at
    # the real file in scps/, so reading through the link finds the marker and
    # would delete a link Headroom is responsible for maintaining, not removing.
    if path.is_symlink() or not path.is_file():
        return False

    try:
        with open(path, 'r') as f:
            first_line = f.readline()
    except (OSError, UnicodeDecodeError):
        # A file we cannot read is a file we cannot prove is ours.
        return False

    return first_line.rstrip("\n") == GENERATED_MARKER


def find_managed_files(directory: Path) -> Set[Path]:
    """
    Find the Headroom-generated Terraform files in one directory.

    The search does not recurse: .terraform/ and any module directory below the
    output directory belong to Terraform, not to Headroom.

    Args:
        directory: Output directory to scan

    Returns:
        Paths of the .tf files carrying the generated marker, empty if the
        directory does not exist
    """
    if not directory.is_dir():
        return set()

    return {path for path in directory.glob("*.tf") if _is_managed(path)}


def reconcile_generated_terraform(
    directories: Iterable[Path],
    expected: Set[Path],
    dry_run: bool = False
) -> List[Path]:
    """
    Delete the generated files this run did not produce.

    Only files carrying the marker are candidates, so anything hand-written,
    symlinked, or of another type survives untouched no matter what `expected`
    holds.

    Args:
        directories: Output directories to reconcile
        expected: Every file this run's plan calls for, across all directories
        dry_run: Report what would be deleted without deleting it

    Returns:
        Deleted paths, sorted, so the caller can report them
    """
    stale: Set[Path] = set()
    for directory in directories:
        stale |= find_managed_files(directory) - expected

    deleted = sorted(stale)
    for path in deleted:
        if dry_run:
            logger.info(f"Would delete stale generated Terraform file: {path}")
            continue
        path.unlink()
        logger.info(f"Deleted stale generated Terraform file: {path}")

    return deleted
