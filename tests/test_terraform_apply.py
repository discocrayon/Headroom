"""
Tests for terraform.apply: the only place Headroom mutates Terraform output.

Covers which files Headroom claims as its own, which it must never touch, and
that a preflight conflict anywhere stops every mutation everywhere.
"""

import os
from pathlib import Path
from typing import Dict, Tuple

import pytest

from headroom.constants import GENERATED_MARKER, ORG_INFO_FILENAME
from headroom.terraform.apply import apply_terraform_plan
from headroom.terraform.plan import TerraformPlan


def generated(body: str = 'module "x" {}\n') -> str:
    """Content carrying the marker Headroom stamps on its own output."""
    return f"{GENERATED_MARKER}\n{body}"


def dirs(tmp_path: Path) -> Tuple[Path, Path]:
    """The two managed directories, created and canonical."""
    scps = Path(os.path.abspath(tmp_path / "scps"))
    rcps = Path(os.path.abspath(tmp_path / "rcps"))
    scps.mkdir()
    rcps.mkdir()
    return scps, rcps


def plan_for(
    scps: Path,
    rcps: Path,
    files: Dict[Path, str],
) -> TerraformPlan:
    """A plan holding the given files plus the reserved link."""
    return TerraformPlan(
        managed_directories=(scps, rcps),
        files=files,
        symlinks={rcps / ORG_INFO_FILENAME: f"../{scps.name}/{ORG_INFO_FILENAME}"},
    )


def test_one_unowned_destination_prevents_every_other_mutation(
    tmp_path: Path
) -> None:
    """
    Preflight is complete before anything is written, so a conflict on one
    file leaves the other files, the link, and the stale deletions all undone.
    """
    scps, rcps = dirs(tmp_path)
    hand_written = scps / "payments_scps.tf"
    hand_written.write_text('module "mine" {}\n')
    stale = scps / "retired_ou_scps.tf"
    stale.write_text(generated())

    plan = plan_for(scps, rcps, {
        scps / ORG_INFO_FILENAME: generated("# org info\n"),
        hand_written: generated("# regenerated\n"),
    })

    with pytest.raises(RuntimeError, match="does not own"):
        apply_terraform_plan(plan)

    assert hand_written.read_text() == 'module "mine" {}\n'
    assert not (scps / ORG_INFO_FILENAME).exists()
    assert stale.exists()
    assert not (rcps / ORG_INFO_FILENAME).exists()
