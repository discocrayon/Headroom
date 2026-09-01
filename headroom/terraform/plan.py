"""
The whole run's desired Terraform state, compiled before any of it is applied.

Compilation renders every file, calculates every destination, and rejects a
plan it cannot apply safely -- all without touching the filesystem. Applying
it is `terraform.apply`'s job, and the split is the point: a run that fails
while parsing, rendering, or validating has mutated nothing.
"""

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Tuple

from .generate_org_info import render_terraform_org_info
from .generate_rcps import render_rcp_terraform
from .generate_scps import render_scp_terraform
from .models import RenderedTerraformFiles
from .utils import claim_plan_path
from ..config import HeadroomConfig
from ..constants import GENERATED_MARKER, ORG_INFO_FILENAME
from ..types import (
    OrganizationHierarchy,
    RCPPlacementRecommendations,
    SCPPlacementRecommendations,
)

logger = logging.getLogger(__name__)

__all__ = [
    "TerraformPlan",
    "compile_terraform_plan",
]


@dataclass(frozen=True)
class TerraformPlan:
    """
    Everything one run means the Terraform directories to hold.

    Attributes:
        managed_directories: The directories this plan owns, canonical and
            absolute. Nothing outside them may be written or deleted.
        files: Destination path -> complete rendered content.
        symlinks: Destination path -> the exact relative link text
            `os.readlink` must return for the link to be considered correct.
    """
    managed_directories: Tuple[Path, ...]
    files: Mapping[Path, str]
    symlinks: Mapping[Path, str]


def _canonical(path: Path) -> Path:
    """
    Reduce a path to the one spelling every comparison uses.

    Lexical, and deliberately so: `os.path.abspath` is `normpath` of the
    cwd-joined path, which reads nothing. Compilation stays free of filesystem
    access, and the same plan validates identically on every machine.

    `Path` already folds away `.` components when it is constructed, so what
    this adds is `..` normalization and agreement between a relative spelling
    and an absolute one. Two directories that are distinct paths reaching one
    inode through a symlink are not caught, and are out of scope: catching
    them needs `resolve()`, which reads the filesystem.

    Args:
        path: Any destination or managed directory

    Returns:
        The absolute, lexically normalized form
    """
    return Path(os.path.abspath(path))


def _validate_plan(plan: TerraformPlan) -> None:
    """
    Refuse a plan that cannot be applied safely.

    Aborts on the first violation, matching `claim_plan_path` and
    `make_ou_base_names`, which already raise one explanatory error rather
    than a list. The order matters: equal managed directories *cause* a
    file-versus-symlink collision, so checking them first names the cause
    instead of the symptom.

    Args:
        plan: The compiled plan

    Raises:
        RuntimeError: On equal managed directories, an unexpected symlink, a
            destination outside the managed directories, two destinations
            that canonicalize alike, or content missing GENERATED_MARKER
    """
    scps, rcps = plan.managed_directories
    if scps == rcps:
        raise RuntimeError(
            f"The SCP and RCP output directories are the same directory: {scps}. "
            "Every RCP file would be generated over an SCP file of the same "
            "name, and rcps/grab_org_info.tf would be a symlink to itself. "
            "Set scps_dir and rcps_dir to different directories."
        )

    reserved_link = rcps / ORG_INFO_FILENAME
    for destination in plan.symlinks:
        if _canonical(destination) != reserved_link:
            raise RuntimeError(
                f"{destination} is planned as a symlink. The only symlink "
                f"Headroom maintains is {reserved_link}, which points at the "
                "shared organization data sources in the SCP directory."
            )

    managed = set(plan.managed_directories)
    claimed: Dict[Path, str] = {}
    for destination, kind in [(d, "file") for d in plan.files] + [
        (d, "symlink") for d in plan.symlinks
    ]:
        canonical = _canonical(destination)
        if canonical.parent not in managed:
            raise RuntimeError(
                f"{destination} is outside the directories this run manages "
                f"({', '.join(str(d) for d in plan.managed_directories)}). "
                "Headroom writes and deletes only directly inside them."
            )
        if canonical in claimed:
            raise RuntimeError(
                f"Two destinations resolve to {canonical}: a {claimed[canonical]} "
                f"and a {kind}. One would silently replace the other."
            )
        claimed[canonical] = kind

    for destination, content in sorted(plan.files.items()):
        if content.split("\n", 1)[0] != GENERATED_MARKER:
            raise RuntimeError(
                f"Rendered content for {destination} does not open with "
                f"{GENERATED_MARKER!r}. Ownership is that first line, so a file "
                "written without it could never be recognized as Headroom's "
                "and would drift on forever."
            )


def compile_terraform_plan(
    config: HeadroomConfig,
    organization_hierarchy: OrganizationHierarchy,
    scp_recommendations: List[SCPPlacementRecommendations],
    rcp_recommendations: List[RCPPlacementRecommendations],
) -> TerraformPlan:
    """
    Render and validate everything this run wants on disk, writing none of it.

    Empty recommendations are a plan for directories holding only org-info and
    the link, not a no-op: applying such a plan is what removes the policy
    files a previous run left behind.

    No AWS call is made. The hierarchy is the one the run already captured.

    Args:
        config: Validated Headroom configuration
        organization_hierarchy: The run's captured organization hierarchy
        scp_recommendations: This run's SCP placements
        rcp_recommendations: This run's RCP placements

    Returns:
        The validated whole-run plan

    Raises:
        RuntimeError: If rendering or validation rejects the result
    """
    scps = _canonical(Path(config.scps_dir))
    rcps = _canonical(Path(config.rcps_dir))

    # Merged through claim_plan_path, never by assignment. The three renderers
    # each keep their own namespace collision-free and none can see the others,
    # so `files.update(...)` would silently drop one component's file and hand
    # validation a plan already missing it.
    files: RenderedTerraformFiles = {}
    claim_plan_path(
        files,
        scps / ORG_INFO_FILENAME,
        render_terraform_org_info(organization_hierarchy),
        "the organization data sources",
    )
    for destination, content in render_scp_terraform(
        scp_recommendations, organization_hierarchy, scps
    ).items():
        claim_plan_path(files, destination, content, "an SCP file")
    for destination, content in render_rcp_terraform(
        rcp_recommendations, organization_hierarchy, rcps
    ).items():
        claim_plan_path(files, destination, content, "an RCP file")

    symlinks = {
        rcps / ORG_INFO_FILENAME: os.path.relpath(scps / ORG_INFO_FILENAME, rcps)
    }

    plan = TerraformPlan(
        managed_directories=(scps, rcps),
        files=files,
        symlinks=symlinks,
    )
    _validate_plan(plan)
    return plan
