"""
SCPs Terraform Generation Module

Generates Terraform files for SCP deployment based on compliance analysis recommendations.
"""

from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

from .models import RenderedTerraformFiles, TerraformModule
from .parameters import render_check_parameters
from .utils import (
    account_id_local_name,
    claim_plan_path,
    make_account_base_names,
    make_ou_base_names,
    ou_id_local_name,
    ou_path_names,
)
from ..checks.registry import get_check_definitions
from ..enums import PlacementLevel
from ..types import GroupedSCPRecommendations, OrganizationHierarchy, SCPPlacementRecommendations


def _get_safe_to_enable_policies(
    module_name: str,
    recommendations: List[SCPPlacementRecommendations]
) -> Dict[str, Optional[List[str]]]:
    """
    Map the checks to enable for one module to their allowlist values.

    A recommendation reaching a module is itself the signal to enable the
    policy: `affected_accounts` holds the zero-violation subset at every
    level, so the placement has already established that no covered account
    violates the check. There is nothing left to re-check here.

    This used to gate on `compliance_percentage == 100.0`. Root and OU
    recommendations hardcode that value, so the gate did nothing for them,
    while account recommendations store an org-wide coverage fraction that is
    below 100% by construction - account placement only happens when some
    other account violates the check. Every per-account file therefore
    emitted every policy as false.

    Args:
        module_name: Terraform module being built, used in the error
        recommendations: Placement recommendations targeting this module

    Returns:
        Each recommended check's registered name, mapped to the allowlist
        values placement unioned for it - None where the check declares no
        allowlist

    Raises:
        RuntimeError: If a "none" recommendation reaches a module
    """
    allowlists: Dict[str, Optional[List[str]]] = {}
    for rec in recommendations:
        if rec.recommended_level == PlacementLevel.NONE.value:
            raise RuntimeError(
                f"Module {module_name} was given a recommendation for "
                f"{rec.check_name} at level 'none'. That is placement saying no "
                f"account is safe for this check, not a placement to deploy, and "
                f"grouping drops it before any module is built. Enabling it here "
                f"would deny actions the covered accounts rely on."
            )
        allowlists[rec.check_name] = rec.allowlist_values
    return allowlists


def _build_scp_terraform_module(
    module_name: str,
    target_id_reference: str,
    recommendations: List[SCPPlacementRecommendations],
    comment: str,
    organization_hierarchy: OrganizationHierarchy
) -> str:
    """
    Build Terraform module call for SCP deployment.

    Every registered SCP check renders here, enabled where a recommendation
    names it and disabled where none does, so registering a check is the
    whole of wiring it into the generated module (INV-13).

    Args:
        module_name: Name of the Terraform module instance (e.g., "scps_root")
        target_id_reference: Reference to the target ID (e.g., "local.root_ou_id")
        recommendations: List of SCP placement recommendations for this target
        comment: Comment line describing the configuration (e.g., "Organization Root")
        organization_hierarchy: Organization structure, forwarded to the
            shared renderer so an ARN allowlist can be rewritten to
            generated locals

    Returns:
        Complete Terraform module block as a string

    Raises:
        RuntimeError: If a recommendation that is not a placement reaches a
            module, or names a check no registered definition describes,
            which would otherwise render as a module silently missing that
            statement, or carries None for a check that declares an
            allowlist - `allowlist_values` defaults to None, and an
            observed-empty allowlist is [], so None is lost data rather
            than a fact about the covered accounts
    """
    allowlists = _get_safe_to_enable_policies(module_name, recommendations)

    parameters = render_check_parameters(
        get_check_definitions("scps"),
        allowlists,
        module_name,
        organization_hierarchy,
    )

    module = TerraformModule(
        name=module_name,
        source="../modules/scps",
        target_id=target_id_reference,
        parameters=parameters,
        comment=comment
    )

    return module.render()


def _render_account_scp_terraform(
    account_id: str,
    account_recs: List[SCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_path: Path
) -> tuple[Path, str]:
    """
    Render the Terraform file for one account's SCPs.

    Args:
        account_id: AWS account ID
        account_recs: List of SCP recommendations for this account
        organization_hierarchy: Organization structure information
        output_path: Directory the file belongs in

    Returns:
        Tuple of (destination path, rendered content)

    Raises:
        RuntimeError: If the account is missing from the organization hierarchy
    """
    account_info = organization_hierarchy.accounts.get(account_id)
    if not account_info:
        raise RuntimeError(f"Account ({account_id}) not found in organization hierarchy")

    # Every reference to an account is built from this one identifier, and two
    # accounts whose names fold to it abort here rather than overwrite each
    # other in the plan.
    account_name = make_account_base_names(organization_hierarchy.accounts)[account_id]
    filepath = output_path / f"{account_name}_scps.tf"

    terraform_content = _build_scp_terraform_module(
        module_name=f"scps_{account_name}",
        target_id_reference=f"local.{account_id_local_name(account_name)}",
        recommendations=account_recs,
        comment=account_info.account_name,
        organization_hierarchy=organization_hierarchy
    )

    return filepath, terraform_content


def _render_ou_scp_terraform(
    ou_id: str,
    ou_recs: List[SCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_path: Path
) -> tuple[Path, str]:
    """
    Render the Terraform file for one OU's SCPs.

    Args:
        ou_id: Organizational Unit ID
        ou_recs: List of SCP recommendations for this OU
        organization_hierarchy: Organization structure information
        output_path: Directory the file belongs in

    Returns:
        Tuple of (destination path, rendered content)

    Raises:
        RuntimeError: If the OU is missing from the organization hierarchy
    """
    ou_info = organization_hierarchy.organizational_units.get(ou_id)
    if not ou_info:
        raise RuntimeError(f"OU {ou_id} not found in organization hierarchy")

    # An OU is named for its path from the root, so a nested OU targets the
    # local grab_org_info.tf declares for it and two OUs sharing a name in
    # different branches cannot write to the same file.
    base_name = make_ou_base_names(
        organization_hierarchy.organizational_units
    )[ou_id]
    path_label = " / ".join(
        ou_path_names(ou_id, organization_hierarchy.organizational_units)
    )
    filepath = output_path / f"{base_name}_ou_scps.tf"

    terraform_content = _build_scp_terraform_module(
        module_name=f"scps_{base_name}_ou",
        target_id_reference=f"local.{ou_id_local_name(base_name)}",
        recommendations=ou_recs,
        comment=f"OU {path_label}",
        organization_hierarchy=organization_hierarchy
    )

    return filepath, terraform_content


def _render_root_scp_terraform(
    root_recommendations: List[SCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_path: Path
) -> tuple[Path, str]:
    """
    Render the Terraform file for root-level SCPs.

    Args:
        root_recommendations: List of SCP recommendations for the root level
        organization_hierarchy: Organization structure information
        output_path: Directory the file belongs in

    Returns:
        Tuple of (destination path, rendered content)
    """
    filepath = output_path / "root_scps.tf"

    terraform_content = _build_scp_terraform_module(
        module_name="scps_root",
        target_id_reference="local.root_ou_id",
        recommendations=root_recommendations,
        comment="Organization Root",
        organization_hierarchy=organization_hierarchy
    )

    return filepath, terraform_content


def render_scp_terraform(
    recommendations: List[SCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_path: Path
) -> RenderedTerraformFiles:
    """
    Render every SCP file this run's recommendations call for.

    Nothing is written here. A target absent from the returned plan is a target
    this run does not want a file for, which is what lets applying the plan
    delete the file a previous run left behind.

    Args:
        recommendations: List of SCP placement recommendations
        organization_hierarchy: Organization structure information
        output_path: Directory the files belong in

    Returns:
        Rendered file contents, keyed by destination path. Nothing is
        written; the caller compiles these into the run's plan.
    """
    # Group recommendations by level and target
    account_recommendations: GroupedSCPRecommendations = defaultdict(list)
    ou_recommendations: GroupedSCPRecommendations = defaultdict(list)
    root_recommendations: List[SCPPlacementRecommendations] = []

    for rec in recommendations:
        if rec.recommended_level == "account":
            for account_id in rec.affected_accounts:
                account_recommendations[account_id].append(rec)
            continue

        if rec.recommended_level == "ou" and rec.target_ou_id:
            ou_recommendations[rec.target_ou_id].append(rec)
            continue

        if rec.recommended_level == "root":
            root_recommendations.append(rec)

    plan: RenderedTerraformFiles = {}

    for account_id, account_recs in account_recommendations.items():
        filepath, content = _render_account_scp_terraform(
            account_id, account_recs, organization_hierarchy, output_path
        )
        claim_plan_path(plan, filepath, content, f"account {organization_hierarchy.accounts[account_id].account_name!r}")

    for ou_id, ou_recs in ou_recommendations.items():
        filepath, content = _render_ou_scp_terraform(
            ou_id, ou_recs, organization_hierarchy, output_path
        )
        claim_plan_path(plan, filepath, content, f"OU {organization_hierarchy.organizational_units[ou_id].name!r}")

    if root_recommendations:
        filepath, content = _render_root_scp_terraform(
            root_recommendations, organization_hierarchy, output_path
        )
        claim_plan_path(plan, filepath, content, "the organization root")

    return plan
