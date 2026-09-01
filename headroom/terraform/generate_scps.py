"""
SCPs Terraform Generation Module

Generates Terraform files for SCP deployment based on compliance analysis recommendations.
"""

import logging
from collections import defaultdict
from pathlib import Path
from typing import List

from .models import (
    TerraformComment,
    TerraformElement,
    TerraformModule,
    TerraformParameter,
    TerraformPlan,
)
from .utils import (
    account_id_local_name,
    claim_plan_path,
    make_account_base_names,
    make_ou_base_names,
    make_safe_variable_name,
    ou_id_local_name,
    ou_path_names,
    write_terraform_plan,
)
from ..enums import PlacementLevel
from ..types import GroupedSCPRecommendations, OrganizationHierarchy, SCPPlacementRecommendations

# Set up logging
logger = logging.getLogger(__name__)


def _replace_account_id_in_arn(
    arn: str,
    organization_hierarchy: OrganizationHierarchy
) -> str:
    """
    Replace account ID in ARN with Terraform local variable reference.

    Args:
        arn: IAM user ARN (e.g., "arn:aws:iam::111111111111:user/path/username")
        organization_hierarchy: Organization structure for account ID lookups

    Returns:
        ARN with account ID replaced by local variable reference
        (e.g., "arn:aws:iam::${local.account_name_account_id}:user/path/username")
    """
    parts = arn.split(":")
    if len(parts) >= 5 and parts[0] == "arn" and parts[2] == "iam":
        account_id = parts[4]
        account_info = organization_hierarchy.accounts.get(account_id)
        if account_info:
            safe_account_name = make_safe_variable_name(account_info.account_name)
            parts[4] = f"${{local.{account_id_local_name(safe_account_name)}}}"
            return ":".join(parts)
    return arn


def _get_safe_to_enable_policies(
    module_name: str,
    recommendations: List[SCPPlacementRecommendations]
) -> set[str]:
    """
    Get the policies to enable for one module, from its recommendations.

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
        Terraform variable names, converted from kebab-case to snake_case

    Raises:
        RuntimeError: If a "none" recommendation reaches a module
    """
    enabled_policies = set()
    for rec in recommendations:
        if rec.recommended_level == PlacementLevel.NONE.value:
            raise RuntimeError(
                f"Module {module_name} was given a recommendation for "
                f"{rec.check_name} at level 'none'. That is placement saying no "
                f"account is safe for this check, not a placement to deploy, and "
                f"grouping drops it before any module is built. Enabling it here "
                f"would deny actions the covered accounts rely on."
            )
        check_name_terraform = rec.check_name.replace("-", "_")
        enabled_policies.add(check_name_terraform)
    return enabled_policies


def _get_ec2_allowed_ami_owners(
    recommendations: List[SCPPlacementRecommendations]
) -> List[str]:
    """Extract allowed AMI owners from deny_ec2_ami_owner recommendations."""
    for rec in recommendations:
        if rec.check_name.replace("-", "_") == "deny_ec2_ami_owner" and rec.ec2_allowed_ami_owners:
            return rec.ec2_allowed_ami_owners
    return []


def _get_allowed_iam_user_arns(
    recommendations: List[SCPPlacementRecommendations]
) -> List[str]:
    """Extract allowed IAM user ARNs from deny_iam_user_creation recommendations."""
    for rec in recommendations:
        if rec.check_name.replace("-", "_") == "deny_iam_user_creation" and rec.allowed_iam_user_arns:
            return rec.allowed_iam_user_arns
    return []


def _build_ec2_terraform_parameters(
    module_name: str,
    enabled_policies: set[str],
    recommendations: List[SCPPlacementRecommendations]
) -> List[TerraformElement]:
    """
    Build EC2 parameters for Terraform configuration.

    Returns:
        List of TerraformElement objects for EC2 policies
    """
    parameters: List[TerraformElement] = []

    parameters.append(TerraformComment("EC2"))
    deny_ec2_ami_owner = "deny_ec2_ami_owner" in enabled_policies
    ec2_allowed_ami_owners = (
        _get_ec2_allowed_ami_owners(recommendations) if deny_ec2_ami_owner else []
    )

    # An empty allowlist denies every ec2:RunInstances call rather than none
    # of them, so it is never rendered. Reaching here means the covered
    # accounts observed no AMI owner at all, which an account running no
    # instances does - a fact about those accounts rather than a broken run,
    # so the policy stays off and the rest of the organization still
    # generates. The other cause, a result file predating AMI owner
    # collection, is rejected during parsing.
    if deny_ec2_ami_owner and not ec2_allowed_ami_owners:
        logger.warning(
            f"Module {module_name}: leaving deny_ec2_ami_owner off because no "
            f"instance in the accounts it covers had a resolvable AMI owner, so "
            f"the allowlist would be empty."
        )
        parameters.append(TerraformComment(
            "deny_ec2_ami_owner stays off here: no instance in the accounts this "
            "module covers had a resolvable AMI owner, so the allowlist would be "
            "empty - and an empty allowlist denies every launch, not none."
        ))
        deny_ec2_ami_owner = False

    parameters.append(TerraformParameter("deny_ec2_ami_owner", deny_ec2_ami_owner))
    if deny_ec2_ami_owner:
        parameters.append(TerraformParameter("ec2_allowed_ami_owners", ec2_allowed_ami_owners))

    deny_ec2_imds_hop_limit = "deny_ec2_imds_hop_limit" in enabled_policies
    parameters.append(TerraformParameter("deny_ec2_imds_hop_limit", deny_ec2_imds_hop_limit))

    deny_ec2_imds_v1 = "deny_ec2_imds_v1" in enabled_policies
    parameters.append(TerraformParameter("deny_ec2_imds_v1", deny_ec2_imds_v1))

    deny_ec2_public_ip = "deny_ec2_public_ip" in enabled_policies
    parameters.append(TerraformParameter("deny_ec2_public_ip", deny_ec2_public_ip))

    return parameters


def _build_eks_terraform_parameters(enabled_policies: set[str]) -> List[TerraformElement]:
    """
    Build EKS parameters for Terraform configuration.

    Returns:
        List of TerraformElement objects for EKS policies
    """
    parameters: List[TerraformElement] = []

    parameters.append(TerraformComment("EKS"))
    deny_eks_create_cluster_without_tag = "deny_eks_create_cluster_without_tag" in enabled_policies
    parameters.append(TerraformParameter("deny_eks_create_cluster_without_tag", deny_eks_create_cluster_without_tag))

    return parameters


def _build_iam_terraform_parameters(
    module_name: str,
    enabled_policies: set[str],
    recommendations: List[SCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy
) -> List[TerraformElement]:
    """
    Build IAM parameters for Terraform configuration.

    Returns:
        List of TerraformElement objects for IAM policies
    """
    parameters: List[TerraformElement] = []

    parameters.append(TerraformComment("IAM"))
    deny_iam_saml_provider_not_aws_sso = "deny_iam_saml_provider_not_aws_sso" in enabled_policies
    parameters.append(TerraformParameter("deny_iam_saml_provider_not_aws_sso", deny_iam_saml_provider_not_aws_sso))

    deny_iam_user_creation = "deny_iam_user_creation" in enabled_policies
    transformed_arns = [
        _replace_account_id_in_arn(arn, organization_hierarchy)
        for arn in (_get_allowed_iam_user_arns(recommendations) if deny_iam_user_creation else [])
    ]

    # An empty allowlist renders NotResource: [], and a policy array takes one
    # or more values, so Organizations rejects the document and the entire SCP
    # fails to attach - every other statement in this module with it. Reaching
    # here means the covered accounts hold no IAM user at all, which is an
    # ordinary fact about them rather than a broken run, so the policy stays
    # off and the rest of the organization still generates (INV-06).
    if deny_iam_user_creation and not transformed_arns:
        logger.warning(
            f"Module {module_name}: leaving deny_iam_user_creation off because no "
            f"IAM user exists in the accounts it covers, so the allowlist would "
            f"be empty."
        )
        parameters.append(TerraformComment(
            "deny_iam_user_creation stays off here: no IAM user in the accounts "
            "this module covers, so the allowlist would be empty - and "
            "NotResource: [] is rejected as a malformed policy."
        ))
        deny_iam_user_creation = False

    parameters.append(TerraformParameter("deny_iam_user_creation", deny_iam_user_creation))
    if deny_iam_user_creation:
        parameters.append(TerraformParameter("iam_allowed_users", transformed_arns))

    return parameters


def _build_lambda_terraform_parameters(enabled_policies: set[str]) -> List[TerraformElement]:
    """
    Build Lambda parameters for Terraform configuration.

    Returns:
        List of TerraformElement objects for Lambda policies
    """
    parameters: List[TerraformElement] = []

    parameters.append(TerraformComment("Lambda"))
    deny_lambda_auth_type_none = "deny_lambda_auth_type_none" in enabled_policies
    parameters.append(TerraformParameter("deny_lambda_auth_type_none", deny_lambda_auth_type_none))

    return parameters


def _build_rds_terraform_parameters(enabled_policies: set[str]) -> List[TerraformElement]:
    """
    Build RDS parameters for Terraform configuration.

    Returns:
        List of TerraformElement objects for RDS policies
    """
    parameters: List[TerraformElement] = []

    parameters.append(TerraformComment("RDS"))
    deny_rds_unencrypted = "deny_rds_unencrypted" in enabled_policies
    parameters.append(TerraformParameter("deny_rds_unencrypted", deny_rds_unencrypted))

    return parameters


def _build_scp_terraform_module(
    module_name: str,
    target_id_reference: str,
    recommendations: List[SCPPlacementRecommendations],
    comment: str,
    organization_hierarchy: OrganizationHierarchy
) -> str:
    """
    Build Terraform module call for SCP deployment.

    Args:
        module_name: Name of the Terraform module instance (e.g., "scps_root")
        target_id_reference: Reference to the target ID (e.g., "local.root_ou_id")
        recommendations: List of SCP placement recommendations for this target
        comment: Comment line describing the configuration (e.g., "Organization Root")
        organization_hierarchy: Organization structure for account ID lookups

    Returns:
        Complete Terraform module block as a string

    Raises:
        RuntimeError: If a recommendation that is not a placement reaches a
            module, or a referenced account or OU is missing from the
            organization hierarchy
    """
    enabled_policies = _get_safe_to_enable_policies(module_name, recommendations)

    parameters: List[TerraformElement] = []
    parameters.extend(_build_ec2_terraform_parameters(module_name, enabled_policies, recommendations))
    parameters.append(TerraformComment(""))
    parameters.extend(_build_eks_terraform_parameters(enabled_policies))
    parameters.append(TerraformComment(""))
    parameters.extend(_build_iam_terraform_parameters(module_name, enabled_policies, recommendations, organization_hierarchy))
    parameters.append(TerraformComment(""))
    parameters.extend(_build_lambda_terraform_parameters(enabled_policies))
    parameters.append(TerraformComment(""))
    parameters.extend(_build_rds_terraform_parameters(enabled_policies))

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


def _render_scp_terraform_plan(
    recommendations: List[SCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_path: Path
) -> TerraformPlan:
    """
    Render every SCP file this run's recommendations call for.

    Nothing is written here. A target absent from the returned plan is a target
    this run does not want a file for, which is what lets reconciliation delete
    the file a previous run left behind.

    Args:
        recommendations: List of SCP placement recommendations
        organization_hierarchy: Organization structure information
        output_path: Directory the files belong in

    Returns:
        Rendered file contents, keyed by destination path
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

    plan: TerraformPlan = {}

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


def generate_scp_terraform(
    recommendations: List[SCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_dir: str
) -> TerraformPlan:
    """
    Generate Terraform files for SCP deployment based on recommendations.

    An empty recommendation list is a plan for an empty directory, not a
    no-op. The caller reconciles against the returned plan, so a policy that no
    longer has a placement loses the file that deploys it.

    Args:
        recommendations: List of SCP placement recommendations
        organization_hierarchy: Organization structure information
        output_dir: Directory to write Terraform files to

    Returns:
        The files this run wants the directory to hold, keyed by path

    Raises:
        RuntimeError: If a recommendation names a target the organization
            hierarchy does not have, or is not a placement at all
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Rendered in full first: a raise here has written nothing, leaving the
    # previous run's output complete rather than half replaced.
    plan = _render_scp_terraform_plan(
        recommendations, organization_hierarchy, output_path
    )
    write_terraform_plan(plan, "SCP")

    return plan
