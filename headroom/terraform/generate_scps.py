"""
SCPs Terraform Generation Module

Generates Terraform files for SCP deployment based on compliance analysis recommendations.
"""

import logging
from collections import defaultdict
from pathlib import Path
from typing import List

from .models import TerraformModule, TerraformParameter, TerraformComment, TerraformElement
from .utils import make_safe_variable_name, write_terraform_file
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
            parts[4] = f"${{local.{safe_account_name}_account_id}}"
            return ":".join(parts)
    return arn


def _get_safe_to_enable_checks(
    recommendations: List[SCPPlacementRecommendations]
) -> set[str]:
    """
    Get set of checks that are safe to enable from recommendations.

    Only includes checks with 100% compliance.
    Converts check names from kebab-case to snake_case.
    """
    enabled_checks = set()
    for rec in recommendations:
        if rec.compliance_percentage == 100.0:
            check_name_terraform = rec.check_name.replace("-", "_")
            enabled_checks.add(check_name_terraform)
    return enabled_checks


def _get_allowed_ami_owners(
    recommendations: List[SCPPlacementRecommendations]
) -> List[str]:
    """Extract allowed AMI owners from deny_ec2_ami_owner recommendations."""
    for rec in recommendations:
        if rec.check_name.replace("-", "_") == "deny_ec2_ami_owner" and rec.allowed_ami_owners:
            return rec.allowed_ami_owners
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
    enabled_checks: set[str],
    recommendations: List[SCPPlacementRecommendations]
) -> List[TerraformElement]:
    """
    Build EC2 parameters for Terraform configuration.

    Returns:
        List of TerraformElement objects for EC2 checks
    """
    parameters: List[TerraformElement] = []

    parameters.append(TerraformComment("EC2"))
    deny_ec2_ami_owner = "deny_ec2_ami_owner" in enabled_checks
    parameters.append(TerraformParameter("deny_ec2_ami_owner", deny_ec2_ami_owner))

    if deny_ec2_ami_owner:
        allowed_ami_owners = _get_allowed_ami_owners(recommendations)
        parameters.append(TerraformParameter("allowed_ami_owners", allowed_ami_owners))

    deny_ec2_imds_v1 = "deny_ec2_imds_v1" in enabled_checks
    parameters.append(TerraformParameter("deny_ec2_imds_v1", deny_ec2_imds_v1))

    deny_ec2_public_ip = "deny_ec2_public_ip" in enabled_checks
    parameters.append(TerraformParameter("deny_ec2_public_ip", deny_ec2_public_ip))

    return parameters


def _build_eks_terraform_parameters(enabled_checks: set[str]) -> List[TerraformElement]:
    """
    Build EKS parameters for Terraform configuration.

    Returns:
        List of TerraformElement objects for EKS checks
    """
    parameters: List[TerraformElement] = []

    parameters.append(TerraformComment("EKS"))
    deny_eks_create_cluster_without_tag = "deny_eks_create_cluster_without_tag" in enabled_checks
    parameters.append(TerraformParameter("deny_eks_create_cluster_without_tag", deny_eks_create_cluster_without_tag))

    return parameters


def _build_iam_terraform_parameters(
    enabled_checks: set[str],
    recommendations: List[SCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy
) -> List[TerraformElement]:
    """
    Build IAM parameters for Terraform configuration.

    Returns:
        List of TerraformElement objects for IAM checks
    """
    parameters: List[TerraformElement] = []

    parameters.append(TerraformComment("IAM"))
    deny_iam_user_creation = "deny_iam_user_creation" in enabled_checks
    parameters.append(TerraformParameter("deny_iam_user_creation", deny_iam_user_creation))

    if deny_iam_user_creation:
        allowed_iam_user_arns = _get_allowed_iam_user_arns(recommendations)
        transformed_arns = [
            _replace_account_id_in_arn(arn, organization_hierarchy)
            for arn in allowed_iam_user_arns
        ]
        parameters.append(TerraformParameter("allowed_iam_users", transformed_arns))

    return parameters


def _build_rds_terraform_parameters(enabled_checks: set[str]) -> List[TerraformElement]:
    """
    Build RDS parameters for Terraform configuration.

    Returns:
        List of TerraformElement objects for RDS checks
    """
    parameters: List[TerraformElement] = []

    parameters.append(TerraformComment("RDS"))
    deny_rds_unencrypted = "deny_rds_unencrypted" in enabled_checks
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
    """
    enabled_checks = _get_safe_to_enable_checks(recommendations)

    parameters: List[TerraformElement] = []
    parameters.extend(_build_ec2_terraform_parameters(enabled_checks, recommendations))
    parameters.append(TerraformComment(""))
    parameters.extend(_build_eks_terraform_parameters(enabled_checks))
    parameters.append(TerraformComment(""))
    parameters.extend(_build_iam_terraform_parameters(enabled_checks, recommendations, organization_hierarchy))
    parameters.append(TerraformComment(""))
    parameters.extend(_build_rds_terraform_parameters(enabled_checks))

    module = TerraformModule(
        name=module_name,
        source="../modules/scps",
        target_id=target_id_reference,
        parameters=parameters,
        comment=comment
    )

    return module.render()


def _generate_account_scp_terraform(
    account_id: str,
    account_recs: List[SCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_path: Path
) -> None:
    """
    Generate Terraform file for account-level SCPs.

    Args:
        account_id: AWS account ID
        account_recs: List of SCP recommendations for this account
        organization_hierarchy: Organization structure information
        output_path: Directory to write Terraform files to
    """
    account_info = organization_hierarchy.accounts.get(account_id)
    if not account_info:
        raise RuntimeError(f"Account ({account_id}) not found in organization hierarchy")

    # Convert account name to terraform-friendly format
    account_name = make_safe_variable_name(account_info.account_name)
    filename = f"{account_name}_scps.tf"
    filepath = output_path / filename

    # Generate Terraform content
    terraform_content = _build_scp_terraform_module(
        module_name=f"scps_{account_name}",
        target_id_reference=f"local.{account_name}_account_id",
        recommendations=account_recs,
        comment=account_info.account_name,
        organization_hierarchy=organization_hierarchy
    )

    # Write the file
    write_terraform_file(filepath, terraform_content, "SCP")


def _generate_ou_scp_terraform(
    ou_id: str,
    ou_recs: List[SCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_path: Path
) -> None:
    """
    Generate Terraform file for OU-level SCPs.

    Args:
        ou_id: Organizational Unit ID
        ou_recs: List of SCP recommendations for this OU
        organization_hierarchy: Organization structure information
        output_path: Directory to write Terraform files to
    """
    ou_info = organization_hierarchy.organizational_units.get(ou_id)
    if not ou_info:
        raise RuntimeError(f"OU {ou_id} not found in organization hierarchy")

    # Convert OU name to terraform-friendly format
    ou_name = make_safe_variable_name(ou_info.name)
    filename = f"{ou_name}_ou_scps.tf"
    filepath = output_path / filename

    # Generate Terraform content
    terraform_content = _build_scp_terraform_module(
        module_name=f"scps_{ou_name}_ou",
        target_id_reference=f"local.top_level_{ou_name}_ou_id",
        recommendations=ou_recs,
        comment=f"OU {ou_info.name}",
        organization_hierarchy=organization_hierarchy
    )

    # Write the file
    write_terraform_file(filepath, terraform_content, "SCP")


def _generate_root_scp_terraform(
    root_recommendations: List[SCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_path: Path
) -> None:
    """
    Generate Terraform file for root-level SCPs.

    Args:
        root_recommendations: List of SCP recommendations for the root level
        organization_hierarchy: Organization structure information
        output_path: Directory to write Terraform files to
    """
    if not root_recommendations:
        return

    filename = "root_scps.tf"
    filepath = output_path / filename

    # Generate Terraform content
    terraform_content = _build_scp_terraform_module(
        module_name="scps_root",
        target_id_reference="local.root_ou_id",
        recommendations=root_recommendations,
        comment="Organization Root",
        organization_hierarchy=organization_hierarchy
    )

    # Write the file
    write_terraform_file(filepath, terraform_content, "SCP")


def generate_scp_terraform(
    recommendations: List[SCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_dir: str = "test_environment/scps"
) -> None:
    """
    Generate Terraform files for SCP deployment based on recommendations.

    Args:
        recommendations: List of SCP placement recommendations
        organization_hierarchy: Organization structure information
        output_dir: Directory to write Terraform files to
    """
    if not recommendations:
        return

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

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

    # Generate Terraform files for each account
    for account_id, account_recs in account_recommendations.items():
        _generate_account_scp_terraform(account_id, account_recs, organization_hierarchy, output_path)

    # Generate Terraform files for each OU
    for ou_id, ou_recs in ou_recommendations.items():
        _generate_ou_scp_terraform(ou_id, ou_recs, organization_hierarchy, output_path)

    # Generate Terraform file for root level
    _generate_root_scp_terraform(root_recommendations, organization_hierarchy, output_path)
