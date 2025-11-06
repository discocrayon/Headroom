"""
RCPs Terraform Generation Module

Generates Terraform files for RCP deployment based on third-party account analysis.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set

from .utils import make_safe_variable_name
from ..types import OrganizationHierarchy, RCPParseResult, RCPPlacementRecommendations
from ..constants import THIRD_PARTY_ASSUMEROLE
from ..write_results import get_results_dir
from ..aws.organization import lookup_account_id_by_name

# Set up logging
logger = logging.getLogger(__name__)

# Minimum number of accounts required in an OU to recommend OU-level RCP
# Set to 1 to allow OU-level RCPs even for single-account OUs
MIN_ACCOUNTS_FOR_OU_LEVEL_RCP = 1


def parse_rcp_result_files(
    results_dir: str,
    organization_hierarchy: OrganizationHierarchy
) -> RCPParseResult:
    """
    Parse third_party_assumerole check result files.

    Results are organized as: {results_dir}/rcps/third_party_assumerole/*.json

    Args:
        results_dir: Directory containing check result files
        organization_hierarchy: Organization structure for account name -> ID lookups

    Returns:
        RCPParseResult containing:
        - account_third_party_map: Dictionary mapping account_id -> set of third-party account IDs
          (only accounts without wildcards)
        - accounts_with_wildcards: Set of account IDs that have wildcard principals
          (cannot have RCPs deployed)
    """
    # Use centralized function to get check directory path
    check_dir_str = get_results_dir(THIRD_PARTY_ASSUMEROLE, results_dir)
    check_dir = Path(check_dir_str)

    account_third_party_map: Dict[str, Set[str]] = {}
    accounts_with_wildcards: Set[str] = set()

    if not check_dir.exists():
        raise RuntimeError(f"Third-party AssumeRole check directory does not exist: {check_dir}")

    for result_file in check_dir.glob("*.json"):
        try:
            with open(result_file, 'r') as f:
                data = json.load(f)

            summary = data.get("summary", {})
            account_id = summary.get("account_id", "")
            account_name = summary.get("account_name", "")
            third_party_accounts = summary.get("unique_third_party_accounts", [])
            roles_with_wildcards = summary.get("roles_with_wildcards", 0)

            if not account_id:
                if not account_name:
                    raise RuntimeError(f"Result file {result_file} missing both account_id and account_name in summary")
                account_id = lookup_account_id_by_name(
                    account_name,
                    organization_hierarchy,
                    str(result_file)
                )

            # Track accounts with wildcard principals separately
            if roles_with_wildcards > 0:
                accounts_with_wildcards.add(account_id)
                logger.info(f"Account {account_name} ({account_id}) has {roles_with_wildcards} roles with wildcard principals - cannot deploy RCP")
                continue

            account_third_party_map[account_id] = set(third_party_accounts)

        except (json.JSONDecodeError, KeyError) as e:
            raise RuntimeError(f"Failed to parse RCP result file {result_file}: {e}")

    return RCPParseResult(
        account_third_party_map=account_third_party_map,
        accounts_with_wildcards=accounts_with_wildcards
    )


def _check_root_level_placement(
    account_third_party_map: Dict[str, Set[str]],
    organization_hierarchy: OrganizationHierarchy,
    accounts_with_wildcards: Set[str]
) -> Optional[RCPPlacementRecommendations]:
    """
    Check if root-level RCP can be deployed by unioning all third-party account IDs.

    Root-level RCPs affect ALL accounts in the organization, so we can only recommend
    root-level deployment if NO accounts have wildcard principals (we can't determine
    their needs from static analysis).

    If safe to deploy at root, unions together all third-party account IDs from all
    accounts into a single allowlist.

    Args:
        account_third_party_map: Dictionary mapping account_id -> set of third-party account IDs
        organization_hierarchy: Organization structure for getting total account count
        accounts_with_wildcards: Set of account IDs that have wildcard principals

    Returns:
        Root-level RCP recommendation with unioned third-party account IDs if no wildcards, None otherwise
    """
    # Cannot deploy root-level RCP if ANY accounts have wildcards
    # Root-level RCPs affect those accounts too, and we can't determine their needs
    if accounts_with_wildcards:
        logger.info(f"Cannot recommend root-level RCP: {len(accounts_with_wildcards)} accounts have wildcard principals")
        return None

    if not account_third_party_map:
        return None

    # Union all third-party account IDs from all accounts
    all_third_party_accounts: Set[str] = set()
    for third_party_set in account_third_party_map.values():
        all_third_party_accounts.update(third_party_set)

    unioned_third_party = sorted(list(all_third_party_accounts))

    # Get ALL accounts in the org (root-level RCPs affect everyone)
    all_account_ids = list(organization_hierarchy.accounts.keys())

    return RCPPlacementRecommendations(
        check_name=THIRD_PARTY_ASSUMEROLE,
        recommended_level="root",
        target_ou_id=None,
        affected_accounts=all_account_ids,
        third_party_account_ids=unioned_third_party,
        reasoning=f"All {len(all_account_ids)} accounts can be protected with root-level RCP (allowlist contains {len(unioned_third_party)} third-party accounts from union of all account requirements)"
    )


def _should_skip_ou_for_rcp(
    ou_id: str,
    organization_hierarchy: OrganizationHierarchy,
    accounts_with_wildcards: Set[str]
) -> bool:
    """
    Determine if an OU should be skipped for RCP deployment due to wildcard accounts.

    OU-level RCPs apply to ALL accounts in the OU, so we cannot deploy if any
    account in that OU has wildcard principals.

    Args:
        ou_id: Organizational Unit ID to check
        organization_hierarchy: Organization structure information
        accounts_with_wildcards: Set of account IDs that have wildcard principals

    Returns:
        True if the OU should be skipped, False otherwise
    """
    ou_accounts_in_org = [
        acc_id for acc_id, acc_info in organization_hierarchy.accounts.items()
        if acc_info.parent_ou_id == ou_id
    ]

    if any(acc_id in accounts_with_wildcards for acc_id in ou_accounts_in_org):
        ou_info = organization_hierarchy.organizational_units.get(ou_id)
        ou_name = ou_info.name if ou_info else ou_id
        logger.info(f"Skipping OU-level RCP for '{ou_name}' - one or more accounts have wildcard principals")
        return True

    return False


def _check_ou_level_placements(
    account_third_party_map: Dict[str, Set[str]],
    organization_hierarchy: OrganizationHierarchy,
    accounts_with_wildcards: Set[str]
) -> List[RCPPlacementRecommendations]:
    """
    Check each OU and create RCPs by unioning third-party accounts within each OU.

    Args:
        account_third_party_map: Dictionary mapping account_id -> set of third-party account IDs
        organization_hierarchy: Organization structure information
        accounts_with_wildcards: Set of account IDs that have wildcard principals

    Returns:
        List of OU-level RCP recommendations
    """
    recommendations: List[RCPPlacementRecommendations] = []

    ou_account_map: Dict[str, List[str]] = {}
    for account_id in account_third_party_map.keys():
        account_info = organization_hierarchy.accounts.get(account_id)
        if not account_info:
            raise RuntimeError(f"Account ({account_id}) not found in organization hierarchy")
        parent_ou_id = account_info.parent_ou_id
        if parent_ou_id not in ou_account_map:
            ou_account_map[parent_ou_id] = []
        ou_account_map[parent_ou_id].append(account_id)

    for ou_id, ou_account_ids in ou_account_map.items():
        if _should_skip_ou_for_rcp(ou_id, organization_hierarchy, accounts_with_wildcards):
            continue

        if len(ou_account_ids) < MIN_ACCOUNTS_FOR_OU_LEVEL_RCP:
            continue

        # Union all third-party account IDs from accounts in this OU
        ou_third_party_accounts: Set[str] = set()
        for acc_id in ou_account_ids:
            if acc_id in account_third_party_map:
                ou_third_party_accounts.update(account_third_party_map[acc_id])

        ou_info = organization_hierarchy.organizational_units.get(ou_id)
        ou_name = ou_info.name if ou_info else ou_id

        unioned_third_party = sorted(list(ou_third_party_accounts))
        recommendations.append(RCPPlacementRecommendations(
            check_name=THIRD_PARTY_ASSUMEROLE,
            recommended_level="ou",
            target_ou_id=ou_id,
            affected_accounts=ou_account_ids,
            third_party_account_ids=unioned_third_party,
            reasoning=f"OU '{ou_name}' with {len(ou_account_ids)} accounts can be protected with OU-level RCP (allowlist contains {len(unioned_third_party)} third-party accounts from union of account requirements)"
        ))

    return recommendations


def _check_account_level_placements(
    account_third_party_map: Dict[str, Set[str]],
    ou_recommendations: List[RCPPlacementRecommendations]
) -> List[RCPPlacementRecommendations]:
    """
    Create account-level RCPs for accounts not covered by OU-level RCPs.

    Args:
        account_third_party_map: Dictionary mapping account_id -> set of third-party account IDs
        ou_recommendations: List of OU-level recommendations (to determine which accounts are already covered)

    Returns:
        List of account-level RCP recommendations
    """
    recommendations: List[RCPPlacementRecommendations] = []

    ou_covered_accounts = set()
    for rec in ou_recommendations:
        if rec.recommended_level == "ou":
            ou_covered_accounts.update(rec.affected_accounts)

    for account_id, third_party_accounts in account_third_party_map.items():
        if account_id not in ou_covered_accounts:
            recommendations.append(RCPPlacementRecommendations(
                check_name=THIRD_PARTY_ASSUMEROLE,
                recommended_level="account",
                target_ou_id=None,
                affected_accounts=[account_id],
                third_party_account_ids=sorted(list(third_party_accounts)),
                reasoning=f"Account has unique third-party account requirements ({len(third_party_accounts)} accounts) - deploy at account level"
            ))

    return recommendations


def determine_rcp_placement(
    account_third_party_map: Dict[str, Set[str]],
    organization_hierarchy: OrganizationHierarchy,
    accounts_with_wildcards: Set[str]
) -> List[RCPPlacementRecommendations]:
    """
    Analyze third-party account results to determine optimal RCP placement level.

    Strategy:
    - Root level: If no accounts have wildcards, union all third-party account IDs for root-level RCP
    - OU level: If any account in OU has wildcards, skip OU-level. Otherwise union third-party IDs for OU
    - Account level: Deploy individual RCPs for remaining accounts

    Args:
        account_third_party_map: Dictionary mapping account_id -> set of third-party account IDs
        organization_hierarchy: Organization structure information
        accounts_with_wildcards: Set of account IDs that have wildcard principals

    Returns:
        List of RCP placement recommendations
    """
    if not account_third_party_map:
        logger.info("No third-party accounts found in any account (excluding accounts with wildcards)")
        return []

    root_recommendation = _check_root_level_placement(
        account_third_party_map,
        organization_hierarchy,
        accounts_with_wildcards
    )
    if root_recommendation:
        return [root_recommendation]

    ou_recommendations = _check_ou_level_placements(
        account_third_party_map,
        organization_hierarchy,
        accounts_with_wildcards
    )

    account_recommendations = _check_account_level_placements(
        account_third_party_map,
        ou_recommendations
    )

    return ou_recommendations + account_recommendations


def _build_rcp_terraform_module(
    module_name: str,
    target_id_reference: str,
    third_party_account_ids: List[str],
    comment: str
) -> str:
    """
    Build Terraform module call for RCP deployment.

    Args:
        module_name: Name of the Terraform module instance (e.g., "rcps_root")
        target_id_reference: Reference to the target ID (e.g., "local.root_ou_id")
        third_party_account_ids: List of third-party AWS account IDs to whitelist
        comment: Comment line describing the configuration (e.g., "Organization Root")

    Returns:
        Complete Terraform module block as a string
    """
    has_wildcard = "*" in third_party_account_ids
    enforce_assume_role_org_identities = not has_wildcard

    terraform_content = f'''# Auto-generated RCP Terraform configuration for {comment}
# Generated by Headroom based on third-party account analysis

module "{module_name}" {{
  source = "../modules/rcps"
  target_id = {target_id_reference}

'''
    if enforce_assume_role_org_identities:
        terraform_content += '  third_party_assumerole_account_ids_allowlist = [\n'
        for account_id in third_party_account_ids:
            terraform_content += f'    "{account_id}",\n'
        terraform_content += '  ]\n'

    terraform_content += f'  enforce_assume_role_org_identities = {str(enforce_assume_role_org_identities).lower()}\n'
    terraform_content += '}\n'
    return terraform_content


def _write_terraform_file(filepath: Path, content: str) -> None:
    """
    Write Terraform content to a file.

    Args:
        filepath: Path object for the file to write
        content: Terraform content to write
    """
    with open(filepath, 'w') as f:
        f.write(content)
    logger.info(f"Generated RCP Terraform file: {filepath}")


def generate_rcp_terraform(
    recommendations: List[RCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_dir: str = "test_environment/rcps"
) -> None:
    """
    Generate Terraform files for RCP deployment based on recommendations.

    Args:
        recommendations: List of RCP placement recommendations
        organization_hierarchy: Organization structure information
        output_dir: Directory to write Terraform files to
    """
    if not recommendations:
        logger.info("No RCP recommendations to generate Terraform for")
        return

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Group recommendations by level and target
    account_recommendations: Dict[str, RCPPlacementRecommendations] = {}
    ou_recommendations: Dict[str, RCPPlacementRecommendations] = {}
    root_recommendation: Optional[RCPPlacementRecommendations] = None

    for rec in recommendations:
        if rec.recommended_level == "account":
            for account_id in rec.affected_accounts:
                account_recommendations[account_id] = rec
        elif rec.recommended_level == "ou" and rec.target_ou_id:
            ou_recommendations[rec.target_ou_id] = rec
        elif rec.recommended_level == "root":
            root_recommendation = rec

    # Generate Terraform files for each account
    for account_id, rec in account_recommendations.items():
        account_info = organization_hierarchy.accounts.get(account_id)
        if not account_info:
            raise RuntimeError(f"Account ({account_id}) not found in organization hierarchy")

        account_name = make_safe_variable_name(account_info.account_name)
        filename = f"{account_name}_rcps.tf"
        filepath = output_path / filename

        terraform_content = _build_rcp_terraform_module(
            module_name=f"rcps_{account_name}",
            target_id_reference=f"local.{account_name}_account_id",
            third_party_account_ids=rec.third_party_account_ids,
            comment=account_info.account_name
        )
        _write_terraform_file(filepath, terraform_content)

    # Generate Terraform files for each OU
    for ou_id, rec in ou_recommendations.items():
        ou_info = organization_hierarchy.organizational_units.get(ou_id)
        if not ou_info:
            raise RuntimeError(f"OU {ou_id} not found in organization hierarchy")

        ou_name = make_safe_variable_name(ou_info.name)
        filename = f"{ou_name}_ou_rcps.tf"
        filepath = output_path / filename

        terraform_content = _build_rcp_terraform_module(
            module_name=f"rcps_{ou_name}_ou",
            target_id_reference=f"local.top_level_{ou_name}_ou_id",
            third_party_account_ids=rec.third_party_account_ids,
            comment=f"OU {ou_info.name}"
        )
        _write_terraform_file(filepath, terraform_content)

    # Generate Terraform file for root level
    if not root_recommendation:
        return

    filename = "root_rcps.tf"
    filepath = output_path / filename

    terraform_content = _build_rcp_terraform_module(
        module_name="rcps_root",
        target_id_reference="local.root_ou_id",
        third_party_account_ids=root_recommendation.third_party_account_ids,
        comment="Organization Root"
    )
    _write_terraform_file(filepath, terraform_content)
