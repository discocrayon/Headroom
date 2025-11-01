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

# Set up logging
logger = logging.getLogger(__name__)


def parse_rcp_result_files(results_dir: str) -> RCPParseResult:
    """
    Parse third_party_role_access check result files.

    Returns:
        RCPParseResult containing:
        - account_third_party_map: Dictionary mapping account_id -> set of third-party account IDs
          (only accounts without wildcards)
        - accounts_with_wildcards: Set of account IDs that have wildcard principals
          (cannot have RCPs deployed)
    """
    results_path = Path(results_dir)
    check_dir = results_path / "third_party_role_access"

    account_third_party_map: Dict[str, Set[str]] = {}
    accounts_with_wildcards: Set[str] = set()

    if not check_dir.exists():
        logger.warning(f"Third-party role access check directory does not exist: {check_dir}")
        return RCPParseResult(
            account_third_party_map=account_third_party_map,
            accounts_with_wildcards=accounts_with_wildcards
        )

    for result_file in check_dir.glob("*.json"):
        try:
            with open(result_file, 'r') as f:
                data = json.load(f)

            summary = data.get("summary", {})
            account_id = summary.get("account_id", "")
            account_name = summary.get("account_name", "")
            third_party_accounts = summary.get("unique_third_party_accounts", [])
            roles_with_wildcards = summary.get("roles_with_wildcards", 0)

            # Track accounts with wildcard principals separately
            if roles_with_wildcards > 0:
                accounts_with_wildcards.add(account_id)
                logger.info(f"Account {account_name} ({account_id}) has {roles_with_wildcards} roles with wildcard principals - cannot deploy RCP")
                continue

            if account_id and third_party_accounts:
                account_third_party_map[account_id] = set(third_party_accounts)

        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to parse RCP result file {result_file}: {e}")
            continue

    return RCPParseResult(
        account_third_party_map=account_third_party_map,
        accounts_with_wildcards=accounts_with_wildcards
    )


def _check_root_level_placement(
    account_third_party_map: Dict[str, Set[str]]
) -> Optional[RCPPlacementRecommendations]:
    """
    Check if all accounts have identical third-party accounts for root-level RCP.

    Args:
        account_third_party_map: Dictionary mapping account_id -> set of third-party account IDs

    Returns:
        Root-level RCP recommendation if all accounts match, None otherwise
    """
    all_third_party_sets = list(account_third_party_map.values())
    if not all_third_party_sets:
        return None

    if all(tp_set == all_third_party_sets[0] for tp_set in all_third_party_sets):
        common_third_party = sorted(list(all_third_party_sets[0]))
        return RCPPlacementRecommendations(
            check_name="third_party_role_access",
            recommended_level="root",
            target_ou_id=None,
            affected_accounts=list(account_third_party_map.keys()),
            third_party_account_ids=common_third_party,
            reasoning=f"All {len(account_third_party_map)} accounts have identical third-party account access ({len(common_third_party)} accounts) - safe to deploy at root level"
        )
    return None


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
    Check each OU for accounts with identical third-party accounts.

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
            continue
        parent_ou_id = account_info.parent_ou_id
        if parent_ou_id not in ou_account_map:
            ou_account_map[parent_ou_id] = []
        ou_account_map[parent_ou_id].append(account_id)

    MIN_ACCOUNTS_FOR_OU_LEVEL_RCP = 2

    for ou_id, ou_account_ids in ou_account_map.items():
        if _should_skip_ou_for_rcp(ou_id, organization_hierarchy, accounts_with_wildcards):
            continue

        if len(ou_account_ids) < MIN_ACCOUNTS_FOR_OU_LEVEL_RCP:
            continue

        ou_third_party_sets = [
            account_third_party_map[acc_id]
            for acc_id in ou_account_ids
            if acc_id in account_third_party_map
        ]

        if ou_third_party_sets and all(tp_set == ou_third_party_sets[0] for tp_set in ou_third_party_sets):
            ou_info = organization_hierarchy.organizational_units.get(ou_id)
            ou_name = ou_info.name if ou_info else ou_id

            common_third_party = sorted(list(ou_third_party_sets[0]))
            recommendations.append(RCPPlacementRecommendations(
                check_name="third_party_role_access",
                recommended_level="ou",
                target_ou_id=ou_id,
                affected_accounts=ou_account_ids,
                third_party_account_ids=common_third_party,
                reasoning=f"All {len(ou_account_ids)} accounts in OU '{ou_name}' have identical third-party account access ({len(common_third_party)} accounts) - safe to deploy at OU level"
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
                check_name="third_party_role_access",
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
    accounts_with_wildcards: Set[str],
    rcp_always_root: bool = True
) -> List[RCPPlacementRecommendations]:
    """
    Analyze third-party account results to determine optimal RCP placement level.

    Groups accounts with identical third-party account sets and recommends:
    - Root level if all accounts have the same third-party accounts
    - Root level with aggregated third-party accounts if rcp_always_root is True
    - OU level if all accounts in an OU have the same third-party accounts (and no accounts have wildcards)
    - Account level otherwise

    Args:
        account_third_party_map: Dictionary mapping account_id -> set of third-party account IDs
        organization_hierarchy: Organization structure information
        accounts_with_wildcards: Set of account IDs that have wildcard principals
        rcp_always_root: If True, always deploy at root level with aggregated third-party accounts

    Returns:
        List of RCP placement recommendations
    """
    if not account_third_party_map:
        logger.info("No third-party accounts found in any account (excluding accounts with wildcards)")
        return []

    if rcp_always_root:
        if accounts_with_wildcards:
            logger.warning(
                f"Cannot deploy RCP at root level: {len(accounts_with_wildcards)} account(s) have wildcard principals. "
                f"Root-level RCPs would apply to all accounts including those with wildcards. "
                f"Accounts with wildcards: {sorted(list(accounts_with_wildcards))}"
            )
            return []

        all_third_party_accounts: Set[str] = set()
        for third_party_set in account_third_party_map.values():
            all_third_party_accounts.update(third_party_set)

        if all_third_party_accounts:
            aggregated_third_party = sorted(list(all_third_party_accounts))
            return [RCPPlacementRecommendations(
                check_name="third_party_role_access",
                recommended_level="root",
                target_ou_id=None,
                affected_accounts=list(account_third_party_map.keys()),
                third_party_account_ids=aggregated_third_party,
                reasoning=f"Aggregated all third-party accounts from {len(account_third_party_map)} accounts ({len(aggregated_third_party)} unique third-party accounts) - deploying at root level"
            )]
        return []

    root_recommendation = _check_root_level_placement(account_third_party_map)
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
        terraform_content += '  third_party_assumerole_account_ids = [\n'
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
    output_dir: str = "test_environment/scps"
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
            logger.warning(f"Account ({account_id}) not found in organization hierarchy")
            continue

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
            logger.warning(f"OU {ou_id} not found in organization hierarchy")
            continue

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
