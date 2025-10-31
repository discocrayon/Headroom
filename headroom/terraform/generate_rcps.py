"""
RCPs Terraform Generation Module

Generates Terraform files for RCP deployment based on third-party account analysis.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Set

from .utils import make_safe_variable_name
from ..types import OrganizationHierarchy, RCPPlacementRecommendations

# Set up logging
logger = logging.getLogger(__name__)


def parse_rcp_result_files(results_dir: str) -> tuple[Dict[str, Set[str]], Set[str]]:
    """
    Parse third_party_role_access check result files.

    Returns:
        Tuple of:
        - Dictionary mapping account_id -> set of third-party account IDs (only accounts without wildcards)
        - Set of account IDs that have wildcard principals (cannot have RCPs deployed)
    """
    results_path = Path(results_dir)
    check_dir = results_path / "third_party_role_access"

    account_third_party_map: Dict[str, Set[str]] = {}
    accounts_with_wildcards: Set[str] = set()

    if not check_dir.exists():
        logger.warning(f"Third-party role access check directory does not exist: {check_dir}")
        return account_third_party_map, accounts_with_wildcards

    for result_file in check_dir.glob("*.json"):
        try:
            with open(result_file, 'r') as f:
                data = json.load(f)

            summary = data.get("summary", {})
            account_id = summary.get("account_id", "")
            third_party_accounts = summary.get("unique_third_party_accounts", [])
            roles_with_wildcards = summary.get("roles_with_wildcards", 0)

            # Track accounts with wildcard principals separately
            if roles_with_wildcards > 0:
                accounts_with_wildcards.add(account_id)
                logger.info(f"Account {account_id} has {roles_with_wildcards} roles with wildcard principals - cannot deploy RCP")
                continue

            if account_id and third_party_accounts:
                account_third_party_map[account_id] = set(third_party_accounts)

        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to parse RCP result file {result_file}: {e}")
            continue

    return account_third_party_map, accounts_with_wildcards


def determine_rcp_placement(
    account_third_party_map: Dict[str, Set[str]],
    organization_hierarchy: OrganizationHierarchy,
    accounts_with_wildcards: Set[str]
) -> List[RCPPlacementRecommendations]:
    """
    Analyze third-party account results to determine optimal RCP placement level.

    Groups accounts with identical third-party account sets and recommends:
    - Root level if all accounts have the same third-party accounts
    - OU level if all accounts in an OU have the same third-party accounts (and no accounts have wildcards)
    - Account level otherwise

    Args:
        account_third_party_map: Dictionary mapping account_id -> set of third-party account IDs
        organization_hierarchy: Organization structure information
        accounts_with_wildcards: Set of account IDs that have wildcard principals

    Returns:
        List of RCP placement recommendations
    """
    recommendations: List[RCPPlacementRecommendations] = []

    if not account_third_party_map:
        logger.info("No third-party accounts found in any account (excluding accounts with wildcards)")
        return recommendations

    # Check if all accounts have the same third-party accounts (root level)
    all_third_party_sets = list(account_third_party_map.values())
    if all_third_party_sets and all(tp_set == all_third_party_sets[0] for tp_set in all_third_party_sets):
        common_third_party = sorted(list(all_third_party_sets[0]))
        recommendations.append(RCPPlacementRecommendations(
            check_name="third_party_role_access",
            recommended_level="root",
            target_ou_id=None,
            affected_accounts=list(account_third_party_map.keys()),
            third_party_account_ids=common_third_party,
            reasoning=f"All {len(account_third_party_map)} accounts have identical third-party account access ({len(common_third_party)} accounts) - safe to deploy at root level"
        ))
        return recommendations

    # Check OU level - group accounts by OU and check if they have same third-party accounts
    ou_account_map: Dict[str, List[str]] = {}
    for account_id in account_third_party_map.keys():
        account_info = organization_hierarchy.accounts.get(account_id)
        if not account_info:
            continue
        parent_ou_id = account_info.parent_ou_id
        if parent_ou_id not in ou_account_map:
            ou_account_map[parent_ou_id] = []
        ou_account_map[parent_ou_id].append(account_id)

    # Check each OU
    for ou_id, ou_account_ids in ou_account_map.items():
        # Check if any accounts in this OU have wildcards
        # OU-level RCPs apply to ALL accounts in the OU, so we cannot deploy if any have wildcards
        ou_accounts_in_org = [
            acc_id for acc_id, acc_info in organization_hierarchy.accounts.items()
            if acc_info.parent_ou_id == ou_id
        ]
        
        if any(acc_id in accounts_with_wildcards for acc_id in ou_accounts_in_org):
            ou_info = organization_hierarchy.organizational_units.get(ou_id)
            ou_name = ou_info.name if ou_info else ou_id
            logger.info(f"Skipping OU-level RCP for '{ou_name}' - one or more accounts have wildcard principals")
            continue
        
        # Skip OUs with less than 2 accounts - not worth creating an OU-level RCP
        # for a single account (use account-level instead)
        if len(ou_account_ids) < 2:
            continue

        # Get third-party accounts for each account in this OU
        ou_third_party_sets = [
            account_third_party_map[acc_id]
            for acc_id in ou_account_ids
            if acc_id in account_third_party_map
        ]

        # Check if all accounts in OU have same third-party accounts
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

    # Account level - each account gets its own RCP
    # Only recommend for accounts not already covered by OU-level RCPs
    ou_covered_accounts = set()
    for rec in recommendations:
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

    # Process each recommendation
    for rec in recommendations:
        if rec.recommended_level == "root":
            filename = "root_rcps.tf"
            filepath = output_path / filename

            terraform_content = '''# Auto-generated RCP Terraform configuration for Organization Root
# Generated by Headroom based on third-party account analysis

module "rcps_root" {
  source = "../modules/rcps"
  target_id = local.root_ou_id

  third_party_account_ids = [
'''
            for account_id in rec.third_party_account_ids:
                terraform_content += f'    "{account_id}",\n'

            terraform_content += '''  ]
}
'''

            with open(filepath, 'w') as f:
                f.write(terraform_content)

            logger.info(f"Generated RCP Terraform file: {filepath}")

        elif rec.recommended_level == "ou" and rec.target_ou_id:
            ou_info = organization_hierarchy.organizational_units.get(rec.target_ou_id)
            if not ou_info:
                logger.warning(f"OU {rec.target_ou_id} not found in organization hierarchy")
                continue

            ou_name = make_safe_variable_name(ou_info.name)
            filename = f"{ou_name}_ou_rcps.tf"
            filepath = output_path / filename

            terraform_content = f'''# Auto-generated RCP Terraform configuration for OU {ou_info.name}
# Generated by Headroom based on third-party account analysis

module "rcps_{ou_name}_ou" {{
  source = "../modules/rcps"
  target_id = local.top_level_{ou_name}_ou_id

  third_party_account_ids = [
'''
            for account_id in rec.third_party_account_ids:
                terraform_content += f'    "{account_id}",\n'

            terraform_content += '''  ]
}
'''

            with open(filepath, 'w') as f:
                f.write(terraform_content)

            logger.info(f"Generated RCP Terraform file: {filepath}")

        elif rec.recommended_level == "account":
            for account_id in rec.affected_accounts:
                account_info = organization_hierarchy.accounts.get(account_id)
                if not account_info:
                    logger.warning(f"Account {account_id} not found in organization hierarchy")
                    continue

                account_name = make_safe_variable_name(account_info.account_name)
                filename = f"{account_name}_rcps.tf"
                filepath = output_path / filename

                terraform_content = f'''# Auto-generated RCP Terraform configuration for {account_info.account_name}
# Generated by Headroom based on third-party account analysis

module "rcps_{account_name}" {{
  source = "../modules/rcps"
  target_id = local.{account_name}_account_id

  third_party_account_ids = [
'''
                for tp_account_id in rec.third_party_account_ids:
                    terraform_content += f'    "{tp_account_id}",\n'

                terraform_content += '''  ]
}
'''

                with open(filepath, 'w') as f:
                    f.write(terraform_content)

                logger.info(f"Generated RCP Terraform file: {filepath}")

