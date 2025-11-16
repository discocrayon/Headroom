"""
RCPs Terraform Generation Module

Generates Terraform files for RCP deployment based on third-party account analysis.
"""

import logging
import os
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set

from .models import TerraformModule, TerraformParameter, TerraformComment, TerraformElement
from .utils import make_safe_variable_name, write_terraform_file
from ..types import (
    AccountThirdPartyMap,
    OrganizationHierarchy,
    RCPCheckResult,
    RCPParseResult,
    RCPPlacementRecommendations,
)
from ..constants import (
    THIRD_PARTY_ASSUMEROLE,
    DENY_ECR_THIRD_PARTY_ACCESS,
    DENY_S3_THIRD_PARTY_ACCESS,
    DENY_AOSS_THIRD_PARTY_ACCESS,
)
from ..write_results import get_results_dir
from ..parse_results import _load_result_file_json, _extract_account_id_from_result
from ..placement import HierarchyPlacementAnalyzer
from ..placement.hierarchy import PlacementCandidate

# Set up logging
logger = logging.getLogger(__name__)


def _parse_single_rcp_result_file(
    result_file: Path,
    organization_hierarchy: OrganizationHierarchy
) -> RCPCheckResult:
    """
    Parse single RCP result file into RCPCheckResult object.

    Args:
        result_file: Path to the JSON result file
        organization_hierarchy: Organization structure for account lookups

    Returns:
        RCPCheckResult object with third-party access data

    Raises:
        RuntimeError: If JSON parsing fails or required fields are missing
    """
    data = _load_result_file_json(result_file)
    summary = data.get("summary", {})

    account_id = _extract_account_id_from_result(
        summary,
        organization_hierarchy,
        result_file
    )

    third_party_accounts = summary.get("unique_third_party_accounts", [])
    roles_with_wildcards = summary.get("roles_with_wildcards", 0)
    has_wildcards = roles_with_wildcards > 0

    if has_wildcards:
        account_name = summary.get("account_name", account_id)
        logger.info(
            f"Account {account_name} ({account_id}) has {roles_with_wildcards} "
            f"roles with wildcard principals - cannot deploy RCP"
        )

    return RCPCheckResult(
        account_id=account_id,
        account_name=summary.get("account_name", ""),
        check_name=summary.get("check", THIRD_PARTY_ASSUMEROLE),
        third_party_account_ids=third_party_accounts,
        has_wildcard=has_wildcards,
        total_roles_analyzed=summary.get("total_roles_analyzed")
    )


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

    account_third_party_map: AccountThirdPartyMap = {}
    accounts_with_wildcards: Set[str] = set()

    if not check_dir.exists():
        raise RuntimeError(f"Third-party AssumeRole check directory does not exist: {check_dir}")

    for result_file in check_dir.glob("*.json"):
        rcp_result = _parse_single_rcp_result_file(
            result_file,
            organization_hierarchy
        )

        if rcp_result.has_wildcard:
            accounts_with_wildcards.add(rcp_result.account_id)
        else:
            account_third_party_map[rcp_result.account_id] = set(rcp_result.third_party_account_ids)

    return RCPParseResult(
        account_third_party_map=account_third_party_map,
        accounts_with_wildcards=accounts_with_wildcards
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


def _create_root_level_rcp_recommendation(
    account_third_party_map: AccountThirdPartyMap,
    organization_hierarchy: OrganizationHierarchy
) -> RCPPlacementRecommendations:
    """
    Create root-level RCP recommendation by unioning all third-party accounts.

    Args:
        account_third_party_map: Dictionary mapping account_id -> set of third-party account IDs
        organization_hierarchy: Organization structure information

    Returns:
        Root-level RCP recommendation
    """
    all_third_party_accounts: Set[str] = set()
    for third_party_set in account_third_party_map.values():
        all_third_party_accounts.update(third_party_set)

    unioned_third_party = sorted(list(all_third_party_accounts))
    all_account_ids = list(organization_hierarchy.accounts.keys())

    return RCPPlacementRecommendations(
        check_name=THIRD_PARTY_ASSUMEROLE,
        recommended_level="root",
        target_ou_id=None,
        affected_accounts=all_account_ids,
        third_party_account_ids=unioned_third_party,
        reasoning=f"All {len(all_account_ids)} accounts can be protected with root-level RCP (allowlist contains {len(unioned_third_party)} third-party accounts from union of all account requirements)"
    )


def _create_ou_level_rcp_recommendations(
    candidates: List[PlacementCandidate],
    account_third_party_map: AccountThirdPartyMap,
    organization_hierarchy: OrganizationHierarchy
) -> tuple[List[RCPPlacementRecommendations], Set[str]]:
    """
    Create OU-level RCP recommendations from placement candidates.

    Args:
        candidates: Placement candidates from analyzer
        account_third_party_map: Dictionary mapping account_id -> set of third-party account IDs
        organization_hierarchy: Organization structure information

    Returns:
        Tuple of (recommendations list, set of covered account IDs)
    """
    recommendations: List[RCPPlacementRecommendations] = []
    ou_covered_accounts: Set[str] = set()

    for candidate in candidates:
        if candidate.level != "ou" or candidate.target_id is None:
            continue

        ou_third_party_accounts: Set[str] = set()
        for acc_id in candidate.affected_accounts:
            if acc_id in account_third_party_map:
                ou_third_party_accounts.update(account_third_party_map[acc_id])

        ou_info = organization_hierarchy.organizational_units.get(candidate.target_id)
        ou_name = ou_info.name if ou_info else candidate.target_id

        unioned_third_party = sorted(list(ou_third_party_accounts))
        recommendations.append(RCPPlacementRecommendations(
            check_name=THIRD_PARTY_ASSUMEROLE,
            recommended_level="ou",
            target_ou_id=candidate.target_id,
            affected_accounts=candidate.affected_accounts,
            third_party_account_ids=unioned_third_party,
            reasoning=f"OU '{ou_name}' with {len(candidate.affected_accounts)} accounts can be protected with OU-level RCP (allowlist contains {len(unioned_third_party)} third-party accounts from union of account requirements)"
        ))
        ou_covered_accounts.update(candidate.affected_accounts)

    return recommendations, ou_covered_accounts


def _create_account_level_rcp_recommendations(
    account_third_party_map: AccountThirdPartyMap,
    covered_accounts: Set[str]
) -> List[RCPPlacementRecommendations]:
    """
    Create account-level RCP recommendations for uncovered accounts.

    Args:
        account_third_party_map: Dictionary mapping account_id -> set of third-party account IDs
        covered_accounts: Accounts already covered by OU-level policies

    Returns:
        List of account-level recommendations
    """
    recommendations: List[RCPPlacementRecommendations] = []

    for account_id, third_party_accounts in account_third_party_map.items():
        if account_id in covered_accounts:
            continue

        recommendations.append(RCPPlacementRecommendations(
            check_name=THIRD_PARTY_ASSUMEROLE,
            recommended_level="account",
            target_ou_id=None,
            affected_accounts=[account_id],
            third_party_account_ids=sorted(list(third_party_accounts)),
            reasoning=f"Account has unique third-party account requirements ({len(third_party_accounts)} accounts) - deploy at account level"
        ))

    return recommendations


def _prepare_account_data_for_placement(
    account_third_party_map: AccountThirdPartyMap
) -> List[Dict[str, Any]]:
    """
    Convert account third-party map to list format for placement analysis.

    Args:
        account_third_party_map: Dictionary mapping account_id -> set of third-party account IDs

    Returns:
        List of dictionaries with account_id and third_party_accounts
    """
    return [
        {"account_id": acc_id, "third_party_accounts": third_parties}
        for acc_id, third_parties in account_third_party_map.items()
    ]


def _is_safe_for_root_rcp(
    accounts_with_wildcards: Set[str]
) -> bool:
    """
    Determine if root-level RCP deployment is safe.

    Root-level RCP is only safe if no accounts have wildcard principals.
    """
    return len(accounts_with_wildcards) == 0


def _is_safe_for_ou_rcp(
    ou_id: str,
    organization_hierarchy: OrganizationHierarchy,
    accounts_with_wildcards: Set[str]
) -> bool:
    """
    Determine if OU-level RCP deployment is safe.

    OU-level RCP is only safe if no accounts in the OU have wildcard principals.
    """
    return not _should_skip_ou_for_rcp(ou_id, organization_hierarchy, accounts_with_wildcards)


def _process_rcp_placement_candidates(
    candidates: List[Any],
    account_third_party_map: AccountThirdPartyMap,
    organization_hierarchy: OrganizationHierarchy
) -> List[RCPPlacementRecommendations]:
    """
    Process placement candidates and generate RCP recommendations.

    Handles root, OU, and account level recommendations based on candidates.

    Args:
        candidates: List of placement candidates from analyzer
        account_third_party_map: Dictionary mapping account_id -> set of third-party account IDs
        organization_hierarchy: Organization structure information

    Returns:
        List of RCP placement recommendations
    """
    for candidate in candidates:
        if candidate.level == "root":
            root_recommendation = _create_root_level_rcp_recommendation(
                account_third_party_map,
                organization_hierarchy
            )
            return [root_recommendation]

    ou_recommendations, ou_covered_accounts = _create_ou_level_rcp_recommendations(
        candidates,
        account_third_party_map,
        organization_hierarchy
    )

    account_recommendations = _create_account_level_rcp_recommendations(
        account_third_party_map,
        ou_covered_accounts
    )

    return ou_recommendations + account_recommendations


def determine_rcp_placement(
    account_third_party_map: AccountThirdPartyMap,
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

    analyzer: HierarchyPlacementAnalyzer = HierarchyPlacementAnalyzer(organization_hierarchy)
    account_data = _prepare_account_data_for_placement(account_third_party_map)

    candidates = analyzer.determine_placement(
        check_results=account_data,
        is_safe_for_root=lambda results: _is_safe_for_root_rcp(accounts_with_wildcards),
        is_safe_for_ou=lambda ou_id, results: _is_safe_for_ou_rcp(ou_id, organization_hierarchy, accounts_with_wildcards),
        get_account_id=lambda r: r["account_id"]
    )

    return _process_rcp_placement_candidates(
        candidates,
        account_third_party_map,
        organization_hierarchy
    )


def _build_rcp_terraform_module(
    module_name: str,
    target_id_reference: str,
    recommendations: List[RCPPlacementRecommendations],
    comment: str
) -> str:
    """
    Build Terraform module call for RCP deployment.

    Args:
        module_name: Name of the Terraform module instance (e.g., "rcps_root")
        target_id_reference: Reference to the target ID (e.g., "local.root_ou_id")
        recommendations: List of RCP recommendations for this target
        comment: Comment line describing the configuration (e.g., "Organization Root")

    Returns:
        Complete Terraform module block as a string
    """
    recs_by_check: Dict[str, RCPPlacementRecommendations] = {}
    for rec in recommendations:
        recs_by_check[rec.check_name] = rec

    assume_role_rec = recs_by_check.get(THIRD_PARTY_ASSUMEROLE)
    ecr_rec = recs_by_check.get(DENY_ECR_THIRD_PARTY_ACCESS)
    s3_rec = recs_by_check.get(DENY_S3_THIRD_PARTY_ACCESS)
    aoss_rec = recs_by_check.get(DENY_AOSS_THIRD_PARTY_ACCESS)

    parameters: List[TerraformElement] = []

    parameters.append(TerraformComment("ECR"))
    if ecr_rec:
        parameters.append(TerraformParameter("deny_ecr_third_party_access_account_ids_allowlist", ecr_rec.third_party_account_ids))
        parameters.append(TerraformParameter("deny_ecr_third_party_access", True))
    else:
        parameters.append(TerraformParameter("deny_ecr_third_party_access", False))

    parameters.append(TerraformComment(""))
    parameters.append(TerraformComment("IAM"))
    if assume_role_rec:
        has_wildcard = "*" in assume_role_rec.third_party_account_ids
        enforce_assume_role_org_identities = not has_wildcard
        if enforce_assume_role_org_identities:
            parameters.append(TerraformParameter("third_party_assumerole_account_ids_allowlist", assume_role_rec.third_party_account_ids))
        parameters.append(TerraformParameter("enforce_assume_role_org_identities", enforce_assume_role_org_identities))
    else:
        parameters.append(TerraformParameter("enforce_assume_role_org_identities", False))

    parameters.append(TerraformComment(""))
    parameters.append(TerraformComment("OpenSearch Serverless"))
    if aoss_rec:
        parameters.append(TerraformParameter("aoss_third_party_account_ids_allowlist", aoss_rec.third_party_account_ids))
        parameters.append(TerraformParameter("deny_aoss_third_party_access", True))
    else:
        parameters.append(TerraformParameter("deny_aoss_third_party_access", False))

    parameters.append(TerraformComment(""))
    parameters.append(TerraformComment("S3"))
    if s3_rec:
        parameters.append(TerraformParameter("third_party_s3_access_account_ids_allowlist", s3_rec.third_party_account_ids))
        parameters.append(TerraformParameter("deny_s3_third_party_access", True))
    else:
        parameters.append(TerraformParameter("deny_s3_third_party_access", False))

    module = TerraformModule(
        name=module_name,
        source="../modules/rcps",
        target_id=target_id_reference,
        parameters=parameters,
        comment=comment,
        policy_type="RCP"
    )

    return module.render()


def _generate_account_rcp_terraform(
    account_id: str,
    recs: List[RCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_path: Path
) -> None:
    """
    Generate and write Terraform file for account-level RCP.

    Args:
        account_id: AWS account ID
        recs: List of RCP recommendations for this account
        organization_hierarchy: Organization structure information
        output_path: Directory to write Terraform files to
    """
    account_info = organization_hierarchy.accounts.get(account_id)
    if not account_info:
        raise RuntimeError(f"Account ({account_id}) not found in organization hierarchy")

    account_name = make_safe_variable_name(account_info.account_name)
    filename = f"{account_name}_rcps.tf"
    filepath = output_path / filename

    if not recs:
        return

    terraform_content = _build_rcp_terraform_module(
        module_name=f"rcps_{account_name}",
        target_id_reference=f"local.{account_name}_account_id",
        recommendations=recs,
        comment=account_info.account_name
    )
    write_terraform_file(filepath, terraform_content, "RCP")


def _generate_ou_rcp_terraform(
    ou_id: str,
    recs: List[RCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_path: Path
) -> None:
    """
    Generate and write Terraform file for OU-level RCP.

    Args:
        ou_id: Organizational Unit ID
        recs: List of RCP recommendations for this OU
        organization_hierarchy: Organization structure information
        output_path: Directory to write Terraform files to
    """
    ou_info = organization_hierarchy.organizational_units.get(ou_id)
    if not ou_info:
        raise RuntimeError(f"OU {ou_id} not found in organization hierarchy")

    ou_name = make_safe_variable_name(ou_info.name)
    filename = f"{ou_name}_ou_rcps.tf"
    filepath = output_path / filename

    if not recs:
        return

    terraform_content = _build_rcp_terraform_module(
        module_name=f"rcps_{ou_name}_ou",
        target_id_reference=f"local.top_level_{ou_name}_ou_id",
        recommendations=recs,
        comment=f"OU {ou_info.name}"
    )
    write_terraform_file(filepath, terraform_content, "RCP")


def _generate_root_rcp_terraform(
    recs: List[RCPPlacementRecommendations],
    output_path: Path
) -> None:
    """
    Generate and write Terraform file for root-level RCP.

    Args:
        recs: List of RCP recommendations for root level
        output_path: Directory to write Terraform files to
    """
    filename = "root_rcps.tf"
    filepath = output_path / filename

    if not recs:
        return

    terraform_content = _build_rcp_terraform_module(
        module_name="rcps_root",
        target_id_reference="local.root_ou_id",
        recommendations=recs,
        comment="Organization Root"
    )
    write_terraform_file(filepath, terraform_content, "RCP")


def _create_org_info_symlink(rcps_output_path: Path, scps_dir: str) -> None:
    """
    Create symlink to scps/grab_org_info.tf in RCP directory.

    The grab_org_info.tf file contains shared organization structure data sources
    needed by both SCP and RCP modules. Rather than duplicating the file, we create
    a symlink from rcps/ to scps/grab_org_info.tf using a relative path.

    Args:
        rcps_output_path: RCP output directory where symlink should be created
        scps_dir: SCP directory path (used to compute relative path to grab_org_info.tf)
    """
    symlink_path = rcps_output_path / "grab_org_info.tf"

    # Compute relative path from RCP directory to SCP grab_org_info.tf
    scps_grab_org_info = Path(scps_dir) / "grab_org_info.tf"
    target_path = os.path.relpath(scps_grab_org_info, rcps_output_path)

    # Remove existing file or symlink if present
    if symlink_path.exists() or symlink_path.is_symlink():
        symlink_path.unlink()
        logger.debug(f"Removed existing file/symlink at {symlink_path}")

    # Create symlink
    os.symlink(target_path, symlink_path)
    logger.info(f"Created symlink: {symlink_path} -> {target_path}")


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
    account_recommendations: defaultdict[str, List[RCPPlacementRecommendations]] = defaultdict(list)
    ou_recommendations: defaultdict[str, List[RCPPlacementRecommendations]] = defaultdict(list)
    root_recommendations: List[RCPPlacementRecommendations] = []

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

    # Generate Terraform file for root level
    if root_recommendations:
        _generate_root_rcp_terraform(
            root_recommendations,
            output_path
        )

    # Generate Terraform files for each account
    for account_id, recs in account_recommendations.items():
        _generate_account_rcp_terraform(
            account_id,
            recs,
            organization_hierarchy,
            output_path
        )

    # Generate Terraform files for each OU
    for ou_id, recs in ou_recommendations.items():
        _generate_ou_rcp_terraform(
            ou_id,
            recs,
            organization_hierarchy,
            output_path
        )
