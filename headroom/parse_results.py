"""
SCP/RCP Compliance Results Analysis Module

Analyzes headroom_results JSON files and determines optimal SCP/RCP placement
levels (root, OU, account) based on violation patterns and organization structure.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Sequence, Union

from .analysis import get_security_analysis_session, get_management_account_session
from .config import HeadroomConfig
from .aws.organization import analyze_organization_structure
from .types import (
    OrganizationalUnit, AccountOrgPlacement, OrganizationHierarchy,
    SCPCheckResult, SCPPlacementRecommendations, RCPPlacementRecommendations
)
from .constants import RCP_CHECK_NAMES
from .aws.organization import lookup_account_id_by_name

# Set up logging
logger = logging.getLogger(__name__)


def _load_result_file_json(result_file: Path) -> Dict[str, Any]:
    """
    Load and parse a result JSON file.

    Args:
        result_file: Path to the JSON result file

    Returns:
        Parsed JSON data as dictionary

    Raises:
        RuntimeError: If JSON parsing fails
    """
    try:
        with open(result_file, 'r') as f:
            data: Dict[str, Any] = json.load(f)
            return data
    except (json.JSONDecodeError, KeyError) as e:
        raise RuntimeError(f"Failed to parse result file {result_file}: {e}")


def _extract_account_id_from_result(
    summary: Dict[str, Any],
    organization_hierarchy: OrganizationHierarchy,
    result_file: Path
) -> str:
    """
    Extract account ID from result summary or organization hierarchy.

    Universal strategy for both SCP and RCP results:
    1. Try to get account_id directly from summary
    2. If missing, look up account by name in organization hierarchy

    Args:
        summary: The summary dict from the result JSON
        organization_hierarchy: Organization structure for account lookups
        result_file: Path to result file (for error messages)

    Returns:
        Account ID string

    Raises:
        RuntimeError: If account ID cannot be determined
    """
    account_id: str = summary.get("account_id", "")
    if not account_id:
        account_name = summary.get("account_name", "")
        if not account_name:
            raise RuntimeError(
                f"Result file {result_file} missing both account_id and account_name in summary"
            )
        # Use org hierarchy lookup - works for both SCP and RCP
        looked_up_id: str = lookup_account_id_by_name(
            account_name,
            organization_hierarchy,
            str(result_file)
        )
        return looked_up_id
    return account_id


def _parse_single_scp_result_file(
    result_file: Path,
    check_name: str,
    organization_hierarchy: OrganizationHierarchy
) -> SCPCheckResult:
    """
    Parse a single SCP result JSON file into SCPCheckResult object.

    Args:
        result_file: Path to the JSON result file
        check_name: Name of the check (from parent directory)
        organization_hierarchy: Organization structure for account lookups

    Returns:
        SCPCheckResult object with compliance data

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

    return SCPCheckResult(
        account_id=account_id,
        account_name=summary.get("account_name", ""),
        check_name=summary.get("check", check_name),
        violations=summary.get("violations", 0),
        exemptions=summary.get("exemptions", 0),
        compliant=summary.get("compliant", 0),
        total_instances=summary.get("total_instances"),
        compliance_percentage=summary.get("compliance_percentage", 0.0)
    )


def parse_scp_result_files(
    results_dir: str,
    organization_hierarchy: OrganizationHierarchy,
    exclude_rcp_checks: bool = True
) -> List[SCPCheckResult]:
    """
    Parse all JSON result files from headroom_results directory.

    Results are organized as: {results_dir}/scps/{check_name}/*.json

    Args:
        results_dir: Path to the headroom_results directory
        organization_hierarchy: Organization structure for account ID lookups
        exclude_rcp_checks: If True, exclude RCP checks (like third_party_assumerole)

    Returns:
        List of SCPCheckResult objects for SCP checks only (if exclude_rcp_checks is True).
    """
    results_path = Path(results_dir)
    if not results_path.exists():
        raise RuntimeError(f"Results directory {results_dir} does not exist")

    check_results: List[SCPCheckResult] = []

    # Look in scps/ subdirectory
    scps_path = results_path / "scps"
    if not scps_path.exists():
        logger.warning(f"SCP results directory {scps_path} does not exist")
        return []

    # Iterate through check directories in scps/ subdirectory
    for check_dir in scps_path.iterdir():
        if not check_dir.is_dir():
            continue

        check_name = check_dir.name

        # Skip RCP checks if requested - they have their own analysis flow
        if exclude_rcp_checks and check_name in RCP_CHECK_NAMES:
            logger.info(f"Skipping RCP check: {check_name} (will be processed separately)")
            continue

        logger.info(f"Processing check: {check_name}")

        # Process each account result file
        for result_file in check_dir.glob("*.json"):
            check_result = _parse_single_scp_result_file(
                result_file,
                check_name,
                organization_hierarchy
            )
            check_results.append(check_result)

    return check_results


def determine_scp_placement(
    results_data: List[SCPCheckResult],
    organization_hierarchy: OrganizationHierarchy
) -> List[SCPPlacementRecommendations]:
    """
    Analyze compliance results to determine optimal SCP/RCP placement level.

    Finds the highest organizational level where ALL accounts have zero violations.
    Ensures safe deployment without breaking existing violations that would cause operational issues.
    """
    recommendations: List[SCPPlacementRecommendations] = []

    # Group results by check name
    check_groups: Dict[str, List[SCPCheckResult]] = {}
    for result in results_data:
        if result.check_name not in check_groups:
            check_groups[result.check_name] = []
        check_groups[result.check_name].append(result)

    for check_name, check_results in check_groups.items():
        logger.info(f"Analyzing placement for check: {check_name}")

        # Check if ALL accounts have zero violations (root level)
        all_accounts_zero_violations = all(
            result.violations == 0 for result in check_results
        )

        if all_accounts_zero_violations:
            recommendations.append(SCPPlacementRecommendations(
                check_name=check_name,
                recommended_level="root",
                target_ou_id=None,
                affected_accounts=[result.account_id for result in check_results],
                compliance_percentage=100.0,
                reasoning="All accounts in organization have zero violations - safe to deploy at root level"
            ))
            continue

        # Check OU level - find OUs where ALL accounts have zero violations
        ou_violation_status: Dict[str, Dict[str, int]] = {}

        for result in check_results:
            # If account_id is missing, look up by account name
            if not result.account_id:
                result.account_id = lookup_account_id_by_name(
                    result.account_name,
                    organization_hierarchy,
                    "SCP check result"
                )

            account_info = organization_hierarchy.accounts.get(result.account_id)
            if not account_info:
                raise RuntimeError(f"Account {result.account_name} ({result.account_id}) not found in organization hierarchy")

            parent_ou_id = account_info.parent_ou_id
            if parent_ou_id not in ou_violation_status:
                ou_violation_status[parent_ou_id] = {"total_accounts": 0, "zero_violation_accounts": 0}

            ou_violation_status[parent_ou_id]["total_accounts"] += 1
            if result.violations == 0:
                ou_violation_status[parent_ou_id]["zero_violation_accounts"] += 1

        # Find OUs where all accounts have zero violations
        safe_ous: List[str] = []
        for ou_id, status in ou_violation_status.items():
            if status["zero_violation_accounts"] == status["total_accounts"] and status["total_accounts"] > 0:
                safe_ous.append(ou_id)

        if safe_ous:
            # Recommend OU level deployment for the largest safe OU
            largest_ou = max(safe_ous, key=lambda ou_id: ou_violation_status[ou_id]["total_accounts"])
            ou_name = organization_hierarchy.organizational_units.get(largest_ou, OrganizationalUnit("", "", None, [], [])).name

            affected_accounts = [
                result.account_id for result in check_results
                if organization_hierarchy.accounts.get(result.account_id, AccountOrgPlacement("", "", "", [])).parent_ou_id == largest_ou
            ]

            recommendations.append(SCPPlacementRecommendations(
                check_name=check_name,
                recommended_level="ou",
                target_ou_id=largest_ou,
                affected_accounts=affected_accounts,
                compliance_percentage=100.0,
                reasoning=f"All accounts in OU '{ou_name}' have zero violations - safe to deploy at OU level"
            ))
            continue

        # Check account level - individual accounts with zero violations
        safe_accounts = [
            result for result in check_results if result.violations == 0
        ]

        if safe_accounts:
            recommendations.append(SCPPlacementRecommendations(
                check_name=check_name,
                recommended_level="account",
                target_ou_id=None,
                affected_accounts=[result.account_id for result in safe_accounts],
                compliance_percentage=len(safe_accounts) / len(check_results) * 100.0,
                reasoning=f"Only {len(safe_accounts)} out of {len(check_results)} accounts have zero violations - deploy at individual account level"
            ))
        else:
            # No safe deployment possible
            recommendations.append(SCPPlacementRecommendations(
                check_name=check_name,
                recommended_level="none",
                target_ou_id=None,
                affected_accounts=[],
                compliance_percentage=0.0,
                reasoning="No accounts have zero violations - SCP deployment would break existing violations"
            ))

    return recommendations


def _get_organization_context(config: HeadroomConfig) -> OrganizationHierarchy:
    """
    Get management account session and analyze organization structure.

    Args:
        config: Headroom configuration

    Returns:
        Organization hierarchy with OUs and accounts

    Raises:
        ValueError: If management_account_id is not set
        RuntimeError: If session creation or organization analysis fails
    """
    security_session = get_security_analysis_session(config)
    mgmt_session = get_management_account_session(config, security_session)

    logger.info("Analyzing organization structure")
    organization_hierarchy = analyze_organization_structure(mgmt_session)
    logger.info(f"Found {len(organization_hierarchy.organizational_units)} OUs and {len(organization_hierarchy.accounts)} accounts")

    return organization_hierarchy


def print_policy_recommendations(
    recommendations: Sequence[Union[SCPPlacementRecommendations, RCPPlacementRecommendations]],
    organization_hierarchy: OrganizationHierarchy,
    title: str = "SCP/RCP PLACEMENT RECOMMENDATIONS"
) -> None:
    """
    Print SCP or RCP placement recommendations to console with check name grouping.

    Groups recommendations by check name and prints each check as a section.
    This handles cases where the same check is recommended multiple times
    (e.g., for an OU and individual accounts).

    Args:
        recommendations: List of SCP or RCP placement recommendations
        organization_hierarchy: Organization structure for OU name lookups
        title: Title for the recommendations section
    """
    if not recommendations:
        return

    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)

    # Group recommendations by check name
    check_groups: Dict[str, List[Union[SCPPlacementRecommendations, RCPPlacementRecommendations]]] = {}
    for rec in recommendations:
        if rec.check_name not in check_groups:
            check_groups[rec.check_name] = []
        check_groups[rec.check_name].append(rec)

    # Print each check group
    for check_name, check_recs in check_groups.items():
        print(f"\nCheck: {check_name}")

        for rec in check_recs:
            print(f"\n  Recommended Level: {rec.recommended_level.upper()}")
            if rec.target_ou_id:
                ou_name = organization_hierarchy.organizational_units.get(
                    rec.target_ou_id,
                    OrganizationalUnit("", "", None, [], [])
                ).name
                print(f"  Target OU: {ou_name} ({rec.target_ou_id})")
            print(f"  Affected Accounts: {len(rec.affected_accounts)}")

            # Print type-specific fields
            if isinstance(rec, SCPPlacementRecommendations):
                print(f"  Compliance: {rec.compliance_percentage:.1f}%")
            elif isinstance(rec, RCPPlacementRecommendations):
                print(f"  Third-Party Accounts: {len(rec.third_party_account_ids)}")

            print(f"  Reasoning: {rec.reasoning}")
            print("  " + "-" * 38)


def parse_scp_results(config: HeadroomConfig) -> List[SCPPlacementRecommendations]:
    """
    Parse SCP results and determine optimal placement recommendations.

    Main orchestration function that coordinates:
    1. Organization context setup (sessions and structure analysis)
    2. Result file parsing
    3. Placement recommendation determination
    4. Console output of recommendations

    Args:
        config: Headroom configuration

    Returns:
        List of SCP placement recommendations for each check
    """
    logger.info("Starting SCP placement analysis")

    # Get organization context (session + structure)
    try:
        organization_hierarchy = _get_organization_context(config)
    except (ValueError, RuntimeError) as e:
        logger.error(f"Failed to get organization context: {e}")
        return []

    # Parse result files
    logger.info(f"Parsing result files from {config.results_dir}")
    results_data = parse_scp_result_files(config.results_dir, organization_hierarchy)

    if not results_data:
        logger.warning("No result files found to analyze")
        return []

    logger.info(f"Parsed {len(results_data)} result entries")

    # Determine SCP placement recommendations
    logger.info("Determining SCP placement recommendations")
    recommendations = determine_scp_placement(results_data, organization_hierarchy)

    logger.info("SCP placement analysis completed")
    return recommendations
