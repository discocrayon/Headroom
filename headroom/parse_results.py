"""
SCP/RCP Compliance Results Analysis Module

Analyzes headroom_results JSON files and determines optimal SCP/RCP placement
levels (root, OU, account) based on violation patterns and organization structure.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Sequence

from .config import HeadroomConfig
from .types import (
    OrganizationalUnit, OrganizationHierarchy, PolicyRecommendation, SCPCheckResult,
    SCPPlacementRecommendations, RCPPlacementRecommendations
)
from .aws.organization import lookup_account_id_by_name
from .placement import HierarchyPlacementAnalyzer
from .output import OutputHandler

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
    except json.JSONDecodeError as e:
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
    # Happy path: account_id present
    account_id: str = summary.get("account_id", "")
    if account_id:
        return account_id

    # Fallback: look up by account name
    account_name = summary.get("account_name", "")
    if not account_name:
        raise RuntimeError(
            f"Result file {result_file} missing both account_id and account_name in summary"
        )

    return lookup_account_id_by_name(
        account_name,
        organization_hierarchy,
        str(result_file)
    )


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
    organization_hierarchy: OrganizationHierarchy
) -> List[SCPCheckResult]:
    """
    Parse all JSON result files from headroom_results directory.

    Results are organized as: {results_dir}/scps/{check_name}/*.json

    Args:
        results_dir: Path to the headroom_results directory
        organization_hierarchy: Organization structure for account ID lookups

    Returns:
        List of SCPCheckResult objects.
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
    analyzer: HierarchyPlacementAnalyzer = HierarchyPlacementAnalyzer(organization_hierarchy)

    check_groups: Dict[str, List[SCPCheckResult]] = {}
    for result in results_data:
        if result.check_name not in check_groups:
            check_groups[result.check_name] = []
        check_groups[result.check_name].append(result)

    for check_name, check_results in check_groups.items():
        logger.info(f"Analyzing placement for check: {check_name}")

        for result in check_results:
            if not result.account_id:
                result.account_id = lookup_account_id_by_name(
                    result.account_name,
                    organization_hierarchy,
                    "SCP check result"
                )

        safe_check_results = [r for r in check_results if r.violations == 0]

        if not safe_check_results:
            recommendations.append(SCPPlacementRecommendations(
                check_name=check_name,
                recommended_level="none",
                target_ou_id=None,
                affected_accounts=[],
                compliance_percentage=0.0,
                reasoning="No accounts have zero violations - SCP deployment would break existing violations"
            ))
            continue

        candidates = analyzer.determine_placement(
            check_results=check_results,
            is_safe_for_root=lambda results: all(r.violations == 0 for r in results),
            is_safe_for_ou=lambda ou_id, results: all(r.violations == 0 for r in results),
            get_account_id=lambda r: r.account_id
        )

        for candidate in candidates:
            if candidate.level == "root":
                recommendations.append(SCPPlacementRecommendations(
                    check_name=check_name,
                    recommended_level="root",
                    target_ou_id=None,
                    affected_accounts=candidate.affected_accounts,
                    compliance_percentage=100.0,
                    reasoning="All accounts in organization have zero violations - safe to deploy at root level"
                ))
            elif candidate.level == "ou" and candidate.target_id is not None:
                ou_name = organization_hierarchy.organizational_units.get(
                    candidate.target_id,
                    OrganizationalUnit("", "", None, [], [])
                ).name
                recommendations.append(SCPPlacementRecommendations(
                    check_name=check_name,
                    recommended_level="ou",
                    target_ou_id=candidate.target_id,
                    affected_accounts=candidate.affected_accounts,
                    compliance_percentage=100.0,
                    reasoning=f"All accounts in OU '{ou_name}' have zero violations - safe to deploy at OU level"
                ))
            elif candidate.level == "account":
                recommendations.append(SCPPlacementRecommendations(
                    check_name=check_name,
                    recommended_level="account",
                    target_ou_id=None,
                    affected_accounts=[r.account_id for r in safe_check_results],
                    compliance_percentage=len(safe_check_results) / len(check_results) * 100.0,
                    reasoning=f"Only {len(safe_check_results)} out of {len(check_results)} accounts have zero violations - deploy at individual account level"
                ))
                break

    return recommendations


def print_policy_recommendations(
    recommendations: Sequence[PolicyRecommendation],
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

    OutputHandler.section_header(title)

    # Group recommendations by check name
    check_groups: Dict[str, List[PolicyRecommendation]] = {}
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


def parse_scp_results(
    config: HeadroomConfig,
    organization_hierarchy: OrganizationHierarchy
) -> List[SCPPlacementRecommendations]:
    """
    Parse SCP results and determine optimal placement recommendations.

    Main orchestration function that coordinates:
    1. Result file parsing
    2. Placement recommendation determination

    Args:
        config: Headroom configuration
        organization_hierarchy: Organization structure (from main.py)

    Returns:
        List of SCP placement recommendations for each check
    """
    logger.info("Starting SCP placement analysis")

    # Parse result files (organization_hierarchy already provided by caller)
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
