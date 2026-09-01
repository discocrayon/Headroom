"""
SCP/RCP Compliance Results Analysis Module

Analyzes headroom_results JSON files and determines optimal SCP/RCP placement
levels (root, OU, account) based on violation patterns and organization structure.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .config import HeadroomConfig
from .types import (
    OrganizationalUnit, OrganizationHierarchy, PolicyRecommendation, SCPCheckResult,
    SCPPlacementRecommendations, RCPPlacementRecommendations
)
from .aws.organization import lookup_account_id_by_name
from .constants import DENY_EC2_AMI_OWNER
from .placement import HierarchyPlacementAnalyzer
from .output import OutputHandler
from .utils import delete_and_rerun_remedy

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


def _extract_ami_owners(
    summary: Dict[str, Any],
    check_name: str,
    result_file: Path
) -> Optional[List[str]]:
    """
    Read the AMI owners a deny_ec2_ami_owner result observed.

    A file with no `unique_ami_owners` key at all predates AMI owner
    collection. Once parsed it is indistinguishable from an account that ran
    no instances - both produce an empty allowlist - and the two need opposite
    handling: one is a stale artifact to re-run, the other is a fact about the
    account that leaves the policy off. The distinction only exists while the
    file is in hand, so it is drawn here.

    Args:
        summary: The result file's summary block
        check_name: Check the result belongs to, taken from the file itself
        result_file: Path to the file, used in the error

    Returns:
        The observed owners for deny_ec2_ami_owner, else None

    Raises:
        RuntimeError: If a deny_ec2_ami_owner result predates AMI owner
            collection
    """
    if check_name != DENY_EC2_AMI_OWNER:
        return None

    if "unique_ami_owners" not in summary:
        raise RuntimeError(
            f"{result_file} predates AMI owner collection: its summary has no "
            f"unique_ami_owners. Placement cannot tell that apart from an "
            f"account running no instances, and would build the allowlist from "
            f"whatever the other accounts happened to observe. Re-run the "
            f"{DENY_EC2_AMI_OWNER} check for this account."
        )

    owners: Optional[List[str]] = summary["unique_ami_owners"]
    return owners


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

    # Un-redact IAM user ARNs if they were redacted
    iam_user_arns = summary.get("users")
    if iam_user_arns and account_id:
        iam_user_arns = [arn.replace("REDACTED", account_id) for arn in iam_user_arns]

    resolved_check_name = summary.get("check", check_name)

    # Placement clears an account when this count is zero, so defaulting it
    # would answer an unanswerable question in the safest possible direction
    # (INV-01). deny_iam_saml_provider_not_aws_sso shipped without the key and
    # had every account it rejected cleared for a root-level deny. The
    # remaining fields below are reporting only and no placement decision reads
    # them, so a missing one costs accuracy rather than safety.
    if "violations" not in summary:
        raise RuntimeError(
            f"{result_file} has no violations count in its summary. Placement "
            f"reads that count and nothing else to decide whether an account is "
            f"safe, so an absent key would clear the account rather than stop "
            f"the run. {delete_and_rerun_remedy(result_file, resolved_check_name)}"
        )

    return SCPCheckResult(
        account_id=account_id,
        account_name=summary.get("account_name", ""),
        check_name=resolved_check_name,
        violations=summary["violations"],
        exemptions=summary.get("exemptions", 0),
        compliant=summary.get("compliant", 0),
        total_instances=summary.get("total_instances"),
        compliance_percentage=summary.get("compliance_percentage", 0.0),
        iam_user_arns=iam_user_arns,
        ami_owners=_extract_ami_owners(summary, resolved_check_name, result_file)
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


def _group_results_by_check_name(
    results_data: List[SCPCheckResult]
) -> Dict[str, List[SCPCheckResult]]:
    """Group check results by check name."""
    check_groups: Dict[str, List[SCPCheckResult]] = {}
    for result in results_data:
        if result.check_name not in check_groups:
            check_groups[result.check_name] = []
        check_groups[result.check_name].append(result)
    return check_groups


def _get_safe_results(
    check_results: List[SCPCheckResult]
) -> List[SCPCheckResult]:
    """Filter results to only those with zero violations."""
    return [r for r in check_results if r.violations == 0]


def _ensure_account_ids_present(
    check_results: List[SCPCheckResult],
    organization_hierarchy: OrganizationHierarchy
) -> None:
    """
    Ensure all check results have account IDs populated.

    Looks up missing account IDs by account name in the organization hierarchy.
    Modifies check_results in place.
    """
    for result in check_results:
        if not result.account_id:
            result.account_id = lookup_account_id_by_name(
                result.account_name,
                organization_hierarchy,
                "SCP check result"
            )


def _create_no_deployment_recommendation(
    check_name: str
) -> SCPPlacementRecommendations:
    """
    Create recommendation for check that cannot be deployed.

    Returns a recommendation with level='none' when no accounts have zero violations.
    """
    return SCPPlacementRecommendations(
        check_name=check_name,
        recommended_level="none",
        target_ou_id=None,
        affected_accounts=[],
        compliance_percentage=0.0,
        reasoning="No accounts have zero violations - SCP deployment would break existing violations"
    )


def _build_iam_user_arns_for_recommendation(
    check_name: str,
    check_results: List[SCPCheckResult],
    affected_accounts: List[str]
) -> List[str]:
    """
    Build list of allowed IAM user ARNs for deny_iam_user_creation check.

    Returns a sorted list of unique IAM user ARNs from all affected accounts.
    Returns empty list if check is not deny_iam_user_creation or no ARNs found.
    """
    if check_name != "deny_iam_user_creation":
        return []

    iam_user_arns_set = set()
    for result in check_results:
        if result.account_id in affected_accounts and result.iam_user_arns:
            iam_user_arns_set.update(result.iam_user_arns)

    return sorted(list(iam_user_arns_set)) if iam_user_arns_set else []


def _build_ami_owners_for_recommendation(
    check_name: str,
    check_results: List[SCPCheckResult],
    affected_accounts: List[str]
) -> List[str]:
    """
    Build list of allowed AMI owners for the deny_ec2_ami_owner check.

    Returns a sorted list of the unique AMI owners observed across all
    affected accounts. Returns empty list if check is not deny_ec2_ami_owner
    or no owners were observed.
    """
    if check_name != DENY_EC2_AMI_OWNER:
        return []

    ami_owners_set = set()
    for result in check_results:
        if result.account_id in affected_accounts and result.ami_owners:
            ami_owners_set.update(result.ami_owners)

    return sorted(list(ami_owners_set)) if ami_owners_set else []


def _build_root_recommendation(
    check_name: str,
    affected_accounts: List[str],
    check_results: List[SCPCheckResult]
) -> SCPPlacementRecommendations:
    """
    Build root-level placement recommendation.

    Creates recommendation for deploying SCP at organization root level.
    Includes allowed IAM user ARNs if applicable.
    """
    allowed_iam_user_arns = _build_iam_user_arns_for_recommendation(
        check_name,
        check_results,
        affected_accounts
    )

    recommendation = SCPPlacementRecommendations(
        check_name=check_name,
        recommended_level="root",
        target_ou_id=None,
        affected_accounts=affected_accounts,
        compliance_percentage=100.0,
        reasoning="All accounts in organization have zero violations - safe to deploy at root level"
    )

    if allowed_iam_user_arns:
        recommendation.allowed_iam_user_arns = allowed_iam_user_arns

    ec2_allowed_ami_owners = _build_ami_owners_for_recommendation(
        check_name,
        check_results,
        affected_accounts
    )

    if ec2_allowed_ami_owners:
        recommendation.ec2_allowed_ami_owners = ec2_allowed_ami_owners

    return recommendation


def _build_ou_recommendation(
    check_name: str,
    target_ou_id: str,
    affected_accounts: List[str],
    check_results: List[SCPCheckResult],
    organization_hierarchy: OrganizationHierarchy
) -> SCPPlacementRecommendations:
    """
    Build OU-level placement recommendation.

    Creates recommendation for deploying SCP at organizational unit level.
    Includes OU name in reasoning and allowed IAM user ARNs if applicable.

    Raises:
        RuntimeError: If the target OU is not present in the hierarchy
    """
    ou_info = organization_hierarchy.organizational_units.get(target_ou_id)
    if not ou_info:
        raise RuntimeError(f"OU {target_ou_id} not found in organization hierarchy")

    ou_name = ou_info.name

    allowed_iam_user_arns = _build_iam_user_arns_for_recommendation(
        check_name,
        check_results,
        affected_accounts
    )

    ec2_allowed_ami_owners = _build_ami_owners_for_recommendation(
        check_name,
        check_results,
        affected_accounts
    )

    return SCPPlacementRecommendations(
        check_name=check_name,
        recommended_level="ou",
        target_ou_id=target_ou_id,
        affected_accounts=affected_accounts,
        compliance_percentage=100.0,
        reasoning=(
            f"All {len(affected_accounts)} accounts under OU '{ou_name}', "
            "including those in its child OUs, have zero violations - safe to "
            "deploy at OU level"
        ),
        allowed_iam_user_arns=allowed_iam_user_arns if allowed_iam_user_arns else None,
        ec2_allowed_ami_owners=ec2_allowed_ami_owners if ec2_allowed_ami_owners else None
    )


def _build_account_recommendation(
    check_name: str,
    safe_check_results: List[SCPCheckResult],
    total_results: int
) -> SCPPlacementRecommendations:
    """
    Build account-level placement recommendation.

    Creates recommendation for deploying SCP at individual account level.

    `compliance_percentage` reports the affected accounts, which are the
    zero-violation subset - the same 100.0 that root and OU recommendations
    carry. It used to hold the org-wide coverage fraction instead, which
    generation read as the safety signal and which account placement can
    never drive to 100%: the tier only exists when some other account
    violates the check. Coverage is in `reasoning`, where it describes reach
    rather than gating deployment.
    """
    affected_accounts = [r.account_id for r in safe_check_results]

    allowed_iam_user_arns = _build_iam_user_arns_for_recommendation(
        check_name,
        safe_check_results,
        affected_accounts
    )

    ec2_allowed_ami_owners = _build_ami_owners_for_recommendation(
        check_name,
        safe_check_results,
        affected_accounts
    )

    return SCPPlacementRecommendations(
        check_name=check_name,
        recommended_level="account",
        target_ou_id=None,
        affected_accounts=affected_accounts,
        compliance_percentage=100.0,
        reasoning=f"Only {len(safe_check_results)} out of {total_results} accounts have zero violations - deploy at individual account level",
        allowed_iam_user_arns=allowed_iam_user_arns if allowed_iam_user_arns else None,
        ec2_allowed_ami_owners=ec2_allowed_ami_owners if ec2_allowed_ami_owners else None
    )


def _determine_check_placement(
    check_name: str,
    check_results: List[SCPCheckResult],
    analyzer: HierarchyPlacementAnalyzer,
    organization_hierarchy: OrganizationHierarchy
) -> List[SCPPlacementRecommendations]:
    """
    Determine placement recommendations for a single check.

    Analyzes check results to find the highest safe organizational level
    for SCP deployment. Returns list of recommendations (may be multiple
    for account-level deployments across different OUs).
    """
    safe_check_results = _get_safe_results(check_results)

    if not safe_check_results:
        return [_create_no_deployment_recommendation(check_name)]

    candidates = analyzer.determine_placement(
        check_results=check_results,
        is_safe_for_root=lambda results: all(r.violations == 0 for r in results),
        is_safe_for_ou=lambda ou_id, results: all(r.violations == 0 for r in results),
        get_account_id=lambda r: r.account_id
    )

    recommendations = []
    for candidate in candidates:
        if candidate.level == "root":
            rec = _build_root_recommendation(
                check_name,
                candidate.affected_accounts,
                check_results
            )
            recommendations.append(rec)
        elif candidate.level == "ou" and candidate.target_id is not None:
            rec = _build_ou_recommendation(
                check_name,
                candidate.target_id,
                candidate.affected_accounts,
                check_results,
                organization_hierarchy
            )
            recommendations.append(rec)
        elif candidate.level == "account":
            candidate_safe_results = [
                r for r in safe_check_results
                if r.account_id in candidate.affected_accounts
            ]
            if not candidate_safe_results:
                continue
            rec = _build_account_recommendation(
                check_name,
                candidate_safe_results,
                len(check_results)
            )
            recommendations.append(rec)

    return recommendations


def determine_scp_placement(
    results_data: List[SCPCheckResult],
    organization_hierarchy: OrganizationHierarchy
) -> List[SCPPlacementRecommendations]:
    """
    Analyze compliance results to determine optimal SCP placement level.

    Finds the highest organizational level where ALL accounts have zero violations.
    Ensures safe deployment without breaking existing violations that would cause operational issues.

    Args:
        results_data: List of SCP check results from all accounts
        organization_hierarchy: Organization structure for placement analysis

    Returns:
        List of placement recommendations for each check
    """
    recommendations: List[SCPPlacementRecommendations] = []
    analyzer: HierarchyPlacementAnalyzer = HierarchyPlacementAnalyzer(organization_hierarchy)

    check_groups = _group_results_by_check_name(results_data)

    for check_name, check_results in check_groups.items():
        logger.info(f"Analyzing placement for check: {check_name}")

        _ensure_account_ids_present(check_results, organization_hierarchy)

        check_recommendations = _determine_check_placement(
            check_name,
            check_results,
            analyzer,
            organization_hierarchy
        )
        recommendations.extend(check_recommendations)

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
                print(f"  Compliance (affected accounts): {rec.compliance_percentage:.1f}%")
            elif isinstance(rec, RCPPlacementRecommendations):
                print(f"  Third-Party Accounts: {len(rec.third_party_account_ids)}")

            print(f"  Reasoning: {rec.reasoning}")
            print("  " + "-" * 38)


def analyze_scp_compliance(
    config: HeadroomConfig,
    organization_hierarchy: OrganizationHierarchy
) -> List[SCPPlacementRecommendations]:
    """
    Analyze SCP compliance results and determine optimal placement recommendations.

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

    # An empty list here means nothing was read, not that nothing needs a
    # policy. The caller reconciles the SCP directory against this function's
    # output, so returning [] would delete every generated policy file and
    # detach every SCP in the organization on the next apply - turning a
    # credential or path problem into a silent removal of the controls.
    # Placement legitimately finding no safe target is a different answer, and
    # it arrives as recommendations that name no placement.
    if not results_data:
        raise RuntimeError(
            f"No SCP result files were parsed from {config.results_dir}. Every "
            "generated policy file is deleted when a run places nothing, so a "
            "run that read nothing cannot be told apart from an organization "
            "that needs no policies. Check that the analysis wrote results to "
            "this directory before generating Terraform."
        )

    logger.info(f"Parsed {len(results_data)} result entries")

    # Determine SCP placement recommendations
    logger.info("Determining SCP placement recommendations")
    recommendations = determine_scp_placement(results_data, organization_hierarchy)

    logger.info("SCP placement analysis completed")
    return recommendations
