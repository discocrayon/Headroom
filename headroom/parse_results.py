"""
SCP/RCP Compliance Results Analysis Module

Analyzes headroom_results JSON files and determines optimal SCP/RCP placement
levels (root, OU, account) based on violation patterns and organization structure.
"""

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .config import HeadroomConfig
from .types import (
    OrganizationalUnit, OrganizationHierarchy, PolicyRecommendation, SCPCheckResult,
    SCPPlacementRecommendations, RCPPlacementRecommendations
)
from .aws.organization import lookup_account_id_by_name
from .checks.registry import Allowlist, CheckDefinition, get_check_definition, get_check_names
from .placement import HierarchyPlacementAnalyzer
from .placement.hierarchy import accounts_under_ou
from .output import OutputHandler
from .utils import delete_and_rerun_remedy
from .write_results import restore_account_id_in_arns

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

    Either way the account must be in the hierarchy. An account that left the
    organization after its scan leaves its file behind; read as written, the
    SCP reader would count it as analyzed under a root placement that cannot
    reach it, and the RCP reader would carry its third parties into an
    allowlist that no longer protects it.

    Args:
        summary: The summary dict from the result JSON
        organization_hierarchy: Organization structure for account lookups
        result_file: Path to result file (for error messages)

    Returns:
        Account ID string

    Raises:
        RuntimeError: If account ID cannot be determined, or names an account
            the hierarchy does not hold
    """
    account_id: str = summary.get("account_id", "")
    if account_id and account_id in organization_hierarchy.accounts:
        return account_id

    if account_id:
        raise RuntimeError(
            f"Result file {result_file} names account {account_id}, which is not "
            f"in the organization hierarchy. The account has left the organization "
            f"since the file was written, or the results directory was written "
            f"from a different organization. Delete the file: read as written, a "
            f"root or OU placement would count the account as analyzed, and an "
            f"RCP allowlist would carry the third parties it granted."
        )

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


def verify_one_result_file_per_account(
    result_files_by_check_and_account: Dict[str, Dict[str, List[Path]]]
) -> None:
    """
    Abort when any check directory holds two result files for one account.

    An account rename leaves the file written under the old name beside the
    one written under the new, under every check that ran, and both carry
    the same `summary.account_id`. Without this the SCP reader deploys from
    whichever copy is clean and the RCP reader builds the allowlist from
    whichever sorts last. Agreeing copies abort too: the directory
    misdescribes what was scanned either way. Every directory is reported in
    one error, so one sweep clears them all.

    Args:
        result_files_by_check_and_account: Every file parsed, keyed by check
            name and then by the account it resolved to

    Raises:
        RuntimeError: If any account has more than one result file under any
            check
    """
    check_listings: List[str] = []
    for check_name in sorted(result_files_by_check_and_account):
        result_files_by_account_id = result_files_by_check_and_account[check_name]
        duplicated_accounts = sorted(
            account_id
            for account_id, result_files in result_files_by_account_id.items()
            if len(result_files) > 1
        )
        if not duplicated_accounts:
            continue

        account_listing = "\n    ".join(
            f"{account_id}: "
            f"{', '.join(sorted(str(path) for path in result_files_by_account_id[account_id]))}"
            for account_id in duplicated_accounts
        )
        check_listings.append(f"{check_name}: {account_listing}")

    if not check_listings:
        return

    listing = "\n  ".join(check_listings)
    raise RuntimeError(
        f"More than one result file for the same account:\n  {listing}\n"
        "An account rename leaves the file written under the old name beside "
        "the one written under the new, under every check that ran, and each "
        "carries the same account_id, so the policy is built from whichever "
        "copy its reader happens to pick. Delete every file listed above and "
        "re-run; the scan writes one result file per account."
    )


def _read_declared_allowlist(
    summary: Dict[str, Any],
    check_name: str,
    allowlist: Allowlist,
    account_id: str,
    result_file: Path
) -> List[str]:
    """
    Read the values one result observed under the allowlist it declares.

    The one rule both result readers apply, SCP and RCP alike: the values
    come from the summary key the check's own definition names, the key is
    required and must hold a list, and a definition saying its values carry
    the owning account's ID has `REDACTED` replaced by that ID in each ARN's
    account field, undoing what `exclude_account_ids` did on write. One rule
    rather than two is what keeps the two policy types from drifting on which
    absent key is fatal, and an absent key is fatal for both: the values are
    what the allowlist is built from, so a file that never recorded them
    cannot be told from an account that had none to record (INV-01). A key
    holding anything but a list is fatal for the same reason: `null` is
    neither an observation nor an absence, and carrying it forward either
    crashed on the restore or was dropped by the placement union as though
    the check declared no allowlist.

    Args:
        summary: The result file's summary block
        check_name: Check the result belongs to, taken from the file itself
        allowlist: The allowlist that check's statement is scoped by
        account_id: Account the result belongs to
        result_file: Path to the file, used in the error

    Returns:
        The values the account observed, empty when it observed none

    Raises:
        RuntimeError: If the file's summary has no such key, or holds
            anything but a list under it
    """
    if allowlist.summary_key not in summary:
        raise RuntimeError(
            f"{result_file} has no {allowlist.summary_key} in its summary. "
            f"{check_name} populates {allowlist.terraform_variable} "
            f"from that key, and an absent key cannot be told apart "
            f"from an account that observed nothing: one is a stale result to "
            f"re-run, the other is an observation the allowlist must carry. "
            f"{delete_and_rerun_remedy(result_file, check_name)}"
        )

    values = summary[allowlist.summary_key]
    if not isinstance(values, list):
        raise RuntimeError(
            f"{result_file} has {allowlist.summary_key} = {values!r} in its summary, "
            f"which is not a list. {check_name} populates {allowlist.terraform_variable} "
            f"from that key, and a value that is not a list is neither an observation "
            f"nor an absent key: an account that observed nothing writes []. "
            f"{delete_and_rerun_remedy(result_file, check_name)}"
        )
    if not allowlist.restores_account_ids:
        return values

    return [restore_account_id_in_arns(value, account_id) for value in values]


def _read_allowlist_values(
    summary: Dict[str, Any],
    definition: CheckDefinition,
    account_id: str,
    result_file: Path
) -> Optional[List[str]]:
    """
    Read the allowlist values one result observed, if its check declares one.

    Args:
        summary: The result file's summary block
        definition: Registry definition of the check the file belongs to
        account_id: Account the result belongs to
        result_file: Path to the file, used in the error

    Returns:
        The observed values, or None when the check declares no allowlist

    Raises:
        RuntimeError: If the check declares an allowlist and the file's
            summary has no such key
    """
    if definition.allowlist is None:
        return None

    return _read_declared_allowlist(
        summary,
        definition.check_name,
        definition.allowlist,
        account_id,
        result_file
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
        RuntimeError: If JSON parsing fails, the file names a check that is
            not a registered SCP check, or required fields are missing
    """
    data = _load_result_file_json(result_file)
    summary = data.get("summary", {})

    account_id = _extract_account_id_from_result(
        summary,
        organization_hierarchy,
        result_file
    )

    resolved_check_name = summary.get("check", check_name)
    # Resolved before any key is required of the file: a stale directory is
    # stale throughout, and the registry's own error names neither the file
    # nor a remedy. Deleting the directory would also be the wrong remedy for
    # a file misfiled under a live check's directory, so the file comes first.
    if resolved_check_name not in get_check_names("scps"):
        raise RuntimeError(
            f"{result_file} names check {resolved_check_name!r}, which is not a "
            f"registered SCP check. The results directory outlives the code that "
            f"wrote it, so a renamed or removed check leaves its files behind, and "
            f"nothing can say which keys those files must carry or which policy "
            f"their placement would feed. Delete the file, and the rest of "
            f"{result_file.parent} when it holds only that check's results, or "
            f"register a check under that name."
        )
    definition = get_check_definition(resolved_check_name)

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

    allowlist_values = _read_allowlist_values(
        summary,
        definition,
        account_id,
        result_file
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
        allowlist_values=allowlist_values
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

    Raises:
        RuntimeError: If the results directory does not exist, a file names
            an unregistered check or is missing a required field, or one
            check directory resolved two files to the same account
    """
    results_path = Path(results_dir)
    if not results_path.exists():
        raise RuntimeError(f"Results directory {results_dir} does not exist")

    check_results: List[SCPCheckResult] = []
    result_files_by_check_and_account: Dict[str, Dict[str, List[Path]]] = defaultdict(dict)

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
            result_files_by_check_and_account[check_name].setdefault(
                check_result.account_id, []
            ).append(result_file)

    # Every directory is read before the abort: a rename leaves a stale file
    # under each of them, and one error names every file the sweep deletes.
    verify_one_result_file_per_account(result_files_by_check_and_account)

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


def _union_allowlist_values(
    check_results: List[SCPCheckResult],
    affected_accounts: List[str]
) -> Optional[List[str]]:
    """
    Union the allowlist values the accounts a recommendation covers observed.

    An empty union and no union at all are distinct: covered accounts that
    observed nothing leave the check's policy off (INV-06), while a check
    with no allowlist renders its statement unconditionally.

    Args:
        check_results: Results for the check being placed
        affected_accounts: Accounts the recommendation covers

    Returns:
        The sorted union over the covered accounts, or None when no covered
        account carried an allowlist
    """
    observed = [
        result.allowlist_values
        for result in check_results
        if result.account_id in affected_accounts and result.allowlist_values is not None
    ]
    if not observed:
        return None

    return sorted({value for values in observed for value in values})


def _plural(count: int, singular: str, plural: str) -> str:
    """
    Pick the form that agrees in number with a count.
    """
    return singular if count == 1 else plural


def _coverage_reasoning(analyzed: int, reached: int, scope: str, level: str) -> str:
    """
    State how many of the accounts a placement reaches were analyzed.

    Every analyzed account had zero violations, or the placement would not
    have been offered; the rest inherit the policy unmeasured, and the
    sentence names them only when there are any. Every count agrees in
    number: one account "was" analyzed, and a placement reaching one account
    names "the only account" rather than "all 1 accounts".

    Args:
        analyzed: Accounts that produced a result file, all with zero violations
        reached: Accounts the placement applies to, the management account excluded
        scope: Phrase that follows "accounts" and precedes "were analyzed",
            carrying its own punctuation
        level: Word that precedes "level"
    """
    unanalyzed = reached - analyzed
    verdict = _plural(analyzed, "with zero violations", "all with zero violations")
    if unanalyzed == 0 and reached == 1:
        return f"The only account {scope} was analyzed, {verdict} - safe to deploy at {level} level"
    if unanalyzed == 0:
        return f"All {reached} accounts {scope} were analyzed, {verdict} - safe to deploy at {level} level"
    return (
        f"{analyzed} of {reached} accounts {scope} {_plural(analyzed, 'was', 'were')} analyzed, {verdict}"
        f" - safe to deploy at {level} level; {unanalyzed} {_plural(unanalyzed, 'account was', 'accounts were')}"
        f" not analyzed and will inherit it"
    )


def _build_root_recommendation(
    check_name: str,
    affected_accounts: List[str],
    check_results: List[SCPCheckResult],
    organization_hierarchy: OrganizationHierarchy,
    management_account_id: str
) -> SCPPlacementRecommendations:
    """
    Build root-level placement recommendation.

    A root SCP reaches every account in the hierarchy except the management
    account, but only the accounts that produced result files were analyzed.
    The reasoning states analyzed-of-reached and, when the two differ, how
    many accounts inherit the policy unmeasured.
    """
    reached = len(organization_hierarchy.accounts.keys() - {management_account_id})
    return SCPPlacementRecommendations(
        check_name=check_name,
        recommended_level="root",
        target_ou_id=None,
        affected_accounts=affected_accounts,
        compliance_percentage=100.0,
        reasoning=_coverage_reasoning(len(affected_accounts), reached, "reached by root", "root"),
        allowlist_values=_union_allowlist_values(check_results, affected_accounts)
    )


def _build_ou_recommendation(
    check_name: str,
    target_ou_id: str,
    affected_accounts: List[str],
    check_results: List[SCPCheckResult],
    organization_hierarchy: OrganizationHierarchy,
    management_account_id: str
) -> SCPPlacementRecommendations:
    """
    Build OU-level placement recommendation.

    An OU SCP reaches every account in the OU and in its child OUs except the
    management account, but only the accounts that produced result files were
    analyzed. The reasoning names the OU and states analyzed-of-reached and,
    when the two differ, how many accounts inherit the policy unmeasured.

    Raises:
        RuntimeError: If the target OU is not present in the hierarchy
    """
    ou_info = organization_hierarchy.organizational_units.get(target_ou_id)
    if not ou_info:
        raise RuntimeError(f"OU {target_ou_id} not found in organization hierarchy")

    ou_name = ou_info.name
    reached = len(accounts_under_ou(target_ou_id, organization_hierarchy) - {management_account_id})
    reasoning = _coverage_reasoning(
        len(affected_accounts),
        reached,
        f"under OU '{ou_name}', including those in its child OUs,",
        "OU"
    )
    return SCPPlacementRecommendations(
        check_name=check_name,
        recommended_level="ou",
        target_ou_id=target_ou_id,
        affected_accounts=affected_accounts,
        compliance_percentage=100.0,
        reasoning=reasoning,
        allowlist_values=_union_allowlist_values(check_results, affected_accounts)
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

    return SCPPlacementRecommendations(
        check_name=check_name,
        recommended_level="account",
        target_ou_id=None,
        affected_accounts=affected_accounts,
        compliance_percentage=100.0,
        reasoning=f"Only {len(safe_check_results)} out of {total_results} accounts have zero violations - deploy at individual account level",
        allowlist_values=_union_allowlist_values(safe_check_results, affected_accounts)
    )


def _determine_check_placement(
    check_name: str,
    check_results: List[SCPCheckResult],
    analyzer: HierarchyPlacementAnalyzer,
    organization_hierarchy: OrganizationHierarchy,
    management_account_id: str
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
                check_results,
                organization_hierarchy,
                management_account_id
            )
            recommendations.append(rec)
        elif candidate.level == "ou" and candidate.target_id is not None:
            rec = _build_ou_recommendation(
                check_name,
                candidate.target_id,
                candidate.affected_accounts,
                check_results,
                organization_hierarchy,
                management_account_id
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
    organization_hierarchy: OrganizationHierarchy,
    management_account_id: str
) -> List[SCPPlacementRecommendations]:
    """
    Analyze compliance results to determine optimal SCP placement level.

    Finds the highest organizational level where ALL accounts have zero violations.
    Ensures safe deployment without breaking existing violations that would cause operational issues.

    Args:
        results_data: List of SCP check results from all accounts
        organization_hierarchy: Organization structure for placement analysis
        management_account_id: The organization's management account, which
            no SCP applies to

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
            organization_hierarchy,
            management_account_id
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

    Raises:
        ValueError: If management_account_id is not set in config
        RuntimeError: If no SCP result files were parsed
    """
    management_account_id = config.management_account_id
    if not management_account_id:
        raise ValueError("management_account_id must be set in config")

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
    recommendations = determine_scp_placement(
        results_data, organization_hierarchy, management_account_id
    )

    logger.info("SCP placement analysis completed")
    return recommendations
