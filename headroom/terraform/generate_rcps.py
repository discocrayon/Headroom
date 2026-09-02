"""
RCPs Terraform Generation Module

Generates Terraform files for RCP deployment based on third-party account analysis.
"""

import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set

from .models import RenderedTerraformFiles, TerraformModule
from .parameters import render_check_parameters
from .utils import (
    account_id_local_name,
    claim_plan_path,
    make_account_base_names,
    make_ou_base_names,
    ou_id_local_name,
    ou_path_names,
)
from ..utils import delete_and_rerun_remedy
from ..checks.registry import get_allowlist, get_check_definitions, get_check_names
from ..types import (
    AccountThirdPartyMap,
    OrganizationHierarchy,
    RCPCheckParseResult,
    RCPCheckResult,
    RCPPlacementRecommendations,
)
from ..write_results import get_results_dir
from ..parse_results import _extract_account_id_from_result, _load_result_file_json, _read_declared_allowlist
from ..placement import HierarchyPlacementAnalyzer
from ..placement.hierarchy import PlacementCandidate, accounts_under_ou

# Set up logging
logger = logging.getLogger(__name__)


def _parse_single_rcp_result_file(
    result_file: Path,
    check_name: str,
    organization_hierarchy: OrganizationHierarchy
) -> RCPCheckResult:
    """
    Parse a single RCP result file into an RCPCheckResult.

    Args:
        result_file: Path to the JSON result file
        check_name: Check the parent directory names
        organization_hierarchy: Organization structure for account lookups

    Returns:
        RCPCheckResult with this account's third-party access data

    Raises:
        RuntimeError: If the file is unparseable, names no check, names a
            different check than its directory, or omits the violations
            count or the third-party account list
    """
    data = _load_result_file_json(result_file)
    summary = data.get("summary", {})

    account_id = _extract_account_id_from_result(
        summary,
        organization_hierarchy,
        result_file
    )

    if "check" not in summary:
        raise RuntimeError(
            f"Result file {result_file} names no check in its summary, so it "
            "cannot be confirmed to belong to the directory it was found in. "
            f"{delete_and_rerun_remedy(result_file, check_name)}"
        )

    reported_check = summary["check"]
    if reported_check != check_name:
        raise RuntimeError(
            f"Result file {result_file} reports check '{reported_check}', which "
            f"does not match its directory '{check_name}'. A result filed under "
            "the wrong check would be attributed to the wrong policy."
        )

    if "violations" not in summary:
        raise RuntimeError(
            f"Result file {result_file} has no 'violations' count in its summary, "
            "so whether this account can take the RCP cannot be determined. "
            f"{delete_and_rerun_remedy(result_file, check_name)}"
        )

    third_party_account_ids = _read_declared_allowlist(
        summary,
        check_name,
        get_allowlist(check_name),
        account_id,
        result_file
    )

    blocks_rcp = summary["violations"] > 0

    if blocks_rcp:
        account_name = summary.get("account_name", account_id)
        logger.info(
            f"Account {account_name} ({account_id}) has {summary['violations']} "
            f"resource(s) whose principals no allowlist can express - cannot "
            f"deploy the {check_name} RCP"
        )

    return RCPCheckResult(
        account_id=account_id,
        account_name=summary.get("account_name", ""),
        check_name=check_name,
        third_party_account_ids=third_party_account_ids,
        blocks_rcp=blocks_rcp,
    )


def parse_rcp_result_files(
    results_dir: str,
    organization_hierarchy: OrganizationHierarchy
) -> List[RCPCheckParseResult]:
    """
    Parse result files for every registered RCP check.

    Results are organized as: {results_dir}/rcps/{check_name}/*.json

    Args:
        results_dir: Directory containing check result files
        organization_hierarchy: Organization structure for account lookups

    Returns:
        One RCPCheckParseResult per registered RCP check, ordered by check
        name

    Raises:
        RuntimeError: If any registered RCP check has no results directory,
            a directory under rcps/ names no registered RCP check, or a
            result file cannot be parsed
    """
    parse_results: List[RCPCheckParseResult] = []
    missing_check_dirs: List[str] = []

    for check_name in sorted(get_check_names("rcps")):
        check_dir = Path(get_results_dir(check_name, "rcps", results_dir))

        if not check_dir.exists():
            missing_check_dirs.append(check_name)
            continue

        account_third_party_map: AccountThirdPartyMap = {}
        accounts_with_blockers: Set[str] = set()

        for result_file in sorted(check_dir.glob("*.json")):
            rcp_result = _parse_single_rcp_result_file(
                result_file,
                check_name,
                organization_hierarchy
            )

            if rcp_result.blocks_rcp:
                accounts_with_blockers.add(rcp_result.account_id)
            else:
                account_third_party_map[rcp_result.account_id] = set(
                    rcp_result.third_party_account_ids
                )

        parse_results.append(RCPCheckParseResult(
            check_name=check_name,
            account_third_party_map=account_third_party_map,
            accounts_with_blockers=accounts_with_blockers,
        ))

    if missing_check_dirs:
        raise RuntimeError(
            f"{len(missing_check_dirs)} registered RCP check(s) have no results "
            f"directory under {results_dir}/rcps: {', '.join(missing_check_dirs)}. "
            "A check absent from the results is indistinguishable from one that "
            "found nothing, and this output gates RCP deployment. Re-run the "
            "analysis."
        )

    # Every registered directory exists by here, so rcps/ does. The loop above
    # visits registered names only, and a directory it never visits holds
    # results nobody reads, which is indistinguishable from results that were
    # read: the SCP reader aborts on the same directory (INV-01).
    registered_check_names = get_check_names("rcps")
    unregistered_check_dirs = sorted(
        str(check_dir)
        for check_dir in (Path(results_dir) / "rcps").iterdir()
        if check_dir.is_dir() and check_dir.name not in registered_check_names
    )
    if unregistered_check_dirs:
        raise RuntimeError(
            f"{', '.join(unregistered_check_dirs)} names no registered RCP check. "
            "The results directory outlives the code that wrote it, so a renamed "
            "or removed check leaves its directory behind, and nothing can say "
            "which policy those results would feed. Delete the directory if the "
            "check is gone, or register a check under that name if it is not."
        )

    return parse_results


def _should_skip_ou_for_rcp(
    ou_id: str,
    organization_hierarchy: OrganizationHierarchy,
    accounts_with_blockers: Set[str]
) -> bool:
    """
    Determine whether an OU cannot take an OU-level RCP.

    One account whose policies name a principal no allowlist can express
    makes the OU-level policy unsafe for every account beneath it. That is the
    whole subtree, not the accounts sharing a level with it: an RCP attached
    to an OU reaches the accounts in its child OUs just the same.

    Args:
        ou_id: Organizational Unit to evaluate
        organization_hierarchy: Organization structure information
        accounts_with_blockers: Accounts that cannot take this RCP

    Returns:
        True if the OU should be skipped for this check
    """
    ou_accounts_in_org = accounts_under_ou(ou_id, organization_hierarchy)

    if any(acc_id in accounts_with_blockers for acc_id in ou_accounts_in_org):
        ou_info = organization_hierarchy.organizational_units.get(ou_id)
        ou_name = ou_info.name if ou_info else ou_id
        logger.info(
            f"Skipping OU-level RCP for '{ou_name}' - one or more accounts "
            "have principals no allowlist can express"
        )
        return True

    return False


def _create_root_level_rcp_recommendation(
    check_name: str,
    account_third_party_map: AccountThirdPartyMap,
    organization_hierarchy: OrganizationHierarchy
) -> RCPPlacementRecommendations:
    """
    Create root-level RCP recommendation by unioning all third-party accounts.

    Args:
        check_name: Name of the RCP check this recommendation is for
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
        check_name=check_name,
        recommended_level="root",
        target_ou_id=None,
        affected_accounts=all_account_ids,
        third_party_account_ids=unioned_third_party,
        reasoning=f"All {len(all_account_ids)} accounts can be protected with root-level RCP (allowlist contains {len(unioned_third_party)} third-party accounts from union of all account requirements)"
    )


def _create_ou_level_rcp_recommendations(
    check_name: str,
    candidates: List[PlacementCandidate],
    account_third_party_map: AccountThirdPartyMap,
    organization_hierarchy: OrganizationHierarchy
) -> tuple[List[RCPPlacementRecommendations], Set[str]]:
    """
    Create OU-level RCP recommendations from placement candidates.

    Args:
        check_name: Name of the RCP check these recommendations are for
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
            check_name=check_name,
            recommended_level="ou",
            target_ou_id=candidate.target_id,
            affected_accounts=candidate.affected_accounts,
            third_party_account_ids=unioned_third_party,
            reasoning=f"OU '{ou_name}' with {len(candidate.affected_accounts)} accounts can be protected with OU-level RCP (allowlist contains {len(unioned_third_party)} third-party accounts from union of account requirements)"
        ))
        ou_covered_accounts.update(candidate.affected_accounts)

    return recommendations, ou_covered_accounts


def _create_account_level_rcp_recommendations(
    check_name: str,
    account_third_party_map: AccountThirdPartyMap,
    covered_accounts: Set[str]
) -> List[RCPPlacementRecommendations]:
    """
    Create account-level RCP recommendations for uncovered accounts.

    Args:
        check_name: Name of the RCP check these recommendations are for
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
            check_name=check_name,
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
    accounts_with_blockers: Set[str]
) -> bool:
    """
    Determine if root-level RCP deployment is safe.

    Root-level RCP is only safe if no accounts have principals no allowlist
    can express.
    """
    return len(accounts_with_blockers) == 0


def _is_safe_for_ou_rcp(
    ou_id: str,
    organization_hierarchy: OrganizationHierarchy,
    accounts_with_blockers: Set[str]
) -> bool:
    """
    Determine if OU-level RCP deployment is safe.

    OU-level RCP is only safe if no accounts in the OU have principals no
    allowlist can express.
    """
    return not _should_skip_ou_for_rcp(ou_id, organization_hierarchy, accounts_with_blockers)


def _process_rcp_placement_candidates(
    check_name: str,
    candidates: List[Any],
    account_third_party_map: AccountThirdPartyMap,
    organization_hierarchy: OrganizationHierarchy
) -> List[RCPPlacementRecommendations]:
    """
    Process placement candidates and generate RCP recommendations.

    Handles root, OU, and account level recommendations based on candidates.

    Args:
        check_name: Name of the RCP check these candidates belong to
        candidates: List of placement candidates from analyzer
        account_third_party_map: Dictionary mapping account_id -> set of third-party account IDs
        organization_hierarchy: Organization structure information

    Returns:
        List of RCP placement recommendations
    """
    for candidate in candidates:
        if candidate.level == "root":
            root_recommendation = _create_root_level_rcp_recommendation(
                check_name,
                account_third_party_map,
                organization_hierarchy
            )
            return [root_recommendation]

    ou_recommendations, ou_covered_accounts = _create_ou_level_rcp_recommendations(
        check_name,
        candidates,
        account_third_party_map,
        organization_hierarchy
    )

    account_recommendations = _create_account_level_rcp_recommendations(
        check_name,
        account_third_party_map,
        ou_covered_accounts
    )

    return ou_recommendations + account_recommendations


def _determine_check_rcp_placement(
    parsed: RCPCheckParseResult,
    organization_hierarchy: OrganizationHierarchy
) -> List[RCPPlacementRecommendations]:
    """
    Determine RCP placement for a single check.

    Args:
        parsed: Findings for one RCP check across all accounts
        organization_hierarchy: Organization structure information

    Returns:
        Placement recommendations for this check, empty if no account has
        findings that can be expressed as an allowlist
    """
    if not parsed.account_third_party_map:
        logger.info(
            f"No deployable third-party findings for {parsed.check_name}"
        )
        return []

    analyzer: HierarchyPlacementAnalyzer = HierarchyPlacementAnalyzer(organization_hierarchy)
    account_data = _prepare_account_data_for_placement(parsed.account_third_party_map)

    candidates = analyzer.determine_placement(
        check_results=account_data,
        is_safe_for_root=lambda results: _is_safe_for_root_rcp(parsed.accounts_with_blockers),
        is_safe_for_ou=lambda ou_id, results: _is_safe_for_ou_rcp(
            ou_id, organization_hierarchy, parsed.accounts_with_blockers
        ),
        get_account_id=lambda r: r["account_id"]
    )

    return _process_rcp_placement_candidates(
        parsed.check_name,
        candidates,
        parsed.account_third_party_map,
        organization_hierarchy
    )


def determine_rcp_placement(
    parse_results: List[RCPCheckParseResult],
    organization_hierarchy: OrganizationHierarchy
) -> List[RCPPlacementRecommendations]:
    """
    Determine optimal RCP placement for every parsed check.

    Each check is placed independently against its own set of blocked
    accounts: a resource policy that blocks the S3 RCP in one account says
    nothing about that account's IAM trust policies, so it must not suppress
    the STS RCP.

    Args:
        parse_results: Findings per RCP check, from parse_rcp_result_files
        organization_hierarchy: Organization structure information

    Returns:
        Placement recommendations across all checks
    """
    recommendations: List[RCPPlacementRecommendations] = []

    for parsed in parse_results:
        recommendations.extend(
            _determine_check_rcp_placement(parsed, organization_hierarchy)
        )

    return recommendations


def _build_rcp_terraform_module(
    module_name: str,
    target_id_reference: str,
    recommendations: List[RCPPlacementRecommendations],
    comment: str,
    organization_hierarchy: OrganizationHierarchy,
) -> str:
    """
    Build Terraform module call for RCP deployment.

    Every registered RCP check renders here, enabled where a recommendation
    names it and disabled where none does, so registering a check is the
    whole of wiring it into the generated module (INV-13).

    Args:
        module_name: Name of the Terraform module instance (e.g., "rcps_root")
        target_id_reference: Reference to the target ID (e.g., "local.root_ou_id")
        recommendations: List of RCP recommendations for this target
        comment: Comment line describing the configuration (e.g., "Organization Root")
        organization_hierarchy: Organization structure, forwarded to the
            shared renderer so an ARN allowlist can be rewritten to
            generated locals. No RCP allowlist declares
            `restores_account_ids` today, so the rewrite is a no-op for
            every RCP module

    Returns:
        Complete Terraform module block as a string

    Raises:
        RuntimeError: If a recommendation names a check no registered
            definition describes, which would otherwise render as a module
            silently missing that statement
    """
    allowlists = {
        rec.check_name: rec.third_party_account_ids for rec in recommendations
    }

    parameters = render_check_parameters(
        get_check_definitions("rcps"),
        allowlists,
        module_name,
        organization_hierarchy,
    )

    module = TerraformModule(
        name=module_name,
        source="../modules/rcps",
        target_id=target_id_reference,
        parameters=parameters,
        comment=comment,
        policy_type="RCP"
    )

    return module.render()


def _render_account_rcp_terraform(
    account_id: str,
    recs: List[RCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_path: Path
) -> tuple[Path, str]:
    """
    Render the Terraform file for one account's RCPs.

    Args:
        account_id: AWS account ID
        recs: List of RCP recommendations for this account
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
    filepath = output_path / f"{account_name}_rcps.tf"

    terraform_content = _build_rcp_terraform_module(
        module_name=f"rcps_{account_name}",
        target_id_reference=f"local.{account_id_local_name(account_name)}",
        recommendations=recs,
        comment=account_info.account_name,
        organization_hierarchy=organization_hierarchy,
    )

    return filepath, terraform_content


def _render_ou_rcp_terraform(
    ou_id: str,
    recs: List[RCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_path: Path
) -> tuple[Path, str]:
    """
    Render the Terraform file for one OU's RCPs.

    Args:
        ou_id: Organizational Unit ID
        recs: List of RCP recommendations for this OU
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
    filepath = output_path / f"{base_name}_ou_rcps.tf"

    terraform_content = _build_rcp_terraform_module(
        module_name=f"rcps_{base_name}_ou",
        target_id_reference=f"local.{ou_id_local_name(base_name)}",
        recommendations=recs,
        comment=f"OU {path_label}",
        organization_hierarchy=organization_hierarchy,
    )

    return filepath, terraform_content


def _render_root_rcp_terraform(
    recs: List[RCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_path: Path
) -> tuple[Path, str]:
    """
    Render the Terraform file for root-level RCPs.

    Args:
        recs: List of RCP recommendations for root level
        organization_hierarchy: Organization structure, forwarded to the
            shared renderer so an ARN allowlist can be rewritten to
            generated locals. No RCP allowlist declares
            `restores_account_ids` today, so the rewrite is a no-op for
            every RCP module
        output_path: Directory the file belongs in

    Returns:
        Tuple of (destination path, rendered content)
    """
    filepath = output_path / "root_rcps.tf"

    terraform_content = _build_rcp_terraform_module(
        module_name="rcps_root",
        target_id_reference="local.root_ou_id",
        recommendations=recs,
        comment="Organization Root",
        organization_hierarchy=organization_hierarchy,
    )

    return filepath, terraform_content


def render_rcp_terraform(
    recommendations: List[RCPPlacementRecommendations],
    organization_hierarchy: OrganizationHierarchy,
    output_path: Path
) -> RenderedTerraformFiles:
    """
    Render every RCP file this run's recommendations call for.

    Nothing is written here. A target absent from the returned plan is a target
    this run does not want a file for, which is what lets applying the plan
    delete the file a previous run left behind.

    Args:
        recommendations: List of RCP placement recommendations
        organization_hierarchy: Organization structure information
        output_path: Directory the files belong in

    Returns:
        Rendered file contents, keyed by destination path. Nothing is
        written; the caller compiles these into the run's plan.
    """
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

    plan: RenderedTerraformFiles = {}

    if root_recommendations:
        filepath, content = _render_root_rcp_terraform(
            root_recommendations, organization_hierarchy, output_path
        )
        claim_plan_path(plan, filepath, content, "the organization root")

    for account_id, recs in account_recommendations.items():
        filepath, content = _render_account_rcp_terraform(
            account_id, recs, organization_hierarchy, output_path
        )
        claim_plan_path(plan, filepath, content, f"account {organization_hierarchy.accounts[account_id].account_name!r}")

    for ou_id, recs in ou_recommendations.items():
        filepath, content = _render_ou_rcp_terraform(
            ou_id, recs, organization_hierarchy, output_path
        )
        claim_plan_path(plan, filepath, content, f"OU {organization_hierarchy.organizational_units[ou_id].name!r}")

    return plan
