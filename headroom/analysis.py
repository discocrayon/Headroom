import logging
import threading
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set
from dataclasses import dataclass

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_organizations.client import OrganizationsClient
from mypy_boto3_organizations.type_defs import AccountTypeDef

from .config import HeadroomConfig
from .checks.registry import get_check_names, get_all_check_classes
from .log_context import set_account
from .write_results import results_exist
from .aws.sessions import assume_role, new_session
from .utils import format_account_identifier

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class AccountInfo:
    account_id: str
    environment: str
    name: str
    owner: str


def get_security_analysis_session(config: HeadroomConfig) -> Session:
    """Assume OrganizationAccountAccessRole in the security analysis account and return a boto3 session."""
    account_id = config.security_analysis_account_id
    if not account_id:
        logger.debug("No security_analysis_account_id provided, assuming already in security analysis account")
        return new_session()
    role_arn = f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole"
    return assume_role(role_arn, "HeadroomSecurityAnalysisSession")


def get_management_account_session(config: HeadroomConfig, security_session: Session) -> Session:
    """
    Assume OrgAndAccountInfoReader role in the management account and return a boto3 session.

    Args:
        config: Headroom configuration
        security_session: boto3 Session with access to security analysis account

    Returns:
        boto3 Session with OrgAndAccountInfoReader role assumed in management account

    Raises:
        ValueError: If management_account_id is not set in config
        RuntimeError: If role assumption fails
    """
    if not config.management_account_id:
        raise ValueError("management_account_id must be set in config")

    role_arn = f"arn:aws:iam::{config.management_account_id}:role/OrgAndAccountInfoReader"
    return assume_role(role_arn, "HeadroomOrgAndAccountInfoReaderSession", security_session)


def _fetch_account_tags(org_client: OrganizationsClient, account_id: str, account_name: str) -> Dict[str, str]:
    """
    Fetch tags for an AWS account from Organizations API.

    Args:
        org_client: AWS Organizations client
        account_id: Account ID to fetch tags for
        account_name: Account name (for logging only)

    Returns:
        Dictionary of tag key-value pairs (empty dict if fetching fails)
    """
    try:
        tags_resp = org_client.list_tags_for_resource(ResourceId=account_id)
        return {tag["Key"]: tag["Value"] for tag in tags_resp.get("Tags", [])}
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        if error_code == 'AccessDenied':
            logger.warning(
                f"Access denied fetching tags for account {account_name} ({account_id}). "
                f"Account will use default values."
            )
        else:
            logger.error(
                f"Unexpected error fetching tags for account {account_name} ({account_id}): {e}",
                exc_info=True
            )
        return {}


def _determine_account_name(account: AccountTypeDef, tags: Dict[str, str], config: HeadroomConfig) -> str:
    """
    Determine the account name to use based on configuration.

    Args:
        account: Account dictionary from Organizations API
        tags: Account tags dictionary
        config: Headroom configuration

    Returns:
        Account name (from tags if configured, otherwise from API, otherwise account ID)
    """
    account_id: str = account["Id"]
    if config.use_account_name_from_tags:
        return tags.get(config.account_tag_layout.name) or account_id
    account_name: str = account.get("Name") or account_id
    return account_name


def _build_account_info_from_account_dict(
    account: AccountTypeDef,
    org_client: OrganizationsClient,
    config: HeadroomConfig
) -> AccountInfo:
    """
    Build AccountInfo object from AWS Organizations account dictionary.

    Fetches account tags, extracts metadata, and constructs AccountInfo.

    Args:
        account: Account dictionary from Organizations API
        org_client: AWS Organizations client for fetching tags
        config: Headroom configuration

    Returns:
        AccountInfo object with account metadata

    Raises:
        ClientError: If AWS API calls fail
    """
    account_id = account["Id"]
    account_name = account.get("Name", account_id)

    tags = _fetch_account_tags(org_client, account_id, account_name)

    layout = config.account_tag_layout
    environment = tags.get(layout.environment) or "unknown"
    owner = tags.get(layout.owner) or "unknown"
    name = _determine_account_name(account, tags, config)

    return AccountInfo(
        account_id=account_id,
        environment=environment,
        name=name,
        owner=owner
    )


# AWS Organizations lifecycle state in which an account can be analyzed.
ACTIVE_ACCOUNT_STATE = "ACTIVE"

# Lifecycle states in which an account is not analyzed.
#
# CLOSED, SUSPENDED and PENDING_ACTIVATION accounts all reject role assumption,
# so attempting to analyze one aborts the whole run. PENDING_CLOSURE accounts
# remain functional, so excluding them is a deliberate policy choice: an account
# on its way out of the organization should not hold back an organization-wide
# policy recommendation.
#
# AWS retires the `Status` field on 2026-09-09 in favour of `State`, which splits
# the old catch-all SUSPENDED into distinct SUSPENDED and CLOSED values. Because
# old-SUSPENDED covers both, this set skips the same accounts under either field.
INACTIVE_ACCOUNT_STATES = frozenset({
    "CLOSED",
    "PENDING_ACTIVATION",
    "PENDING_CLOSURE",
    "SUSPENDED",
})


def _get_account_state(account: AccountTypeDef) -> Optional[str]:
    """
    Return an account's lifecycle state, preferring `State` over `Status`.

    AWS retires `Status` on 2026-09-09, which makes `State` authoritative. SDKs
    released before 2025-09-09 do not model `State`, so botocore drops it from
    the response and only `Status` is available.

    Args:
        account: Account dictionary from the Organizations API

    Returns:
        The lifecycle state, or None if the account reports neither field
    """
    return account.get("State") or account.get("Status")


def _should_skip_account(account: AccountTypeDef, account_id: str) -> bool:
    """
    Determine whether an account is excluded from analysis by lifecycle state.

    Only ACTIVE accounts are analyzed.

    Any state this function cannot classify aborts the run rather than being
    guessed at, for two distinct causes with two distinct remedies.

    An account reporting neither `State` nor `Status` means the SDK is too old to
    model `State` at a point when `Status` has been retired. That cause is
    environment-wide rather than per-account, so every account would report
    nothing; continuing would attempt every closed account and then fail inside
    `assume_role` with an error naming none of the real cause.

    An account reporting a state absent from both ACTIVE_ACCOUNT_STATE and
    INACTIVE_ACCOUNT_STATES means AWS has added a lifecycle state. Neither guess
    is safe there: analyzing an account that turns out to be unusable burns the
    run on a downstream error that explains nothing, and skipping one that is
    usable drops it from the compliance picture that gates policy deployment.
    test_every_state_aws_defines_is_classified is meant to catch this when
    boto3-stubs is upgraded, so reaching this branch in production means that
    test was not run.

    Args:
        account: Account dictionary from the Organizations API
        account_id: Account identifier, used for logging

    Returns:
        True if the account should be excluded from analysis

    Raises:
        RuntimeError: If the account's lifecycle state cannot be classified
    """
    state = _get_account_state(account)

    if state is None:
        raise RuntimeError(
            f"Account {account_id} reports neither State nor Status, so its lifecycle "
            "state cannot be determined. The AWS SDK is too old to model State, which "
            "replaced Status on 2026-09-09; upgrade boto3 to continue."
        )

    if state == ACTIVE_ACCOUNT_STATE:
        return False

    if state in INACTIVE_ACCOUNT_STATES:
        logger.info(f"Skipping account {account_id} in lifecycle state {state}")
        return True

    known_states = ", ".join(sorted({ACTIVE_ACCOUNT_STATE} | INACTIVE_ACCOUNT_STATES))
    raise RuntimeError(
        f"Account {account_id} reports lifecycle state {state}, which Headroom does "
        f"not recognize. Known states are {known_states}. If AWS has added a state, "
        "add it to INACTIVE_ACCOUNT_STATES in headroom/analysis.py when accounts in "
        "that state cannot be analyzed, or to ACTIVE_ACCOUNT_STATE handling when they "
        "can."
    )


def _verify_skip_account_ids_matched(config: HeadroomConfig, seen_account_ids: Set[str]) -> None:
    """
    Abort if a skip_account_ids entry matched no account in the organization.

    An entry that matches nothing is silent: the account the operator meant to
    exclude keeps being analyzed, and nothing in the output says so. A typo, a
    wrong digit count, or an account that has left the organization all look
    identical to a correctly spelled entry, so the mismatch has to surface here
    rather than be discovered in the generated policy.

    Args:
        config: Headroom configuration
        seen_account_ids: Every account ID the Organizations API returned,
            including the management account

    Raises:
        RuntimeError: If any skip_account_ids entry matched no account
    """
    unmatched = sorted(set(config.skip_account_ids) - seen_account_ids)

    if not unmatched:
        return

    raise RuntimeError(
        f"skip_account_ids names {len(unmatched)} account(s) that are not in the "
        f"organization: {', '.join(unmatched)}. Every entry must match an account "
        "ID that AWS Organizations reports, so an entry matching nothing means the "
        "account meant to be skipped is still being analyzed. Correct the entries "
        "or remove them."
    )


def get_subaccount_information(config: HeadroomConfig, session: Session) -> List[AccountInfo]:
    """
    Get subaccount information from the management account.

    Uses the provided session to assume the OrgAndAccountInfoReader role in the
    management account, then retrieves account information with tags.

    Excludes the management account, which SCPs and RCPs do not affect, any
    account named in `config.skip_account_ids`, and any account that is not in
    the ACTIVE lifecycle state.

    An excluded account writes no result files, and policy placement only ever
    sees accounts that have results, so exclusion here removes the account from
    the compliance picture entirely rather than holding back a policy. An
    org-wide policy can therefore deny actions a skipped account relies on.

    Args:
        config: Headroom configuration
        session: boto3 Session with access to security analysis account

    Returns:
        List of AccountInfo objects for the ACTIVE accounts, excluding the
        management account and any account in `config.skip_account_ids`

    Raises:
        ValueError: If management_account_id is not set in config
        RuntimeError: If role assumption or API calls fail, if an account's
            lifecycle state cannot be determined, or if a `skip_account_ids`
            entry matches no account in the organization
    """
    mgmt_session = get_management_account_session(config, session)
    org_client = mgmt_session.client("organizations")
    paginator = org_client.get_paginator("list_accounts")
    accounts = []
    skipped_states: Dict[str, int] = {}
    skip_account_ids = set(config.skip_account_ids)
    skipped_by_config = []
    seen_account_ids: Set[str] = set()

    for page in paginator.paginate():
        for acct in page.get("Accounts", []):
            account_id = acct["Id"]
            seen_account_ids.add(account_id)

            if account_id == config.management_account_id:
                continue

            # Consulted before the lifecycle check so that an account whose state
            # `_should_skip_account` cannot classify can be skipped by config
            # instead of aborting every other account's analysis.
            if account_id in skip_account_ids:
                skipped_by_config.append(account_id)
                continue

            if _should_skip_account(acct, account_id):
                # An account is only skipped for a state in INACTIVE_ACCOUNT_STATES,
                # so the state is always a known string here.
                skipped_state = str(_get_account_state(acct))
                skipped_states[skipped_state] = skipped_states.get(skipped_state, 0) + 1
                continue

            account_info = _build_account_info_from_account_dict(acct, org_client, config)
            accounts.append(account_info)

    if skipped_by_config:
        logger.info(
            f"Skipped {len(skipped_by_config)} account(s) named in skip_account_ids: "
            f"{', '.join(sorted(skipped_by_config))}"
        )

    if skipped_states:
        breakdown = ", ".join(f"{count} {state}" for state, count in sorted(skipped_states.items()))
        logger.info(f"Skipped {sum(skipped_states.values())} non-active account(s): {breakdown}")

    _verify_skip_account_ids_matched(config, seen_account_ids)

    return accounts


def get_all_organization_account_ids(config: HeadroomConfig, session: Session) -> Set[str]:
    """
    Get all account IDs in the organization (including management account).

    Args:
        config: Headroom configuration
        session: boto3 Session with access to security analysis account

    Returns:
        Set of all account IDs in the organization

    Raises:
        ValueError: If management_account_id is not set in config
        RuntimeError: If role assumption or API calls fail
    """
    mgmt_session = get_management_account_session(config, session)
    org_client = mgmt_session.client("organizations")
    paginator = org_client.get_paginator("list_accounts")

    account_ids: Set[str] = set()
    for page in paginator.paginate():
        for acct in page.get("Accounts", []):
            account_ids.add(acct["Id"])

    return account_ids


def get_relevant_subaccounts(account_infos: List[AccountInfo]) -> List[AccountInfo]:
    """
    Filter account_infos based on CLI and configuration arguments.

    For now, returns all accounts. Future implementation will support filtering by:
    - All accounts
    - Specific OU
    - Specific owner
    - Specific environment

    Filtering by explicit account ID already happens upstream, in
    `get_subaccount_information`, where it costs no per-account tag lookup.
    """
    return account_infos


def get_headroom_session(config: HeadroomConfig, security_session: Session, account_id: str) -> Session:
    """Assume Headroom role in the target account and return a boto3 session."""
    role_arn = f"arn:aws:iam::{account_id}:role/Headroom"
    return assume_role(role_arn, "HeadroomAnalysisSession", security_session)


def all_check_results_exist(check_type: str, account_info: AccountInfo, config: HeadroomConfig) -> bool:
    """
    Check if all check results of a given type exist for an account.

    Args:
        check_type: Type of checks to verify (scps, rcps)
        account_info: Account information
        config: Headroom configuration

    Returns:
        True if all check results exist, False otherwise
    """
    check_names = get_check_names(check_type)
    return all(
        results_exist(
            check_name=check_name,
            account_name=account_info.name,
            account_id=account_info.account_id,
            results_base_dir=config.results_dir,
            exclude_account_ids=config.exclude_account_ids,
        )
        for check_name in check_names
    )


def run_checks_for_type(
    check_type: str,
    headroom_session: Session,
    account_info: AccountInfo,
    config: HeadroomConfig,
    org_account_ids: Set[str],
    abort: threading.Event
) -> None:
    """
    Run all checks of a given type for a single account.

    This function automatically discovers and runs all registered checks
    of the specified type. No code changes needed when adding new checks.

    Args:
        check_type: Type of checks to run (scps, rcps)
        headroom_session: boto3 Session with Headroom role assumed
        account_info: Account information
        config: Headroom configuration
        org_account_ids: Set of all account IDs in the organization
        abort: Set when another account has failed, ending this account's run
            at the next check boundary
    """
    check_classes = get_all_check_classes(check_type)

    for check_class in check_classes:
        if abort.is_set():
            return

        if results_exist(
            check_name=check_class.CHECK_NAME,
            account_name=account_info.name,
            account_id=account_info.account_id,
            results_base_dir=config.results_dir,
            exclude_account_ids=config.exclude_account_ids,
        ):
            continue

        check = check_class(
            check_name=check_class.CHECK_NAME,
            account_name=account_info.name,
            account_id=account_info.account_id,
            results_dir=config.results_dir,
            org_account_ids=org_account_ids,
            exclude_account_ids=config.exclude_account_ids,
        )
        check.execute(headroom_session)


def _get_account_identifier(account_info: AccountInfo) -> str:
    """Get display identifier for an account."""
    return format_account_identifier(account_info.name, account_info.account_id)


def _all_checks_complete(
    account_info: AccountInfo,
    config: HeadroomConfig
) -> bool:
    """Check if all checks are complete for an account."""
    return all_check_results_exist("scps", account_info, config) and all_check_results_exist("rcps", account_info, config)


def _run_checks_for_account(
    account_info: AccountInfo,
    security_session: Session,
    config: HeadroomConfig,
    org_account_ids: Set[str],
    abort: threading.Event
) -> None:
    """
    Run all checks for a single account.

    Assumes the Headroom role in the target account and runs any missing
    SCP and RCP checks.

    Runs on a worker thread, so it registers the account with `set_account`
    before anything else: every log record this thread emits from here on
    names the account it belongs to, including records from `headroom/aws/`
    that mention only a region or a resource.

    The session created here is touched by this thread alone, which is what
    lets `aws/helpers.py` and `aws/ec2.py` memoize per-session without
    locking.

    Args:
        account_info: Information about the target account
        security_session: boto3 Session for security analysis account
        config: Headroom configuration
        org_account_ids: Set of all account IDs in the organization
        abort: Set when another account has failed, ending this account's run
            at the next check boundary
    """
    account_identifier = _get_account_identifier(account_info)
    set_account(account_identifier)

    if abort.is_set():
        return

    logger.info(f"Running checks for account: {account_identifier}")

    headroom_session = get_headroom_session(config, security_session, account_info.account_id)

    scp_exist = all_check_results_exist("scps", account_info, config)
    if not scp_exist:
        run_checks_for_type("scps", headroom_session, account_info, config, org_account_ids, abort)

    rcp_exist = all_check_results_exist("rcps", account_info, config)
    if not rcp_exist:
        run_checks_for_type("rcps", headroom_session, account_info, config, org_account_ids, abort)

    logger.info(f"Checks completed for account: {account_identifier}")


def run_checks(
    security_session: Session,
    relevant_account_infos: List[AccountInfo],
    config: HeadroomConfig,
    org_account_ids: Set[str]
) -> None:
    """
    Run security checks against all relevant accounts.

    Accounts whose results are all present are filtered out serially, then the
    rest are analyzed by a `ThreadPoolExecutor` of `config.max_account_workers`
    workers, one account per worker. For each account a worker:
    1. Assumes the Headroom role in that account
    2. Runs all registered SCP/RCP checks
    3. Writes results to headroom_results folder

    Args:
        security_session: boto3 Session for security analysis account
        relevant_account_infos: List of accounts to check
        config: Headroom configuration
        org_account_ids: Set of all account IDs in the organization

    Raises:
        ClientError: If assuming the Headroom role in an account fails
        RuntimeError: If a check's underlying AWS API calls fail

    Error handling is deliberately absent: the first failure aborts the entire
    run rather than being logged and skipped. A partial run is more dangerous
    than no run, because this output drives SCP and RCP deployment and an
    account skipped for a transient error is indistinguishable in the results
    from an account with zero violations, so swallowing the error could
    green-light a policy that breaks it. Accounts that cannot or should not be
    analyzed are excluded earlier, in `get_subaccount_information`: by lifecycle
    state, or by being named in `config.skip_account_ids`.

    Aborting takes two mechanisms because Python cannot kill a running thread.
    `Future.cancel` clears the queue but does nothing to accounts already in
    flight; the `abort` Event stops those at their next check boundary. Without
    it, leaving this `with` block would block until every in-flight account had
    run all its remaining checks.

    Leaving the block joins the in-flight workers before the exception reaches
    `main`, so no thread is still writing result files when the run gives up. A
    check already inside `execute()` finishes and writes its file, which is
    harmless: the file is complete and valid, and `results_exist` makes the run
    resumable at per-account, per-check granularity.

    "First" means first to complete with an exception, since `as_completed`
    yields in completion order. Workers that fail after the abort have their
    exceptions discarded unretrieved.

    An operator's Ctrl-C takes the same path. `shutdown(wait=True)` defaults to
    `cancel_futures=False` and puts its sentinel at the back of the work queue,
    so an interrupt that only propagated would still wait out every queued
    account -- hours of it at one worker. Catching it here makes interrupting
    as prompt as a failure: bounded by the one check each in-flight worker is
    already inside.
    """
    pending = []
    for account_info in relevant_account_infos:
        if _all_checks_complete(account_info, config):
            account_identifier = _get_account_identifier(account_info)
            logger.info(f"All results already exist for account {account_identifier}, skipping checks")
            continue
        pending.append(account_info)

    logger.info(
        f"Analyzing {len(pending)} account(s) with {config.max_account_workers} worker(s)"
    )

    abort = threading.Event()

    with ThreadPoolExecutor(max_workers=config.max_account_workers) as executor:
        futures: List[Future[None]] = [
            executor.submit(
                _run_checks_for_account,
                account_info,
                security_session,
                config,
                org_account_ids,
                abort,
            )
            for account_info in pending
        ]

        try:
            for future in as_completed(futures):
                error = future.exception()
                if error is None:
                    continue

                abort.set()
                for outstanding in futures:
                    outstanding.cancel()
                raise error
        except KeyboardInterrupt:
            abort.set()
            for outstanding in futures:
                outstanding.cancel()
            raise


def _verify_no_duplicate_account_names(
    config: HeadroomConfig,
    account_infos: List[AccountInfo]
) -> None:
    """
    Abort if two accounts would write to the same result file.

    With `exclude_account_ids` set, the result filename is the account name
    alone: `ResultFilePathResolver._build_filename` drops the account ID, which
    is the only guaranteed-unique component. Two accounts sharing a name then
    resolve to one path.

    Run serially that is a quiet last-writer-wins. Run with a worker per
    account it is two threads interleaving `json.dump` output into one file,
    producing either corrupt JSON or a valid file holding two accounts' results
    spliced together -- which then feeds policy generation.

    Names are compared case-insensitively. Development happens on macOS,
    where APFS is case-insensitive by default, so accounts named `Prod` and
    `prod` resolve to the same file on the filesystem this tool actually runs
    on even though the two strings differ. This can abort a run on a
    case-sensitive filesystem where `Prod` and `prod` would not actually have
    collided; that is a deliberate trade-off -- a loud abort resolved by
    renaming beats two accounts' JSON interleaved into one file that then
    feeds policy generation.

    The message names the colliding spellings and how many accounts carry
    them, never the account IDs. Printing those would defeat the setting that
    created the collision.

    Args:
        config: Headroom configuration
        account_infos: Accounts about to be analyzed

    Raises:
        RuntimeError: If `exclude_account_ids` is set and two accounts share a
            name, comparing names case-insensitively
    """
    if not config.exclude_account_ids:
        return

    names_by_lower: Dict[str, List[str]] = {}
    for account_info in account_infos:
        names_by_lower.setdefault(account_info.name.lower(), []).append(account_info.name)

    collisions = sorted(lower for lower, names in names_by_lower.items() if len(names) > 1)

    if not collisions:
        return

    breakdown = ", ".join(
        f"{', '.join(sorted(set(names_by_lower[lower])))} ({len(names_by_lower[lower])} accounts)"
        for lower in collisions
    )
    raise RuntimeError(
        "exclude_account_ids is set, so result files are named by account name "
        f"alone, but these names are not unique: {breakdown}. Every such account "
        "would write to the same file, and because accounts are analyzed "
        "concurrently the file would hold interleaved output from all of them. "
        "Rename the accounts, or unset exclude_account_ids so the account ID "
        "makes each filename unique."
    )


def perform_analysis(config: HeadroomConfig) -> None:
    """
    Perform security analysis using the security analysis account session.

    `get_subaccount_information` excludes the management account because it is not
    affected by SCPs/RCPs.
    """
    logger.info("Starting security analysis")
    security_session = get_security_analysis_session(config)
    logger.info("Successfully obtained security analysis session")

    # Get all organization account IDs (including management account)
    # This is needed for RCP checks to identify third-party accounts
    logger.info("Fetching all organization account IDs")
    org_account_ids = get_all_organization_account_ids(config, security_session)
    logger.info(f"Found {len(org_account_ids)} accounts in organization")

    account_infos = get_subaccount_information(config, security_session)
    logger.info(f"Fetched subaccount information: {account_infos}")

    relevant_account_infos = get_relevant_subaccounts(account_infos)
    logger.info(f"Filtered to {len(relevant_account_infos)} relevant accounts for analysis")

    _verify_no_duplicate_account_names(config, relevant_account_infos)

    run_checks(security_session, relevant_account_infos, config, org_account_ids)
    logger.info("Security analysis completed")
