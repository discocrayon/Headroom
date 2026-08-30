import logging
import threading
import unicodedata
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_organizations.client import OrganizationsClient
from mypy_boto3_organizations.type_defs import AccountTypeDef

from .config import HeadroomConfig
from .checks.registry import get_check_names, get_all_check_classes
from .log_context import NO_ACCOUNT, set_account
from .write_results import results_exist
from .aws.sessions import assume_role, new_session
from .utils import format_account_identifier

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


def get_organization_id(config: HeadroomConfig, session: Session) -> str:
    """
    Get this organization's ID from the management account.

    Every source guard scoped to an organization - `aws:SourceOrgID` and
    `aws:SourceOrgPaths` - is classified against this value: a guard naming
    this organization needs no allowlist entry, and one naming any other
    organization names accounts no allowlist can carry. The deployed RCP
    already resolves the same value through
    `data.aws_organizations_organization.current.id`, so this is discovery
    catching up to deployment.

    A response without an ID aborts the run rather than falling back. The
    fallback would put a foreign organization's sources in an allowlist, or
    leave this organization's out, and would look like a healthy run while
    doing it.

    Args:
        config: Headroom configuration
        session: boto3 Session with access to security analysis account

    Returns:
        This organization's ID, such as `o-example12345`

    Raises:
        ValueError: If management_account_id is not set in config
        RuntimeError: If role assumption fails, or if the response carries
            no organization ID
        ClientError: If the OrgAndAccountInfoReader role lacks
            `organizations:DescribeOrganization`
    """
    mgmt_session = get_management_account_session(config, session)
    org_client: OrganizationsClient = mgmt_session.client("organizations")

    organization = org_client.describe_organization().get("Organization", {})
    org_id = organization.get("Id")
    if not org_id:
        raise RuntimeError(
            "DescribeOrganization returned no organization ID. Every source "
            "guard scoped to an organization is classified against it, so "
            "continuing would put a foreign organization's sources in an "
            "allowlist, or leave this organization's out."
        )

    return org_id


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
    org_id: str,
    abort: threading.Event
) -> bool:
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
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization
        abort: Set when another account has failed, ending this account's run
            at the next check boundary

    Returns:
        True if every check of this type ran or was already on disk, False if
        a checkpoint stopped the loop with checks still to run. The caller
        needs the distinction to label the account, and cannot recover it by
        re-reading `abort`: the Event can be set by another account's failure
        after this loop's last iteration, when nothing was skipped here.
    """
    check_classes = get_all_check_classes(check_type)

    for check_class in check_classes:
        # The skip is tested before the checkpoint, never after. A check
        # already on disk is work this account does not owe, so an abort that
        # lands with only such checks left has stopped nothing. Reading the
        # Event first reports the account aborted anyway, and the re-run that
        # sends the operator answers "All results already exist".
        if results_exist(
            check_name=check_class.CHECK_NAME,
            account_name=account_info.name,
            account_id=account_info.account_id,
            results_base_dir=config.results_dir,
            exclude_account_ids=config.exclude_account_ids,
        ):
            continue

        if abort.is_set():
            return False

        check = check_class(
            check_name=check_class.CHECK_NAME,
            account_name=account_info.name,
            account_id=account_info.account_id,
            results_dir=config.results_dir,
            org_account_ids=org_account_ids,
            org_id=org_id,
            exclude_account_ids=config.exclude_account_ids,
        )
        check.execute(headroom_session)

    return True


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
    org_id: str,
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

    The session created here is touched by this thread alone. That is what
    makes the per-session memos in `aws/helpers.py` and `aws/ec2.py` correct:
    each keys on the session object, so no worker can be served another
    account's region list, instances, or resource policies. The memos still
    take a lock -- the dictionaries holding them are shared between workers,
    even though no two workers ever contend for one entry.

    The account is cleared on the way out. `set_account` writes to
    thread-local storage and the pool reuses its threads, so a worker that
    returned without clearing would leave the next records that thread emits
    named for the account that just finished, until the next worker reaches
    the `set_account` above. `-` is the honest answer in that window, and the
    `finally` is what extends it to the account that raised.

    The closing log line comes from what the check loops report, not from
    re-reading `abort`. Another account can fail while this worker is inside
    its last `check.execute()`, and this account has then run and written
    every check it owns; reading the Event at that point labels a complete
    account aborted, sending the operator after a re-run that answers "All
    results already exist".

    Args:
        account_info: Information about the target account
        security_session: boto3 Session for security analysis account
        config: Headroom configuration
        org_account_ids: Set of all account IDs in the organization
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization
        abort: Set when another account has failed, ending this account's run
            at the next check boundary
    """
    account_identifier = _get_account_identifier(account_info)
    set_account(account_identifier)
    try:
        _run_every_missing_check(
            account_info,
            account_identifier,
            security_session,
            config,
            org_account_ids,
            org_id,
            abort,
        )
    finally:
        set_account(NO_ACCOUNT)


def _run_every_missing_check(
    account_info: AccountInfo,
    account_identifier: str,
    security_session: Session,
    config: HeadroomConfig,
    org_account_ids: Set[str],
    org_id: str,
    abort: threading.Event
) -> None:
    """
    Run the SCP and RCP checks this account does not already have on disk.

    Split from `_run_checks_for_account` only so that the account context it
    registers is set and cleared in one place, around a body with several
    exits.

    Args:
        account_info: Information about the target account
        account_identifier: Formatted identifier, for the log lines
        security_session: boto3 Session for security analysis account
        config: Headroom configuration
        org_account_ids: Set of all account IDs in the organization
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization
        abort: Set when another account has failed, ending this account's run
            at the next check boundary
    """
    if abort.is_set():
        logger.info(f"Checks aborted for account: {account_identifier}")
        return

    logger.info(f"Running checks for account: {account_identifier}")

    headroom_session = get_headroom_session(config, security_session, account_info.account_id)

    # Either operand order yields the same `completed`. run_checks_for_type
    # returns False only after reading the abort Event, so a False from the
    # SCP loop means the Event is set and the RCP loop could not have
    # returned True with work still to do. Written this way the RCP loop is
    # entered either way, which keeps the two blocks symmetrical.
    completed = True

    scp_exist = all_check_results_exist("scps", account_info, config)
    if not scp_exist:
        completed = run_checks_for_type(
            "scps", headroom_session, account_info, config, org_account_ids, org_id, abort
        ) and completed

    rcp_exist = all_check_results_exist("rcps", account_info, config)
    if not rcp_exist:
        completed = run_checks_for_type(
            "rcps", headroom_session, account_info, config, org_account_ids, org_id, abort
        ) and completed

    if not completed:
        logger.info(f"Checks aborted for account: {account_identifier}")
        return

    logger.info(f"Checks completed for account: {account_identifier}")


def _log_every_failure(
    accounts_by_future: Dict[Future[None], AccountInfo]
) -> None:
    """
    Report every account that failed, not only the one that propagated.

    One exception reaches `main`; the rest are held by futures nobody asks
    again. `concurrent.futures.Future` has no `__del__`, so unlike an asyncio
    future it is collected without even an "exception was never retrieved"
    warning -- the other failures leave no trace at all. An operator missing
    the Headroom role in forty accounts is told about one, fixes it, re-runs,
    and is told about the next.

    Cancelled futures are skipped because `exception()` raises
    `CancelledError` for them, and a cancelled account never ran anyway.

    Unfinished ones are skipped because `exception()` would block, and that
    branch is not dead. `__exit__` has normally joined every worker before
    this runs, but a second Ctrl-C lands inside `shutdown(wait=True)` and
    reaches the outer handler with workers still going. Waiting there to
    collect their failures is the opposite of what an operator pressing
    Ctrl-C twice is asking for.

    Args:
        accounts_by_future: Every future submitted, mapped to its account
    """
    for future, account_info in accounts_by_future.items():
        if future.cancelled() or not future.done():
            continue

        error = future.exception()
        if error is not None:
            logger.error(
                f"Checks failed for account {_get_account_identifier(account_info)}: {error!r}"
            )


def _log_the_accounts_that_never_ran(
    accounts_by_future: Dict[Future[None], AccountInfo]
) -> None:
    """
    Report how much of the organization the abort left unanalyzed.

    Every other outcome announces itself: an account that finishes logs
    `Checks completed`, one stopped at a checkpoint logs `Checks aborted`,
    and one that failed is named by `_log_every_failure`. A cancelled account
    is the exception -- it never ran, so it never logged, and
    `_log_every_failure` skips it because it holds no exception to report.

    Without this the operator saw `Analyzing 300 account(s)`, some
    completions, the failures, and a traceback, and had to reach the number
    that matters by subtraction. It is the number that decides whether the
    results now on disk are worth generating policies from.

    Counted from `Future.cancelled()`, which is true only for futures the
    handler took off the queue before they started. Accounts already in
    flight are not counted here: they logged their own abort.

    Args:
        accounts_by_future: Every future submitted, mapped to its account
    """
    cancelled = sum(1 for future in accounts_by_future if future.cancelled())

    if not cancelled:
        return

    logger.error(
        f"Aborting: {cancelled} account(s) were never analyzed. Results on disk "
        "cover the rest, and a re-run resumes from them."
    )


def run_checks(
    security_session: Session,
    relevant_account_infos: List[AccountInfo],
    config: HeadroomConfig,
    org_account_ids: Set[str],
    org_id: str
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
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization

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

    "First" is first as `as_completed` reports it. That is true completion
    order for every future still running when it is called, but the futures
    already finished at that moment are collected into a set and yielded in
    hash order. The window is empty in a real run -- the submit loop takes
    milliseconds and the quickest failure is an AssumeRole round trip -- and
    wide open in a test whose work returns instantly.

    Which failure propagates therefore does not decide which failures the
    operator is told about. `_log_every_failure` reports all of them, because
    only one exception can reach `main` and the rest would otherwise vanish
    silently: `Future` has no `__del__`, so nothing warns that they went
    unretrieved.

    An operator's Ctrl-C takes the same path. `shutdown(wait=True)` defaults to
    `cancel_futures=False` and puts its sentinel at the back of the work queue,
    so an interrupt that only propagated would still wait out every queued
    account -- hours of it at one worker. Catching it here makes interrupting
    as prompt as a failure: bounded by the one check each in-flight worker is
    already inside.

    Submission sits inside the same `try` because the submit loop can raise
    too. `executor.submit` reaches `_adjust_thread_count`, whose
    `Thread.start()` raises `RuntimeError("can't start new thread")` on a host
    at its thread limit -- likeliest at `max_account_workers=32` -- and a
    Ctrl-C can land there as readily as in `as_completed`. Submitting outside
    the `try` would let either escape with `abort` unset and nothing
    cancelled, and `__exit__` would then run every account already submitted
    to completion: the drain this handler exists to prevent.
    `accounts_by_future` is bound before the `with` so the handler always has
    the partial map to cancel, whatever the submit loop got through.

    The Event is what covers that window, not the cancel loop. CPython's
    `submit` puts the work item on the queue and only then calls
    `_adjust_thread_count`, so the item whose thread failed to start is
    already queued while `submit` never returned its future: it is not in
    `accounts_by_future` and nothing can cancel it. An existing worker picks
    it up, finds the abort set, and returns at its first checkpoint.
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
    accounts_by_future: Dict[Future[None], AccountInfo] = {}

    # The outer handler runs after `__exit__`, which is the whole point of it:
    # `_log_every_failure` reads the other workers' exceptions, and those are
    # not set until `shutdown(wait=True)` has joined them. Inside the block
    # there is nothing yet to find.
    try:
        with ThreadPoolExecutor(max_workers=config.max_account_workers) as executor:
            try:
                # Recorded one at a time rather than built as a comprehension.
                # A comprehension binds the mapping only once it finishes, so a
                # `submit` that raises halfway would discard the partial result
                # and leave the handler below with nothing to cancel.
                for account_info in pending:
                    accounts_by_future[
                        executor.submit(
                            _run_checks_for_account,
                            account_info,
                            security_session,
                            config,
                            org_account_ids,
                            org_id,
                            abort,
                        )
                    ] = account_info

                for future in as_completed(accounts_by_future):
                    error = future.exception()
                    if error is not None:
                        raise error
            except BaseException:
                # Broader than Exception deliberately, and not a swallow: it
                # re-raises unconditionally. Its job is to run the abort on every
                # abnormal exit, which is why it has to catch the two that are not
                # Exceptions -- the KeyboardInterrupt of an operator's Ctrl-C and
                # SystemExit. Narrowing it back to `except Exception` would let
                # those reach `__exit__` uncaught, and `shutdown(wait=True)` would
                # then run every queued account before the process gave up.
                # `abort.set()` comes before the cancel loop so a second Ctrl-C
                # landing inside that loop still finds the in-flight workers
                # already headed for their next checkpoint.
                abort.set()
                for outstanding in accounts_by_future:
                    outstanding.cancel()
                raise
    except BaseException:
        # Broad for the same reason the inner handler is, and pinned by
        # `test_a_keyboard_interrupt_still_reports_the_failures_already_collected`:
        # an operator's Ctrl-C is the case where the report matters most, and
        # `except Exception` would skip it, leaving a traceback that names one
        # account out of however many failed.
        _log_every_failure(accounts_by_future)
        _log_the_accounts_that_never_ran(accounts_by_future)
        raise


def _is_usable_as_a_filename(name: str) -> bool:
    """
    Report whether a name lands in the directory it is joined to.

    Args:
        name: Account name that will be interpolated into a result filename

    Returns:
        True if the name is a plain filename the readers' glob will match
    """
    if not name or name.startswith("."):
        return False
    return Path(name).name == name


def _verify_account_names_are_filename_safe(account_infos: List[AccountInfo]) -> None:
    """
    Abort if an account's name would not survive becoming a result filename.

    Both naming modes put the account name into the filename -- alone when
    `exclude_account_ids` is set, and ahead of the account ID otherwise -- so
    unlike the duplicate-name guard this one is not conditional on that
    setting.

    `ResultFilePathResolver` interpolates the name and hands the result to
    `Path`, which reads a separator as structure rather than as text. Three
    names go wrong there, and the two quiet ones are the reason this runs
    before the scan rather than being left to fail at write time:

    - `Prod/US` becomes `check_dir/Prod/US.json`. With no such directory a
      worker thread raises FileNotFoundError partway through the run. With
      one, the write succeeds somewhere the reader does not look.
    - `../Prod` becomes `check_dir/../Prod.json`. The write succeeds, one
      level up, over whatever was already there.
    - An empty name becomes `.json`, which the readers' `*.json` glob does
      not match.

    The last two lose the account silently: policy generation reads the
    results directory, finds nothing for that account, and generates as
    though it did not exist. Organizations constrains an account name only by
    length, so it will hand back every one of these.

    Like the duplicate-name guard, the message names the offending names and
    never the account IDs.

    Args:
        account_infos: Accounts about to be analyzed

    Raises:
        RuntimeError: If an account name is not usable as a filename
    """
    unsafe = sorted(
        account_info.name
        for account_info in account_infos
        if not _is_usable_as_a_filename(account_info.name)
    )

    if not unsafe:
        return

    listed = ", ".join(repr(name) for name in unsafe)
    raise RuntimeError(
        f"These account names cannot be used as result filenames: {listed}. "
        "The name is interpolated into the filename, so a path separator "
        "reads as a directory and a leading dot hides the file from the "
        "glob that reads results back -- either way the account's results "
        "are written somewhere policy generation does not look. Rename the "
        "accounts, or set use_account_name_from_tags and give them a tag "
        "that is a plain filename."
    )


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

    Names are compared as the filesystem compares them, not as `==` does.
    Development happens on macOS, where APFS folds two axes by default: case,
    so `Prod` and `prod` are one file, and Unicode normal form, so `café`
    composed and decomposed are one file even though the two strings hold
    different code points.

    Closing the two axes in sequence does not close their composition,
    because case folding can undo the normalization that just ran. `ſ`
    followed by a combining acute has no precomposed form, so NFC returns it
    unchanged; the fold then maps `ſ` to `s`, yielding the decomposition
    of `ś` rather than `ś`. The two names key differently while APFS
    stores them in one inode. Decomposing first is what closes that: under
    NFD both spellings reach the fold already decomposed, and both come out
    `s` followed by the combining acute.

    Unicode's closed form for this comparison is canonical caseless matching
    (D145), `NFD(casefold(NFD(x)))`, and that is what this uses. The trailing
    NFD is there because D145 specifies it, not because a name has been found
    that needs it -- against this Unicode data no single codepoint changes
    key when it is dropped, the example above included. It costs one pass,
    and it means the guard does not have to be re-derived from scratch when
    the case-folding data changes.

    This can abort a run on a filesystem that folds neither axis, where the
    names would not actually have collided; that is a deliberate trade-off --
    a loud abort resolved by renaming beats two accounts' JSON interleaved
    into one file that then feeds policy generation.

    The message names the colliding spellings and how many accounts carry
    them, never the account IDs. Printing those would defeat the setting that
    created the collision.

    Args:
        config: Headroom configuration
        account_infos: Accounts about to be analyzed

    Raises:
        RuntimeError: If `exclude_account_ids` is set and two accounts share a
            name under canonical caseless matching
    """
    if not config.exclude_account_ids:
        return

    names_by_key: Dict[str, List[str]] = {}
    for account_info in account_infos:
        key = unicodedata.normalize(
            "NFD", unicodedata.normalize("NFD", account_info.name).casefold()
        )
        names_by_key.setdefault(key, []).append(account_info.name)

    collisions = sorted(key for key, names in names_by_key.items() if len(names) > 1)

    if not collisions:
        return

    breakdown = ", ".join(
        f"{', '.join(sorted(set(names_by_key[key])))} ({len(names_by_key[key])} accounts)"
        for key in collisions
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

    # Classifies aws:SourceOrgID and aws:SourceOrgPaths guards on service
    # principals: a guard naming this organization needs no allowlist entry
    org_id = get_organization_id(config, security_session)
    logger.info(f"Organization ID: {org_id}")

    account_infos = get_subaccount_information(config, security_session)
    logger.info(f"Fetched subaccount information: {account_infos}")

    relevant_account_infos = get_relevant_subaccounts(account_infos)
    logger.info(f"Filtered to {len(relevant_account_infos)} relevant accounts for analysis")

    _verify_account_names_are_filename_safe(relevant_account_infos)
    _verify_no_duplicate_account_names(config, relevant_account_infos)

    run_checks(security_session, relevant_account_infos, config, org_account_ids, org_id)
    logger.info("Security analysis completed")
