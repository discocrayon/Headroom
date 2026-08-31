import logging
import threading
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import AbstractSet, Dict, Sequence, Set

from boto3.session import Session

from .config import HeadroomConfig
from .checks.registry import get_check_names, get_all_check_classes
from .log_context import NO_ACCOUNT, set_account
from .write_results import results_exist
from .aws.sessions import assume_role, new_session
from .utils import format_account_identifier
from .types import AccountInfo, OrganizationSnapshot

logger = logging.getLogger(__name__)


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
    relevant_account_infos: Sequence[AccountInfo],
    config: HeadroomConfig,
    org_account_ids: AbstractSet[str],
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
        relevant_account_infos: The accounts to check
        config: Headroom configuration
        org_account_ids: Every account ID in the organization, as the snapshot
            captured it: the management account, accounts skipped by
            configuration, and accounts in every non-ACTIVE lifecycle state
            are all members, because a principal in any of them is not a third
            party
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
    analyzed are excluded earlier, in `discover_organization`: by lifecycle
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
    `accounts_by_future` and nothing can cancel it. If a worker already
    exists it picks the item up, finds the abort set, and returns at its
    first checkpoint. If the failure came on the first submit there is no
    worker to pick it up and the item is never run at all -- the same
    outcome by a different route, since `shutdown` joins no threads and
    leaves the queue where it lies.
    """
    # frozenset reaches here from the snapshot, and frozenset is not a subtype
    # of Set[str] -- typing.Set is builtins.set. The parameter threads from the
    # RCP checks down through every service adapter that reads a policy
    # document, so widening the annotation is a change to all of them. One
    # conversion at the boundary instead.
    mutable_org_account_ids = set(org_account_ids)

    pending = []
    for account_info in relevant_account_infos:
        if _all_checks_complete(account_info, config):
            account_identifier = _get_account_identifier(account_info)
            logger.info(f"All results already exist for account {account_identifier}, skipping checks")
            continue
        pending.append(account_info)

    # The account count is what the pool is given. The worker count is not:
    # the executor is built with the full `max_account_workers`, and this is
    # the most threads it can go on to create, since ThreadPoolExecutor
    # spawns on demand and never has more work queued than `pending`.
    logger.info(
        f"Analyzing {len(pending)} account(s) with "
        f"{min(len(pending), config.max_account_workers)} worker(s)"
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
                            mutable_org_account_ids,
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


def perform_analysis(
    config: HeadroomConfig,
    security_session: Session,
    snapshot: OrganizationSnapshot
) -> None:
    """
    Run every check against the accounts the snapshot names.

    Discovery is `main`'s job and happens once, before this. What used to be
    three Organizations reads here -- membership, organization ID, and account
    information -- are three projections of one captured view, so the scan
    cannot observe a different organization from the one Terraform generation
    goes on to use.

    Args:
        config: Headroom configuration
        security_session: boto3 Session for the security analysis account
        snapshot: The run's captured organization view
    """
    logger.info("Starting security analysis")

    run_checks(
        security_session,
        snapshot.analyzable_accounts,
        config,
        snapshot.member_account_ids,
        snapshot.organization_id,
    )
    logger.info("Security analysis completed")
