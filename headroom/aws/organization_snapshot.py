"""
Build the run's one-time snapshot of the AWS Organization.

`discover_organization` is the only place a run reads AWS Organizations:
every other stage -- the scan, SCP generation, RCP generation -- consumes the
`OrganizationSnapshot` it returns instead of calling AWS again. The helpers
below it are the account-level building blocks: tag lookups, lifecycle
classification, name resolution, and the filename-safety checks that gate
which accounts a run may write result files for.
"""

import logging
import unicodedata
from pathlib import Path
from typing import AbstractSet, Dict, List, Optional, Sequence, cast

from botocore.exceptions import ClientError
from mypy_boto3_organizations.client import OrganizationsClient
from mypy_boto3_organizations.type_defs import AccountTypeDef, TagTypeDef

from ..config import HeadroomConfig
from ..types import AccountInfo, OrganizationHierarchy, OrganizationSnapshot
from .helpers import paginate
from .organization import (
    build_organization_hierarchy,
    find_organization_root,
    list_organization_accounts,
)

logger = logging.getLogger(__name__)


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
    tags: Dict[str, str] = {}

    try:
        pages = paginate(org_client, "list_tags_for_resource", ResourceId=account_id)
        for page in pages:
            for tag in cast(Sequence[TagTypeDef], page.get("Tags", [])):
                tags[tag["Key"]] = tag["Value"]
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

    return tags


def _determine_account_name(account: AccountTypeDef, tags: Dict[str, str], config: HeadroomConfig) -> str:
    """
    Determine the account name to use based on configuration.

    Args:
        account: Account dictionary from Organizations API
        tags: Account tags dictionary
        config: Headroom configuration

    Returns:
        The configured name tag when use_account_name_from_tags is set,
        otherwise the name Organizations reports. Each path falls back to the
        account ID, and never to the other: a missing name tag yields the
        account ID rather than the Organizations name.
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
        "add it to INACTIVE_ACCOUNT_STATES in headroom/aws/organization_snapshot.py when accounts in "
        "that state cannot be analyzed, or to ACTIVE_ACCOUNT_STATE handling when they "
        "can."
    )


def _verify_no_duplicate_account_ids(member_accounts: Sequence[AccountTypeDef]) -> None:
    """
    Abort if `list_accounts` reports the same account ID more than once.

    `build_organization_hierarchy` already guards this on the traversal
    side: an account under two parents raises rather than being placed
    twice. The membership view had no equivalent, and nothing downstream
    would have noticed on its own -- `member_account_ids` is a frozenset, so
    a repeated ID dedupes there harmlessly, and `_verify_views_agree` keys
    `inventory_names` by ID, so the duplicate collapses before the
    cross-check can see it. Left unguarded, a repeated ID becomes two
    `AccountInfo` for one account, therefore two workers in the pool,
    therefore two threads writing the same result file.

    AWS returns a duplicate only if the organization is mutated
    mid-listing, the same condition every other guard in this module
    treats as an abort and retry rather than something to reconcile.

    Args:
        member_accounts: Every organization member, from `list_accounts`

    Raises:
        RuntimeError: If an account ID appears more than once
    """
    seen_counts: Dict[str, int] = {}
    for account in member_accounts:
        account_id = account["Id"]
        seen_counts[account_id] = seen_counts.get(account_id, 0) + 1

    duplicated = sorted(
        account_id for account_id, count in seen_counts.items() if count > 1
    )

    if not duplicated:
        return

    raise RuntimeError(
        f"{len(duplicated)} account ID(s) were returned more than once by "
        f"list_accounts: {', '.join(duplicated)}. The organization was "
        "modified during discovery. Re-run Headroom."
    )


def _verify_skip_account_ids_matched(config: HeadroomConfig, seen_account_ids: AbstractSet[str]) -> None:
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


# Both Linux and macOS cap a single path component at 255 bytes, and
# `ResultFilePathResolver._build_filename` spends eighteen of them on the
# longest suffix it adds: `_`, a twelve-digit account ID, and `.json`.
MAX_FILENAME_COMPONENT_BYTES = 255
RESULT_FILENAME_SUFFIX_BYTES = len("_111111111111.json")
MAX_ACCOUNT_NAME_BYTES = MAX_FILENAME_COMPONENT_BYTES - RESULT_FILENAME_SUFFIX_BYTES


def _unusable_as_a_filename_because(name: str) -> Optional[str]:
    """
    Report why a name cannot become a result filename, or None if it can.

    The reason travels with the name because the failures are unrelated to
    each other, and an operator reading one message about several accounts
    needs to know which account hit which.

    Args:
        name: Account name that will be interpolated into a result filename

    Returns:
        A phrase completing "cannot be used because ...", or None if usable
    """
    if not name:
        return "it is empty"
    if "\x00" in name:
        return "it holds a null byte"
    if len(name.encode("utf-8")) > MAX_ACCOUNT_NAME_BYTES:
        return (
            f"it is too long: {MAX_ACCOUNT_NAME_BYTES} bytes is the most that "
            "leaves room for the account ID and the extension"
        )
    if Path(name).name != name:
        return "it reads as a path rather than a filename"
    return None


def _verify_account_names_are_filename_safe(account_infos: Sequence[AccountInfo]) -> None:
    """
    Abort if an account's name would not survive becoming a result filename.

    Both naming modes put the account name into the filename -- alone when
    `exclude_account_ids` is set, and ahead of the account ID otherwise -- so
    unlike the duplicate-name guard this one is not conditional on that
    setting.

    `ResultFilePathResolver` interpolates the name and hands the result to
    `Path`, which reads a separator as structure rather than as text. Four
    names go wrong, and the quiet one is the reason this runs before the scan
    rather than being left to fail at write time:

    - `Prod/US` becomes `check_dir/Prod/US.json`. With no such directory a
      worker thread raises FileNotFoundError partway through the run. With
      one, the write succeeds somewhere the reader does not look, and the
      account is silently missing from the results policy generation reads.
    - `../Prod` becomes `check_dir/../Prod.json`. The write succeeds, one
      level up, over whatever was already there.
    - A name holding a null byte reaches `open()`, which raises ValueError.
    - A name past `MAX_ACCOUNT_NAME_BYTES` overruns the 255-byte component
      limit, and `open()` raises OSError. Organizations caps a name at 50,
      but `use_account_name_from_tags` reads it from a tag value, which runs
      to 256.

    An empty name is rejected too, though not for a filename reason: it
    becomes `.json`, which `pathlib`'s glob matches perfectly well. It cannot
    become a Terraform identifier, so `make_account_base_names` would abort
    generation after the whole scan had run. Rejecting it here is the same
    check, paid in seconds.

    A leading dot is deliberately allowed. `pathlib.Path.glob` matches
    dotfiles -- `glob.glob` is the one that skips them -- and neither reader
    takes account identity from the filename, so `.Prod.json` is read back
    like any other result.

    Like the duplicate-name guard, the message names the offending names and
    never the account IDs.

    Args:
        account_infos: Accounts about to be analyzed

    Raises:
        RuntimeError: If an account name is not usable as a filename
    """
    unsafe = sorted(
        (account_info.name, reason)
        for account_info in account_infos
        if (reason := _unusable_as_a_filename_because(account_info.name))
    )

    if not unsafe:
        return

    listed = ", ".join(f"{name!r} ({reason})" for name, reason in unsafe)
    raise RuntimeError(
        f"These account names cannot be used as result filenames: {listed}. "
        "The name is interpolated into the filename, so a path separator "
        "reads as a directory and the account's results are written "
        "somewhere policy generation does not look, while a null byte or an "
        "over-long name fails the write outright. Rename the accounts, or "
        "set use_account_name_from_tags and give them a tag that is a plain "
        "filename."
    )


def _verify_no_duplicate_account_names(
    config: HeadroomConfig,
    account_infos: Sequence[AccountInfo]
) -> None:
    """
    Abort if two accounts would write to the same result file.

    With `exclude_account_ids` set the filename is the account name alone --
    `ResultFilePathResolver._build_filename` drops the only guaranteed-unique
    component -- so two accounts sharing a name resolve to one path. Run with
    a worker per account, that is two threads interleaving `json.dump` output
    into one file: either corrupt JSON, or a valid file holding both accounts'
    results spliced together, which then feeds policy generation.

    Names are compared the way a filesystem compares them, by Unicode
    canonical caseless matching -- `NFD(casefold(NFD(x)))`, D145. It folds
    case and normal form together rather than in sequence, which is not the
    same thing; "Account name validation" in `Headroom-Specification.md`
    carries the worked example that rules out the cheaper orderings, and the
    trade-off this makes on a filesystem that folds neither axis.

    The message names the colliding spellings and how many accounts carry
    them, never the account IDs -- printing those would defeat the setting
    that created the collision.

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


def _read_organization_id(org_client: OrganizationsClient) -> str:
    """
    Read this organization's ID.

    Every source guard scoped to an organization -- `aws:SourceOrgID` and
    `aws:SourceOrgPaths` -- is classified against this value: a guard naming
    this organization needs no allowlist entry, and one naming any other
    organization names accounts no allowlist can carry.

    A response without an ID aborts rather than falling back. The fallback
    would put a foreign organization's sources in an allowlist, or leave this
    organization's out, and would look like a healthy run while doing it.

    Args:
        org_client: AWS Organizations client

    Returns:
        This organization's ID, such as `o-11111111111`

    Raises:
        RuntimeError: If the response carries no organization ID
    """
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


def _select_analyzable_accounts(
    config: HeadroomConfig,
    member_accounts: Sequence[AccountTypeDef]
) -> List[AccountTypeDef]:
    """
    Narrow full membership to the accounts the scan will run against.

    Three exclusions, in this order: the management account, which SCPs and
    RCPs do not affect; accounts named in `skip_account_ids`; accounts not in
    the ACTIVE lifecycle state.

    Configured skips are consulted before the lifecycle check so that an
    account whose state `_should_skip_account` cannot classify can be excluded
    by configuration instead of aborting every other account's analysis.

    Args:
        config: Headroom configuration
        member_accounts: Every organization member, from `list_accounts`

    Returns:
        The raw account dicts for the accounts to analyze, in the order
        Organizations reported them

    Raises:
        RuntimeError: If an otherwise-analyzable account's lifecycle state
            cannot be classified
    """
    analyzable: List[AccountTypeDef] = []
    skip_account_ids = set(config.skip_account_ids)
    skipped_by_config: List[str] = []
    skipped_states: Dict[str, int] = {}

    for account in member_accounts:
        account_id = account["Id"]

        if account_id == config.management_account_id:
            continue

        if account_id in skip_account_ids:
            skipped_by_config.append(account_id)
            continue

        if _should_skip_account(account, account_id):
            skipped_state = str(_get_account_state(account))
            skipped_states[skipped_state] = skipped_states.get(skipped_state, 0) + 1
            continue

        analyzable.append(account)

    if skipped_by_config:
        logger.info(
            f"Skipped {len(skipped_by_config)} account(s) named in skip_account_ids: "
            f"{', '.join(sorted(skipped_by_config))}"
        )

    if skipped_states:
        breakdown = ", ".join(
            f"{count} {state}" for state, count in sorted(skipped_states.items())
        )
        logger.info(
            f"Skipped {sum(skipped_states.values())} non-active account(s): {breakdown}"
        )

    return analyzable


def _verify_views_agree(
    member_accounts: Sequence[AccountTypeDef],
    hierarchy: OrganizationHierarchy
) -> None:
    """
    Abort unless the global listing and the OU traversal describe one organization.

    `list_accounts` is canonical for membership and lifecycle; the traversal
    is canonical for placement. Every account has exactly one parent, and
    `list_accounts_for_parent` returns accounts in every lifecycle state, so
    in a quiescent organization the two views hold the same accounts under the
    same names. That is what makes an unconditional abort safe here: it cannot
    misfire on an organization that has merely closed an account.

    The names must agree because the two feed different consumers.
    `AccountOrgPlacement.account_name` comes from the traversal and is what
    `lookup_account_id_by_name` matches; `AccountInfo.name` comes from the
    global view plus tags and names the result files. The canonicalization
    fallback in `lookup_account_id_by_name` bridges the two, and it can only
    do that if the raw Organizations names are the same on both sides.

    Every disagreement means the organization changed between the two reads.
    This is a captured view, not transaction isolation, so the remedy is to
    re-run rather than to reconcile.

    Args:
        member_accounts: Every organization member, from `list_accounts`
        hierarchy: The placement view, from `build_organization_hierarchy`

    Raises:
        RuntimeError: If an account is in one view only, or is named
            differently by the two
    """
    inventory_names = {account["Id"]: account["Name"] for account in member_accounts}
    placed_names = {
        account_id: placement.account_name
        for account_id, placement in hierarchy.accounts.items()
    }

    unplaced = sorted(set(inventory_names) - set(placed_names))
    if unplaced:
        raise RuntimeError(
            f"{len(unplaced)} organization member(s) sit under no root or OU: "
            f"{', '.join(unplaced)}. Every account has a parent, so the "
            "organization was modified while Headroom was reading it. Re-run "
            "Headroom."
        )

    unknown = sorted(set(placed_names) - set(inventory_names))
    if unknown:
        raise RuntimeError(
            f"{len(unknown)} account(s) sit under a root or OU but are not "
            f"organization members: {', '.join(unknown)}. The organization was "
            "modified while Headroom was reading it. Re-run Headroom."
        )

    renamed = sorted(
        account_id
        for account_id in inventory_names
        if inventory_names[account_id] != placed_names[account_id]
    )
    if renamed:
        listed = ", ".join(
            f"{account_id} ('{inventory_names[account_id]}' and "
            f"'{placed_names[account_id]}')"
            for account_id in renamed
        )
        raise RuntimeError(
            f"{len(renamed)} account(s) are named differently by the two "
            f"Organizations views: {listed}. Result files are named from the "
            "first and placement is matched against the second, so the "
            "organization was modified while Headroom was reading it. Re-run "
            "Headroom."
        )


def discover_organization(
    config: HeadroomConfig,
    org_client: OrganizationsClient
) -> OrganizationSnapshot:
    """
    Read the organization once and return the run's whole view of it.

    This is the only place a run reads AWS Organizations. Membership,
    placement, the analyzable set, and the Terraform data sources all come
    from this one call, so every stage reasons about the same organization.
    Before it existed, four independent reads could each observe a different
    one, and nothing detected the disagreement.

    Two views are taken: `list_accounts` for membership and lifecycle, and an
    OU traversal for placement. They are cross-checked, and any disagreement
    aborts.

    Order matters twice. `skip_account_ids` is verified against full
    membership before any filtering, so a mistyped entry reports itself rather
    than losing the race to a lifecycle abort it may have caused. Tags and
    name validation come last, so a structural abort costs no per-account
    calls.

    This captures a view; it is not transaction isolation. Organizations
    offers no consistent snapshot across calls, so an organization modified
    while it is being read can fail the cross-check. That aborts the run and
    the operator re-runs it -- proceeding on two disagreeing views would
    produce placement and Terraform matching no organization that ever
    existed.

    Args:
        config: Headroom configuration
        org_client: Organizations client on the management account session

    Returns:
        The run's organization snapshot

    Raises:
        RuntimeError: If the organization has no ID, no root or several, if
            `list_accounts` returns an account ID more than once, if a
            `skip_account_ids` entry matches nothing, if a lifecycle state
            cannot be classified, if the two views disagree, or if an account
            name cannot become a result filename
    """
    organization_id = _read_organization_id(org_client)
    logger.info(f"Organization ID: {organization_id}")

    member_accounts = list_organization_accounts(org_client)
    _verify_no_duplicate_account_ids(member_accounts)
    member_account_ids = frozenset(account["Id"] for account in member_accounts)
    logger.info(f"Found {len(member_account_ids)} accounts in organization")

    _verify_skip_account_ids_matched(config, member_account_ids)

    analyzable = _select_analyzable_accounts(config, member_accounts)

    hierarchy = build_organization_hierarchy(
        org_client, find_organization_root(org_client)
    )
    _verify_views_agree(member_accounts, hierarchy)

    analyzable_accounts = tuple(
        _build_account_info_from_account_dict(account, org_client, config)
        for account in analyzable
    )
    logger.info(f"Analyzing {len(analyzable_accounts)} accounts")

    _verify_account_names_are_filename_safe(analyzable_accounts)
    _verify_no_duplicate_account_names(config, analyzable_accounts)

    return OrganizationSnapshot(
        organization_id=organization_id,
        member_account_ids=member_account_ids,
        analyzable_accounts=analyzable_accounts,
        hierarchy=hierarchy,
    )
