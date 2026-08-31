"""
AWS Organizations analysis module.

This module contains functions for analyzing AWS Organizations structure
using the AWS Organizations API.
"""

import logging
from collections import deque
from typing import Deque, Dict, List, Optional, Sequence, Set, Tuple, cast

from boto3.session import Session
from botocore.exceptions import BotoCoreError, ClientError
from mypy_boto3_organizations.client import OrganizationsClient
from mypy_boto3_organizations.type_defs import AccountTypeDef, OrganizationalUnitTypeDef, RootTypeDef

from ..types import OrganizationHierarchy, OrganizationalUnit, AccountOrgPlacement
from ..utils import make_safe_variable_name
from .helpers import paginate

# Set up logging
logger = logging.getLogger(__name__)


def _list_child_ous(
    org_client: OrganizationsClient,
    parent_id: str
) -> List[OrganizationalUnitTypeDef]:
    """
    Return every OU directly under one parent, across all pages.

    Args:
        org_client: AWS Organizations client
        parent_id: Root or OU ID to list the children of

    Returns:
        The parent's direct child OUs

    Raises:
        RuntimeError: If the listing fails at any page
    """
    child_ous: List[OrganizationalUnitTypeDef] = []

    try:
        pages = paginate(
            org_client, "list_organizational_units_for_parent", ParentId=parent_id
        )
        for page in pages:
            child_ous.extend(
                cast(
                    Sequence[OrganizationalUnitTypeDef],
                    page.get("OrganizationalUnits", []),
                )
            )
    except (ClientError, BotoCoreError) as e:
        raise RuntimeError(f"Failed to list the OUs under {parent_id}: {e}")

    return child_ous


def _list_child_accounts(
    org_client: OrganizationsClient,
    parent_id: str
) -> List[AccountTypeDef]:
    """
    Return every account directly under one parent, across all pages.

    Accounts in every lifecycle state come back, CLOSED and SUSPENDED
    included, which is what lets the snapshot cross-check this view against
    the global `list_accounts` view without misfiring on an organization that
    has closed an account.

    Args:
        org_client: AWS Organizations client
        parent_id: Root or OU ID to list the accounts of

    Returns:
        The parent's direct child accounts

    Raises:
        RuntimeError: If the listing fails at any page
    """
    child_accounts: List[AccountTypeDef] = []

    try:
        for page in paginate(org_client, "list_accounts_for_parent", ParentId=parent_id):
            child_accounts.extend(
                cast(Sequence[AccountTypeDef], page.get("Accounts", []))
            )
    except (ClientError, BotoCoreError) as e:
        raise RuntimeError(f"Failed to list the accounts under {parent_id}: {e}")

    return child_accounts


# A parent still to expand: its ID, its own name (None for the root, which
# gets no OrganizationalUnit entry), the ID its children record as their
# parent OU, and the path from the root down to and including it.
_PendingParent = Tuple[str, Optional[str], Optional[str], List[str]]


def build_organization_hierarchy(
    org_client: OrganizationsClient,
    root_id: str
) -> OrganizationHierarchy:
    """
    Walk the organization once, reading each parent's children exactly once.

    A breadth-first worklist replaces the previous recursion, which listed
    every OU's children twice -- once entering the recursive call, once again
    to fill `child_ous` -- and read only the first page of each listing.

    Every account is retained whatever its lifecycle state, and whether or not
    it is skipped by configuration. Placement is driven by the results that
    exist on disk, and a result written before an account closed must still
    resolve to a placement.

    Two invariants abort rather than resolving quietly, because both mean the
    organization changed while it was being read and neither has a safe
    reading:

    - An account under two parents. Organizations gives an account one parent,
      so seeing two means it moved between pages. The accounts dict would keep
      whichever placement was written last, which is page order deciding where
      a policy lands.
    - A parent reached twice. The same cause one level up, and left alone it
      is unbounded recursion rather than a wrong answer.

    Args:
        org_client: AWS Organizations client
        root_id: The organization root, from `find_organization_root`

    Returns:
        The complete hierarchy: root ID, every OU, every account placement

    Raises:
        RuntimeError: If a listing fails, or if the organization is observed
            to change during the traversal
    """
    organizational_units: Dict[str, OrganizationalUnit] = {}
    accounts: Dict[str, AccountOrgPlacement] = {}
    visited: Set[str] = set()

    queue: Deque[_PendingParent] = deque([(root_id, None, None, [])])

    while queue:
        parent_id, ou_name, parent_ou_id, path = queue.popleft()

        if parent_id in visited:
            raise RuntimeError(
                f"Organizational unit {parent_id} was reached more than once while "
                "walking the organization. Organizations gives an OU one parent, so "
                "the organization was modified during discovery. Re-run Headroom."
            )
        visited.add(parent_id)

        child_ous = _list_child_ous(org_client, parent_id)
        child_accounts = _list_child_accounts(org_client, parent_id)

        # A top-level OU and a root-parented account both record no parent OU:
        # neither can be targeted by an OU-level policy, and the root ID is not
        # a substitute for one.
        child_parent_ou_id = None if parent_id == root_id else parent_id
        child_ou_path = ["Root"] if parent_id == root_id else list(path)

        for account in child_accounts:
            account_id = account["Id"]
            if account_id in accounts:
                raise RuntimeError(
                    f"Account {account_id} appears under more than one parent: "
                    f"{accounts[account_id].parent_ou_id or root_id} and {parent_id}. "
                    "The organization was modified during discovery. Re-run Headroom."
                )
            accounts[account_id] = AccountOrgPlacement(
                account_id=account_id,
                account_name=account["Name"],
                parent_ou_id=child_parent_ou_id,
                ou_path=child_ou_path,
            )

        if ou_name is not None:
            organizational_units[parent_id] = OrganizationalUnit(
                ou_id=parent_id,
                name=ou_name,
                parent_ou_id=parent_ou_id,
                child_ous=[child_ou["Id"] for child_ou in child_ous],
                accounts=[account["Id"] for account in child_accounts],
            )

        for child_ou in child_ous:
            queue.append((
                child_ou["Id"],
                child_ou["Name"],
                child_parent_ou_id,
                path + [child_ou["Name"]],
            ))

    return OrganizationHierarchy(
        root_id=root_id,
        organizational_units=organizational_units,
        accounts=accounts,
    )


def find_organization_root(org_client: OrganizationsClient) -> str:
    """
    Return the organization's single root ID.

    `list_roots` paginates. An organization has one root today, but the
    paginator is free to split any listing, so reading page one alone
    reported "No roots found" for a root that arrived on page two.

    Two roots abort rather than resolving to the first. Which root came first
    is page order, and picking one would traverse half the organization while
    reporting a complete hierarchy -- placement would then recommend
    account-level policies for accounts whose OU it never saw.

    Args:
        org_client: AWS Organizations client

    Returns:
        The organization root ID, such as `r-1111`

    Raises:
        RuntimeError: If the listing fails, or reports no root or several
    """
    roots: List[RootTypeDef] = []

    try:
        for page in paginate(org_client, "list_roots"):
            roots.extend(cast(Sequence[RootTypeDef], page.get("Roots", [])))
    except (ClientError, BotoCoreError) as e:
        raise RuntimeError(f"Failed to get organization root: {e}")

    if not roots:
        raise RuntimeError("No roots found in organization")

    if len(roots) > 1:
        listed = ", ".join(sorted(root["Id"] for root in roots))
        raise RuntimeError(
            f"Organizations reported {len(roots)} roots: {listed}. Headroom "
            "traverses one root, and choosing among them by page order would "
            "report a complete hierarchy after seeing part of the organization."
        )

    root_id = roots[0]["Id"]
    logger.info(f"Found organization root: {root_id}")
    return root_id


def analyze_organization_structure(session: Session) -> OrganizationHierarchy:
    """Analyze AWS Organizations structure. Superseded by `discover_organization`."""
    org_client: OrganizationsClient = session.client("organizations")
    return build_organization_hierarchy(org_client, find_organization_root(org_client))


def create_account_ou_mapping(session: Session) -> Dict[str, Optional[str]]:
    """
    Create mapping of account IDs to their direct parent OU IDs.

    Returns dictionary with account_id -> parent_ou_id relationships.

    parent_ou_id is None for accounts attached directly to the organization root.
    """
    hierarchy = analyze_organization_structure(session)
    mapping: Dict[str, Optional[str]] = {}

    for account_id, account_info in hierarchy.accounts.items():
        mapping[account_id] = account_info.parent_ou_id

    return mapping


def _format_account_candidates(candidates: List[Tuple[str, str]]) -> str:
    """
    Render account candidates as a readable list for error messages.

    Args:
        candidates: List of (account_id, account_name) pairs

    Returns:
        Comma-separated string, e.g. "111111111111 ('Prod'), 222222222222 ('prod')"
    """
    return ", ".join(f"{acc_id} ('{name}')" for acc_id, name in sorted(candidates))


def lookup_account_id_by_name(
    account_name: str,
    organization_hierarchy: OrganizationHierarchy,
    context: str = "result file"
) -> str:
    """
    Look up account ID by name in organization hierarchy.

    Matches the name exactly first. Result files are written under the name
    configured by use_account_name_from_tags, which can be a slug such as
    "management-account" where Organizations reports "Management Account", so a
    name that matches nothing exactly falls back to comparing names with case
    and separators ignored. The fallback resolves only when exactly one account
    matches; anything else aborts rather than attribute results to a guess.

    Args:
        account_name: Account name to look up
        organization_hierarchy: Organization structure containing accounts
        context: Context string for error message (e.g., "result file", "check processing")

    Returns:
        Account ID of the single account matching the account name

    Raises:
        RuntimeError: If the account name matches no account, or matches more
            than one (Organizations enforces uniqueness on account email, not
            on account name)
    """
    exact_matches = [
        (acc_id, acc_info.account_name)
        for acc_id, acc_info in organization_hierarchy.accounts.items()
        if acc_info.account_name == account_name
    ]

    if len(exact_matches) == 1:
        acc_id = exact_matches[0][0]
        logger.info(f"Looked up account_id {acc_id} for account name '{account_name}'")
        return acc_id

    if exact_matches:
        raise RuntimeError(
            f"Account name '{account_name}' from {context} matches multiple accounts "
            f"in the organization hierarchy: {_format_account_candidates(exact_matches)}"
        )

    # A name of only separators canonicalizes to "", which would otherwise
    # match every other such name, so it is left unresolved.
    canonical_name = make_safe_variable_name(account_name)
    canonical_matches: List[Tuple[str, str]] = []
    if canonical_name:
        canonical_matches = [
            (acc_id, acc_info.account_name)
            for acc_id, acc_info in organization_hierarchy.accounts.items()
            if make_safe_variable_name(acc_info.account_name) == canonical_name
        ]

    if len(canonical_matches) == 1:
        acc_id, matched_name = canonical_matches[0]
        logger.warning(
            f"Account name '{account_name}' from {context} does not match any "
            f"account name in the organization hierarchy exactly; resolved to "
            f"account_id {acc_id} ('{matched_name}') by ignoring case and separators"
        )
        return acc_id

    if canonical_matches:
        raise RuntimeError(
            f"Account name '{account_name}' from {context} matches multiple accounts "
            f"in the organization hierarchy when ignoring case and separators: "
            f"{_format_account_candidates(canonical_matches)}"
        )

    raise RuntimeError(
        f"Account name '{account_name}' from {context} not found in organization hierarchy"
    )
