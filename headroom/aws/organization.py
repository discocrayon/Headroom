"""
AWS Organizations analysis module.

This module contains functions for analyzing AWS Organizations structure
using the AWS Organizations API.
"""

import logging
from typing import Any, Dict, List, Optional

import boto3  # type: ignore

from ..types import OrganizationHierarchy, OrganizationalUnit, AccountOrgPlacement

# Set up logging
logger = logging.getLogger(__name__)


def _build_ou_hierarchy(
    org_client: Any,
    root_id: str,
    organizational_units: Dict[str, OrganizationalUnit],
    accounts: Dict[str, AccountOrgPlacement],
    parent_ou_id: Optional[str] = None,
    ou_path: Optional[List[str]] = None
) -> None:
    """
    Recursively build OU hierarchy starting from parent_ou_id.

    Args:
        org_client: AWS Organizations client
        root_id: Organization root ID
        organizational_units: Dictionary to store OU information
        accounts: Dictionary to store account information
        parent_ou_id: Parent OU ID to start from
        ou_path: Current OU path from root
    """
    if ou_path is None:
        ou_path = []

    try:
        # List OUs under this parent
        if parent_ou_id:
            ous_response = org_client.list_organizational_units_for_parent(
                ParentId=parent_ou_id
            )
        else:
            ous_response = org_client.list_organizational_units_for_parent(
                ParentId=root_id
            )

        for ou in ous_response.get("OrganizationalUnits", []):
            ou_id = ou["Id"]
            ou_name = ou["Name"]
            current_path = ou_path + [ou_name]

            # Get child OUs
            child_ous = []
            _build_ou_hierarchy(org_client, root_id, organizational_units, accounts, ou_id, current_path)

            # Get accounts in this OU
            try:
                accounts_response = org_client.list_accounts_for_parent(
                    ParentId=ou_id
                )
                account_ids = [acc["Id"] for acc in accounts_response.get("Accounts", [])]

                # Store account information
                for acc in accounts_response.get("Accounts", []):
                    accounts[acc["Id"]] = AccountOrgPlacement(
                        account_id=acc["Id"],
                        account_name=acc["Name"],
                        parent_ou_id=ou_id,
                        ou_path=current_path
                    )

                # Get child OUs for this OU
                child_ous_response = org_client.list_organizational_units_for_parent(
                    ParentId=ou_id
                )
                child_ous = [child_ou["Id"] for child_ou in child_ous_response.get("OrganizationalUnits", [])]

            except Exception as e:
                logger.warning(f"Failed to get accounts/child OUs for OU {ou_id}: {e}")
                account_ids = []

            organizational_units[ou_id] = OrganizationalUnit(
                ou_id=ou_id,
                name=ou_name,
                parent_ou_id=parent_ou_id,
                child_ous=child_ous,
                accounts=account_ids
            )

    except Exception as e:
        logger.warning(f"Failed to list OUs for parent {parent_ou_id}: {e}")


def analyze_organization_structure(session: boto3.Session) -> OrganizationHierarchy:
    """
    Analyze AWS Organizations structure including root, OUs, and account relationships.

    Returns comprehensive hierarchy mapping.
    """
    org_client = session.client("organizations")

    # Get root information
    try:
        roots_response = org_client.list_roots()
        if not roots_response.get("Roots"):
            raise RuntimeError("No roots found in organization")
        root_id = roots_response["Roots"][0]["Id"]
        logger.info(f"Found organization root: {root_id}")
    except Exception as e:
        raise RuntimeError(f"Failed to get organization root: {e}")

    # Build OU hierarchy recursively
    organizational_units: Dict[str, OrganizationalUnit] = {}
    accounts: Dict[str, AccountOrgPlacement] = {}

    # Build hierarchy starting from root
    _build_ou_hierarchy(org_client, root_id, organizational_units, accounts)

    # Get accounts directly under root
    try:
        root_accounts_response = org_client.list_accounts_for_parent(
            ParentId=root_id
        )
        for acc in root_accounts_response.get("Accounts", []):
            accounts[acc["Id"]] = AccountOrgPlacement(
                account_id=acc["Id"],
                account_name=acc["Name"],
                parent_ou_id=root_id,
                ou_path=["Root"]
            )
    except Exception as e:
        logger.warning(f"Failed to get accounts under root: {e}")

    return OrganizationHierarchy(
        root_id=root_id,
        organizational_units=organizational_units,
        accounts=accounts
    )


def create_account_ou_mapping(session: boto3.Session) -> Dict[str, str]:
    """
    Create mapping of account IDs to their direct parent OU IDs.

    Returns dictionary with account_id -> parent_ou_id relationships.
    """
    hierarchy = analyze_organization_structure(session)
    mapping: Dict[str, str] = {}

    for account_id, account_info in hierarchy.accounts.items():
        mapping[account_id] = account_info.parent_ou_id

    return mapping
