"""
AWS KMS key policy analysis.

This module contains functions for analyzing KMS key policies,
specifically for identifying third-party account access (RCP checks).
"""

import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_kms.client import KMSClient
from mypy_boto3_kms.type_defs import KeyListEntryTypeDef

from .helpers import get_all_regions, paginate

logger = logging.getLogger(__name__)


class UnknownPrincipalTypeError(Exception):
    """Raised when an unknown principal type is encountered in a key policy."""


class UnsupportedPrincipalTypeError(Exception):
    """
    Raised when a principal type would break RCP deployment.

    This includes Federated principals or other types that the RCP cannot handle.
    """


ALLOWED_PRINCIPAL_TYPES = {"AWS", "Service"}
FAIL_FAST_PRINCIPAL_TYPES = {"Federated"}


@dataclass
class KMSKeyPolicyAnalysis:
    """
    Analysis of a KMS key's resource policy.

    Attributes:
        key_id: KMS key ID
        key_arn: ARN of the KMS key
        region: AWS region where key exists
        third_party_account_ids: Set of account IDs not in the organization
        actions_by_account: Mapping of account ID to list of KMS actions allowed
        has_wildcard_principal: True if policy contains wildcard principals
    """
    key_id: str
    key_arn: str
    region: str
    third_party_account_ids: Set[str]
    actions_by_account: Dict[str, List[str]] = field(default_factory=dict)
    has_wildcard_principal: bool = False


def _extract_account_ids_from_principal(principal: Any) -> Set[str]:
    """
    Extract AWS account IDs from a KMS policy principal.

    Args:
        principal: Principal field from policy statement (can be string, list, or dict)

    Returns:
        Set of extracted account IDs (12-digit strings)

    Raises:
        UnknownPrincipalTypeError: If an unknown principal type is encountered
        UnsupportedPrincipalTypeError: If a principal type would break RCP deployment
    """
    account_ids: Set[str] = set()

    if isinstance(principal, str):
        if principal == "*":
            return set()
        arn_match = re.match(r'^arn:aws:iam::(\d{12}):', principal)
        if arn_match:
            account_ids.add(arn_match.group(1))
        else:
            if re.match(r'^\d{12}$', principal):
                account_ids.add(principal)
    elif isinstance(principal, list):
        for item in principal:
            account_ids.update(_extract_account_ids_from_principal(item))
    elif isinstance(principal, dict):
        unknown_types = set(principal.keys()) - ALLOWED_PRINCIPAL_TYPES - FAIL_FAST_PRINCIPAL_TYPES
        if unknown_types:
            raise UnknownPrincipalTypeError(
                f"Unknown principal type(s) found in KMS policy: {unknown_types}. "
                f"Expected one of: {ALLOWED_PRINCIPAL_TYPES}"
            )

        fail_fast_types = set(principal.keys()) & FAIL_FAST_PRINCIPAL_TYPES
        if fail_fast_types:
            raise UnsupportedPrincipalTypeError(
                f"KMS key policy contains {fail_fast_types} principal type(s). "
                f"These principal types would break if the RCP is deployed because the RCP "
                f"restricts based on aws:PrincipalAccount, which does not apply to {fail_fast_types} principals. "
                f"Remove these principals from the KMS policy before deploying the RCP."
            )

        if "AWS" in principal:
            value = principal["AWS"]
            if isinstance(value, str):
                account_ids.update(_extract_account_ids_from_principal(value))
            elif isinstance(value, list):
                for item in value:
                    account_ids.update(_extract_account_ids_from_principal(item))

    return account_ids


def _has_wildcard_principal(principal: Any) -> bool:
    """
    Check if principal contains a wildcard.

    Args:
        principal: Principal field from policy statement

    Returns:
        True if principal contains wildcard
    """
    if isinstance(principal, str):
        return principal == "*"
    elif isinstance(principal, list):
        return any(_has_wildcard_principal(item) for item in principal)
    elif isinstance(principal, dict):
        for key, value in principal.items():
            if key == "AWS":
                if isinstance(value, str) and value == "*":
                    return True
                if isinstance(value, list) and any(item == "*" for item in value):
                    return True
    return False


def _normalize_actions(action: Any) -> List[str]:
    """
    Normalize action field to list of strings.

    Args:
        action: Action field from policy statement (can be string or list)

    Returns:
        List of action strings
    """
    if isinstance(action, str):
        return [action]
    elif isinstance(action, list):
        return action
    return []


def _analyze_key_in_region(
    kms_client: KMSClient,
    key: KeyListEntryTypeDef,
    region: str,
    org_account_ids: Set[str]
) -> KMSKeyPolicyAnalysis:
    """
    Analyze a single KMS key's policy.

    Args:
        kms_client: Boto3 KMS client
        key: Key dict from list_keys
        region: AWS region
        org_account_ids: Set of all account IDs in the organization

    Returns:
        KMSKeyPolicyAnalysis result for this key

    Raises:
        UnsupportedPrincipalTypeError: If policy contains principals that would break RCP
    """
    key_id = key["KeyId"]
    key_arn = key["KeyArn"]

    third_party_accounts: Set[str] = set()
    actions_by_account: defaultdict[str, Set[str]] = defaultdict(set)
    has_wildcard = False

    try:
        response = kms_client.get_key_policy(KeyId=key_id, PolicyName="default")
        policy_text = response.get("Policy", "{}")
        policy = json.loads(policy_text)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "NotFoundException":
            logger.debug(f"No policy found for key {key_id} in {region}")
            return KMSKeyPolicyAnalysis(
                key_id=key_id,
                key_arn=key_arn,
                region=region,
                third_party_account_ids=set(),
                actions_by_account={},
                has_wildcard_principal=False
            )
        raise

    for statement in policy.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal")
        if not principal:
            continue

        if _has_wildcard_principal(principal):
            has_wildcard = True

        account_ids = _extract_account_ids_from_principal(principal)

        actions = _normalize_actions(statement.get("Action", []))

        for account_id in account_ids:
            if account_id in org_account_ids:
                continue

            third_party_accounts.add(account_id)
            actions_by_account[account_id].update(actions)

    actions_by_account_serializable = {
        account_id: sorted(actions)
        for account_id, actions in actions_by_account.items()
    }

    return KMSKeyPolicyAnalysis(
        key_id=key_id,
        key_arn=key_arn,
        region=region,
        third_party_account_ids=third_party_accounts,
        actions_by_account=actions_by_account_serializable,
        has_wildcard_principal=has_wildcard
    )


def analyze_kms_key_policies(
    session: Session,
    org_account_ids: Set[str]
) -> List[KMSKeyPolicyAnalysis]:
    """
    Analyze all KMS keys in an account for third-party access.

    Examines the resource policy of each KMS key and identifies
    account IDs that are not part of the organization.

    Algorithm:
    1. Get all enabled regions via describe_regions()
    2. For each region:
       a. List all keys via list_keys() (paginated)
       b. Get key policy via get_key_policy()
       c. Parse policy JSON
       d. Extract principals and actions
       e. Identify third-party account IDs (not in org)
       f. Track which actions each third-party account can perform
       g. Detect wildcard principals
    3. Return all results across all regions

    Args:
        session: boto3 Session for the target account
        org_account_ids: Set of all account IDs in the organization

    Returns:
        List of KMSKeyPolicyAnalysis for keys with third-party
        access or wildcards

    Raises:
        ClientError: If AWS API calls fail
        UnsupportedPrincipalTypeError: If any key policy contains principal
            types that would break RCP deployment (like Federated)
    """
    results: List[KMSKeyPolicyAnalysis] = []

    regions = get_all_regions(session)

    for region in regions:
        logger.info(f"Analyzing KMS keys in {region}")
        kms_client: KMSClient = session.client("kms", region_name=region)

        try:
            for page in paginate(kms_client, "list_keys"):
                for key in page.get("Keys", []):
                    analysis = _analyze_key_in_region(
                        kms_client,
                        key,
                        region,
                        org_account_ids
                    )

                    if analysis.third_party_account_ids or analysis.has_wildcard_principal:
                        results.append(analysis)

        except ClientError as e:
            logger.error(f"Failed to analyze KMS in region {region}: {e}")
            raise

    logger.info(
        f"Analyzed KMS keys across {len(regions)} regions, "
        f"found {len(results)} keys with third-party access or wildcards"
    )
    return results
