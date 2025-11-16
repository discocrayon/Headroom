"""
AWS Secrets Manager resource policy analysis.

This module contains functions for analyzing Secrets Manager secrets and their
resource policies, specifically for identifying third-party account access (RCP checks).
"""

import json
import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Union

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_secretsmanager.client import SecretsManagerClient

from ..constants import BASE_PRINCIPAL_TYPES
from ..types import JsonDict

logger = logging.getLogger(__name__)


class UnknownPrincipalTypeError(Exception):
    """Raised when an unknown principal type is encountered in a resource policy."""


class UnsupportedPrincipalTypeError(Exception):
    """
    Raised when a resource policy contains principal types that can't be handled by RCP.

    Federated and CanonicalUser principals don't have account IDs, so the RCP
    (which uses aws:PrincipalAccount for allowlisting) would break their access.
    """


ALLOWED_PRINCIPAL_TYPES = BASE_PRINCIPAL_TYPES


@dataclass
class SecretsPolicyAnalysis:
    """
    Analysis of a Secrets Manager secret's resource policy.

    Attributes:
        secret_name: Name of the secret
        secret_arn: ARN of the secret
        third_party_account_ids: Set of account IDs not in the organization
        has_wildcard_principal: True if policy contains wildcard principals
        has_non_account_principals: True if policy has Federated/CanonicalUser principals
        actions_by_account: Dict mapping account IDs to sets of allowed actions
    """
    secret_name: str
    secret_arn: str
    third_party_account_ids: Set[str]
    has_wildcard_principal: bool
    has_non_account_principals: bool
    actions_by_account: Dict[str, Set[str]]


def _extract_account_ids_from_principal(
    principal: Union[str, List[str], Dict[str, Union[str, List[str]]]]
) -> Set[str]:
    """
    Extract AWS account IDs from a Secrets Manager policy principal.

    Args:
        principal: Principal field from policy statement (can be string, list, or dict)

    Returns:
        Set of extracted account IDs (12-digit strings)
    """
    account_ids: Set[str] = set()

    if isinstance(principal, str):
        if principal == "*":
            return set()
        arn_match = re.match(r'^arn:aws:[^:]+:[^:]*:(\d{12}):', principal)
        if arn_match:
            account_ids.add(arn_match.group(1))
        else:
            if re.match(r'^\d{12}$', principal):
                account_ids.add(principal)
    elif isinstance(principal, list):
        for item in principal:
            account_ids.update(_extract_account_ids_from_principal(item))
    elif isinstance(principal, dict):
        unknown_types = set(principal.keys()) - ALLOWED_PRINCIPAL_TYPES
        if unknown_types:
            raise UnknownPrincipalTypeError(
                f"Unknown principal type(s) found: {unknown_types}. "
                f"Expected one of: {ALLOWED_PRINCIPAL_TYPES}"
            )

        if "AWS" in principal:
            value = principal["AWS"]
            if isinstance(value, str):
                account_ids.update(_extract_account_ids_from_principal(value))
            elif isinstance(value, list):
                for item in value:
                    account_ids.update(_extract_account_ids_from_principal(item))

    return account_ids


def _has_wildcard_principal(
    principal: Union[str, List[str], Dict[str, Union[str, List[str]]]]
) -> bool:
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


def _has_non_account_principals(
    principal: Union[str, List[str], Dict[str, Union[str, List[str]]]]
) -> bool:
    """
    Check if principal contains Federated or CanonicalUser types.

    These principal types cannot be represented as account IDs, so an RCP that
    uses aws:PrincipalAccount for allowlisting would break their access.

    Args:
        principal: Principal field from policy statement

    Returns:
        True if principal contains Federated or CanonicalUser types
    """
    if isinstance(principal, dict):
        return "Federated" in principal or "CanonicalUser" in principal
    return False


def _normalize_actions(action: Union[str, List[str]]) -> Set[str]:
    """
    Normalize action field to a set of action strings.

    Args:
        action: Action field from policy statement (can be string or list)

    Returns:
        Set of action strings
    """
    if isinstance(action, str):
        return {action}
    if isinstance(action, list):
        return set(action)
    # Fallback for unexpected types (e.g., dict, None)
    return set()  # type: ignore[unreachable]


def analyze_secrets_manager_policies(
    session: Session,
    org_account_ids: Set[str]
) -> List[SecretsPolicyAnalysis]:
    """
    Analyze all Secrets Manager resource policies and identify third-party account principals.

    Examines the resource policy of each secret and identifies account IDs that are
    not part of the organization.

    Algorithm:
    1. Get all enabled regions via describe_regions()
    2. For each region:
       a. List all secrets via list_secrets() paginator
       b. For each secret, get resource policy via get_resource_policy()
       c. Parse policy JSON
       d. Extract AWS principals from statements
       e. Identify third-party accounts (not in org)
       f. Track which actions each third-party account can perform
    3. Return analysis results for secrets with third-party access

    Args:
        session: boto3 Session for the target account
        org_account_ids: Set of all account IDs in the organization

    Returns:
        List of SecretsPolicyAnalysis for secrets with third-party accounts or wildcards

    Raises:
        ClientError: If AWS API calls fail
        UnsupportedPrincipalTypeError: If policy contains Federated/CanonicalUser principals
    """
    ec2_client = session.client("ec2")
    results: List[SecretsPolicyAnalysis] = []

    regions_response = ec2_client.describe_regions()
    regions = [region["RegionName"] for region in regions_response["Regions"]]

    for region in regions:
        logger.info(f"Analyzing Secrets Manager in {region}")
        regional_results = _analyze_secrets_in_region(session, region, org_account_ids)
        results.extend(regional_results)

    logger.info(
        f"Analyzed {len(results)} Secrets Manager secrets with third-party access "
        f"across {len(regions)} regions"
    )
    return results


def _analyze_secrets_in_region(
    session: Session,
    region: str,
    org_account_ids: Set[str]
) -> List[SecretsPolicyAnalysis]:
    """
    Analyze Secrets Manager secrets in a specific region.

    Args:
        session: boto3 Session for the target account
        region: AWS region to analyze
        org_account_ids: Set of all account IDs in the organization

    Returns:
        List of SecretsPolicyAnalysis results for this region

    Raises:
        ClientError: If AWS API calls fail
        UnsupportedPrincipalTypeError: If policy contains Federated/CanonicalUser principals
    """
    sm_client: SecretsManagerClient = session.client("secretsmanager", region_name=region)
    results: List[SecretsPolicyAnalysis] = []

    try:
        paginator = sm_client.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                secret_name = secret["Name"]
                secret_arn = secret["ARN"]

                try:
                    policy_response = sm_client.get_resource_policy(SecretId=secret_arn)
                    policy_str = policy_response.get("ResourcePolicy")
                    if not policy_str:
                        logger.debug(f"Secret '{secret_name}' has no resource policy, skipping")
                        continue
                    policy = json.loads(policy_str)
                except ClientError as e:
                    if e.response["Error"]["Code"] == "ResourceNotFoundException":
                        logger.debug(f"Secret '{secret_name}' has no resource policy, skipping")
                        continue
                    else:
                        logger.error(f"Failed to get resource policy for secret '{secret_name}': {e}")
                        raise

                analysis_result = _analyze_secret_policy(
                    secret_name,
                    secret_arn,
                    policy,
                    org_account_ids
                )

                if analysis_result:
                    results.append(analysis_result)

    except ClientError as e:
        logger.error(f"Failed to list secrets in region {region}: {e}")
        raise

    return results


def _analyze_secret_policy(
    secret_name: str,
    secret_arn: str,
    policy: JsonDict,
    org_account_ids: Set[str]
) -> Optional[SecretsPolicyAnalysis]:
    """
    Analyze a single secret's resource policy.

    Args:
        secret_name: Name of the secret
        secret_arn: ARN of the secret
        policy: Parsed policy JSON
        org_account_ids: Set of all account IDs in the organization

    Returns:
        SecretsPolicyAnalysis if secret has third-party access, None otherwise

    Raises:
        UnsupportedPrincipalTypeError: If policy contains Federated/CanonicalUser principals
    """
    third_party_accounts: Set[str] = set()
    has_wildcard = False
    has_non_account_principals = False
    actions_by_account: Dict[str, Set[str]] = {}

    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = []
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal")
        if not principal:
            continue

        if _has_wildcard_principal(principal):
            has_wildcard = True

        if _has_non_account_principals(principal):
            has_non_account_principals = True
            raise UnsupportedPrincipalTypeError(
                f"Secret '{secret_name}' has Federated or CanonicalUser principal in resource policy. "
                f"RCP deployment would break this access. Secret ARN: {secret_arn}"
            )

        account_ids = _extract_account_ids_from_principal(principal)
        actions = _normalize_actions(statement.get("Action", []))

        for account_id in account_ids:
            if account_id not in org_account_ids:
                third_party_accounts.add(account_id)
                if account_id not in actions_by_account:
                    actions_by_account[account_id] = set()
                actions_by_account[account_id].update(actions)

    if third_party_accounts or has_wildcard or has_non_account_principals:
        return SecretsPolicyAnalysis(
            secret_name=secret_name,
            secret_arn=secret_arn,
            third_party_account_ids=third_party_accounts,
            has_wildcard_principal=has_wildcard,
            has_non_account_principals=has_non_account_principals,
            actions_by_account=actions_by_account
        )

    return None
