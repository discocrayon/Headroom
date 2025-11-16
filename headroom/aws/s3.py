"""
AWS S3 bucket policy analysis.

This module contains functions for analyzing S3 buckets and their resource policies,
specifically for identifying third-party account access (RCP checks).
"""

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Set

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_s3.client import S3Client

from ..constants import AWS_ARN_ACCOUNT_ID_PATTERN, BASE_PRINCIPAL_TYPES

logger = logging.getLogger(__name__)


class UnknownPrincipalTypeError(Exception):
    """Raised when an unknown principal type is encountered in a bucket policy."""


class UnsupportedPrincipalTypeError(Exception):
    """
    Raised when a bucket policy contains principal types that can't be handled by RCP.

    Federated and CanonicalUser principals don't have account IDs, so the RCP
    (which uses aws:PrincipalAccount for allowlisting) would break their access.
    """


# S3 bucket policies support CanonicalUser in addition to base types
# Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-bucket-user-policy-specifying-principal-intro.html
ALLOWED_PRINCIPAL_TYPES = BASE_PRINCIPAL_TYPES | {"CanonicalUser"}


@dataclass
class S3BucketPolicyAnalysis:
    """
    Analysis of an S3 bucket's resource policy.

    Attributes:
        bucket_name: Name of the S3 bucket
        bucket_arn: ARN of the S3 bucket
        third_party_account_ids: Set of account IDs not in the organization
        has_wildcard_principal: True if policy contains wildcard principals
        has_non_account_principals: True if policy has Federated/CanonicalUser principals
        actions_by_account: Dict mapping account IDs to sets of allowed actions
    """
    bucket_name: str
    bucket_arn: str
    third_party_account_ids: Set[str]
    has_wildcard_principal: bool
    has_non_account_principals: bool
    actions_by_account: Dict[str, Set[str]]


def _extract_account_ids_from_principal(principal: Any) -> Set[str]:
    """
    Extract AWS account IDs from an S3 policy principal.

    Args:
        principal: Principal field from S3 policy statement (can be string, list, or dict)

    Returns:
        Set of extracted account IDs (12-digit strings)
    """
    account_ids: Set[str] = set()

    if isinstance(principal, str):
        if principal == "*":
            return set()
        arn_match = re.match(AWS_ARN_ACCOUNT_ID_PATTERN, principal)
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


def _has_wildcard_principal(principal: Any) -> bool:
    """
    Check if principal contains a wildcard.

    Args:
        principal: Principal field from S3 policy statement

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


def _has_non_account_principals(principal: Any) -> bool:
    """
    Check if principal contains Federated or CanonicalUser types.

    These principal types cannot be represented as account IDs, so an RCP that
    uses aws:PrincipalAccount for allowlisting would break their access.

    Args:
        principal: Principal field from S3 policy statement

    Returns:
        True if principal contains Federated or CanonicalUser types
    """
    if isinstance(principal, dict):
        # Check if any non-account-based principal types are present
        return "Federated" in principal or "CanonicalUser" in principal
    return False


def _normalize_actions(action: Any) -> Set[str]:
    """
    Normalize action field to a set of action strings.

    Args:
        action: Action field from policy statement (can be string or list)

    Returns:
        Set of action strings
    """
    if isinstance(action, str):
        return {action}
    elif isinstance(action, list):
        return set(action)
    return set()


def analyze_s3_bucket_policies(
    session: Session,
    org_account_ids: Set[str]
) -> List[S3BucketPolicyAnalysis]:
    """
    Analyze all S3 bucket policies and identify third-party account principals.

    Examines the resource policy (bucket policy) of each S3 bucket
    and identifies account IDs that are not part of the organization.

    Algorithm:
    1. List all S3 buckets via list_buckets()
    2. For each bucket:
       a. Get bucket policy via get_bucket_policy()
       b. Parse policy JSON
       c. Extract AWS principals from statements
       d. Identify third-party accounts (not in org)
       e. Track which actions each third-party account can perform
    3. Return analysis results for buckets with third-party access

    Args:
        session: boto3 Session for the target account
        org_account_ids: Set of all account IDs in the organization

    Returns:
        List of S3BucketPolicyAnalysis for buckets with third-party accounts or wildcards
    """
    s3_client: S3Client = session.client("s3")
    results: List[S3BucketPolicyAnalysis] = []

    try:
        response = s3_client.list_buckets()
        buckets = response.get("Buckets", [])
    except ClientError as e:
        logger.error(f"Failed to list S3 buckets from AWS API: {e}")
        raise

    for bucket in buckets:
        bucket_name = bucket["Name"]
        bucket_arn = f"arn:aws:s3:::{bucket_name}"

        try:
            policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_str = policy_response["Policy"]
            policy = json.loads(policy_str)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                logger.debug(f"Bucket '{bucket_name}' has no bucket policy, skipping")
                continue
            else:
                logger.error(f"Failed to get bucket policy for '{bucket_name}': {e}")
                raise

        third_party_accounts: Set[str] = set()
        has_wildcard = False
        has_non_account_principals = False
        actions_by_account: Dict[str, Set[str]] = {}

        for statement in policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue

            principal = statement.get("Principal")
            if not principal:
                continue

            if _has_wildcard_principal(principal):
                has_wildcard = True

            if _has_non_account_principals(principal):
                has_non_account_principals = True

            account_ids = _extract_account_ids_from_principal(principal)
            actions = _normalize_actions(statement.get("Action", []))

            for account_id in account_ids:
                if account_id not in org_account_ids:
                    third_party_accounts.add(account_id)
                    if account_id not in actions_by_account:
                        actions_by_account[account_id] = set()
                    actions_by_account[account_id].update(actions)

        if third_party_accounts or has_wildcard or has_non_account_principals:
            results.append(S3BucketPolicyAnalysis(
                bucket_name=bucket_name,
                bucket_arn=bucket_arn,
                third_party_account_ids=third_party_accounts,
                has_wildcard_principal=has_wildcard,
                has_non_account_principals=has_non_account_principals,
                actions_by_account=actions_by_account
            ))

    return results
