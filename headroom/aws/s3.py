"""
AWS S3 bucket access analysis.

This module contains functions for analyzing S3 buckets and the two surfaces
that authorize access to them - the bucket policy and the bucket ACL -
specifically for identifying third-party account access (RCP checks).
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, NamedTuple, Optional, Set

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_s3.client import S3Client

from ..constants import AWS_ARN_ACCOUNT_ID_PATTERN, BASE_PRINCIPAL_TYPES
from ..types import JsonDict
from .policy_documents import (
    ServicePrincipalSource,
    has_actionable_service_principal_source,
    has_not_principal,
    normalize_statements,
    read_service_principal_sources,
)

logger = logging.getLogger(__name__)


class UnknownPrincipalTypeError(Exception):
    """Raised when an unknown principal type is encountered in a bucket policy."""


class UnsupportedPrincipalTypeError(Exception):
    """
    Raised when a bucket policy contains principal types that can't be handled by RCP.

    Federated and CanonicalUser principals don't have account IDs, so the RCP
    (which uses aws:PrincipalAccount for allowlisting) would break their access.
    """


class UnknownGranteeTypeError(Exception):
    """Raised when an unknown grantee type or group is encountered in a bucket ACL."""


# S3 bucket policies support CanonicalUser in addition to base types
# Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-bucket-user-policy-specifying-principal-intro.html
ALLOWED_PRINCIPAL_TYPES = BASE_PRINCIPAL_TYPES | {"CanonicalUser"}

# ACL grantee groups, which name an audience rather than an account.
# Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html
ALL_USERS_GROUP_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHENTICATED_USERS_GROUP_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
PUBLIC_ACL_GROUP_URIS = frozenset({ALL_USERS_GROUP_URI, AUTHENTICATED_USERS_GROUP_URI})

# Granting this group by ACL and granting `logging.s3.amazonaws.com` by bucket
# policy authorize the same principal - AWS documents the ACL form as "grant
# permissions to the logging service principal by using a bucket ACL". The RCP
# spares AWS services, so the grant reaches nobody the RCP would deny.
# Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html
LOG_DELIVERY_GROUP_URI = "http://acs.amazonaws.com/groups/s3/LogDelivery"


class AclGrantFindings(NamedTuple):
    """
    What a bucket ACL's grants amount to for RCP purposes.

    Attributes:
        has_wildcard_grantee: True if the ACL grants to a public group, whose
            members the analyzer cannot enumerate
        has_non_account_grantee: True if the ACL grants to a canonical user or
            an email address, neither of which resolves to an account ID
    """
    has_wildcard_grantee: bool
    has_non_account_grantee: bool


@dataclass
class S3BucketPolicyAnalysis:
    """
    Analysis of an S3 bucket's resource policy and ACL.

    Attributes:
        bucket_name: Name of the S3 bucket
        bucket_arn: ARN of the S3 bucket
        third_party_account_ids: Set of account IDs not in the organization.
            Only the policy contributes: an ACL names canonical user IDs,
            which no API resolves to an account ID
        has_wildcard_principal: True if the bucket grants to principals the
            analyzer cannot enumerate - `Principal: "*"`, an Allow with
            NotPrincipal, which reaches everyone it does not name, or an ACL
            grant to a public group
        has_non_account_principals: True if the policy names a Federated or
            CanonicalUser principal, or the ACL grants to a canonical user
            other than the bucket owner, or to an email address
        actions_by_account: Dict mapping account IDs to sets of allowed
            actions. Only the policy contributes: ACL permissions are not IAM
            actions, and an ACL grantee never reaches the allowlist
        service_principal_sources: Service principals this policy trusts,
            with the cross-service source guard on each. Read by the
            deny_service_confused_deputy check; contributes nothing to this
            analysis's own third-party accounts or wildcard flag.
    """
    bucket_name: str
    bucket_arn: str
    third_party_account_ids: Set[str]
    has_wildcard_principal: bool
    has_non_account_principals: bool
    actions_by_account: Dict[str, Set[str]]
    service_principal_sources: List[ServicePrincipalSource] = field(default_factory=list)


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


def _analyze_bucket_acl(s3_client: S3Client, bucket_name: str) -> AclGrantFindings:
    """
    Read a bucket's ACL and report what its grants reach.

    A bucket ACL authorizes principals independently of the bucket policy, so
    a bucket whose policy names nobody can still be shared. The RCP denies
    every principal outside the organization however the bucket authorized
    them, which makes an unread ACL a grant that breaks on apply with nothing
    in the scan to warn of it.

    ACL grantees carry canonical user IDs rather than account IDs, and no API
    resolves one to the other, so an external grantee cannot be expressed in
    the allowlist and has to keep the account out of the RCP instead.

    A bucket whose Object Ownership is BucketOwnerEnforced has ACLs disabled;
    reads still succeed and return the owner's grant alone, so that case needs
    no separate lookup.

    Args:
        s3_client: boto3 S3 client for the target account
        bucket_name: Name of the bucket to read

    Returns:
        AclGrantFindings recording what the ACL's grants reach

    Raises:
        ClientError: If the ACL cannot be read
        UnknownGranteeTypeError: If a grantee's type or group is unrecognized
    """
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
    except ClientError as e:
        logger.error(f"Failed to get bucket ACL for '{bucket_name}': {e}")
        raise

    owner_id = acl.get("Owner", {}).get("ID")
    has_wildcard = False
    has_non_account = False

    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        grantee_type = grantee.get("Type")

        if grantee_type == "CanonicalUser":
            # Every bucket grants its own owner, which shares nothing
            if grantee.get("ID") != owner_id:
                has_non_account = True
        elif grantee_type == "AmazonCustomerByEmail":
            has_non_account = True
        elif grantee_type == "Group":
            uri = grantee.get("URI")
            if uri in PUBLIC_ACL_GROUP_URIS:
                has_wildcard = True
            elif uri != LOG_DELIVERY_GROUP_URI:
                raise UnknownGranteeTypeError(
                    f"Bucket '{bucket_name}' has an ACL grant to unrecognized "
                    f"group '{uri}'. Whether it reaches outside the "
                    f"organization cannot be determined."
                )
        else:
            raise UnknownGranteeTypeError(
                f"Bucket '{bucket_name}' has an ACL grant to unrecognized "
                f"grantee type '{grantee_type}'. Whether it reaches outside "
                f"the organization cannot be determined."
            )

    return AclGrantFindings(
        has_wildcard_grantee=has_wildcard,
        has_non_account_grantee=has_non_account,
    )


def _read_bucket_policy(s3_client: S3Client, bucket_name: str) -> Optional[JsonDict]:
    """
    Read a bucket's policy, or report that it carries none.

    A bucket with no policy is not a bucket with nothing to find: its ACL can
    still grant access, so the caller carries on to that rather than
    abandoning the bucket here.

    Args:
        s3_client: boto3 S3 client for the target account
        bucket_name: Name of the bucket to read

    Returns:
        The parsed policy document, or None if the bucket carries no policy

    Raises:
        ClientError: If the policy cannot be read for any other reason
    """
    try:
        policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            logger.debug(f"Bucket '{bucket_name}' has no bucket policy")
            return None
        logger.error(f"Failed to get bucket policy for '{bucket_name}': {e}")
        raise

    policy: JsonDict = json.loads(policy_response["Policy"])
    return policy


def analyze_s3_bucket_policies(
    session: Session,
    org_account_ids: Set[str]
) -> List[S3BucketPolicyAnalysis]:
    """
    Analyze all S3 bucket policies and ACLs for third-party access.

    Examines both surfaces that authorize access to a bucket - its resource
    policy and its ACL - and identifies principals that are not part of the
    organization. The RCP denies every principal outside the organization
    however the bucket authorized them, so a surface left unread is a grant
    that breaks on apply with nothing in the scan to warn of it.

    Algorithm:
    1. List all S3 buckets via list_buckets()
    2. For each bucket:
       a. Get bucket ACL via get_bucket_acl() and classify its grantees
       b. Get bucket policy via get_bucket_policy(), if the bucket carries one
       c. Parse policy JSON
       d. Extract AWS principals from statements
       e. Identify third-party accounts (not in org)
       f. Track which actions each third-party account can perform
    3. Return analysis results for buckets with third-party access

    Args:
        session: boto3 Session for the target account
        org_account_ids: Set of all account IDs in the organization

    Returns:
        List of S3BucketPolicyAnalysis for buckets with third-party accounts or wildcards

    Raises:
        MalformedPolicyError: If a Statement is neither an object nor a list
        UnknownGranteeTypeError: If an ACL grantee's type or group is unrecognized
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

        third_party_accounts: Set[str] = set()
        actions_by_account: Dict[str, Set[str]] = {}
        sources: List[ServicePrincipalSource] = []

        # The ACL is read before the policy because a bucket that shares only
        # by ACL carries no policy at all, and abandoning the bucket for want
        # of one would skip the grant most likely to be the only grant on it
        acl_findings = _analyze_bucket_acl(s3_client, bucket_name)
        has_wildcard = acl_findings.has_wildcard_grantee
        has_non_account_principals = acl_findings.has_non_account_grantee

        policy = _read_bucket_policy(s3_client, bucket_name)

        if policy is not None:
            statements = normalize_statements(policy, f"Bucket '{bucket_name}'")

            for statement in statements:
                if statement.get("Effect") != "Allow":
                    continue

                # An Allow with NotPrincipal reaches everyone it does not name,
                # which is what the wildcard flag records
                if has_not_principal(statement):
                    has_wildcard = True
                    continue

                principal = statement.get("Principal")
                if not principal:
                    continue

                sources.extend(
                    read_service_principal_sources(statement, org_account_ids, f"Bucket '{bucket_name}'")
                )

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

        has_service_source = has_actionable_service_principal_source(sources)
        if third_party_accounts or has_wildcard or has_non_account_principals or has_service_source:
            results.append(S3BucketPolicyAnalysis(
                bucket_name=bucket_name,
                bucket_arn=bucket_arn,
                third_party_account_ids=third_party_accounts,
                has_wildcard_principal=has_wildcard,
                has_non_account_principals=has_non_account_principals,
                actions_by_account=actions_by_account,
                service_principal_sources=sources,
            ))

    return results
