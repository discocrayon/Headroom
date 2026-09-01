"""
AWS S3 bucket access analysis.

This module contains functions for analyzing S3 buckets and the two surfaces
that authorize access to them - the bucket policy and the bucket ACL -
specifically for identifying third-party account access (RCP checks).
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, NamedTuple, Optional, Set

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_s3.client import S3Client

from ..types import JsonDict
from .helpers import memoize_per_session, paginate
from .policy_documents import (
    normalize_actions,
    RESOURCE_POLICY_PRINCIPAL_TYPES,
    ServicePrincipalSource,
    has_actionable_service_principal_source,
    has_not_principal,
    normalize_statements,
    read_principal,
    read_service_principal_sources,
)

logger = logging.getLogger(__name__)


class UnknownGranteeTypeError(Exception):
    """Raised when an unknown grantee type or group is encountered in a bucket ACL."""


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
        has_non_account_grantee: True if the ACL grants to a canonical user,
            which no API resolves to an account ID
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
            other than the bucket owner
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


@memoize_per_session
def analyze_s3_bucket_policies(
    session: Session,
    org_account_ids: Set[str],
    org_id: str
) -> List[S3BucketPolicyAnalysis]:
    """
    Analyze all S3 bucket policies and ACLs for third-party access.

    Examines both surfaces that authorize access to a bucket - its resource
    policy and its ACL - and identifies principals that are not part of the
    organization. The RCP denies every principal outside the organization
    however the bucket authorized them, so a surface left unread is a grant
    that breaks on apply with nothing in the scan to warn of it.

    Algorithm:
    1. List all S3 buckets via list_buckets() (paginated)
    2. For each bucket:
       a. Get bucket ACL via get_bucket_acl() and classify its grantees
       b. Get bucket policy via get_bucket_policy(), if the bucket carries one
       c. Parse policy JSON
       d. Extract AWS principals from statements
       e. Identify third-party accounts (not in org)
       f. Track which actions each third-party account can perform
       g. Detect wildcard principals, and principals carrying no account ID
    3. Return analysis results for buckets with a finding

    Args:
        session: boto3 Session for the target account
        org_account_ids: Set of all account IDs in the organization
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization

    Returns:
        List of S3BucketPolicyAnalysis for buckets with third-party accounts or wildcards

    Raises:
        MalformedPolicyError: If a Statement is neither an object nor a list,
            or a Principal is neither a string, a list, nor an object
        UnknownGranteeTypeError: If an ACL grantee's type or group is unrecognized
        UnknownPrincipalTypeError: If a bucket policy names a principal key
            AWS does not document
    """
    s3_client: S3Client = session.client("s3")
    results: List[S3BucketPolicyAnalysis] = []

    # Materialized rather than streamed so that a failure on any page is
    # raised here, where it is reported as the listing failure it is, rather
    # than inside the loop where the bucket-policy handler would catch it.
    try:
        pages = list(paginate(s3_client, "list_buckets"))
    except ClientError as e:
        logger.error(f"Failed to list S3 buckets from AWS API: {e}")
        raise

    for bucket in [bucket for page in pages for bucket in page.get("Buckets", [])]:
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
                    read_service_principal_sources(statement, org_account_ids, org_id, f"Bucket '{bucket_name}'")
                )

                reading = read_principal(
                    principal, RESOURCE_POLICY_PRINCIPAL_TYPES, f"Bucket '{bucket_name}'"
                )

                has_wildcard = has_wildcard or reading.has_wildcard
                has_non_account_principals = (
                    has_non_account_principals or reading.has_non_account_principals
                )

                account_ids = reading.account_ids
                actions = normalize_actions(statement.get("Action", []))

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
