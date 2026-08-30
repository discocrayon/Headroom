"""
AWS KMS key access analysis.

This module contains functions for analyzing the two surfaces that
authorize access to a KMS key - the key policy and the key's grants -
specifically for identifying third-party account access (RCP checks).
"""

import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_kms.client import KMSClient
from mypy_boto3_kms.type_defs import KeyListEntryTypeDef

from ..constants import AWS_ARN_ACCOUNT_ID_PATTERN
from ..types import JsonDict
from .helpers import get_all_regions, paginate
from .policy_documents import (
    ServicePrincipalSource,
    has_actionable_service_principal_source,
    has_not_principal,
    normalize_statements,
    read_service_principal_sources,
)

logger = logging.getLogger(__name__)


class UnknownPrincipalTypeError(Exception):
    """Raised when an unknown principal type is encountered in a key policy."""


class UnsupportedPrincipalTypeError(Exception):
    """
    Raised when a principal type would break RCP deployment.

    This includes Federated principals or other types that the RCP cannot handle.
    """


class UnknownGranteePrincipalError(Exception):
    """
    Raised when a grant names a principal the analyzer cannot classify.

    Dropping it silently would leave its account out of the allowlist,
    which is the failure this analysis exists to prevent.
    """


ALLOWED_PRINCIPAL_TYPES = {"AWS", "Service"}
FAIL_FAST_PRINCIPAL_TYPES = {"Federated"}

# A grant held by an AWS service names the service rather than an account.
# The generated RCP exempts those callers with aws:PrincipalIsAWSService,
# so they are never denied and never need an allowlist entry.
AWS_SERVICE_PRINCIPAL_SUFFIX = ".amazonaws.com"

# The only thing a retiring principal can do with a grant. Attributing the
# grant's own operations to it would overstate its access.
KMS_RETIRE_GRANT_ACTION = "kms:RetireGrant"


@dataclass
class KMSGrantFinding:
    """
    One grant on a key that reaches outside the organization.

    Both account fields record only out-of-organization accounts, so a
    finding exists when at least one of them is set and each says which
    side of the grant reaches outside.

    Attributes:
        grant_id: The grant's ID, which is what RetireGrant takes
        grantee_account_id: Account of the grantee, when it is outside the
            organization. None for an AWS service principal, which the RCP
            exempts, and None for an in-organization grantee
        retiring_principal_account_id: Account of the retiring principal,
            when it is outside the organization. That principal can call
            RetireGrant and nothing else
        operations: The grant's operations, prefixed with `kms:` to match
            the spelling a key policy uses
        has_constraints: True if the grant carries an encryption context
            constraint. The constraint itself is not parsed, so this records
            that real access may be narrower than the operations suggest
    """
    grant_id: str
    grantee_account_id: Optional[str]
    retiring_principal_account_id: Optional[str]
    operations: List[str]
    has_constraints: bool


@dataclass
class KMSKeyPolicyAnalysis:
    """
    Analysis of a KMS key's policy and grants.

    KMS authorizes access through two surfaces. A grant is a separate
    object that GetKeyPolicy cannot see, so a key whose policy names
    nobody outside the organization can still hand Decrypt to a vendor.
    Both surfaces feed the account-level fields below, because a grant
    attaches to this same key in this same region.

    Attributes:
        key_id: KMS key ID
        key_arn: ARN of the KMS key
        region: AWS region where key exists
        third_party_account_ids: Set of account IDs not in the organization,
            drawn from both the key policy and the key's grants
        actions_by_account: Mapping of account ID to list of KMS actions
            allowed, drawn from both surfaces
        has_wildcard_principal: True if the policy grants to principals the
            analyzer cannot enumerate - `Principal: "*"`, or an Allow with
            NotPrincipal, which reaches everyone it does not name. Only the
            policy contributes: CreateGrant requires a concrete principal,
            so no grant can be a wildcard
        grants: The key's grants that reach outside the organization, which
            is where a reader looks when the key policy alone does not
            explain an entry in third_party_account_ids
        service_principal_sources: Service principals this policy trusts,
            with the cross-service source guard on each. Read by the
            deny_service_confused_deputy check; contributes nothing to this
            analysis's own third-party accounts or wildcard flag.
    """
    key_id: str
    key_arn: str
    region: str
    third_party_account_ids: Set[str]
    actions_by_account: Dict[str, List[str]] = field(default_factory=dict)
    has_wildcard_principal: bool = False
    grants: List[KMSGrantFinding] = field(default_factory=list)
    service_principal_sources: List[ServicePrincipalSource] = field(default_factory=list)


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
    return list(action)


def _grant_principal_account_id(principal: str) -> Optional[str]:
    """
    Resolve a grant principal to an account ID.

    Serves both GranteePrincipal and RetiringPrincipal, which take the same
    shapes. An AWS service principal has no account and is exempt from the
    RCP, so it resolves to None rather than to a third party.

    Args:
        principal: Principal string from a ListGrants entry

    Returns:
        The 12-digit account ID, or None for an AWS service principal

    Raises:
        UnknownGranteePrincipalError: If the principal is neither an ARN
            nor an AWS service principal
    """
    arn_match = re.match(AWS_ARN_ACCOUNT_ID_PATTERN, principal)
    if arn_match:
        return arn_match.group(1)

    if principal.endswith(AWS_SERVICE_PRINCIPAL_SUFFIX):
        return None

    raise UnknownGranteePrincipalError(
        f"Grant names principal '{principal}', which is neither an ARN nor "
        f"an AWS service principal. The analyzer cannot tell whether it "
        f"belongs to a third-party account, and guessing would risk "
        f"omitting that account from the RCP allowlist."
    )


def _external_grant_account(
    principal: Optional[str],
    org_account_ids: Set[str]
) -> Optional[str]:
    """
    Resolve a grant principal, keeping it only if it is outside the org.

    Args:
        principal: Principal string from a ListGrants entry, or None when
            the grant does not carry that field
        org_account_ids: Set of all account IDs in the organization

    Returns:
        The account ID if it is outside the organization, else None

    Raises:
        UnknownGranteePrincipalError: If the principal cannot be classified
    """
    if not principal:
        return None

    account_id = _grant_principal_account_id(principal)
    if account_id is None or account_id in org_account_ids:
        return None

    return account_id


def _analyze_key_grants(
    kms_client: KMSClient,
    key_id: str,
    region: str,
    org_account_ids: Set[str]
) -> List[KMSGrantFinding]:
    """
    Read a key's grants and return those reaching outside the organization.

    Grants authorize access independently of the key policy, so a key whose
    policy is clean can still be reachable by a vendor. GetKeyPolicy does
    not report them, which makes an unread grant access that breaks on
    apply with nothing in the results to explain why.

    Args:
        kms_client: Boto3 KMS client
        key_id: KMS key ID
        region: AWS region
        org_account_ids: Set of all account IDs in the organization

    Returns:
        List of KMSGrantFinding, one per grant reaching outside the org

    Raises:
        ClientError: If the grants cannot be listed
        UnknownGranteePrincipalError: If a grant names a principal the
            analyzer cannot classify
    """
    findings: List[KMSGrantFinding] = []

    logger.debug(f"Listing grants for key {key_id} in {region}")
    for page in paginate(kms_client, "list_grants", KeyId=key_id):
        for grant in page.get("Grants", []):
            grantee_account = _external_grant_account(
                grant.get("GranteePrincipal"), org_account_ids
            )
            retiring_account = _external_grant_account(
                grant.get("RetiringPrincipal"), org_account_ids
            )

            if grantee_account is None and retiring_account is None:
                continue

            findings.append(KMSGrantFinding(
                grant_id=grant.get("GrantId", ""),
                grantee_account_id=grantee_account,
                retiring_principal_account_id=retiring_account,
                operations=sorted(
                    f"kms:{operation}"
                    for operation in grant.get("Operations", [])
                ),
                has_constraints=bool(grant.get("Constraints")),
            ))

    return findings


def _read_key_policy(
    kms_client: KMSClient,
    key_id: str,
    region: str
) -> Optional[JsonDict]:
    """
    Read a key's policy, or None when the key has no policy.

    A key with no policy is not a key with nothing to find: its grants can
    still reach outside the organization, so the caller keeps going rather
    than treating a missing policy as the end of the analysis.

    Args:
        kms_client: Boto3 KMS client
        key_id: KMS key ID
        region: AWS region

    Returns:
        The parsed policy document, or None if the key has no policy

    Raises:
        ClientError: If the policy cannot be read for any other reason
    """
    try:
        response = kms_client.get_key_policy(KeyId=key_id, PolicyName="default")
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "NotFoundException":
            logger.debug(f"No policy found for key {key_id} in {region}")
            return None
        raise

    policy: JsonDict = json.loads(response.get("Policy", "{}"))
    return policy


def _analyze_key_in_region(
    kms_client: KMSClient,
    key: KeyListEntryTypeDef,
    region: str,
    org_account_ids: Set[str],
    org_id: str
) -> KMSKeyPolicyAnalysis:
    """
    Analyze a single KMS key's policy and grants.

    Both surfaces are read, and the key is analyzed even when it has no
    policy, because its grants can still reach outside the organization.

    Args:
        kms_client: Boto3 KMS client
        key: Key dict from list_keys
        region: AWS region
        org_account_ids: Set of all account IDs in the organization
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization

    Returns:
        KMSKeyPolicyAnalysis result for this key

    Raises:
        UnsupportedPrincipalTypeError: If policy contains principals that would break RCP
        UnknownGranteePrincipalError: If a grant names a principal the analyzer
            cannot classify
        MalformedPolicyError: If Statement is neither an object nor a list
    """
    key_id = key["KeyId"]
    key_arn = key["KeyArn"]

    third_party_accounts: Set[str] = set()
    actions_by_account: defaultdict[str, Set[str]] = defaultdict(set)
    has_wildcard = False
    sources: List[ServicePrincipalSource] = []

    policy = _read_key_policy(kms_client, key_id, region)
    statements = (
        normalize_statements(policy, f"Key '{key_id}' in {region}")
        if policy is not None
        else []
    )

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
            read_service_principal_sources(statement, org_account_ids, org_id, f"Key '{key_id}' in {region}")
        )

        if _has_wildcard_principal(principal):
            has_wildcard = True

        account_ids = _extract_account_ids_from_principal(principal)

        actions = _normalize_actions(statement.get("Action", []))

        for account_id in account_ids:
            if account_id in org_account_ids:
                continue

            third_party_accounts.add(account_id)
            actions_by_account[account_id].update(actions)

    grants = _analyze_key_grants(kms_client, key_id, region, org_account_ids)

    for grant in grants:
        if grant.grantee_account_id is not None:
            third_party_accounts.add(grant.grantee_account_id)
            actions_by_account[grant.grantee_account_id].update(grant.operations)

        if grant.retiring_principal_account_id is not None:
            third_party_accounts.add(grant.retiring_principal_account_id)
            actions_by_account[grant.retiring_principal_account_id].add(
                KMS_RETIRE_GRANT_ACTION
            )

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
        has_wildcard_principal=has_wildcard,
        grants=grants,
        service_principal_sources=sources,
    )


def analyze_kms_key_policies(
    session: Session,
    org_account_ids: Set[str],
    org_id: str
) -> List[KMSKeyPolicyAnalysis]:
    """
    Analyze all KMS keys in an account for third-party access.

    Examines both surfaces that authorize access to a key - its resource
    policy and its grants - and identifies account IDs that are not part
    of the organization. Reading only the policy would miss a vendor
    reached entirely by grant, and the resulting RCP would deny it.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region:
       a. List all keys via list_keys() (paginated)
       b. Get key policy via get_key_policy(), tolerating a key with none
       c. Parse policy JSON
       d. Extract principals and actions
       e. List the key's grants via list_grants() (paginated)
       f. Resolve each grantee and retiring principal to an account
       g. Identify third-party account IDs (not in org) from both surfaces
       h. Track which actions each third-party account can perform
       i. Detect wildcard principals, which only a policy can carry
    3. Return all results across all regions

    Args:
        session: boto3 Session for the target account
        org_account_ids: Set of all account IDs in the organization
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization

    Returns:
        List of KMSKeyPolicyAnalysis for keys with third-party
        access or wildcards

    Raises:
        ClientError: If AWS API calls fail
        UnsupportedPrincipalTypeError: If any key policy contains principal
            types that would break RCP deployment (like Federated)
        UnknownGranteePrincipalError: If a grant names a principal the
            analyzer cannot classify
    """
    results: List[KMSKeyPolicyAnalysis] = []

    regions = get_all_regions(session)

    for region in regions:
        logger.debug(f"Analyzing KMS keys in {region}")
        kms_client: KMSClient = session.client("kms", region_name=region)

        try:
            for page in paginate(kms_client, "list_keys"):
                for key in page.get("Keys", []):
                    analysis = _analyze_key_in_region(
                        kms_client,
                        key,
                        region,
                        org_account_ids,
                        org_id
                    )

                    has_service_source = has_actionable_service_principal_source(analysis.service_principal_sources)
                    if analysis.third_party_account_ids or analysis.has_wildcard_principal or has_service_source:
                        results.append(analysis)

        except ClientError:
            logger.error(f"Failed to analyze KMS in region {region}")
            raise

    logger.info(
        f"Analyzed KMS keys across {len(regions)} regions, "
        f"found {len(results)} keys with third-party access or wildcards"
    )
    return results
