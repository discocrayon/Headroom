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
from typing import Dict, List, Literal, Optional, Set, Tuple

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_kms.client import KMSClient
from mypy_boto3_kms.type_defs import KeyListEntryTypeDef

from ..constants import AWS_ARN_ACCOUNT_ID_PATTERN
from ..types import JsonDict
from .helpers import get_all_regions, memoize_per_session, paginate
from .iam_unique_ids import IAMUniqueIDKind, decode_account_id, iam_unique_id_kind
from .policy_documents import (
    normalize_actions,
    RESOURCE_POLICY_PRINCIPAL_TYPES,
    ServicePrincipalSource,
    has_actionable_service_principal_source,
    has_not_principal,
    is_service_linked_role_arn,
    normalize_statements,
    read_principal,
    read_service_principal_sources,
)

logger = logging.getLogger(__name__)


class UnknownGrantPrincipalError(Exception):
    """
    Raised when a grant names a principal the analyzer cannot classify.

    An identifier in the documented IAM unique ID shape does not reach
    here: its account is read out of it, or, when the encoding does not
    support it, the grant is recorded as unresolved. What reaches here
    matched no shape the analyzer reads at all. Dropping it silently would
    leave its account out of the allowlist, which is the failure this
    analysis exists to prevent. Only `GranteePrincipal` is read; the
    message names the grant and the key carrying it.
    """


# A grant held by an AWS service names the service rather than an account.
# The generated RCP exempts those callers with aws:PrincipalIsAWSService,
# so they are never denied and never need an allowlist entry.
AWS_SERVICE_PRINCIPAL_SUFFIX = ".amazonaws.com"

# The one KMS permission RCPs do not impact, so a statement or grant carrying
# only it authorizes nothing the RCP can deny. The check's specification owns
# the argument, and why the retiring principal is not read at all.
KMS_RETIRE_GRANT_ACTION = "kms:RetireGrant"

# DescribeKey reports this KeyManager for a key an AWS service created and
# controls on the account's behalf. AWS documents it as the definitive test
# for an AWS-managed key; the `aws/` alias prefix is the informal one.
AWS_MANAGED_KEY_MANAGER = "AWS"


# How KMSGrantFinding.grantee_account_id was arrived at: "arn" when the
# GranteePrincipal spelled the account out, "iam_unique_id" when the account
# was decoded from a bare identifier instead. It sits here rather than in
# iam_unique_ids.py because "arn" has nothing to do with unique IDs.
#
# Both values are written verbatim into the results file as
# grants[].grantee_account_id_source, which the check's specification
# enumerates, so they are part of the contract operators, greps, and
# downstream tooling read those files by. Headroom's own readers take only
# the summary block, so renaming one would fail no test - which is why the
# constraint is written down here.
GranteeAccountIDSource = Literal["arn", "iam_unique_id"]


@dataclass
class KMSGrantFinding:
    """
    One grant on a key that reaches outside the organization.

    Attributes:
        grant_id: The grant's ID, which is what RetireGrant takes
        grantee_account_id: Account of the grantee, which is outside the
            organization
        grantee_principal: The complete GranteePrincipal string exactly as
            ListGrants returned it, never truncated, so the account above
            can be checked against what the grant says. An ARN-backed one
            is redacted on the way to disk like every other ARN, under
            --exclude-account-ids
        grantee_account_id_source: Which of the two readings produced that
            account: an ARN stated it, or a unique ID encoded it.
            iam_unique_ids.py owns what the second reading is worth and what
            a wrong one would cost
        retiring_principal_account_id: Always None. The retiring principal
            is not read; the field is kept so persisted results keep their
            shape (INV-14)
        operations: The grant's operations, prefixed with `kms:` to match
            the spelling a key policy uses. Empty when the grant listed
            none, which is kept rather than read as harmless
        has_constraints: True if the grant carries an encryption context
            constraint. The constraint itself is not parsed, so this records
            that real access may be narrower than the operations suggest
    """
    grant_id: str
    grantee_account_id: str
    grantee_principal: str
    grantee_account_id_source: GranteeAccountIDSource
    retiring_principal_account_id: Optional[str]
    operations: List[str]
    has_constraints: bool


@dataclass
class UnresolvedKMSGrantFinding:
    """
    One grant whose grantee is an IAM unique ID no account can be read
    out of.

    Two identifiers land here: one in the older random format, which sits
    below the offset the account encoding starts at, and one that decodes
    past the largest account ID AWS can issue. Neither carries an account.

    The grantee holds whatever the grant's operations authorize, which the
    RCP would deny, and nothing in the grant says which account it belongs
    to. IAM documents that a *policy* naming a deleted user or role is
    rewritten to the unique ID and then grants no one access; KMS documents
    no such rule for a grant, so the grant is not read as dead (INV-01). It
    is recorded so the key's account is blocked for KMS and the operator can
    find the grant, and nothing about it enters the allowlist.

    Attributes:
        grant_id: The grant's ID, which is what RetireGrant takes
        grantee_principal: The complete GranteePrincipal string exactly as
            ListGrants returned it, never truncated, and never redacted
            either - not because the field is exempt, but because a bare
            unique ID has no ARN account field for the redactor to match
        principal_kind: Which prefix the identifier carries
        operations: The grant's operations, prefixed with `kms:`, sorted.
            Empty when the grant listed none, which is kept rather than
            read as harmless
        has_constraints: True if the grant carries an encryption context
            constraint, which is recorded and not read
    """
    grant_id: str
    grantee_principal: str
    principal_kind: IAMUniqueIDKind
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
        has_non_account_principals: True if the policy grants to a principal
            type carrying no account ID - Federated or CanonicalUser - which
            no allowlist keyed on aws:PrincipalAccount can preserve
        grants: The key's grants that reach outside the organization, which
            is where a reader looks when the key policy alone does not
            explain an entry in third_party_account_ids
        unresolved_grants: The key's grants whose grantee is an IAM unique
            ID the encoding does not support, so no account can be read out
            of it. Each one is a blocker for this key's account, the
            grant-surface counterpart of has_non_account_principals: access
            exists that the RCP would deny, and no allowlist entry can
            preserve it
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
    has_non_account_principals: bool = False
    grants: List[KMSGrantFinding] = field(default_factory=list)
    unresolved_grants: List[UnresolvedKMSGrantFinding] = field(default_factory=list)
    service_principal_sources: List[ServicePrincipalSource] = field(default_factory=list)


def _grant_principal_account_id(principal: str, principal_description: str) -> Optional[str]:
    """
    Resolve a grantee principal to an account ID.

    Two kinds of grantee resolve to None because the RCP cannot deny them:
    an AWS service principal, which has no account and which the RCP
    exempts with aws:PrincipalIsAWSService, and a service-linked role,
    recognized by the same rule `read_principal` applies to a policy's
    Principal element, before its account is read.

    An identifier in the documented IAM unique ID shape never reaches
    here either: the caller sets it aside and reads the account out of it
    or records the grant as unresolved. The message still names that
    shape, because an operator reading the abort has to be able to tell a
    near miss from a shape the analyzer has never seen.

    Args:
        principal: GranteePrincipal string from a ListGrants entry
        principal_description: Which grant on which key named this
            principal, opening the error message

    Returns:
        The 12-digit account ID, or None for an AWS service principal or
        a service-linked role

    Raises:
        UnknownGrantPrincipalError: If the principal is neither an ARN
            nor an AWS service principal
    """
    if is_service_linked_role_arn(principal):
        return None

    arn_match = re.match(AWS_ARN_ACCOUNT_ID_PATTERN, principal)
    if arn_match:
        return arn_match.group(1)

    if principal.endswith(AWS_SERVICE_PRINCIPAL_SUFFIX):
        return None

    raise UnknownGrantPrincipalError(
        f"{principal_description} is '{principal}', which is neither an "
        f"ARN, an AWS service principal, nor an IAM unique ID in the "
        f"documented shape. The analyzer cannot tell whether it belongs "
        f"to a third-party account, and guessing would risk omitting that "
        f"account from the RCP allowlist."
    )


def _external_grant_account(
    principal: str,
    org_account_ids: Set[str],
    principal_description: str
) -> Optional[str]:
    """
    Resolve a grantee principal, keeping it only if it is outside the org.

    Args:
        principal: GranteePrincipal string from a ListGrants entry
        org_account_ids: Set of all account IDs in the organization
        principal_description: Which grant on which key named this
            principal, for the error message

    Returns:
        The account ID if it is outside the organization, else None

    Raises:
        UnknownGrantPrincipalError: If the principal cannot be classified
    """
    account_id = _grant_principal_account_id(principal, principal_description)
    if account_id is None or account_id in org_account_ids:
        return None

    return account_id


def _analyze_key_grants(
    kms_client: KMSClient,
    key_id: str,
    key_arn: str,
    org_account_ids: Set[str]
) -> Tuple[List[KMSGrantFinding], List[UnresolvedKMSGrantFinding]]:
    """
    Read a key's grants: those reaching outside the organization, and those
    whose grantee is an IAM unique ID no account can be read out of.

    Grants authorize access independently of the key policy, so a key whose
    policy is clean can still be reachable by a vendor. GetKeyPolicy does
    not report them, which makes an unread grant access that breaks on
    apply with nothing in the results to explain why.

    A grant is skipped before its grantee is read when it is listed with
    GranteeServicePrincipal, or when its only operation is RetireGrant.

    A grantee named by IAM unique ID is attributed from the identifier
    alone, which carries its owning account when it is in the current
    format - a decoding is evidence of that format rather than proof of
    it, and iam_unique_ids.py owns what the difference costs. Whatever
    account comes back, that account and its membership in the
    organization decide the outcome and nothing else does: IssuingAccount
    names who created the grant, not who holds it, and the key's own
    account and the key's other grants say nothing about this grantee.
    Which of the two readings produced the account is recorded on the
    finding, so the difference reaches the results file rather than dying
    here.

    Args:
        kms_client: Boto3 KMS client
        key_id: KMS key ID, which is what ListGrants takes
        key_arn: ARN of the same key, which names its account and region
            in the messages a failure leaves behind
        org_account_ids: Set of all account IDs in the organization

    Returns:
        Two lists: one KMSGrantFinding per grant reaching outside the
        organization, and one UnresolvedKMSGrantFinding per grant whose
        GranteePrincipal is an IAM unique ID the encoding does not support

    Raises:
        ClientError: If the grants cannot be listed
        KeyError: If a grant carries no GrantId, or neither
            GranteeServicePrincipal nor GranteePrincipal, unless the grant
            carries only RetireGrant
        UnknownGrantPrincipalError: If a grant names a grantee that is
            neither an ARN, an AWS service principal, nor an IAM unique ID
            in the documented shape, which is read or recorded instead
    """
    findings: List[KMSGrantFinding] = []
    unresolved: List[UnresolvedKMSGrantFinding] = []

    logger.debug(f"Listing grants for key {key_arn}")
    for page in paginate(kms_client, "list_grants", KeyId=key_id):
        for grant in page.get("Grants", []):
            # ListGrants always returns the ID RetireGrant takes, and the
            # description below is worth nothing without it.
            grant_description = f"grant '{grant['GrantId']}' on key {key_arn}"

            # A grant created for a service is listed with this typed field,
            # and the RCP exempts services with aws:PrincipalIsAWSService.
            # Whatever display value sits in GranteePrincipal beside it is
            # not read.
            if grant.get("GranteeServicePrincipal"):
                continue

            operations = sorted(
                f"kms:{operation}"
                for operation in grant.get("Operations", [])
            )

            # A grant carrying no operations is not one carrying only
            # RetireGrant: nothing says what it authorizes, so it is kept.
            # Read before the grantee, because what the permission does not
            # authorize does not depend on who holds it.
            if operations == [KMS_RETIRE_GRANT_ACTION]:
                continue

            # Every grant not listed with the typed field carries this one.
            # Dropping a grant with neither would read a missing grantee as
            # no grantee - of the grants that reach this line, since one
            # carrying only RetireGrant was already skipped above.
            principal_kind = iam_unique_id_kind(grant["GranteePrincipal"])
            grantee_account: Optional[str]
            account_source: GranteeAccountIDSource

            if principal_kind is not None:
                # Reached only once the shape has been classified,
                # because decode_account_id does not re-check it.
                decoded_account = decode_account_id(grant["GranteePrincipal"])

                # No account to allowlist and none to compare against the
                # organization. Recorded as a blocker rather than raised
                # on, which cost the whole organization its results, and
                # rather than dropped, which INV-01 forbids.
                if decoded_account is None:
                    logger.warning(
                        f"The GranteePrincipal of {grant_description} is "
                        f"'{grant['GranteePrincipal']}', an IAM unique ID the "
                        f"encoding does not support, so the key's account is "
                        f"blocked for KMS and no account is inferred for the "
                        f"allowlist"
                    )
                    unresolved.append(UnresolvedKMSGrantFinding(
                        grant_id=grant["GrantId"],
                        grantee_principal=grant["GranteePrincipal"],
                        principal_kind=principal_kind,
                        operations=operations,
                        has_constraints=bool(grant.get("Constraints")),
                    ))
                    continue

                # The one exit from this loop that records nothing, so it
                # is the one an operator cannot reconstruct from the
                # results. DEBUG and not WARNING: the drop is correct, and
                # a warning here would fire for every internal unique ID.
                if decoded_account in org_account_ids:
                    logger.debug(
                        f"The GranteePrincipal of {grant_description} is "
                        f"'{grant['GranteePrincipal']}', which decodes to "
                        f"{decoded_account}, an account the organization "
                        f"holds, so the grant is not third-party access"
                    )
                    continue

                grantee_account = decoded_account
                account_source = "iam_unique_id"
            else:
                grantee_account = _external_grant_account(
                    grant["GranteePrincipal"],
                    org_account_ids,
                    f"The GranteePrincipal of {grant_description}",
                )

                # An AWS service principal, a service-linked role, or an
                # account the organization already holds. Nothing is
                # recorded, so no reading produced an account to source.
                if grantee_account is None:
                    continue

                account_source = "arn"

            findings.append(KMSGrantFinding(
                grant_id=grant["GrantId"],
                grantee_account_id=grantee_account,
                grantee_principal=grant["GranteePrincipal"],
                grantee_account_id_source=account_source,
                retiring_principal_account_id=None,
                operations=operations,
                has_constraints=bool(grant.get("Constraints")),
            ))

    return findings, unresolved


def _is_aws_managed_key(kms_client: KMSClient, key_id: str) -> bool:
    """
    Report whether a key is an AWS-managed key.

    RCPs do not apply to AWS-managed keys, so no statement this scan
    generates can reach one, and nothing about one is worth reading. Its
    policy is written by the owning service and cannot be changed, and it
    grants `Principal: {"AWS": "*"}` narrowed by `kms:CallerAccount` to the
    key's own account - which `read_principal` reads as a wildcard, so
    reading it blocked every account holding such a key for the KMS RCP
    over a policy the operator could not fix. The key is described before
    its policy and grants are read, so a skipped key costs one call rather
    than three.

    Args:
        kms_client: Boto3 KMS client
        key_id: KMS key ID

    Returns:
        True if DescribeKey reports the key as AWS-managed

    Raises:
        ClientError: If the key cannot be described
    """
    response = kms_client.describe_key(KeyId=key_id)
    return response["KeyMetadata"]["KeyManager"] == AWS_MANAGED_KEY_MANAGER


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
        KeyError: If a grant carries no GrantId, or neither
            GranteeServicePrincipal nor GranteePrincipal, unless the grant
            carries only RetireGrant
        UnknownGrantPrincipalError: If a grant names a principal the analyzer
            cannot classify, an IAM unique ID excepted, which is read or
            recorded instead
        MalformedPolicyError: If a Statement is neither an object nor a list,
            or a Principal is neither a string, a list, nor an object
    """
    key_id = key["KeyId"]
    key_arn = key["KeyArn"]

    # The ARN names the partition, region, account, and key in one token,
    # so a message carrying it identifies the key on its own.
    resource_description = f"Key {key_arn}"

    third_party_accounts: Set[str] = set()
    actions_by_account: defaultdict[str, Set[str]] = defaultdict(set)
    has_wildcard = False
    has_non_account_principals = False
    sources: List[ServicePrincipalSource] = []

    policy = _read_key_policy(kms_client, key_id, region)
    statements = (
        normalize_statements(policy, resource_description)
        if policy is not None
        else []
    )

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        # kms:RetireGrant is not effective in a key policy, so a statement
        # granting only it authorizes nothing, whoever it names - not even
        # a wildcard is a blocker here.
        actions = normalize_actions(statement.get("Action", []))
        if actions == {KMS_RETIRE_GRANT_ACTION}:
            continue

        # An Allow with NotPrincipal reaches everyone it does not name,
        # which is what the wildcard flag records
        if has_not_principal(statement):
            has_wildcard = True
            continue

        principal = statement.get("Principal")
        if not principal:
            continue

        reading = read_principal(principal, RESOURCE_POLICY_PRINCIPAL_TYPES, resource_description)
        sources.extend(
            read_service_principal_sources(statement, org_account_ids, org_id, resource_description)
        )

        has_non_account_principals = (
            has_non_account_principals or reading.has_non_account_principals
        )

        has_wildcard = has_wildcard or reading.has_wildcard
        for account_id in reading.account_ids:
            if account_id in org_account_ids:
                continue

            third_party_accounts.add(account_id)
            actions_by_account[account_id].update(actions)

    grants, unresolved_grants = _analyze_key_grants(kms_client, key_id, key_arn, org_account_ids)

    for grant in grants:
        third_party_accounts.add(grant.grantee_account_id)
        actions_by_account[grant.grantee_account_id].update(grant.operations)

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
        has_non_account_principals=has_non_account_principals,
        grants=grants,
        unresolved_grants=unresolved_grants,
        service_principal_sources=sources,
    )


@memoize_per_session
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
       b. Describe each key via describe_key() and skip AWS-managed keys,
          which RCPs do not apply to, before reading anything else
       c. Get key policy via get_key_policy(), tolerating a key with none
       d. Parse policy JSON
       e. Extract principals and actions
       f. List the key's grants via list_grants() (paginated)
       g. Resolve each grantee to an account, skipping a grant held by a
          service or a service-linked role, or carrying only RetireGrant,
          reading the account a grantee's IAM unique ID encodes and
          recording one the encoding does not support as unresolved. The
          retiring principal is not read
       h. Identify third-party account IDs (not in org) from both surfaces
       i. Track which actions each third-party account can perform
       j. Detect wildcard principals, which only a policy can carry
    3. Return all results across all regions

    Args:
        session: boto3 Session for the target account
        org_account_ids: Set of all account IDs in the organization
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization

    Returns:
        List of KMSKeyPolicyAnalysis for keys with third-party access,
        wildcards, or a grant to an IAM unique ID the encoding does not
        support

    Raises:
        ClientError: If AWS API calls fail
        KeyError: If a grant carries no GrantId, or neither
            GranteeServicePrincipal nor GranteePrincipal, unless the grant
            carries only RetireGrant
        UnknownGrantPrincipalError: If a grant names a principal the
            analyzer cannot classify, an IAM unique ID excepted
    """
    results: List[KMSKeyPolicyAnalysis] = []
    aws_managed_keys_skipped = 0

    regions = get_all_regions(session)

    for region in regions:
        logger.debug(f"Analyzing KMS keys in {region}")
        kms_client: KMSClient = session.client("kms", region_name=region)

        try:
            for page in paginate(kms_client, "list_keys"):
                for key in page.get("Keys", []):
                    if _is_aws_managed_key(kms_client, key["KeyId"]):
                        logger.debug(
                            f"Key {key['KeyId']} in {region} is AWS-managed, which RCPs "
                            "do not apply to, skipping"
                        )
                        aws_managed_keys_skipped += 1
                        continue

                    analysis = _analyze_key_in_region(
                        kms_client,
                        key,
                        region,
                        org_account_ids,
                        org_id
                    )

                    # The union of what both consumers of this analyzer
                    # look for: deny_kms_third_party_access reads every term
                    # but has_service_source, deny_service_confused_deputy
                    # reads that one. A key dropped here reaches neither, so
                    # a term added to either check's own filter has to be
                    # added here too or that check silently stops seeing it.
                    has_service_source = has_actionable_service_principal_source(analysis.service_principal_sources)
                    if analysis.third_party_account_ids or analysis.has_wildcard_principal or analysis.has_non_account_principals or has_service_source or analysis.unresolved_grants:
                        results.append(analysis)

        except ClientError:
            logger.error(f"Failed to analyze KMS in region {region}")
            raise

    logger.info(
        f"Analyzed KMS keys across {len(regions)} regions, "
        f"found {len(results)} keys with third-party access, wildcards, or "
        f"unresolved grants, skipped {aws_managed_keys_skipped} "
        f"AWS-managed keys"
    )
    return results
