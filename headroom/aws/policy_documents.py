"""
Shared grammar for the IAM policy documents Headroom reads.

Resource policies and trust policies come back from every service in the
shape they were stored, so the analyzers all face the same variations. The
rules live here once rather than in each of them.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional, Set, Union

from ..constants import AWS_ARN_ACCOUNT_ID_PATTERN

__all__ = [
    "MalformedPolicyError",
    "NON_ACCOUNT_PRINCIPAL_TYPES",
    "PrincipalElement",
    "PrincipalReading",
    "RESOURCE_POLICY_PRINCIPAL_TYPES",
    "ServicePrincipalSource",
    "TRUST_POLICY_PRINCIPAL_TYPES",
    "UnknownPrincipalTypeError",
    "UnknownSourceConditionError",
    "has_actionable_service_principal_source",
    "has_not_principal",
    "normalize_actions",
    "normalize_statements",
    "read_principal",
    "read_service_principal_sources",
    "unreadable_service_principal_source",
]

# The cross-service source keys, lower-cased. IAM matches condition key
# names without regard to case, so a policy written `aws:sourceaccount`
# names the same key as one written `aws:SourceAccount`.
SOURCE_ACCOUNT_CONDITION_KEY = "aws:sourceaccount"
SOURCE_ARN_CONDITION_KEY = "aws:sourcearn"
SOURCE_ORG_ID_CONDITION_KEY = "aws:sourceorgid"
SOURCE_ORG_PATHS_CONDITION_KEY = "aws:sourceorgpaths"

# The two keys that pin a source to an organization rather than to an
# account. An aws:SourceOrgPaths value carries the organization ID as its
# first path element and an aws:SourceOrgID value is that element alone, so
# both reduce to the same comparison against our own.
ORG_SCOPE_CONDITION_KEYS = frozenset({
    SOURCE_ORG_ID_CONDITION_KEY,
    SOURCE_ORG_PATHS_CONDITION_KEY,
})

# The base operators that constrain a source to a value. A negated operator
# excludes rather than permits, and reading one as a guard would put the wrong
# account in the allowlist. This frozenset is not the whole rule for reading an
# operator as a guard; spec/contracts/policy-model.md owns that rule.
SOURCE_GUARD_OPERATORS = frozenset({
    "ArnEquals",
    "ArnEqualsIfExists",
    "ArnLike",
    "ArnLikeIfExists",
    "StringEquals",
    "StringEqualsIfExists",
    "StringLike",
    "StringLikeIfExists",
})

# The ...IfExists forms among them, named rather than matched on a suffix.
# IfExists is satisfied when the key is absent, so a guard written with one
# also matches a request that omits the key. The deployed statement exempts
# that case for aws:SourceAccount alone, through its `Null aws:SourceAccount =
# "false"` clause; on any other key the resource policy permits a call the RCP
# denies, and the statement has to be withheld from the account instead.
SOURCE_GUARD_IF_EXISTS_OPERATORS = frozenset({
    "ArnEqualsIfExists",
    "ArnLikeIfExists",
    "StringEqualsIfExists",
    "StringLikeIfExists",
})

# The two set operators AWS defines. A multivalued condition key - which
# aws:SourceOrgPaths is - must carry one, so a guard written the way AWS
# documents it reaches this parser as "ForAllValues:StringLike" rather than
# as a bare operator.
FOR_ANY_VALUE = "ForAnyValue"
FOR_ALL_VALUES = "ForAllValues"
SOURCE_GUARD_SET_OPERATORS = frozenset({FOR_ANY_VALUE, FOR_ALL_VALUES})

# Null pins no value. `Null <key> = "false"` asserts the key is present, which
# is the clause AWS pairs with ForAllValues to forbid the empty case.
NULL_OPERATOR = "Null"

ACCOUNT_ID_PATTERN = re.compile(r"\d{12}")

# The keys AWS documents for the Principal element, split by the policy type
# that accepts them. A canonical user ID is an Amazon S3 identifier and appears
# only in the policies of services that accept one; a role trust policy does
# not. Reference:
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
RESOURCE_POLICY_PRINCIPAL_TYPES = frozenset({"AWS", "CanonicalUser", "Federated", "Service"})
TRUST_POLICY_PRINCIPAL_TYPES = frozenset({"AWS", "Federated", "Service"})

# The principal types that carry no account ID, so that no allowlist keyed on
# aws:PrincipalAccount can preserve their access. A SAML provider ARN does hold
# twelve digits, but they name the account hosting the provider rather than the
# caller, and a canonical user ID maps to an account only through an API call
# the scan does not make.
NON_ACCOUNT_PRINCIPAL_TYPES = frozenset({"CanonicalUser", "Federated"})


# A Principal element is a string, an array of them, or an object keyed by
# principal type whose values are again strings or arrays.
PrincipalElement = Union[str, List["PrincipalElement"], Dict[str, "PrincipalElement"]]


class MalformedPolicyError(Exception):
    """
    Raised when part of a policy document is not shaped like a policy.

    Two elements raise it: a `Statement` that is neither an object nor a
    list, and a `Principal` that is neither a string, a list, nor an object
    keyed by principal type. Both name the resource, because a document
    Headroom cannot read is worth nothing to an operator who cannot tell
    which document it was.
    """


class UnknownPrincipalTypeError(Exception):
    """
    Raised when a Principal element names a key AWS does not document.

    Five of the six analyzers let this abort the run: ECR, KMS, S3, Secrets
    Manager, and IAM role trust policies. AWS validates the Principal element
    when it stores a policy, so a key outside the documented set is a document
    Headroom has misread or a principal type AWS has added since this was
    written - not an ordinary fact about the account. Recording it as a
    finding would state a verdict on a grant nobody has modelled.

    SQS is the exception, and deliberately so. `_analyze_queues_in_region`
    catches it and records the queue through `_unreadable_queue`, which
    withholds the confused-deputy statement from the account instead of
    letting the queue vanish on a log line.
    `spec/checks/rcps/deny_sqs_third_party_access.md` owns that departure.
    """


@dataclass(frozen=True)
class PrincipalReading:
    """
    What one Principal element grants, as far as an RCP allowlist can express it.

    Attributes:
        account_ids: Every account ID the element names
        has_wildcard: True if it reaches principals the analyzer cannot
            enumerate, which is `*` under `Principal` or under `AWS`
        has_non_account_principals: True if it names a principal type that
            carries no account ID, so no allowlist can preserve its access
    """
    account_ids: Set[str]
    has_wildcard: bool
    has_non_account_principals: bool


def normalize_statements(policy: Mapping[str, Any], resource_description: str) -> List[Any]:
    """
    Return a policy document's statements as a list.

    IAM accepts a lone statement object where a one-element list would do,
    so both forms reach the analyzers. Iterating the object directly walks
    its keys as strings, which fails on the first `statement.get`.

    Read-only Mapping rather than dict because boto3 hands trust policies
    back as a TypedDict, which a dict parameter would reject.

    Args:
        policy: Parsed policy document
        resource_description: The resource this policy belongs to, named in
            the error message

    Returns:
        The document's statements, always as a list

    Raises:
        MalformedPolicyError: If Statement is neither an object nor a list
    """
    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        return [statements]

    if not isinstance(statements, list):
        raise MalformedPolicyError(
            f"{resource_description} has a Statement of type "
            f"{type(statements).__name__}, expected an object or a list. "
            "Reading it as no statements would report the policy as granting "
            "nothing, which is not a safe guess."
        )

    return statements


def normalize_actions(action: Union[str, List[str]]) -> Set[str]:
    """
    Return a statement's Action element as a set of action strings.

    IAM accepts a string or an array of strings and nothing else, so anything
    else is a document AWS could not have stored - the same kind of trouble as
    a principal key AWS does not document, and answered the same way. Reading
    it as no actions would record the resource as granting nothing, which is a
    verdict on a grant nobody measured.

    Args:
        action: The statement's Action element

    Returns:
        Every action the element names

    Raises:
        TypeError: If the element is neither a string nor a list
    """
    if isinstance(action, str):
        return {action}

    if isinstance(action, list):
        return set(action)

    raise TypeError(
        f"Unexpected action type: {type(action).__name__}. Expected str or list."
    )


def has_not_principal(statement: Mapping[str, Any]) -> bool:
    """
    Report whether a statement names NotPrincipal in place of Principal.

    An Allow statement with NotPrincipal grants to every principal except
    the ones it names, so its reach is everyone outside a short list. That
    is what `has_wildcard_principal` already records for `Principal: "*"`,
    and reading NotPrincipal the same way is the accurate reading rather
    than a cautious one: the two forms grant the same access.

    Callers must apply this after their own Effect gate. Deny with
    NotPrincipal is the form AWS recommends, it restricts rather than
    grants, and a resource policy's Deny hands access to nobody.

    A statement carrying both elements is not valid IAM and cannot be
    stored, but were one to arrive, answering True keeps it on the blocking
    path rather than letting the Principal half stand in for a grant that
    is broader than it looks.

    Args:
        statement: One statement from a resource policy or trust policy

    Returns:
        True if the statement carries a NotPrincipal element
    """
    return "NotPrincipal" in statement


class UnknownSourceConditionError(Exception):
    """
    Raised when a source guard on a Service principal cannot be read.

    Dropping it silently would leave its account out of the allowlist, and
    the RCP would then deny access the account depended on. That is the
    failure this analysis exists to prevent.

    This is an internal signal rather than a contract on the six analyzers
    that read sources. `read_service_principal_sources` catches it and
    returns the message as `ServicePrincipalSource.read_failure`, because a
    raise there would abort the whole estate run and take down the six
    pre-existing checks that share those analyzers but never read a source
    guard. The `deny_service_confused_deputy` check turns a recorded
    failure into a violation, which withholds the statement from that
    account - so an allowlist we could not compute is still never deployed.
    """


@dataclass
class ServicePrincipalSource:
    """
    One Allow statement's Service principal and the source guard on it.

    `source_account_ids` records only out-of-organization accounts, so an
    entry there is an allowlist requirement. An empty list does not mean the
    statement is harmless: an unguarded trust names no source at all, yet the
    driving service still populates `aws:SourceAccount`, so the deny reaches
    it and an out-of-organization driver is blocked. It means only that the
    policy gives nothing an allowlist could carry - which is why finding
    those drivers takes CloudTrail rather than this parser.
    `has_wildcard_source` marks a guard no allowlist can express, which is
    what withholds the statement from the account. A guard scoped to
    another organization is one of those: the allowlist holds account IDs,
    and another organization's accounts are not knowable from here. A guard
    scoped to this organization is the opposite - the deployed statement
    already exempts it, so it needs no allowlist entry at all.

    An entry can instead record that the read failed. Such an entry carries
    `read_failure` and no `service_principal`; the other three fields are
    empty and mean nothing, because nothing about the guard was readable.

    Attributes:
        service_principal: The service the statement names, such as
            `sns.amazonaws.com`, None on a failed read
        source_account_ids: Out-of-organization accounts the guard permits,
            sorted
        has_source_condition: True if any source key guards the statement
        has_wildcard_source: True if the guard names sources no allowlist
            can enumerate
        read_failure: Why this resource's source read could not be
            completed, None when it was read in full
    """
    service_principal: Optional[str]
    source_account_ids: List[str]
    has_source_condition: bool
    has_wildcard_source: bool
    read_failure: Optional[str] = None


def unreadable_service_principal_source(reason: str) -> ServicePrincipalSource:
    """
    Record that a resource's service principal sources could not be read.

    The `deny_service_confused_deputy` check turns this into a violation,
    which withholds the statement from the account. Analyzers use it in
    place of dropping the resource, so a source the parser could not reach
    never becomes a silently empty allowlist.

    Args:
        reason: What could not be read, named in the check's results

    Returns:
        A source entry carrying only the failure
    """
    return ServicePrincipalSource(
        service_principal=None,
        source_account_ids=[],
        has_source_condition=False,
        has_wildcard_source=False,
        read_failure=reason,
    )


def _as_condition_values(value: Any, key: str, resource_description: str) -> List[str]:
    """
    Return a condition entry's value as a list of strings.

    IAM accepts a lone string where a one-element list would do, so both
    forms reach the analyzers.

    Args:
        value: One condition entry's value
        key: The condition key it was stored under, named in the error
        resource_description: The resource this policy belongs to

    Returns:
        The entry's values, always as a list

    Raises:
        UnknownSourceConditionError: If the value is neither a string nor a
            list of strings
    """
    if isinstance(value, str):
        return [value]

    if isinstance(value, list) and all(isinstance(entry, str) for entry in value):
        return list(value)

    raise UnknownSourceConditionError(
        f"{resource_description} guards a Service principal with '{key}' "
        f"holding {type(value).__name__}, expected a string or a list of "
        "strings. Reading it as no guard would leave its account out of the "
        "allowlist."
    )


def _service_principals(principal: Any, resource_description: str) -> List[str]:
    """
    Return the services a statement's Principal element names.

    Args:
        principal: The statement's Principal element
        resource_description: The resource this policy belongs to

    Returns:
        Every service principal named, in the order given

    Raises:
        UnknownSourceConditionError: If the Service entry is neither a
            string nor a list of strings
    """
    if not isinstance(principal, dict):
        return []

    services = principal.get("Service")
    if services is None:
        return []

    return _as_condition_values(services, "Service", resource_description)


@dataclass
class _SourceGuards:
    """
    The source keys one Condition block pins.

    Attributes:
        accounts: The aws:SourceAccount values the block pins
        arns: The aws:SourceArn values the block pins
        has_org_scope: True if the block pins aws:SourceOrgID or
            aws:SourceOrgPaths
        names_foreign_org: True if any organization scope names an
            organization other than this one
        permits_absent_source_key: True if an ...IfExists operator guards a
            key other than aws:SourceAccount, so the guard also matches a
            request that omits it
    """
    accounts: List[str]
    arns: List[str]
    has_org_scope: bool
    names_foreign_org: bool
    permits_absent_source_key: bool


def _names_this_organization(scope: str, org_id: str) -> bool:
    """
    Report whether one organization scope names this organization.

    An `aws:SourceOrgPaths` value carries the organization ID as its first
    path element and an `aws:SourceOrgID` value is that element alone, so
    both keys reduce to the same comparison.

    The comparison is exact, with no wildcard expansion. A trailing
    wildcard on our own ID, `o-11111111111*`, matches this organization
    and every organization whose ID extends that prefix, so reading it as
    ours would deploy the statement against sources it does not cover.
    Treating it as foreign withholds the statement instead, which
    under-blocks rather than breaking a legitimate integration.

    Args:
        scope: One aws:SourceOrgID or aws:SourceOrgPaths value
        org_id: This organization's ID

    Returns:
        True if the scope names this organization
    """
    return scope.split("/")[0] == org_id


def _asserts_key_present(value: object) -> bool:
    """
    Report whether one `Null` clause entry asserts its key carries a value.

    `Null <key> = "false"` is the assertion, and IAM's grammar sanctions two
    further spellings of the same thing: quotation marks are optional on a
    Boolean value, and a condition value is a list whose brackets may be
    dropped when it holds one entry. All three are stored, so reading only
    the quoted string turns AWS's own recommended `aws:SourceOrgPaths` guard
    into a wildcard whenever a generator emitted one of the others.

    Anything else is read as no assertion: `"true"` asserts the opposite, a
    capitalised `"False"` is not a form AWS documents for `Null`, which
    defines no case-insensitive variant, and a list of several entries
    asserts nothing coherent about one key. Each leaves the empty case open,
    and the statement is withheld rather than deployed over a guess (INV-01).

    Args:
        value: One value from the statement's `Null` clause

    Returns:
        True if the entry asserts the key is present

    """
    if isinstance(value, list):
        if len(value) != 1:
            return False
        value = value[0]
    return value is False or value == "false"


def _keys_asserted_present(
    condition: Mapping[str, Any],
    resource_description: str,
) -> Set[str]:
    """
    Return the condition keys a Null clause asserts are present.

    `Null <key> = "false"` requires the key to carry a value; the "true"
    form requires the opposite and asserts nothing about a guard. Only the
    "false" form closes the hole ForAllValues opens, and
    `_asserts_key_present` owns which spellings of it IAM stores.

    Args:
        condition: The statement's Condition element
        resource_description: The resource this policy belongs to

    Returns:
        The lowercased keys asserted present, empty if there is no Null block

    Raises:
        UnknownSourceConditionError: If the Null clause holds something
            other than a mapping of condition keys to values
    """
    entries = condition.get(NULL_OPERATOR, {})
    if not isinstance(entries, dict):
        raise UnknownSourceConditionError(
            f"{resource_description} guards a Service principal with a "
            f"'{NULL_OPERATOR}' clause holding {type(entries).__name__}, "
            "expected a mapping of condition keys to values. Reading it as "
            "asserting nothing would guess a ForAllValues guard's "
            "absent-key verdict elsewhere in this block instead of reading "
            "what the policy actually asserts."
        )
    return {
        key.lower()
        for key, value in entries.items()
        if _asserts_key_present(value)
    }


def _read_source_guards(
    condition: Any,
    org_id: str,
    resource_description: str,
) -> _SourceGuards:
    """
    Return the sources a Condition block pins.

    Args:
        condition: The statement's Condition element
        org_id: This organization's ID
        resource_description: The resource this policy belongs to

    Returns:
        The accounts, ARNs, organization scopes, and whether an ...IfExists
        operator guards a key other than aws:SourceAccount

    Raises:
        UnknownSourceConditionError: If a source key sits under an operator
            that does not pin it to a value, or a Null clause does not hold
            a mapping of condition keys to values
    """
    accounts: List[str] = []
    arns: List[str] = []
    org_scopes: List[str] = []
    permits_absent_source_key = False

    if not isinstance(condition, dict):
        return _SourceGuards(
            accounts=accounts,
            arns=arns,
            has_org_scope=False,
            names_foreign_org=False,
            permits_absent_source_key=False,
        )

    asserted_present = _keys_asserted_present(condition, resource_description)

    for operator, entries in condition.items():
        if not isinstance(entries, dict):
            continue

        set_operator, _, base_operator = operator.rpartition(":")

        for key, value in entries.items():
            normalized = key.lower()

            if normalized == SOURCE_ACCOUNT_CONDITION_KEY:
                target = accounts
            elif normalized == SOURCE_ARN_CONDITION_KEY:
                target = arns
            elif normalized in ORG_SCOPE_CONDITION_KEYS:
                target = org_scopes
            else:
                continue

            # A Null clause pins no value, so it names no source to record.
            # _keys_asserted_present has already read what it does assert.
            if base_operator == NULL_OPERATOR:
                continue

            if set_operator and set_operator not in SOURCE_GUARD_SET_OPERATORS:
                raise UnknownSourceConditionError(
                    f"{resource_description} guards a Service principal with "
                    f"'{key}' under set operator '{set_operator}', which is "
                    "neither ForAnyValue nor ForAllValues. Reading it as a "
                    "guard would put the wrong account in the allowlist."
                )

            if base_operator not in SOURCE_GUARD_OPERATORS:
                raise UnknownSourceConditionError(
                    f"{resource_description} guards a Service principal with "
                    f"'{key}' under operator '{operator}', which does not pin "
                    "the source to a value. Reading it as a guard would put "
                    "the wrong account in the allowlist."
                )

            uses_an_if_exists_operator = base_operator in SOURCE_GUARD_IF_EXISTS_OPERATORS
            is_satisfied_by_an_absent_key = set_operator == FOR_ALL_VALUES and normalized not in asserted_present
            permits_the_key_to_be_absent = uses_an_if_exists_operator or is_satisfied_by_an_absent_key
            guards_a_key_other_than_source_account = normalized != SOURCE_ACCOUNT_CONDITION_KEY
            if permits_the_key_to_be_absent and guards_a_key_other_than_source_account:
                permits_absent_source_key = True

            target.extend(_as_condition_values(value, key, resource_description))

    return _SourceGuards(
        accounts=accounts,
        arns=arns,
        has_org_scope=bool(org_scopes),
        names_foreign_org=any(
            not _names_this_organization(scope, org_id) for scope in org_scopes
        ),
        permits_absent_source_key=permits_absent_source_key,
    )


def read_service_principal_sources(
    statement: Mapping[str, Any],
    org_account_ids: Set[str],
    org_id: str,
    resource_description: str,
) -> List[ServicePrincipalSource]:
    """
    Return the source guard on each Service principal a statement names.

    One Condition block guards every principal in its statement, so each
    service the statement names carries the same guard.

    Callers must apply their own Effect gate first. A Deny statement's
    Service principal grants nothing.

    A guard this parser cannot read comes back as a single entry carrying
    `read_failure` rather than as a raise. The six analyzers that call this
    all serve six pre-existing checks that never read a source guard, and a
    raise here would abort the estate run for all of them. The
    `deny_service_confused_deputy` check files the recorded failure as a
    violation instead, which withholds the statement from that account -
    the same protection the raise gave, without the blast radius.

    Args:
        statement: One statement from a resource policy or trust policy
        org_account_ids: Every account ID in the organization
        org_id: This organization's ID, which decides whether an
            organization scope on the guard names this organization
        resource_description: The resource this policy belongs to, named in
            the recorded failure

    Returns:
        One entry per service principal, empty if the statement names none,
        or one entry carrying `read_failure` if a guard could not be read
    """
    try:
        return _read_service_principal_sources(
            statement, org_account_ids, org_id, resource_description
        )
    except UnknownSourceConditionError as error:
        return [unreadable_service_principal_source(str(error))]


def _read_service_principal_sources(
    statement: Mapping[str, Any],
    org_account_ids: Set[str],
    org_id: str,
    resource_description: str,
) -> List[ServicePrincipalSource]:
    """
    Read the source guard on each Service principal a statement names.

    An organization scope naming this organization is a perfect guard: the
    deployed statement exempts a source carrying this organization's ID, so
    the resource needs no allowlist entry. A scope naming any other
    organization is treated as a wildcard, because the allowlist holds
    account IDs and another organization's accounts are not knowable from
    here.

    A scope naming this organization suppresses nothing else the guard
    says. An accountless `aws:SourceArn` alongside it still reads as a
    wildcard, even though the two conditions AND together and the source
    must therefore be in this organization. Acting on that reasoning would
    turn a withheld statement into a deployed one, and this analysis errs
    toward withholding.

    A guard written with an ...IfExists operator is also a wildcard, unless
    the key it guards is aws:SourceAccount. IfExists is satisfied when the
    key is absent, so such a guard also matches a request that omits the
    key. The deployed statement exempts that case for aws:SourceAccount
    alone, through its `Null aws:SourceAccount = "false"` clause; on any
    other key the resource policy permits a call the RCP denies, and no
    allowlist can express that, so the statement is withheld from the
    account instead.

    Args:
        statement: One statement from a resource policy or trust policy
        org_account_ids: Every account ID in the organization
        org_id: This organization's ID
        resource_description: The resource this policy belongs to, named in
            error messages

    Returns:
        One entry per service principal, empty if the statement names none

    Raises:
        UnknownSourceConditionError: If a source guard cannot be read
    """
    services = _service_principals(statement.get("Principal"), resource_description)
    if not services:
        return []

    guards = _read_source_guards(
        statement.get("Condition"), org_id, resource_description
    )

    resolved: Set[str] = set()
    has_wildcard = guards.names_foreign_org or guards.permits_absent_source_key

    for account in guards.accounts:
        if "*" in account or "?" in account:
            has_wildcard = True
        elif ACCOUNT_ID_PATTERN.fullmatch(account):
            resolved.add(account)
        else:
            raise UnknownSourceConditionError(
                f"{resource_description} guards a Service principal with "
                f"aws:SourceAccount '{account}', which is neither an account "
                "ID nor a wildcard. Reading it as no guard would leave its "
                "account out of the allowlist."
            )

    for arn in guards.arns:
        match = re.match(AWS_ARN_ACCOUNT_ID_PATTERN, arn)
        if match:
            resolved.add(match.group(1))
        elif not guards.accounts:
            # A wildcard in the account field, or an S3 ARN, which carries
            # no account at all. Without a companion aws:SourceAccount the
            # source cannot be identified, so no allowlist can express it.
            has_wildcard = True

    third_party = sorted(
        account for account in resolved if account not in org_account_ids
    )

    return [
        ServicePrincipalSource(
            service_principal=service,
            source_account_ids=third_party,
            has_source_condition=(
                bool(guards.accounts) or bool(guards.arns) or guards.has_org_scope
            ),
            has_wildcard_source=has_wildcard,
        )
        for service in services
    ]


def has_actionable_service_principal_source(
    sources: List[ServicePrincipalSource]
) -> bool:
    """
    Report whether any service principal source is worth keeping.

    A source is actionable when it names an out-of-organization account the
    allowlist must carry, when its guard names sources no allowlist can
    express, or when the read failed and the guard is therefore unknown.

    A guard scoped to this organization by `aws:SourceOrgID` or
    `aws:SourceOrgPaths` is none of those. The deployed statement exempts
    it, so it needs no allowlist entry and is not a violation - AWS's own
    recommended service principal guard costs the account nothing.

    An unguarded source is not actionable, and the reason is volume, not
    safety. Every log bucket and every service role carries a service trust
    with no source guard, so treating them as actionable would return every
    ordinary service integration in the account and bury the sources that
    matter.

    They are not harmless. `aws:SourceAccount` is populated by the calling
    service, from the resource that drove the call, so an unguarded trust
    still receives requests carrying that key - the confused deputy
    statement's Null gate tests the request, not the policy document. An
    out-of-organization account driving one of these trusts is inside the
    statement's reach and will be denied. Discovery cannot enumerate those
    drivers, because the policy does not name them; only CloudTrail can.
    That is the check's principal deployment risk.

    Args:
        sources: The service principal sources one resource's statements
            recorded

    Returns:
        True if a source names an out-of-organization account, a guard no
        allowlist can express, or a failed read
    """
    return any(
        source.source_account_ids or source.has_wildcard_source or source.read_failure
        for source in sources
    )


def _account_ids_in_string(principal: str) -> Set[str]:
    """
    Return the account ID a principal string names, if it names one.

    A wildcard, a service principal, and a canonical user ID all name none.

    Args:
        principal: One principal string from a Principal element

    Returns:
        The account ID as a one-element set, or an empty set
    """
    arn_match = re.match(AWS_ARN_ACCOUNT_ID_PATTERN, principal)
    if arn_match:
        return {arn_match.group(1)}

    if ACCOUNT_ID_PATTERN.fullmatch(principal):
        return {principal}

    return set()


def read_principal(
    principal: PrincipalElement,
    permitted_types: FrozenSet[str],
    resource_description: str,
) -> PrincipalReading:
    """
    Read one Principal element into the three facts an RCP allowlist turns on.

    An allowlist keyed on `aws:PrincipalAccount` can preserve exactly one kind
    of grant: one naming accounts. This reports which accounts a principal
    names, and the two ways it can name something no allowlist can carry - a
    wildcard, and a principal type that has no account ID.

    The two are one verdict, not two mechanisms: both mean the RCP would deny
    a grant that exists today, so both must block the account. Which of them
    it was is reported, not acted on differently.

    An undocumented principal key is the separate case, and raises. See
    `UnknownPrincipalTypeError`.

    Args:
        principal: The Principal element's value, as a string, a list, or an
            object keyed by principal type
        permitted_types: The principal keys this policy type accepts, either
            `RESOURCE_POLICY_PRINCIPAL_TYPES` or `TRUST_POLICY_PRINCIPAL_TYPES`
        resource_description: The resource this policy belongs to, named in
            the error message

    Returns:
        What the element names

    Raises:
        UnknownPrincipalTypeError: If it names a key AWS does not document,
            or one this policy type does not accept
    """
    if isinstance(principal, str):
        return PrincipalReading(
            account_ids=_account_ids_in_string(principal),
            has_wildcard=principal == "*",
            has_non_account_principals=False,
        )

    if isinstance(principal, list):
        readings = [
            read_principal(item, permitted_types, resource_description)
            for item in principal
        ]
        account_ids: Set[str] = set()
        for reading in readings:
            account_ids.update(reading.account_ids)
        return PrincipalReading(
            account_ids=account_ids,
            has_wildcard=any(reading.has_wildcard for reading in readings),
            has_non_account_principals=any(
                reading.has_non_account_principals for reading in readings
            ),
        )

    if not isinstance(principal, dict):
        raise MalformedPolicyError(
            f"{resource_description} has a Principal of type "
            f"{type(principal).__name__}, which is neither a string, a list, "
            "nor an object keyed by principal type. Reading it as naming no "
            "principal would report the statement as granting nothing, which "
            "is not a safe guess (INV-01)."
        )

    unknown_types = set(principal.keys()) - permitted_types
    if unknown_types:
        raise UnknownPrincipalTypeError(
            f"{resource_description} names principal type(s) "
            f"{sorted(unknown_types)}, which this policy type does not accept. "
            f"Expected one of: {sorted(permitted_types)}. AWS validates the "
            f"Principal element when it stores a policy, so this is a document "
            f"Headroom has misread or a principal type it does not model, and "
            f"either way it cannot say whether the RCP is safe to attach here."
        )

    named = read_principal(principal.get("AWS", []), permitted_types, resource_description)

    return PrincipalReading(
        account_ids=named.account_ids,
        has_wildcard=named.has_wildcard,
        has_non_account_principals=bool(
            set(principal.keys()) & NON_ACCOUNT_PRINCIPAL_TYPES
        ),
    )
