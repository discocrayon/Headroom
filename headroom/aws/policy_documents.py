"""
Shared grammar for the IAM policy documents Headroom reads.

Resource policies and trust policies come back from every service in the
shape they were stored, so the analyzers all face the same variations. The
rules live here once rather than in each of them.
"""

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, NamedTuple, Optional, Set, Union

from ..constants import AWS_ARN_ACCOUNT_ID_PATTERN
from ..enums import PolicyService

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
    "read_service_principal_sources",
    "read_statement_principals",
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

# The cross-service keys that enumerate who a principal may be, lower-cased.
# IAM matches condition key names without regard to case, so a policy written
# `aws:principalaccount` names the same key as one written
# `aws:PrincipalAccount`.
PRINCIPAL_ACCOUNT_CONDITION_KEY = "aws:principalaccount"

# The key that names the callers themselves rather than their accounts. Its
# values are read as principals, not as strings: a service-linked role's ARN
# bounds the statement while naming no account to preserve, because RCPs do
# not impact one.
PRINCIPAL_ARN_CONDITION_KEY = "aws:principalarn"

# The two keys that pin a principal to an organization rather than to an
# account. Every caller they admit is already in the organization, so they
# bound the statement without naming an account the allowlist has to carry.
# An aws:PrincipalOrgPaths value carries the organization ID as its first
# path element and an aws:PrincipalOrgID value is that element alone, so both
# reduce to the same comparison against our own.
PRINCIPAL_ORG_ID_CONDITION_KEY = "aws:principalorgid"
PRINCIPAL_ORG_PATHS_CONDITION_KEY = "aws:principalorgpaths"

PRINCIPAL_ORG_SCOPE_CONDITION_KEYS = frozenset({
    PRINCIPAL_ORG_ID_CONDITION_KEY,
    PRINCIPAL_ORG_PATHS_CONDITION_KEY,
})

# The account of the caller as KMS itself reports it, lower-cased like every
# other key here because IAM matches condition key names without regard to
# case. KMS names it rather than AWS, so it is only a key at all in a KMS
# policy - which is what SERVICE_SCOPED_ACCOUNT_CONDITION_KEYS below decides.
KMS_CALLER_ACCOUNT_CONDITION_KEY = "kms:calleraccount"

# The service-scoped keys that name a calling principal's account, by the
# service whose policies may carry them. kms:CallerAccount is the account of
# the caller, which is what aws:PrincipalAccount is, so it bounds a wildcard
# the same way - but only in a KMS policy. The same clause elsewhere names a
# key no request carries, so that statement grants nobody anything and
# reading it as a bound would put an account in an allowlist no policy
# granted. A service with no row here recognizes no service-scoped key,
# which is the answer for STS and not an omission.
SERVICE_SCOPED_ACCOUNT_CONDITION_KEYS: Mapping[PolicyService, FrozenSet[str]] = {
    PolicyService.KMS: frozenset({KMS_CALLER_ACCOUNT_CONDITION_KEY}),
}

# The base operators that pin a principal key to values this reader can
# enumerate, split by what they compare. A string operator compares the
# whole value; an ARN operator compares six colon-delimited components,
# which only a key holding an ARN has. Only an operator on one of these
# lists is read as a bound: a negated one excludes rather than permits, and
# every operator absent from them leaves the wildcard standing, which
# withholds the RCP from the account. The negations they deliberately omit
# are ArnNotEquals, ArnNotLike, StringNotEquals and StringNotLike; leaving
# them off is the whole rule.
# Named on its own because the aws:PrincipalArn reader compares against it:
# it is the one confining operator that expands no wildcard.
STRING_EQUALS = "StringEquals"
STRING_CONFINING_OPERATORS = frozenset({STRING_EQUALS, "StringLike"})
ARN_CONFINING_OPERATORS = frozenset({"ArnEquals", "ArnLike"})
CONFINING_OPERATORS = STRING_CONFINING_OPERATORS | ARN_CONFINING_OPERATORS

# Which operators bound which key. The pairing is the unit, not the operator
# alone: aws:PrincipalArn is the one key here whose values are ARNs, so it is
# the one key an ARN operator can compare, and `ArnEquals aws:PrincipalAccount`
# pairs a six-component comparison with a twelve-digit value that has one
# component. What IAM makes of that pairing is not something this reader
# guesses at - it confines nothing, which leaves the wildcard standing.
# aws:PrincipalArn carries the string operators as well, because
# `StringLike aws:PrincipalArn arn:aws:iam::111111111111:role/vendor-*` is
# the ordinary way the key is written. A key absent from this table confines
# nothing at all.
CONFINING_OPERATORS_BY_KEY: Mapping[str, FrozenSet[str]] = {
    PRINCIPAL_ACCOUNT_CONDITION_KEY: STRING_CONFINING_OPERATORS,
    PRINCIPAL_ARN_CONDITION_KEY: CONFINING_OPERATORS,
    PRINCIPAL_ORG_ID_CONDITION_KEY: STRING_CONFINING_OPERATORS,
    PRINCIPAL_ORG_PATHS_CONDITION_KEY: STRING_CONFINING_OPERATORS,
    KMS_CALLER_ACCOUNT_CONDITION_KEY: STRING_CONFINING_OPERATORS,
}

# Twelve ASCII digits, and not Python's `\d`, which also accepts the digits
# of every other script. AWS validates no condition value, so a policy may
# carry twelve fullwidth digits; read as an account they would reach the
# generated allowlist and fail the module's own `^[0-9]{12}$` check, taking
# the whole Terraform plan down rather than one account's RCP.
ACCOUNT_ID_PATTERN = re.compile(r"[0-9]{12}")

# The resource path IAM reserves to AWS services. A role under it is a
# service-linked role, whatever partition or account the ARN names, and the
# partition and account are matched by AWS_ARN_ACCOUNT_ID_PATTERN.
AWS_SERVICE_LINKED_ROLE_PATH_PREFIX = "role/aws-service-role/"

# The ARN of a role session, as STS issues it. It is a valid Principal, and
# _read_principal reads it as one, but aws:PrincipalArn never holds it: for a
# role session the key carries the role's own ARN, and AWS documents that
# the session ARN must not be written as the key's value. A federated-user
# session under the same service segment is different - the key does hold
# that ARN - so only the assumed-role resource is matched.
STS_ASSUMED_ROLE_SESSION_ARN_PATTERN = re.compile(r"^arn:aws[a-z0-9-]*:sts:[^:]*:[0-9]{12}:assumed-role/")

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

# What `ServicePrincipalSource.service_principal` records when the statement's
# principal is a wildcard narrowed by a source key rather than a named service.
WILDCARD_SERVICE_PRINCIPAL = "*"


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

    Every analyzer lets this abort the run: ECR, KMS, S3, Secrets Manager,
    SQS, and IAM role trust policies. AWS validates the Principal element
    when it stores a policy, so a key outside the documented set is a document
    Headroom has misread or a principal type AWS has added since this was
    written - not an ordinary fact about the account. Recording it as a
    finding would state a verdict on a grant nobody has modelled, and
    recording the resource with its findings left empty, as the SQS analyzer
    once did, clears the account on the strength of a document nobody read.
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
        confined_by: The condition keys, lower-cased, that each bounded the
            statement on their own; frozen for an immutable default on this
            frozen dataclass, unlike the mutable Set[str] the analysis
            dataclasses that accumulate these across statements use
        principal_types: The principal-type keys the element carries -
            `AWS`, `Service`, `Federated`, `CanonicalUser` - and none for a
            bare string. A fact about the element rather than a verdict on
            it, kept so that the trust-policy analyzer's Federated check
            asks the reading and never the element
    """
    account_ids: Set[str]
    has_wildcard: bool
    has_non_account_principals: bool
    confined_by: FrozenSet[str] = frozenset()
    principal_types: FrozenSet[str] = frozenset()


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
    Allow statement gives nothing an allowlist could carry. A companion Deny
    statement may name the driver, and no adapter reads one, so finding
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
            `sns.amazonaws.com`; `*` when the statement's principal is a
            wildcard narrowed by a source key, since only a service call
            carries one; None on a failed read
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
        f"{resource_description} has a '{key}' entry holding "
        f"{type(value).__name__}, expected a string or a list of strings. "
        "Reading it as empty would leave its account out of the allowlist."
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


class _ConditionClause(NamedTuple):
    """
    One clause of a Condition block, as every reader of the block sees it.

    Attributes:
        operator: The operator as the document spells it, kept for error
            messages
        set_operator: The `ForAnyValue` or `ForAllValues` prefix, or the
            empty string when the operator carries none
        base_operator: The operator with that prefix removed
        key: The condition key as the document spells it, kept for error
            messages
        normalized_key: The key lower-cased, which is how IAM matches it
        value: The clause's value as the document holds it
    """

    operator: str
    set_operator: str
    base_operator: str
    key: str
    normalized_key: str
    value: object


def _condition_clauses(condition: Mapping[str, Any]) -> Iterator[_ConditionClause]:
    """
    Yield each clause of a Condition block, parsed the one way IAM defines.

    A block maps operators to mappings of keys to values. Three rules of
    that grammar are stated here and nowhere else, so the readers of the
    block cannot disagree on them: the operator is split at its last colon
    into an optional set-operator prefix and a base operator; the key is
    folded to lower case, because IAM matches condition keys without regard
    to case; and a key carrying a non-ASCII character is dropped before its
    case is touched. IAM has no such key, so one matches nobody, and the
    fold is not safe on it: `lower()` maps the Kelvin sign U+212A to `k`,
    which would read a key IAM never populates as kms:CallerAccount.

    An operator whose entries are not a mapping yields nothing. Each reader
    decides for itself what a clause proves; this decides only what a
    clause is.

    Args:
        condition: The statement's Condition element

    Yields:
        The block's clauses, in document order
    """
    for operator, entries in condition.items():
        if not isinstance(entries, dict):
            continue

        set_operator, _, base_operator = operator.rpartition(":")

        for key, value in entries.items():
            if not key.isascii():
                continue

            yield _ConditionClause(
                operator=operator,
                set_operator=set_operator,
                base_operator=base_operator,
                key=key,
                normalized_key=key.lower(),
                value=value,
            )


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
            f"{resource_description} has a source guard with a "
            f"'{NULL_OPERATOR}' clause holding {type(entries).__name__}, "
            "expected a mapping of condition keys to values. Reading it as "
            "asserting nothing would guess a ForAllValues guard's "
            "absent-key verdict elsewhere in this block instead of reading "
            "what the policy actually asserts."
        )
    return {
        clause.normalized_key
        for clause in _condition_clauses(condition)
        if clause.operator == NULL_OPERATOR and _asserts_key_present(clause.value)
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

    for clause in _condition_clauses(condition):
        if clause.normalized_key == SOURCE_ACCOUNT_CONDITION_KEY:
            target = accounts
        elif clause.normalized_key == SOURCE_ARN_CONDITION_KEY:
            target = arns
        elif clause.normalized_key in ORG_SCOPE_CONDITION_KEYS:
            target = org_scopes
        else:
            continue

        # A Null clause pins no value, so it names no source to record.
        # _keys_asserted_present has already read what it does assert.
        if clause.base_operator == NULL_OPERATOR:
            continue

        if clause.set_operator and clause.set_operator not in SOURCE_GUARD_SET_OPERATORS:
            raise UnknownSourceConditionError(
                f"{resource_description} has a source guard with "
                f"'{clause.key}' under set operator '{clause.set_operator}', "
                "which is neither ForAnyValue nor ForAllValues. Reading it as "
                "a guard would put the wrong account in the allowlist."
            )

        if clause.base_operator not in SOURCE_GUARD_OPERATORS:
            raise UnknownSourceConditionError(
                f"{resource_description} has a source guard with "
                f"'{clause.key}' under operator '{clause.operator}', which "
                "does not pin the source to a value. Reading it as a guard "
                "would put the wrong account in the allowlist."
            )

        uses_an_if_exists_operator = clause.base_operator in SOURCE_GUARD_IF_EXISTS_OPERATORS
        is_satisfied_by_an_absent_key = (
            clause.set_operator == FOR_ALL_VALUES and clause.normalized_key not in asserted_present
        )
        permits_the_key_to_be_absent = uses_an_if_exists_operator or is_satisfied_by_an_absent_key
        guards_a_key_other_than_source_account = clause.normalized_key != SOURCE_ACCOUNT_CONDITION_KEY
        if permits_the_key_to_be_absent and guards_a_key_other_than_source_account:
            permits_absent_source_key = True

        target.extend(_as_condition_values(clause.value, clause.key, resource_description))

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

    This reader never narrows a wildcard against a confining key such as
    `aws:PrincipalAccount`; it always probes the raw, unbounded wildcard.
    `read_statement_principals` is the reader that narrows on those keys.
    Staying raw here is deliberate and permanent: a wildcard narrowed by a
    source key is exactly the shape `deny_service_confused_deputy` records,
    and making this probe condition-aware would silently change that
    check's verdicts too.

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

    A wildcard principal narrowed by a source key is read as one source
    named `*`. AWS's own cross-account SNS-to-SQS queue policy is written
    that way: `Principal: "*"` under `ArnEquals aws:SourceArn`. Only a
    service call carries a source key, so the guard names who the grant is
    for even though the Principal element does not. A wildcard under no
    source key names no source, and is left to the six third-party-access
    checks, which block the account for it.

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
        statement: One Allow statement from a resource policy or trust
            policy, carrying a Principal element the adapter has already
            read through `read_statement_principals` against its own
            type set; every adapter applies its Effect gate and reads the
            Principal through that reader, which raises on a statement
            carrying none, before reaching here
        org_account_ids: Every account ID in the organization
        org_id: This organization's ID
        resource_description: The resource this policy belongs to, named in
            error messages

    Returns:
        One entry per service principal, or one entry for a wildcard
        principal narrowed by a source key; empty if the statement has
        neither

    Raises:
        UnknownSourceConditionError: If a source guard cannot be read
    """
    principal = statement["Principal"]
    services = _service_principals(principal, resource_description)
    # Only a service call carries a source key, so a wildcard principal under
    # one is a grant to whichever service delivers for those sources. The
    # adapter has already read this principal against its own type set, and
    # the resource-policy set is the wider of the two, so this read cannot
    # raise: a malformed or undocumented principal is reported by the
    # adapter, under its own description.
    reads_wildcard = not services and _read_principal(
        principal, RESOURCE_POLICY_PRINCIPAL_TYPES, resource_description
    ).has_wildcard
    if not services and not reads_wildcard:
        return []

    guards = _read_source_guards(
        statement.get("Condition"), org_id, resource_description
    )
    has_source_condition = bool(guards.accounts) or bool(guards.arns) or guards.has_org_scope
    if reads_wildcard and not has_source_condition:
        return []
    if reads_wildcard:
        services = [WILDCARD_SERVICE_PRINCIPAL]

    resolved: Set[str] = set()
    has_wildcard = guards.names_foreign_org or guards.permits_absent_source_key

    for account in guards.accounts:
        if "*" in account or "?" in account:
            has_wildcard = True
        elif ACCOUNT_ID_PATTERN.fullmatch(account):
            resolved.add(account)
        else:
            raise UnknownSourceConditionError(
                f"{resource_description} has a source guard with "
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
            has_source_condition=has_source_condition,
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
    statement's reach and will be denied. Discovery does not enumerate
    those drivers: a policy that names one does so in a companion Deny
    statement no adapter reads, and one that does not leaves it to
    CloudTrail. That is the check's principal deployment risk.

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


def is_service_linked_role_arn(principal: str) -> bool:
    """
    Report whether a principal string is a service-linked role's ARN.

    IAM reserves the `aws-service-role/` role path to AWS services, so the
    path identifies the role in any partition and its name is not consulted.
    RCPs do not impact the permissions of any service-linked role, so no
    statement Headroom generates can deny one, and its account is never a
    third party to preserve. Read by `_read_principal` for a policy's
    Principal element and by the KMS grant reader for a grantee, so the two
    surfaces agree on what a service-linked role is.

    Args:
        principal: One principal string, from a Principal element or a
            ListGrants entry

    Returns:
        True if the string is an ARN whose resource is under the reserved path
    """
    arn_match = re.match(AWS_ARN_ACCOUNT_ID_PATTERN, principal)
    if not arn_match:
        return False

    return principal[arn_match.end():].startswith(AWS_SERVICE_LINKED_ROLE_PATH_PREFIX)


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


def _read_principal(
    principal: PrincipalElement,
    permitted_types: FrozenSet[str],
    resource_description: str,
) -> PrincipalReading:
    """
    Read one Principal element into the four facts the analyzers act on.

    An allowlist keyed on `aws:PrincipalAccount` can preserve exactly one kind
    of grant: one naming accounts. This reports which accounts a principal
    names, and the two ways it can name something no allowlist can carry - a
    wildcard, and a principal that has no account ID, whether a `Federated`
    or `CanonicalUser` type or an ARN whose account field is not an account,
    which is what CloudFront's origin access identity user carries. A bare
    unique ID is neither: AWS writes it in place of a deleted user's or
    role's ARN and documents that the entry then grants no one access, so
    there is nothing behind it for an RCP to deny.

    The two are one verdict, not two mechanisms: both mean the RCP would deny
    a grant that exists today, so both must block the account. Which of them
    it was is reported, not acted on differently.

    The reading also carries the principal-type keys the element names -
    `AWS`, `Service`, `Federated`, `CanonicalUser` - and none for a bare
    string. That is a fact about the element rather than a verdict on it,
    kept so that the trust-policy analyzer's Federated check asks the
    reading and never the element.

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
        # Neither an account nor a blocker: RCPs do not impact a
        # service-linked role, so there is nothing behind it to preserve.
        if is_service_linked_role_arn(principal):
            return PrincipalReading(
                account_ids=set(),
                has_wildcard=False,
                has_non_account_principals=False,
            )

        accounts_named = _account_ids_in_string(principal)
        return PrincipalReading(
            account_ids=accounts_named,
            has_wildcard=principal == "*",
            # An ARN that names no account. CloudFront's origin access
            # identity user carries the service's name where an account ID
            # would be, and no allowlist keyed on aws:PrincipalAccount can
            # carry it. Read as naming nothing, it cleared the account.
            has_non_account_principals=principal.startswith("arn:") and not accounts_named,
        )

    if isinstance(principal, list):
        readings = [
            _read_principal(item, permitted_types, resource_description)
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
            principal_types=frozenset().union(*(reading.principal_types for reading in readings)),
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

    named = _read_principal(principal.get("AWS", []), permitted_types, resource_description)
    names_non_account_type = bool(set(principal.keys()) & NON_ACCOUNT_PRINCIPAL_TYPES)

    return PrincipalReading(
        account_ids=named.account_ids,
        has_wildcard=named.has_wildcard,
        has_non_account_principals=named.has_non_account_principals or names_non_account_type,
        principal_types=frozenset(principal.keys()),
    )


@dataclass(frozen=True)
class _PrincipalConfinement:
    """
    What one Condition block proves about who a wildcard can reach.

    Attributes:
        confining_keys: The condition keys, lower-cased, that each bound the
            statement on their own
        account_ids: Every account those bounds enumerate, in-organization
            ones included; the caller filters
    """
    confining_keys: FrozenSet[str]
    account_ids: FrozenSet[str]


def _confining_clause_values(value: Any) -> Optional[List[str]]:
    """
    Return one confining clause's value as a list of strings.

    IAM accepts a lone string where a one-element list would do, so both
    forms reach this reader. Every other shape is answered with None, the
    empty list included: whatever an empty list asserts, it is not a list of
    principals this reader can name, and a shape it cannot name does not
    confine.

    `_as_condition_values` answers the same question for a source guard by
    raising, which is right there: a source value read as empty leaves its
    account out of the allowlist. Here an unread value costs only coverage,
    so this reader never raises. The two also part company over the empty
    list, which the source reader records as the value set it is: a source
    guard naming nothing still says the statement is guarded, while a
    confining key naming nothing enumerates nobody and so proves no bound.

    Args:
        value: One condition entry's value

    Returns:
        The entry's values, or None if the entry is neither a string nor a
        non-empty list of strings
    """
    if isinstance(value, str):
        return [value]

    if isinstance(value, list) and value and all(isinstance(entry, str) for entry in value):
        return list(value)

    return None


def _accounts_bound_by_principal_arns(values: List[str], base_operator: str) -> Optional[Set[str]]:
    """
    Return the accounts a set of aws:PrincipalArn values enumerates.

    A service-linked role bounds the statement without naming an account to
    preserve, because RCPs do not impact one. Every other value has to carry
    a twelve-digit account field; a wildcard after that field is harmless
    under `StringLike`, `ArnEquals`, and `ArnLike`, since the account an
    allowlist would hold is already pinned. Under `StringEquals` it is a
    literal star that no ARN carries, so the value matches nobody and the
    author meant `StringLike`; the clause proves no bound, which leaves the
    wildcard standing until the policy is fixed. An assumed-role session ARN
    matches nobody under any operator, because the key holds the role's ARN
    and not the session's, and is read the same way.

    Args:
        values: Every aws:PrincipalArn value the Condition block gives
        base_operator: The operator naming the key, with any set-operator
            prefix removed

    Returns:
        The accounts the values name, or None if any of them names none
    """
    accounts: Set[str] = set()

    for value in values:
        if base_operator == STRING_EQUALS and any(character in value for character in "*?"):
            return None

        if STS_ASSUMED_ROLE_SESSION_ARN_PATTERN.match(value):
            return None

        if is_service_linked_role_arn(value):
            continue

        match = re.match(AWS_ARN_ACCOUNT_ID_PATTERN, value)
        if not match:
            return None

        accounts.add(match.group(1))

    return accounts


def _accounts_bound_by_key(
    key: str,
    values: List[str],
    base_operator: str,
    policy_service: PolicyService,
    org_id: str,
) -> Optional[Set[str]]:
    """
    Return the accounts one condition key enumerates, or None if it bounds none.

    Every value under the key has to be enumerable for the key to bound the
    statement at all, because values under one key are ORed: one value this
    reader cannot pin reaches principals the rest do not.

    Args:
        key: One condition key, lower-cased
        values: Every value the Condition block gives that key
        base_operator: The operator naming the key, with any set-operator
            prefix removed; aws:PrincipalArn reads a wildcard differently
            under `StringEquals`
        policy_service: The service whose policy holds the statement, which
            decides whether a service-scoped key names an account here
        org_id: This organization's ID

    Returns:
        The accounts the key enumerates, empty when it bounds the statement
        without naming one; None when it bounds nothing
    """
    # A service-scoped account key is read by exactly the rule
    # aws:PrincipalAccount is read by, because it says the same thing about
    # the caller. What differs is where it says it, and that is the lookup.
    service_scoped_account_keys = SERVICE_SCOPED_ACCOUNT_CONDITION_KEYS.get(policy_service, frozenset())

    if key == PRINCIPAL_ACCOUNT_CONDITION_KEY or key in service_scoped_account_keys:
        if not all(ACCOUNT_ID_PATTERN.fullmatch(value) for value in values):
            return None

        return set(values)

    if key in PRINCIPAL_ORG_SCOPE_CONDITION_KEYS:
        if not all(_names_this_organization(value, org_id) for value in values):
            return None

        return set()

    if key == PRINCIPAL_ARN_CONDITION_KEY:
        return _accounts_bound_by_principal_arns(values, base_operator)

    # The one key that reaches here without a branch above it:
    # kms:CallerAccount in a policy for some other service, where it names
    # a key no request carries. Every key this reader does not model at all
    # - `s3:prefix` among them - was dropped by CONFINING_OPERATORS_BY_KEY
    # before the call.
    return None


def _read_principal_confinement(
    condition: Any,
    policy_service: PolicyService,
    org_id: str,
) -> _PrincipalConfinement:
    """
    Return what a Condition block proves about who its statement reaches.

    Every clause is judged on its own, and one that bounds the principals
    bounds the whole statement: clauses AND together, so a companion clause
    can only narrow what the first one admitted. Values within a clause are
    ORed, so the clause bounds nothing unless every one of them is
    enumerable.

    A block, an operator, a value, or a key this reader does not fully
    understand simply proves no bound, and so does a key it understands
    only in another service's policies, or one paired with an operator that
    does not compare its values. That is the reading of the document rather
    than a swallowed failure: an unproven bound leaves the wildcard
    standing, and a standing wildcard withholds the RCP from the account.

    Args:
        condition: The statement's Condition element
        policy_service: The service whose policy holds the statement,
            deciding which service-scoped condition keys can confine it
        org_id: This organization's ID, deciding whether an organization
            scope on a confining key names this organization

    Returns:
        The keys that bound the statement and the accounts they enumerate
    """
    if not isinstance(condition, dict):
        return _PrincipalConfinement(confining_keys=frozenset(), account_ids=frozenset())

    confining_keys: Set[str] = set()
    account_ids: Set[str] = set()

    for clause in _condition_clauses(condition):
        # A multivalued condition key - which aws:PrincipalOrgPaths is - must
        # carry a set operator, so AWS's own guard on it reaches this parser
        # prefixed. ForAnyValue is satisfied by one matching value, which is
        # the reading a bare operator gets; every other prefix, ForAllValues
        # included, is left to bound nothing.
        if clause.set_operator not in ("", FOR_ANY_VALUE):
            continue

        # The operator is judged against the key it names rather than
        # on its own, so that an ARN comparison reaches only the key
        # whose values are ARNs. A negated operator is dropped by the
        # same lookup rather than allowed to unbind the key it names:
        # `StringEquals aws:PrincipalAccount` beside `StringNotEquals`
        # on the same account admits nobody, so recording the account
        # is over-wide by one allowlist entry - and over-wide is the
        # direction that breaks nothing.
        if clause.base_operator not in CONFINING_OPERATORS_BY_KEY.get(clause.normalized_key, frozenset()):
            continue

        # A clause this reader cannot enumerate is dropped rather than
        # taken as unbinding its key, because clauses AND together: a
        # companion clause on the same key still admits nobody the
        # dropped one would have excluded.
        clause_values = _confining_clause_values(clause.value)
        if clause_values is None:
            continue

        bounded = _accounts_bound_by_key(
            clause.normalized_key, clause_values, clause.base_operator, policy_service, org_id
        )
        if bounded is None:
            continue

        confining_keys.add(clause.normalized_key)
        account_ids.update(bounded)

    return _PrincipalConfinement(
        confining_keys=frozenset(confining_keys),
        account_ids=frozenset(account_ids),
    )


def read_statement_principals(
    statement: Mapping[str, Any],
    permitted_types: FrozenSet[str],
    policy_service: PolicyService,
    org_id: str,
    resource_description: str,
) -> PrincipalReading:
    """
    Read one statement's Principal element, bounded by its Condition block.

    `_read_principal` reads a Principal element and nothing else, so a
    wildcard narrowed by a condition that enumerates its callers reads as a
    wildcard. This reads the statement, so such a wildcard reads as the set
    the condition bounds it to.

    Four global keys can prove such a bound: `aws:PrincipalAccount`,
    `aws:PrincipalArn`, `aws:PrincipalOrgID`, and `aws:PrincipalOrgPaths`.
    A service-scoped key can prove one too, but only in the policies of its
    own service: `kms:CallerAccount` is the account of the caller in a KMS
    key policy and names a key no request carries anywhere else. Keys AND
    together, so any one of them that enumerates the callers bounds the
    whole statement, and each is read only under an operator that compares
    its values - `CONFINING_OPERATORS_BY_KEY` is that pairing.

    The Condition is read only for a statement whose Principal is a
    wildcard, because narrowing one is the only thing a bound is read for.
    Clauses AND with the Principal element, so a Condition cannot reach a
    caller the Principal does not already name; joining an account it
    enumerates to a Principal that names its callers outright would write
    an allowlist entry exempting an account no grant reaches.

    A bound is only ever recognized when it can be proven. Every operator,
    key, and value this reader does not fully understand leaves the wildcard
    standing, which withholds the RCP from the account - the outcome that
    breaks nothing. Reading the Condition never raises: a condition it
    cannot read costs coverage, unlike a source guard it cannot read, which
    would put a wrong account in the allowlist. Reading the Principal element
    still does, since `_read_principal` aborts on a malformed or undocumented
    one - the abort belongs to the element and never to the condition.

    Callers apply their own Effect gate and their own NotPrincipal gate
    first. An `Allow` with `NotPrincipal` never reaches here and is never
    confined. Nobody applies a missing-Principal skip: an Allow carrying
    neither element is a document AWS could not have stored, and it aborts
    here rather than being read as a grant to nobody.

    `read_service_principal_sources` reads the same statement for its
    Service principal's source guard, and deliberately never narrows on a
    confining key: it must keep seeing the raw wildcard that
    `deny_service_confused_deputy` records, so this is the one reader that
    narrows and that one stays raw, permanently.

    Args:
        statement: One Allow statement from a resource policy or trust
            policy, carrying a Principal element and, optionally, a
            Condition element
        permitted_types: The principal keys this policy type accepts, either
            `RESOURCE_POLICY_PRINCIPAL_TYPES` or `TRUST_POLICY_PRINCIPAL_TYPES`
        policy_service: The AWS service whose policy this statement belongs
            to, deciding which service-scoped condition keys can confine it
        org_id: This organization's ID, deciding whether an organization
            scope on a confining key names this organization
        resource_description: The resource this policy belongs to, named in
            the error message

    Returns:
        What the statement's Principal names, narrowed by any bound its
        Condition proves

    Raises:
        MalformedPolicyError: If the statement carries neither a Principal
            nor a NotPrincipal element, which AWS stores in no resource
            policy or trust policy, or a Principal of a shape that is not
            one
    """
    if "Principal" not in statement:
        raise MalformedPolicyError(
            f"{resource_description} has an Allow statement carrying neither a "
            "Principal nor a NotPrincipal element. AWS stores no such statement "
            "in a resource policy or a trust policy, so this is a document "
            "Headroom has misread, and reading it as granting nothing is not a "
            "safe guess (INV-01)."
        )

    principal = statement["Principal"]
    reading = _read_principal(principal, permitted_types, resource_description)
    if not reading.has_wildcard:
        return reading

    confinement = _read_principal_confinement(statement.get("Condition"), policy_service, org_id)

    return PrincipalReading(
        account_ids=reading.account_ids | confinement.account_ids,
        has_wildcard=not confinement.confining_keys,
        has_non_account_principals=reading.has_non_account_principals,
        confined_by=confinement.confining_keys,
        principal_types=reading.principal_types,
    )
