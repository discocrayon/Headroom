"""
Shared grammar for the IAM policy documents Headroom reads.

Resource policies and trust policies come back from every service in the
shape they were stored, so the analyzers all face the same variations. The
rules live here once rather than in each of them.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, List, Set

from ..constants import AWS_ARN_ACCOUNT_ID_PATTERN

__all__ = [
    "MalformedPolicyError",
    "ServicePrincipalSource",
    "UnknownSourceConditionError",
    "has_not_principal",
    "normalize_statements",
    "read_service_principal_sources",
]

# The cross-service source keys, lower-cased. IAM matches condition key
# names without regard to case, so a policy written `aws:sourceaccount`
# names the same key as one written `aws:SourceAccount`.
SOURCE_ACCOUNT_CONDITION_KEY = "aws:sourceaccount"
SOURCE_ARN_CONDITION_KEY = "aws:sourcearn"
SOURCE_ORG_ID_CONDITION_KEY = "aws:sourceorgid"

# Operators that pin a source to a value. Anything else on a source key is
# not a guard - a negated operator excludes rather than permits - and
# reading one as a guard would put the wrong account in the allowlist.
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

ACCOUNT_ID_PATTERN = re.compile(r"\d{12}")


class MalformedPolicyError(Exception):
    """Raised when a policy document's Statement is neither an object nor a list."""


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
    """


@dataclass
class ServicePrincipalSource:
    """
    One Allow statement's Service principal and the source guard on it.

    `source_account_ids` records only out-of-organization accounts, so an
    entry there is an allowlist requirement and an empty list means the
    statement asks nothing of the allowlist. `has_wildcard_source` marks a
    guard no allowlist can express, which is what withholds the statement
    from the account.

    Attributes:
        service_principal: The service the statement names, such as
            `sns.amazonaws.com`
        source_account_ids: Out-of-organization accounts the guard permits,
            sorted
        has_source_condition: True if any source key guards the statement
        has_wildcard_source: True if the guard names sources no allowlist
            can enumerate
    """

    service_principal: str
    source_account_ids: List[str]
    has_source_condition: bool
    has_wildcard_source: bool


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


def _read_source_guards(
    condition: Any,
    resource_description: str,
) -> tuple[List[str], List[str]]:
    """
    Return the source accounts and source ARNs a Condition block pins.

    Args:
        condition: The statement's Condition element
        resource_description: The resource this policy belongs to

    Returns:
        Tuple of (aws:SourceAccount values, aws:SourceArn values)

    Raises:
        UnknownSourceConditionError: If aws:SourceOrgID appears, or a source
            key sits under an operator that does not pin it to a value
    """
    accounts: List[str] = []
    arns: List[str] = []

    if not isinstance(condition, dict):
        return accounts, arns

    for operator, entries in condition.items():
        if not isinstance(entries, dict):
            continue

        for key, value in entries.items():
            normalized = key.lower()

            if normalized == SOURCE_ORG_ID_CONDITION_KEY:
                raise UnknownSourceConditionError(
                    f"{resource_description} guards a Service principal with "
                    f"'{key}'. Deciding whether it names this organization "
                    "needs the organization ID, which the analyzers do not "
                    "receive. Guessing would put a foreign organization's "
                    "sources in the allowlist, or leave this one's out."
                )

            if normalized == SOURCE_ACCOUNT_CONDITION_KEY:
                target = accounts
            elif normalized == SOURCE_ARN_CONDITION_KEY:
                target = arns
            else:
                continue

            if operator not in SOURCE_GUARD_OPERATORS:
                raise UnknownSourceConditionError(
                    f"{resource_description} guards a Service principal with "
                    f"'{key}' under operator '{operator}', which does not pin "
                    "the source to a value. Reading it as a guard would put "
                    "the wrong account in the allowlist."
                )

            target.extend(_as_condition_values(value, key, resource_description))

    return accounts, arns


def read_service_principal_sources(
    statement: Mapping[str, Any],
    org_account_ids: Set[str],
    resource_description: str,
) -> List[ServicePrincipalSource]:
    """
    Return the source guard on each Service principal a statement names.

    One Condition block guards every principal in its statement, so each
    service the statement names carries the same guard.

    Callers must apply their own Effect gate first. A Deny statement's
    Service principal grants nothing.

    Args:
        statement: One statement from a resource policy or trust policy
        org_account_ids: Every account ID in the organization
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

    accounts, arns = _read_source_guards(
        statement.get("Condition"), resource_description
    )

    resolved: Set[str] = set()
    has_wildcard = False

    for account in accounts:
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

    for arn in arns:
        match = re.match(AWS_ARN_ACCOUNT_ID_PATTERN, arn)
        if match:
            resolved.add(match.group(1))
        elif not accounts:
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
            has_source_condition=bool(accounts) or bool(arns),
            has_wildcard_source=has_wildcard,
        )
        for service in services
    ]
