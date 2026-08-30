"""
AWS IAM role trust policy analysis.

This module contains functions for analyzing IAM roles and their trust policies,
specifically for identifying third-party account access (RCP checks).
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, List, Set
from urllib.parse import unquote

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_iam.client import IAMClient

from ...constants import AWS_ARN_ACCOUNT_ID_PATTERN, BASE_PRINCIPAL_TYPES
from ..helpers import memoize_per_session
from ..policy_documents import (
    ServicePrincipalSource,
    has_actionable_service_principal_source,
    has_not_principal,
    normalize_statements,
    read_service_principal_sources,
)

# Set up logging
logger = logging.getLogger(__name__)


class UnknownPrincipalTypeError(Exception):
    """Raised when an unknown principal type is encountered in a trust policy."""


class InvalidFederatedPrincipalError(Exception):
    """Raised when a Federated principal has sts:AssumeRole in its actions."""


class MalformedStatementError(Exception):
    """Raised when a trust policy statement names neither or both action keys."""


ALLOWED_PRINCIPAL_TYPES = BASE_PRINCIPAL_TYPES

ASSUME_ROLE_ACTION = "sts:AssumeRole"


@dataclass
class TrustPolicyAnalysis:
    """
    Analysis of an IAM role's trust policy.

    Attributes:
        role_name: Name of the IAM role
        role_arn: ARN of the IAM role
        third_party_account_ids: Set of account IDs not in the organization
        has_wildcard_principal: True if the trust policy grants to principals the
            analyzer cannot enumerate - `Principal: "*"`, or an Allow with
            NotPrincipal, which reaches everyone it does not name
        service_principal_sources: Service principals this policy trusts,
            with the cross-service source guard on each. Read by the
            deny_service_confused_deputy check; contributes nothing to this
            analysis's own third-party accounts or wildcard flag.
    """
    role_name: str
    role_arn: str
    third_party_account_ids: Set[str]
    has_wildcard_principal: bool
    service_principal_sources: List[ServicePrincipalSource] = field(default_factory=list)


def _extract_account_ids_from_principal(principal: Any) -> Set[str]:
    """
    Extract AWS account IDs from an IAM policy principal.

    Args:
        principal: Principal field from IAM policy statement (can be string, list, or dict)

    Returns:
        Set of extracted account IDs (12-digit strings)
    """
    account_ids: Set[str] = set()

    if isinstance(principal, str):
        # Handle wildcard
        if principal == "*":
            return set()
        # Extract the account ID from any principal ARN, whatever its
        # partition or service. A trust policy principal can be an STS
        # session ARN as well as an IAM one.
        arn_match = re.match(AWS_ARN_ACCOUNT_ID_PATTERN, principal)
        if arn_match:
            account_ids.add(arn_match.group(1))
        else:
            # If not an ARN, check if it's a plain 12-digit account ID
            if re.match(r'^\d{12}$', principal):
                account_ids.add(principal)
    elif isinstance(principal, list):
        for item in principal:
            account_ids.update(_extract_account_ids_from_principal(item))
    elif isinstance(principal, dict):
        # Validate that all principal types are known
        unknown_types = set(principal.keys()) - ALLOWED_PRINCIPAL_TYPES
        if unknown_types:
            raise UnknownPrincipalTypeError(
                f"Unknown principal type(s) found: {unknown_types}. "
                f"Expected one of: {ALLOWED_PRINCIPAL_TYPES}"
            )

        # Process AWS principals to extract account IDs
        if "AWS" in principal:
            value = principal["AWS"]
            if isinstance(value, str):
                account_ids.update(_extract_account_ids_from_principal(value))
            elif isinstance(value, list):
                for item in value:
                    account_ids.update(_extract_account_ids_from_principal(item))

    return account_ids


def _action_pattern_matches(pattern: str, action: str) -> bool:
    """
    Test one IAM action pattern against a concrete action name.

    IAM compares action names case-insensitively and supports two wildcards
    anywhere in the name: `*` for any run of characters and `?` for exactly
    one. Character classes are not IAM syntax, so the pattern is escaped and
    only those two wildcards are reinstated, rather than handing it to fnmatch.

    Args:
        pattern: Action pattern from a policy statement, e.g. "sts:Assume*"
        action: Concrete action name to test, e.g. "sts:AssumeRole"

    Returns:
        True if IAM would consider the pattern to cover the action
    """
    expression = re.escape(pattern.lower()).replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(expression, action.lower()) is not None


def _grants_assume_role(statement: Any, role_name: str) -> bool:
    """
    Report whether an Allow statement grants sts:AssumeRole.

    Reads whichever of Action and NotAction the statement carries. NotAction
    inverts the test: an Allow statement grants every action its NotAction
    patterns do not cover.

    Args:
        statement: One statement from a trust policy document
        role_name: Role the statement belongs to, used in error messages

    Returns:
        True if the statement's actions include sts:AssumeRole

    Raises:
        MalformedStatementError: If the statement carries both Action and
            NotAction, or neither
    """
    has_action = "Action" in statement
    has_not_action = "NotAction" in statement

    if has_action == has_not_action:
        named = "both Action and NotAction" if has_action else "neither Action nor NotAction"
        raise MalformedStatementError(
            f"Role '{role_name}' has an Allow statement naming {named}. IAM "
            "requires exactly one, so whether the statement grants "
            f"{ASSUME_ROLE_ACTION} cannot be determined, and guessing either "
            "way misstates who can assume this role."
        )

    patterns = statement["Action"] if has_action else statement["NotAction"]
    if isinstance(patterns, str):
        patterns = [patterns]

    covered = any(_action_pattern_matches(p, ASSUME_ROLE_ACTION) for p in patterns)

    return covered if has_action else not covered


def _has_wildcard_principal(principal: Any) -> bool:
    """
    Check if principal contains a wildcard.

    Args:
        principal: Principal field from IAM policy statement

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


@memoize_per_session
def analyze_iam_roles_trust_policies(
    session: Session,
    org_account_ids: Set[str],
    org_id: str
) -> List[TrustPolicyAnalysis]:
    """
    Analyze all IAM roles in an account and identify third-party account principals.

    Examines the trust policy (AssumeRole statements) of each IAM role
    and identifies account IDs that are not part of the organization.

    Args:
        session: boto3 Session for the target account
        org_account_ids: Set of all account IDs in the organization
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization

    Returns:
        List of TrustPolicyAnalysis for roles with third-party accounts or wildcards

    Raises:
        MalformedPolicyError: If a Statement is neither an object nor a list
    """
    iam_client: IAMClient = session.client("iam")
    results: List[TrustPolicyAnalysis] = []

    # List all IAM roles
    paginator = iam_client.get_paginator("list_roles")
    try:
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                role_arn = role["Arn"]

                # Get the trust policy (AssumeRolePolicyDocument)
                # The policy can be either a URL-encoded JSON string or a dict
                assume_role_policy_doc = role["AssumeRolePolicyDocument"]
                if isinstance(assume_role_policy_doc, dict):
                    trust_policy = assume_role_policy_doc
                else:
                    trust_policy_str = unquote(assume_role_policy_doc)
                    try:
                        trust_policy = json.loads(trust_policy_str)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse trust policy JSON for role '{role_name}': {e}")
                        raise

                third_party_accounts: Set[str] = set()
                has_wildcard = False
                sources: List[ServicePrincipalSource] = []

                # Analyze each statement in the trust policy
                statements = normalize_statements(trust_policy, f"Role '{role_name}'")

                for statement in statements:
                    # Only look at statements that allow AssumeRole
                    if statement.get("Effect") != "Allow":
                        continue

                    if not _grants_assume_role(statement, role_name):
                        continue

                    # An Allow with NotPrincipal reaches everyone it does not name,
                    # which is what the wildcard flag records
                    if has_not_principal(statement):
                        has_wildcard = True
                        continue

                    # Extract principal
                    principal = statement.get("Principal")
                    if not principal:
                        continue

                    sources.extend(
                        read_service_principal_sources(statement, org_account_ids, org_id, f"Role '{role_name}'")
                    )

                    # Validate that Federated principals don't have sts:AssumeRole
                    # Federated principals should use sts:AssumeRoleWithSAML or sts:AssumeRoleWithWebIdentity
                    #
                    # This stays an exact match while the gate above matches
                    # IAM's wildcards. A Federated principal paired with
                    # `sts:*` is sloppy rather than wrong - AWS will not let a
                    # federated identity call plain AssumeRole - and aborting
                    # the run over it would cost more than it catches. The
                    # literal pairing is a clearer sign of real confusion.
                    if isinstance(principal, dict) and "Federated" in principal:
                        declared_actions = statement.get("Action", [])
                        if isinstance(declared_actions, str):
                            declared_actions = [declared_actions]
                        if ASSUME_ROLE_ACTION in declared_actions:
                            raise InvalidFederatedPrincipalError(
                                f"Role '{role_name}' has Federated principal with sts:AssumeRole action. "
                                f"Federated principals should use sts:AssumeRoleWithSAML or sts:AssumeRoleWithWebIdentity."
                            )

                    # Check for wildcard
                    if _has_wildcard_principal(principal):
                        has_wildcard = True
                        # TODO: Check CloudTrail logs to find which accounts actually assume this role

                    # Extract account IDs
                    account_ids = _extract_account_ids_from_principal(principal)

                    # Filter to only third-party accounts (not in org)
                    for account_id in account_ids:
                        if account_id not in org_account_ids:
                            third_party_accounts.add(account_id)

                # Only include roles with findings
                has_service_source = has_actionable_service_principal_source(sources)
                if third_party_accounts or has_wildcard or has_service_source:
                    results.append(TrustPolicyAnalysis(
                        role_name=role_name,
                        role_arn=role_arn,
                        third_party_account_ids=third_party_accounts,
                        has_wildcard_principal=has_wildcard,
                        service_principal_sources=sources,
                    ))
    except ClientError as e:
        logger.error(f"Failed to list IAM roles from AWS API: {e}")
        raise

    return results
