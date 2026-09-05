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

from ...enums import PolicyService
from ..helpers import memoize_per_session
from ..policy_documents import (
    ServicePrincipalSource,
    TRUST_POLICY_PRINCIPAL_TYPES,
    has_actionable_service_principal_source,
    has_not_principal,
    normalize_actions,
    normalize_statements,
    read_service_principal_sources,
    read_statement_principals,
)

# Set up logging
logger = logging.getLogger(__name__)


class InvalidFederatedPrincipalError(Exception):
    """Raised when a Federated principal has sts:AssumeRole in its actions."""


class MalformedStatementError(Exception):
    """Raised when a trust policy statement names neither or both action keys."""


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
        confined_by: The condition keys, lower-cased, that each bounded a
            statement on their own, unioned across this policy's statements.
            Recorded whether or not the resource still blocks, and whether or
            not the statement they bounded named a wildcard.
    """
    role_name: str
    role_arn: str
    third_party_account_ids: Set[str]
    has_wildcard_principal: bool
    service_principal_sources: List[ServicePrincipalSource] = field(default_factory=list)
    confined_by: Set[str] = field(default_factory=set)


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
        TypeError: If the element it carries is neither a string nor a list
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

    covered = any(
        _action_pattern_matches(pattern, ASSUME_ROLE_ACTION)
        for pattern in normalize_actions(statement["Action"] if has_action else statement["NotAction"])
    )

    return covered if has_action else not covered


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
        MalformedPolicyError: If a Statement is neither an object nor a list,
            or a Principal is neither a string, a list, nor an object
        KeyError: If a page carries no `Roles` key. Indexed rather than
            defaulted: botocore marks `Roles` required on the response, so a
            page without it is a shape the service model forbids, and reading
            it as no roles would clear the account on a listing nobody
            read (INV-01). An account with none comes back as an empty list,
            which is a different thing and passes through
        TypeError: If a statement's Action or NotAction element is neither a
            string nor a list
    """
    iam_client: IAMClient = session.client("iam")
    results: List[TrustPolicyAnalysis] = []

    # List all IAM roles
    paginator = iam_client.get_paginator("list_roles")
    try:
        for page in paginator.paginate():
            for role in page["Roles"]:
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
                confined_by: Set[str] = set()

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

                    # A trust policy is not a resource policy, so the
                    # permitted principal keys are the trust-policy set: a
                    # canonical user ID is an Amazon S3 identifier and cannot
                    # appear here. A Federated principal can and does, and
                    # the reading's has_non_account_principals is discarded:
                    # TrustPolicyAnalysis carries no field for it.
                    #
                    # The Federated gate below is not what makes that safe.
                    # That gate is a literal membership test on the actions,
                    # so `sts:*` clears _grants_assume_role, misses the gate,
                    # and leaves no trace at all. What makes it safe is that
                    # this RCP denies sts:AssumeRole alone and a federated
                    # identity cannot call it, so the grant the RCP could
                    # break is not one a Federated principal holds. See
                    # spec/checks/rcps/deny_sts_third_party_assumerole.md.
                    reading = read_statement_principals(
                        statement, TRUST_POLICY_PRINCIPAL_TYPES, PolicyService.STS, org_id, f"Role '{role_name}'"
                    )

                    # Validate that Federated principals don't have sts:AssumeRole
                    # Federated principals should use sts:AssumeRoleWithSAML or sts:AssumeRoleWithWebIdentity
                    #
                    # This stays an exact match while _grants_assume_role
                    # matches IAM's wildcards. A Federated principal paired
                    # with `sts:*` is sloppy rather than wrong - AWS will not
                    # let a federated identity call plain AssumeRole - and
                    # aborting the run over it would cost more than it
                    # catches. The literal pairing is a clearer sign of real
                    # confusion. The principal type is read off the reading:
                    # the element itself is read in policy_documents.py alone.
                    names_federated_principal = "Federated" in reading.principal_types
                    grants_literal_assume_role = "Action" in statement and ASSUME_ROLE_ACTION in normalize_actions(statement["Action"])
                    if names_federated_principal and grants_literal_assume_role:
                        raise InvalidFederatedPrincipalError(
                            f"Role '{role_name}' has Federated principal with sts:AssumeRole action. "
                            f"Federated principals should use sts:AssumeRoleWithSAML or sts:AssumeRoleWithWebIdentity."
                        )
                    sources.extend(
                        read_service_principal_sources(statement, org_account_ids, org_id, f"Role '{role_name}'")
                    )

                    if reading.has_wildcard:
                        has_wildcard = True
                        # TODO: Check CloudTrail logs to find which accounts actually assume this role

                    confined_by.update(reading.confined_by)

                    # Filter to only third-party accounts (not in org)
                    for account_id in reading.account_ids:
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
                        confined_by=confined_by,
                    ))
    except ClientError as e:
        logger.error(f"Failed to list IAM roles from AWS API: {e}")
        raise

    return results
