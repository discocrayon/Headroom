"""
AWS IAM analysis module.

This module contains functions for analyzing IAM roles and their trust policies.
"""

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Set
from urllib.parse import unquote

import boto3  # type: ignore

# Set up logging
logger = logging.getLogger(__name__)


class UnknownPrincipalTypeError(Exception):
    """Raised when an unknown principal type is encountered in a trust policy."""
    pass


class InvalidFederatedPrincipalError(Exception):
    """Raised when a Federated principal has sts:AssumeRole in its actions."""
    pass


ALLOWED_PRINCIPAL_TYPES = {"AWS", "Service", "Federated"}


@dataclass
class TrustPolicyAnalysis:
    """
    Analysis of an IAM role's trust policy.

    Attributes:
        role_name: Name of the IAM role
        role_arn: ARN of the IAM role
        third_party_account_ids: Set of account IDs not in the organization
        has_wildcard_principal: True if trust policy contains wildcard principals
    """
    role_name: str
    role_arn: str
    third_party_account_ids: Set[str]
    has_wildcard_principal: bool


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
        # Extract account ID from ARN format: arn:aws:iam::123456789012:*
        # The account ID is always in the 5th field (index 4) when split by ':'
        arn_match = re.match(r'^arn:aws:iam::(\d{12}):', principal)
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
        
        # Service principals (like ec2.amazonaws.com) don't contain account IDs
        # Federated principals (like SAML providers) don't contain account IDs
        # These are intentionally skipped

    return account_ids


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


def analyze_iam_roles_trust_policies(
    session: boto3.Session,
    org_account_ids: Set[str]
) -> List[TrustPolicyAnalysis]:
    """
    Analyze all IAM roles in an account and identify third-party account principals.

    Examines the trust policy (AssumeRole statements) of each IAM role
    and identifies account IDs that are not part of the organization.

    Args:
        session: boto3 Session for the target account
        org_account_ids: Set of all account IDs in the organization

    Returns:
        List of TrustPolicyAnalysis for roles with third-party accounts or wildcards
    """
    iam_client = session.client("iam")
    results: List[TrustPolicyAnalysis] = []

    try:
        # List all IAM roles
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                role_arn = role["Arn"]

                try:
                    # Get the trust policy (AssumeRolePolicyDocument)
                    # The policy is URL-encoded JSON
                    trust_policy_str = unquote(role["AssumeRolePolicyDocument"])
                    trust_policy = json.loads(trust_policy_str)

                    third_party_accounts: Set[str] = set()
                    has_wildcard = False

                    # Analyze each statement in the trust policy
                    for statement in trust_policy.get("Statement", []):
                        # Only look at statements that allow AssumeRole
                        if statement.get("Effect") != "Allow":
                            continue

                        action = statement.get("Action", [])
                        # Normalize action to list
                        if isinstance(action, str):
                            action = [action]

                        # Check if this statement allows AssumeRole
                        has_assume_role = "sts:AssumeRole" in action or "*" in action
                        if not has_assume_role:
                            continue

                        # Extract principal
                        principal = statement.get("Principal")
                        if not principal:
                            continue

                        # Validate that Federated principals don't have sts:AssumeRole
                        # Federated principals should use sts:AssumeRoleWithSAML or sts:AssumeRoleWithWebIdentity
                        if isinstance(principal, dict) and "Federated" in principal:
                            if "sts:AssumeRole" in action:
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
                    if third_party_accounts or has_wildcard:
                        results.append(TrustPolicyAnalysis(
                            role_name=role_name,
                            role_arn=role_arn,
                            third_party_account_ids=third_party_accounts,
                            has_wildcard_principal=has_wildcard
                        ))

                except UnknownPrincipalTypeError as e:
                    logger.error(f"Unknown principal type in role '{role_name}': {e}")
                    raise
                except InvalidFederatedPrincipalError as e:
                    logger.error(f"Invalid federated principal configuration in role '{role_name}': {e}")
                    raise
                except Exception as e:
                    logger.warning(f"Failed to analyze role '{role_name}': {e}")
                    continue

    except Exception as e:
        logger.error(f"Failed to analyze IAM roles: {e}")
        raise

    return results

