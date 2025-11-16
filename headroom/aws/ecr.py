"""
AWS ECR repository policy analysis.

This module contains functions for analyzing ECR repository policies,
specifically for identifying third-party account access (RCP checks).
"""

import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_ecr.client import ECRClient
from mypy_boto3_ecr.type_defs import RepositoryTypeDef

from .helpers import get_all_regions, paginate

logger = logging.getLogger(__name__)


class UnknownPrincipalTypeError(Exception):
    """Raised when an unknown principal type is encountered in a repository policy."""


class UnsupportedPrincipalTypeError(Exception):
    """
    Raised when a principal type would break RCP deployment.

    This includes Federated principals or other types that the RCP cannot handle.
    """


ALLOWED_PRINCIPAL_TYPES = {"AWS", "Service"}
FAIL_FAST_PRINCIPAL_TYPES = {"Federated"}


@dataclass
class ECRRepositoryPolicyAnalysis:
    """
    Analysis of an ECR repository's resource policy.

    Attributes:
        repository_name: Name of the ECR repository
        repository_arn: ARN of the ECR repository
        region: AWS region where repository exists
        third_party_account_ids: Set of account IDs not in the organization
        actions_by_account: Mapping of account ID to list of ECR actions allowed
        has_wildcard_principal: True if policy contains wildcard principals
    """
    repository_name: str
    repository_arn: str
    region: str
    third_party_account_ids: Set[str]
    actions_by_account: Dict[str, List[str]] = field(default_factory=dict)
    has_wildcard_principal: bool = False


def _extract_account_ids_from_principal(principal: Any) -> Set[str]:
    """
    Extract AWS account IDs from an ECR policy principal.

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
        arn_match = re.match(r'^arn:aws:iam::(\d{12}):', principal)
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
                f"Unknown principal type(s) found in ECR policy: {unknown_types}. "
                f"Expected one of: {ALLOWED_PRINCIPAL_TYPES}"
            )

        fail_fast_types = set(principal.keys()) & FAIL_FAST_PRINCIPAL_TYPES
        if fail_fast_types:
            raise UnsupportedPrincipalTypeError(
                f"ECR repository policy contains {fail_fast_types} principal type(s). "
                f"These principal types would break if the RCP is deployed because the RCP "
                f"restricts based on aws:PrincipalAccount, which does not apply to {fail_fast_types} principals. "
                f"Remove these principals from the ECR policy before deploying the RCP."
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
    elif isinstance(action, list):
        return action
    return []


def _analyze_repository_in_region(
    ecr_client: ECRClient,
    repository: RepositoryTypeDef,
    region: str,
    org_account_ids: Set[str]
) -> ECRRepositoryPolicyAnalysis:
    """
    Analyze a single ECR repository's policy.

    Args:
        ecr_client: Boto3 ECR client
        repository: Repository dict from describe_repositories
        region: AWS region
        org_account_ids: Set of all account IDs in the organization

    Returns:
        ECRRepositoryPolicyAnalysis result for this repository

    Raises:
        UnsupportedPrincipalTypeError: If policy contains principals that would break RCP
    """
    repository_name = repository["repositoryName"]
    repository_arn = repository["repositoryArn"]

    third_party_accounts: Set[str] = set()
    actions_by_account: defaultdict[str, Set[str]] = defaultdict(set)
    has_wildcard = False

    try:
        response = ecr_client.get_repository_policy(repositoryName=repository_name)
        policy_text = response.get("policyText", "{}")
        policy = json.loads(policy_text)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "RepositoryPolicyNotFoundException":
            logger.debug(f"No policy found for repository {repository_name} in {region}")
            return ECRRepositoryPolicyAnalysis(
                repository_name=repository_name,
                repository_arn=repository_arn,
                region=region,
                third_party_account_ids=set(),
                actions_by_account={},
                has_wildcard_principal=False
            )
        raise

    for statement in policy.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal")
        if not principal:
            continue

        if _has_wildcard_principal(principal):
            has_wildcard = True

        account_ids = _extract_account_ids_from_principal(principal)

        actions = _normalize_actions(statement.get("Action", []))

        for account_id in account_ids:
            if account_id in org_account_ids:
                continue

            third_party_accounts.add(account_id)
            actions_by_account[account_id].update(actions)

    actions_by_account_serializable = {
        account_id: sorted(actions)
        for account_id, actions in actions_by_account.items()
    }

    return ECRRepositoryPolicyAnalysis(
        repository_name=repository_name,
        repository_arn=repository_arn,
        region=region,
        third_party_account_ids=third_party_accounts,
        actions_by_account=actions_by_account_serializable,
        has_wildcard_principal=has_wildcard
    )


def analyze_ecr_repository_policies(
    session: Session,
    org_account_ids: Set[str]
) -> List[ECRRepositoryPolicyAnalysis]:
    """
    Analyze all ECR repositories in an account for third-party access.

    Examines the resource policy of each ECR repository and identifies
    account IDs that are not part of the organization.

    Algorithm:
    1. Get all enabled regions via describe_regions()
    2. For each region:
       a. List all repositories via describe_repositories() (paginated)
       b. Get repository policy via get_repository_policy()
       c. Parse policy JSON
       d. Extract principals and actions
       e. Identify third-party account IDs (not in org)
       f. Track which actions each third-party account can perform
       g. Detect wildcard principals
    3. Return all results across all regions

    Args:
        session: boto3 Session for the target account
        org_account_ids: Set of all account IDs in the organization

    Returns:
        List of ECRRepositoryPolicyAnalysis for repositories with third-party
        access or wildcards

    Raises:
        ClientError: If AWS API calls fail
        UnsupportedPrincipalTypeError: If any repository policy contains principal
            types that would break RCP deployment (like Federated)
    """
    results: List[ECRRepositoryPolicyAnalysis] = []

    regions = get_all_regions(session)

    for region in regions:
        logger.info(f"Analyzing ECR repositories in {region}")
        ecr_client: ECRClient = session.client("ecr", region_name=region)

        try:
            for page in paginate(ecr_client, "describe_repositories"):
                for repository in page.get("repositories", []):
                    analysis = _analyze_repository_in_region(
                        ecr_client,
                        repository,
                        region,
                        org_account_ids
                    )

                    if analysis.third_party_account_ids or analysis.has_wildcard_principal:
                        results.append(analysis)

        except ClientError as e:
            logger.error(f"Failed to analyze ECR in region {region}: {e}")
            raise

    logger.info(
        f"Analyzed ECR repositories across {len(regions)} regions, "
        f"found {len(results)} repositories with third-party access or wildcards"
    )
    return results
