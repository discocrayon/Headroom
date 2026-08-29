"""
AWS ECR policy analysis.

This module contains functions for analyzing the two policy surfaces that
authorize access to a private registry - the repository policy, which governs
one repository, and the registry policy, which AWS enforces on every ECR
request in the region - specifically for identifying third-party account
access (RCP checks).
"""

import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, NamedTuple, Optional, Set

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_ecr.client import ECRClient
from mypy_boto3_ecr.type_defs import RepositoryTypeDef

from ..constants import AWS_ARN_ACCOUNT_ID_PATTERN
from ..types import JsonDict
from .helpers import get_all_regions, paginate
from .policy_documents import has_not_principal, normalize_statements

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


PolicyScope = Literal["repository", "registry"]


@dataclass
class ECRPolicyAnalysis:
    """
    Analysis of one ECR resource policy.

    ECR authorizes access through two policies rather than one, and they are
    separate resources rather than two halves of the same one, so each gets
    its own analysis. `scope` says which was read.

    Attributes:
        scope: "repository" for one repository's policy, "registry" for the
            region's registry policy, which AWS enforces on every ECR request
            in that region
        region: AWS region the policy was read from
        third_party_account_ids: Set of account IDs not in the organization
        repository_name: Name of the ECR repository, or None for a registry
            policy, which governs no single repository
        repository_arn: ARN of the ECR repository, or None for a registry policy
        actions_by_account: Mapping of account ID to list of ECR actions allowed
        has_wildcard_principal: True if the policy grants to principals the
            analyzer cannot enumerate - `Principal: "*"`, or an Allow with
            NotPrincipal, which reaches everyone it does not name
    """
    scope: PolicyScope
    region: str
    third_party_account_ids: Set[str]
    repository_name: Optional[str] = None
    repository_arn: Optional[str] = None
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


class PolicyFindings(NamedTuple):
    """
    What one ECR policy's statements amount to for RCP purposes.

    Attributes:
        third_party_account_ids: Account IDs the policy allows that are not
            in the organization
        actions_by_account: ECR actions each of those accounts is allowed
        has_wildcard_principal: True if the policy grants to principals the
            analyzer cannot enumerate
    """
    third_party_account_ids: Set[str]
    actions_by_account: Dict[str, List[str]]
    has_wildcard_principal: bool


def _analyze_policy_statements(
    policy: JsonDict,
    context: str,
    org_account_ids: Set[str]
) -> PolicyFindings:
    """
    Read the third-party grants out of one ECR policy document.

    Repository policies and registry policies share a grammar, so they share
    this reader. What differs is reach, which the caller records as scope.

    Args:
        policy: Parsed policy JSON
        context: Human-readable name for the policy, used in error messages
        org_account_ids: Set of all account IDs in the organization

    Returns:
        PolicyFindings summarizing the policy's third-party grants

    Raises:
        UnknownPrincipalTypeError: If an unknown principal type is encountered
        UnsupportedPrincipalTypeError: If policy contains principals that would break RCP
        MalformedPolicyError: If Statement is neither an object nor a list
    """
    third_party_accounts: Set[str] = set()
    actions_by_account: defaultdict[str, Set[str]] = defaultdict(set)
    has_wildcard = False

    for statement in normalize_statements(policy, context):
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

        if _has_wildcard_principal(principal):
            has_wildcard = True

        account_ids = _extract_account_ids_from_principal(principal)

        actions = _normalize_actions(statement.get("Action", []))

        for account_id in account_ids:
            if account_id in org_account_ids:
                continue

            third_party_accounts.add(account_id)
            actions_by_account[account_id].update(actions)

    return PolicyFindings(
        third_party_account_ids=third_party_accounts,
        actions_by_account={
            account_id: sorted(actions)
            for account_id, actions in actions_by_account.items()
        },
        has_wildcard_principal=has_wildcard,
    )


def _analyze_repository_in_region(
    ecr_client: ECRClient,
    repository: RepositoryTypeDef,
    region: str,
    org_account_ids: Set[str]
) -> ECRPolicyAnalysis:
    """
    Analyze a single ECR repository's policy.

    Args:
        ecr_client: Boto3 ECR client
        repository: Repository dict from describe_repositories
        region: AWS region
        org_account_ids: Set of all account IDs in the organization

    Returns:
        ECRPolicyAnalysis result for this repository

    Raises:
        UnsupportedPrincipalTypeError: If policy contains principals that would break RCP
        MalformedPolicyError: If Statement is neither an object nor a list
    """
    repository_name = repository["repositoryName"]
    repository_arn = repository["repositoryArn"]

    try:
        response = ecr_client.get_repository_policy(repositoryName=repository_name)
        policy_text = response.get("policyText", "{}")
        policy = json.loads(policy_text)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "RepositoryPolicyNotFoundException":
            logger.debug(f"No policy found for repository {repository_name} in {region}")
            return ECRPolicyAnalysis(
                scope="repository",
                region=region,
                third_party_account_ids=set(),
                repository_name=repository_name,
                repository_arn=repository_arn,
            )
        raise

    findings = _analyze_policy_statements(
        policy, f"Repository '{repository_name}' in {region}", org_account_ids
    )

    return ECRPolicyAnalysis(
        scope="repository",
        region=region,
        third_party_account_ids=findings.third_party_account_ids,
        repository_name=repository_name,
        repository_arn=repository_arn,
        actions_by_account=findings.actions_by_account,
        has_wildcard_principal=findings.has_wildcard_principal,
    )


def _grants_third_party_access(analysis: ECRPolicyAnalysis) -> bool:
    """
    Report whether an analysis found anything an RCP could break.

    Args:
        analysis: Result for one ECR policy

    Returns:
        True if the policy names a third-party account or a wildcard principal
    """
    return bool(analysis.third_party_account_ids) or analysis.has_wildcard_principal


def _analyze_registry_policy(
    ecr_client: ECRClient,
    region: str,
    org_account_ids: Set[str]
) -> Optional[ECRPolicyAnalysis]:
    """
    Analyze the registry policy for one region.

    AWS allows every ECR action in a registry policy and enforces it on every
    ECR request, so a third party named here reaches the whole registry
    without any repository policy granting it.
    Reference: https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry-permissions.html

    Args:
        ecr_client: Boto3 ECR client
        region: AWS region
        org_account_ids: Set of all account IDs in the organization

    Returns:
        ECRPolicyAnalysis for the registry policy, or None if the region's
        registry carries no policy

    Raises:
        ClientError: If the call fails for any reason other than a missing policy
        UnsupportedPrincipalTypeError: If policy contains principals that would break RCP
        MalformedPolicyError: If Statement is neither an object nor a list
    """
    try:
        response = ecr_client.get_registry_policy()
        policy_text = response.get("policyText", "{}")
        policy = json.loads(policy_text)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "RegistryPolicyNotFoundException":
            logger.debug(f"No registry policy in {region}")
            return None
        raise

    findings = _analyze_policy_statements(
        policy, f"Registry policy in {region}", org_account_ids
    )

    return ECRPolicyAnalysis(
        scope="registry",
        region=region,
        third_party_account_ids=findings.third_party_account_ids,
        actions_by_account=findings.actions_by_account,
        has_wildcard_principal=findings.has_wildcard_principal,
    )


def analyze_ecr_policies(
    session: Session,
    org_account_ids: Set[str]
) -> List[ECRPolicyAnalysis]:
    """
    Analyze an account's ECR policies for third-party access.

    Examines both surfaces that authorize ECR access - each repository's own
    policy, and the region's registry policy, which AWS enforces on every ECR
    request in that region - and identifies account IDs that are not part of
    the organization.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region:
       a. Get the registry policy via get_registry_policy()
       b. List all repositories via describe_repositories() (paginated)
       c. Get each repository policy via get_repository_policy()
       d. Parse policy JSON
       e. Extract principals and actions
       f. Identify third-party account IDs (not in org)
       g. Track which actions each third-party account can perform
       h. Detect wildcard principals
    3. Return all results across all regions

    Args:
        session: boto3 Session for the target account
        org_account_ids: Set of all account IDs in the organization

    Returns:
        List of ECRPolicyAnalysis for policies granting third-party access
        or naming a wildcard principal

    Raises:
        ClientError: If AWS API calls fail
        UnsupportedPrincipalTypeError: If any policy contains principal types
            that would break RCP deployment (like Federated)
    """
    results: List[ECRPolicyAnalysis] = []

    regions = get_all_regions(session)

    for region in regions:
        logger.info(f"Analyzing ECR policies in {region}")
        ecr_client: ECRClient = session.client("ecr", region_name=region)

        try:
            # The registry policy is read first because it is the wider
            # surface: it governs every repository the region holds,
            # including repositories that carry no policy of their own
            registry_analysis = _analyze_registry_policy(
                ecr_client, region, org_account_ids
            )
            if registry_analysis is not None and _grants_third_party_access(registry_analysis):
                results.append(registry_analysis)

            for page in paginate(ecr_client, "describe_repositories"):
                for repository in page.get("repositories", []):
                    analysis = _analyze_repository_in_region(
                        ecr_client,
                        repository,
                        region,
                        org_account_ids
                    )

                    if _grants_third_party_access(analysis):
                        results.append(analysis)

        except ClientError as e:
            logger.error(f"Failed to analyze ECR in region {region}: {e}")
            raise

    logger.info(
        f"Analyzed ECR policies across {len(regions)} regions, "
        f"found {len(results)} with third-party access or wildcards"
    )
    return results
