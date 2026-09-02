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
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Literal, NamedTuple, Optional, Set

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_ecr.client import ECRClient
from mypy_boto3_ecr.type_defs import RepositoryTypeDef

from ..types import JsonDict
from .helpers import get_all_regions, memoize_per_session, paginate
from .policy_documents import (
    normalize_actions,
    RESOURCE_POLICY_PRINCIPAL_TYPES,
    ServicePrincipalSource,
    has_actionable_service_principal_source,
    has_not_principal,
    normalize_statements,
    read_principal,
    read_service_principal_sources,
)

logger = logging.getLogger(__name__)


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
        has_non_account_principals: True if the policy grants to a principal
            type carrying no account ID - Federated or CanonicalUser - which
            no allowlist keyed on aws:PrincipalAccount can preserve
        service_principal_sources: Service principals this policy trusts,
            with the cross-service source guard on each. Read by the
            deny_service_confused_deputy check; contributes nothing to this
            analysis's own third-party accounts or wildcard flag.
    """
    scope: PolicyScope
    region: str
    third_party_account_ids: Set[str]
    repository_name: Optional[str] = None
    repository_arn: Optional[str] = None
    actions_by_account: Dict[str, List[str]] = field(default_factory=dict)
    has_wildcard_principal: bool = False
    has_non_account_principals: bool = False
    service_principal_sources: List[ServicePrincipalSource] = field(default_factory=list)


class PolicyFindings(NamedTuple):
    """
    What one ECR policy's statements amount to for RCP purposes.

    Attributes:
        third_party_account_ids: Account IDs the policy allows that are not
            in the organization
        actions_by_account: ECR actions each of those accounts is allowed
        has_wildcard_principal: True if the policy grants to principals the
            analyzer cannot enumerate
        has_non_account_principals: True if the policy grants to a principal
            type carrying no account ID - Federated or CanonicalUser - which
            no allowlist keyed on aws:PrincipalAccount can preserve
        service_principal_sources: Service principals this policy trusts,
            with the cross-service source guard on each. Read by the
            deny_service_confused_deputy check; contributes nothing to this
            analysis's own third-party accounts or wildcard flag.
    """
    third_party_account_ids: Set[str]
    actions_by_account: Dict[str, List[str]]
    has_wildcard_principal: bool
    has_non_account_principals: bool
    service_principal_sources: List[ServicePrincipalSource]


def _analyze_policy_statements(
    policy: JsonDict,
    context: str,
    org_account_ids: Set[str],
    org_id: str
) -> PolicyFindings:
    """
    Read the third-party grants out of one ECR policy document.

    Repository policies and registry policies share a grammar, so they share
    this reader. What differs is reach, which the caller records as scope.

    Args:
        policy: Parsed policy JSON
        context: Human-readable name for the policy, used in error messages
        org_account_ids: Set of all account IDs in the organization
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization

    Returns:
        PolicyFindings summarizing the policy's third-party grants

    Raises:
        MalformedPolicyError: If a Statement is neither an object nor a list,
            or a Principal is neither a string, a list, nor an object
    """
    third_party_accounts: Set[str] = set()
    actions_by_account: defaultdict[str, Set[str]] = defaultdict(set)
    has_wildcard = False
    has_non_account_principals = False
    sources: List[ServicePrincipalSource] = []

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

        reading = read_principal(principal, RESOURCE_POLICY_PRINCIPAL_TYPES, context)
        sources.extend(
            read_service_principal_sources(statement, org_account_ids, org_id, context)
        )

        has_non_account_principals = (
            has_non_account_principals or reading.has_non_account_principals
        )

        if reading.has_wildcard:
            has_wildcard = True

        account_ids = reading.account_ids

        actions = normalize_actions(statement.get("Action", []))

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
        has_non_account_principals=has_non_account_principals,
        service_principal_sources=sources,
    )


def _analyze_repository_in_region(
    ecr_client: ECRClient,
    repository: RepositoryTypeDef,
    region: str,
    org_account_ids: Set[str],
    org_id: str
) -> ECRPolicyAnalysis:
    """
    Analyze a single ECR repository's policy.

    Args:
        ecr_client: Boto3 ECR client
        repository: Repository dict from describe_repositories
        region: AWS region
        org_account_ids: Set of all account IDs in the organization
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization

    Returns:
        ECRPolicyAnalysis result for this repository

    Raises:
        MalformedPolicyError: If a Statement is neither an object nor a list,
            or a Principal is neither a string, a list, nor an object
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
        policy, f"Repository '{repository_name}' in {region}", org_account_ids, org_id
    )

    return ECRPolicyAnalysis(
        scope="repository",
        region=region,
        third_party_account_ids=findings.third_party_account_ids,
        repository_name=repository_name,
        repository_arn=repository_arn,
        actions_by_account=findings.actions_by_account,
        has_wildcard_principal=findings.has_wildcard_principal,
        has_non_account_principals=findings.has_non_account_principals,
        service_principal_sources=findings.service_principal_sources,
    )


def _grants_third_party_access(analysis: ECRPolicyAnalysis) -> bool:
    """
    Report whether an analysis found anything an RCP could break.

    Args:
        analysis: Result for one ECR policy

    Returns:
        True if the policy names a third-party account, a wildcard
        principal, a principal type carrying no account ID, or a service
        principal source worth allowlisting
    """
    if bool(analysis.third_party_account_ids) or analysis.has_wildcard_principal:
        return True
    if analysis.has_non_account_principals:
        return True
    return has_actionable_service_principal_source(analysis.service_principal_sources)


def _analyze_registry_policy(
    ecr_client: ECRClient,
    region: str,
    org_account_ids: Set[str],
    org_id: str
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
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization

    Returns:
        ECRPolicyAnalysis for the registry policy, or None if the region's
        registry carries no policy

    Raises:
        ClientError: If the call fails for any reason other than a missing policy
        MalformedPolicyError: If a Statement is neither an object nor a list,
            or a Principal is neither a string, a list, nor an object
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
        policy, f"Registry policy in {region}", org_account_ids, org_id
    )

    return ECRPolicyAnalysis(
        scope="registry",
        region=region,
        third_party_account_ids=findings.third_party_account_ids,
        actions_by_account=findings.actions_by_account,
        has_wildcard_principal=findings.has_wildcard_principal,
        has_non_account_principals=findings.has_non_account_principals,
        service_principal_sources=findings.service_principal_sources,
    )


@memoize_per_session
def analyze_ecr_policies(
    session: Session,
    org_account_ids: Set[str],
    org_id: str
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
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization

    Returns:
        List of ECRPolicyAnalysis for policies granting third-party access
        or naming a wildcard principal

    Raises:
        ClientError: If AWS API calls fail
    """
    results: List[ECRPolicyAnalysis] = []

    regions = get_all_regions(session)

    for region in regions:
        logger.debug(f"Analyzing ECR policies in {region}")
        ecr_client: ECRClient = session.client("ecr", region_name=region)

        try:
            # The registry policy is read first because it is the wider
            # surface: it governs every repository the region holds,
            # including repositories that carry no policy of their own
            registry_analysis = _analyze_registry_policy(
                ecr_client, region, org_account_ids, org_id
            )
            if registry_analysis is not None and _grants_third_party_access(registry_analysis):
                results.append(registry_analysis)

            for page in paginate(ecr_client, "describe_repositories"):
                for repository in page.get("repositories", []):
                    analysis = _analyze_repository_in_region(
                        ecr_client,
                        repository,
                        region,
                        org_account_ids,
                        org_id
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
