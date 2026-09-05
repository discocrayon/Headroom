"""
AWS Secrets Manager resource policy analysis.

This module contains functions for analyzing Secrets Manager secrets and their
resource policies, specifically for identifying third-party account access (RCP checks).
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_secretsmanager.client import SecretsManagerClient

from ..enums import PolicyService
from ..types import JsonDict
from .helpers import get_all_regions, memoize_per_session
from .policy_documents import (
    normalize_actions,
    RESOURCE_POLICY_PRINCIPAL_TYPES,
    ServicePrincipalSource,
    has_actionable_service_principal_source,
    has_not_principal,
    normalize_statements,
    read_service_principal_sources,
    read_statement_principals,
)

logger = logging.getLogger(__name__)


@dataclass
class SecretsPolicyAnalysis:
    """
    Analysis of a Secrets Manager secret's resource policy.

    Attributes:
        secret_name: Name of the secret
        secret_arn: ARN of the secret
        third_party_account_ids: Set of account IDs not in the organization
        has_wildcard_principal: True if the policy grants to principals the
            analyzer cannot enumerate - `Principal: "*"`, or an Allow with
            NotPrincipal, which reaches everyone it does not name
        has_non_account_principals: True if policy has Federated/CanonicalUser principals
        actions_by_account: Dict mapping account IDs to sets of allowed actions
        service_principal_sources: Service principals this policy trusts,
            with the cross-service source guard on each. Read by the
            deny_service_confused_deputy check; contributes nothing to this
            analysis's own third-party accounts or wildcard flag.
        confined_by: The condition keys, lower-cased, that each bounded a
            statement on their own, unioned across this policy's statements.
            Recorded whether or not the resource still blocks, and whether or
            not the statement they bounded named a wildcard.
    """
    secret_name: str
    secret_arn: str
    third_party_account_ids: Set[str]
    has_wildcard_principal: bool
    has_non_account_principals: bool
    actions_by_account: Dict[str, Set[str]]
    service_principal_sources: List[ServicePrincipalSource] = field(default_factory=list)
    confined_by: Set[str] = field(default_factory=set)


@memoize_per_session
def analyze_secrets_manager_policies(
    session: Session,
    org_account_ids: Set[str],
    org_id: str
) -> List[SecretsPolicyAnalysis]:
    """
    Analyze all Secrets Manager resource policies and identify third-party account principals.

    Examines the resource policy of each secret and identifies account IDs that are
    not part of the organization.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region:
       a. List all secrets via list_secrets() paginator
       b. For each secret, get resource policy via get_resource_policy()
       c. Parse policy JSON
       d. Extract AWS principals from statements
       e. Identify third-party accounts (not in org)
       f. Track which actions each third-party account can perform
       g. Detect wildcard principals, and principals carrying no account ID
    3. Return analysis results for secrets with a finding

    Args:
        session: boto3 Session for the target account
        org_account_ids: Set of all account IDs in the organization
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization

    Returns:
        List of SecretsPolicyAnalysis for secrets with third-party accounts,
        wildcards, or principals carrying no account ID

    Raises:
        ClientError: If AWS API calls fail
        UnknownPrincipalTypeError: If a resource policy names a principal key
            AWS does not document
    """
    results: List[SecretsPolicyAnalysis] = []
    regions = get_all_regions(session)

    for region in regions:
        logger.debug(f"Analyzing Secrets Manager in {region}")
        regional_results = _analyze_secrets_in_region(session, region, org_account_ids, org_id)
        results.extend(regional_results)

    logger.info(
        f"Analyzed {len(results)} Secrets Manager secrets with third-party access "
        f"across {len(regions)} regions"
    )
    return results


def _analyze_secrets_in_region(
    session: Session,
    region: str,
    org_account_ids: Set[str],
    org_id: str
) -> List[SecretsPolicyAnalysis]:
    """
    Analyze Secrets Manager secrets in a specific region.

    Args:
        session: boto3 Session for the target account
        region: AWS region to analyze
        org_account_ids: Set of all account IDs in the organization
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard names this organization

    Returns:
        List of SecretsPolicyAnalysis results for this region

    Raises:
        ClientError: If AWS API calls fail
        UnknownPrincipalTypeError: If a resource policy names a principal key
            AWS does not document
    """
    sm_client: SecretsManagerClient = session.client("secretsmanager", region_name=region)
    results: List[SecretsPolicyAnalysis] = []

    try:
        paginator = sm_client.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                secret_name = secret["Name"]
                secret_arn = secret["ARN"]

                try:
                    policy_response = sm_client.get_resource_policy(SecretId=secret_arn)
                    policy_str = policy_response.get("ResourcePolicy")
                    if not policy_str:
                        logger.debug(f"Secret '{secret_name}' has no resource policy, skipping")
                        continue
                    policy = json.loads(policy_str)
                except ClientError as e:
                    if e.response["Error"]["Code"] == "ResourceNotFoundException":
                        logger.debug(f"Secret '{secret_name}' has no resource policy, skipping")
                        continue
                    else:
                        logger.error(f"Failed to get resource policy for secret '{secret_name}': {e}")
                        raise

                analysis_result = _analyze_secret_policy(
                    secret_name,
                    secret_arn,
                    policy,
                    org_account_ids,
                    org_id
                )

                if analysis_result:
                    results.append(analysis_result)

    except ClientError as e:
        logger.error(f"Failed to list secrets in region {region}: {e}")
        raise

    return results


def _analyze_secret_policy(
    secret_name: str,
    secret_arn: str,
    policy: JsonDict,
    org_account_ids: Set[str],
    org_id: str
) -> Optional[SecretsPolicyAnalysis]:
    """
    Analyze a single secret's resource policy.

    Args:
        secret_name: Name of the secret
        secret_arn: ARN of the secret
        policy: Parsed policy JSON
        org_account_ids: Set of all account IDs in the organization
        org_id: This organization's ID, deciding whether an
            organization scope on a source guard or on a confining
            principal key names this organization

    Returns:
        SecretsPolicyAnalysis if secret has third-party access, None otherwise

    Raises:
        UnknownPrincipalTypeError: If a statement names a principal key AWS
            does not document
        MalformedPolicyError: If a Statement is neither an object nor a list,
            or a Principal is neither a string, a list, nor an object
    """
    third_party_accounts: Set[str] = set()
    has_wildcard = False
    has_non_account_principals = False
    actions_by_account: Dict[str, Set[str]] = {}
    sources: List[ServicePrincipalSource] = []
    confined_by: Set[str] = set()

    statements = normalize_statements(policy, f"Secret '{secret_name}' ({secret_arn})")

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        # An Allow with NotPrincipal reaches everyone it does not name,
        # which is what the wildcard flag records
        if has_not_principal(statement):
            has_wildcard = True
            continue

        resource_description = f"Secret '{secret_name}' ({secret_arn})"
        reading = read_statement_principals(
            statement, RESOURCE_POLICY_PRINCIPAL_TYPES, PolicyService.SECRETS_MANAGER, org_id, resource_description
        )
        sources.extend(
            read_service_principal_sources(statement, org_account_ids, org_id, resource_description)
        )

        if reading.has_non_account_principals:
            has_non_account_principals = True

        has_wildcard = has_wildcard or reading.has_wildcard
        confined_by.update(reading.confined_by)

        account_ids = reading.account_ids
        actions = normalize_actions(statement.get("Action", []))

        for account_id in account_ids:
            if account_id not in org_account_ids:
                third_party_accounts.add(account_id)
                if account_id not in actions_by_account:
                    actions_by_account[account_id] = set()
                actions_by_account[account_id].update(actions)

    has_service_source = has_actionable_service_principal_source(sources)
    if third_party_accounts or has_wildcard or has_non_account_principals or has_service_source:
        return SecretsPolicyAnalysis(
            secret_name=secret_name,
            secret_arn=secret_arn,
            third_party_account_ids=third_party_accounts,
            has_wildcard_principal=has_wildcard,
            has_non_account_principals=has_non_account_principals,
            actions_by_account=actions_by_account,
            service_principal_sources=sources,
            confined_by=confined_by,
        )

    return None
