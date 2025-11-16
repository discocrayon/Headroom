"""
AWS SQS queue policy analysis.

This module contains functions for analyzing SQS queues and their resource policies,
specifically for identifying third-party account access (RCP checks).
"""

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Set

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_sqs.client import SQSClient

from ..constants import BASE_PRINCIPAL_TYPES

logger = logging.getLogger(__name__)


class UnknownPrincipalTypeError(Exception):
    """Raised when an unknown principal type is encountered in a queue policy."""


class UnsupportedPrincipalTypeError(Exception):
    """
    Raised when a queue policy contains principal types that can't be handled by RCP.

    Federated principals don't have account IDs, so the RCP
    (which uses aws:PrincipalAccount for allowlisting) would break their access.
    """


ALLOWED_PRINCIPAL_TYPES = BASE_PRINCIPAL_TYPES


@dataclass
class SQSQueuePolicyAnalysis:
    """
    Analysis of an SQS queue's resource policy.

    Attributes:
        queue_url: URL of the SQS queue
        queue_arn: ARN of the SQS queue
        region: AWS region where queue exists
        third_party_account_ids: Set of account IDs not in the organization
        has_wildcard_principal: True if policy contains wildcard principals
        has_non_account_principals: True if policy has Federated principals
        actions_by_account: Dict mapping account IDs to sets of allowed actions
    """
    queue_url: str
    queue_arn: str
    region: str
    third_party_account_ids: Set[str]
    has_wildcard_principal: bool
    has_non_account_principals: bool
    actions_by_account: Dict[str, Set[str]]


def _extract_account_ids_from_principal(principal: Any) -> Set[str]:
    """
    Extract AWS account IDs from an SQS policy principal.

    Args:
        principal: Principal field from SQS policy statement (can be string, list, or dict)

    Returns:
        Set of extracted account IDs (12-digit strings)
    """
    account_ids: Set[str] = set()

    if isinstance(principal, str):
        if principal == "*":
            return set()
        arn_match = re.match(r'^arn:aws:[^:]+:[^:]*:(\d{12}):', principal)
        if arn_match:
            account_ids.add(arn_match.group(1))
        else:
            if re.match(r'^\d{12}$', principal):
                account_ids.add(principal)
    elif isinstance(principal, list):
        for item in principal:
            account_ids.update(_extract_account_ids_from_principal(item))
    elif isinstance(principal, dict):
        unknown_types = set(principal.keys()) - ALLOWED_PRINCIPAL_TYPES
        if unknown_types:
            raise UnknownPrincipalTypeError(
                f"Unknown principal type(s) found: {unknown_types}. "
                f"Expected one of: {ALLOWED_PRINCIPAL_TYPES}"
            )

        if "AWS" in principal:
            value = principal["AWS"]
            if isinstance(value, str):
                account_ids.update(_extract_account_ids_from_principal(value))
            elif isinstance(value, list):
                for item in value:
                    account_ids.update(_extract_account_ids_from_principal(item))

    return account_ids


def _check_for_wildcard_principal(principal: Any) -> bool:
    """
    Check if principal contains wildcard (*) access.

    Args:
        principal: Principal field from policy statement

    Returns:
        True if wildcard principal found
    """
    if isinstance(principal, str):
        return principal == "*"
    if isinstance(principal, list):
        return any(_check_for_wildcard_principal(item) for item in principal)
    if isinstance(principal, dict):
        if "AWS" in principal:
            value = principal["AWS"]
            if isinstance(value, str):
                return value == "*"
            if isinstance(value, list):
                return "*" in value
    return False


def _check_for_non_account_principals(principal: Any) -> bool:
    """
    Check if principal contains Federated or other non-account principal types.

    These principals don't have aws:PrincipalAccount values, so an RCP using
    aws:PrincipalAccount for allowlisting would break their access.

    Args:
        principal: Principal field from policy statement

    Returns:
        True if Federated or other non-account principals found
    """
    if isinstance(principal, dict):
        return bool({"Federated"} & set(principal.keys()))
    return False


def _normalize_actions(actions: Any) -> Set[str]:
    """
    Normalize action field to a set of action strings.

    Args:
        actions: Action field from policy statement (string or list)

    Returns:
        Set of action strings
    """
    if isinstance(actions, str):
        return {actions}
    if isinstance(actions, list):
        return set(actions)
    return set()


def _analyze_queue_policy(
    queue_url: str,
    queue_arn: str,
    region: str,
    policy_json: str,
    org_account_ids: Set[str]
) -> SQSQueuePolicyAnalysis:
    """
    Analyze a single queue's resource policy.

    Args:
        queue_url: Queue URL
        queue_arn: Queue ARN
        region: AWS region
        policy_json: Policy JSON string
        org_account_ids: Set of organization account IDs to exclude

    Returns:
        SQSQueuePolicyAnalysis result

    Raises:
        UnknownPrincipalTypeError: If unknown principal type encountered
        UnsupportedPrincipalTypeError: If Federated principals found
    """
    policy = json.loads(policy_json)
    all_account_ids: Set[str] = set()
    actions_by_account: Dict[str, Set[str]] = {}
    has_wildcard_principal = False
    has_non_account_principals = False

    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal")
        if not principal:
            continue

        if _check_for_wildcard_principal(principal):
            has_wildcard_principal = True

        if _check_for_non_account_principals(principal):
            has_non_account_principals = True
            raise UnsupportedPrincipalTypeError(
                f"Queue {queue_arn} has Federated principal(s) in policy. "
                "RCP deployment would break this access because Federated principals "
                "don't have aws:PrincipalAccount values."
            )

        account_ids = _extract_account_ids_from_principal(principal)
        all_account_ids.update(account_ids)

        actions = _normalize_actions(statement.get("Action", []))

        for account_id in account_ids:
            if account_id not in actions_by_account:
                actions_by_account[account_id] = set()
            actions_by_account[account_id].update(actions)

    third_party_account_ids = all_account_ids - org_account_ids

    return SQSQueuePolicyAnalysis(
        queue_url=queue_url,
        queue_arn=queue_arn,
        region=region,
        third_party_account_ids=third_party_account_ids,
        has_wildcard_principal=has_wildcard_principal,
        has_non_account_principals=has_non_account_principals,
        actions_by_account=actions_by_account,
    )


def _analyze_queues_in_region(
    session: Session,
    region: str,
    org_account_ids: Set[str]
) -> List[SQSQueuePolicyAnalysis]:
    """
    Analyze SQS queues in a specific region.

    Args:
        session: boto3.Session for the target account
        region: AWS region to analyze
        org_account_ids: Set of organization account IDs to exclude

    Returns:
        List of SQSQueuePolicyAnalysis results for queues with policies
    """
    sqs_client: SQSClient = session.client("sqs", region_name=region)
    results: List[SQSQueuePolicyAnalysis] = []

    try:
        paginator = sqs_client.get_paginator("list_queues")
        for page in paginator.paginate():
            queue_urls = page.get("QueueUrls", [])

            for queue_url in queue_urls:
                try:
                    attrs = sqs_client.get_queue_attributes(
                        QueueUrl=queue_url,
                        AttributeNames=["Policy", "QueueArn"]
                    )
                    attributes = attrs.get("Attributes", {})
                    policy_json = attributes.get("Policy")
                    queue_arn = attributes.get("QueueArn", "")

                    if not policy_json:
                        continue

                    result = _analyze_queue_policy(
                        queue_url=queue_url,
                        queue_arn=queue_arn,
                        region=region,
                        policy_json=policy_json,
                        org_account_ids=org_account_ids
                    )
                    results.append(result)

                except UnsupportedPrincipalTypeError:
                    raise
                except (ClientError, json.JSONDecodeError, UnknownPrincipalTypeError) as e:
                    logger.warning(f"Failed to analyze queue {queue_url} in {region}: {e}")
                    continue

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "AccessDenied":
            logger.warning(f"Access denied listing SQS queues in region {region}")
        else:
            logger.error(f"Failed to list SQS queues in region {region}: {e}")
        return []

    return results


def analyze_sqs_queue_policies(
    session: Session,
    org_account_ids: Set[str]
) -> List[SQSQueuePolicyAnalysis]:
    """
    Analyze SQS queue policies across all regions.

    Algorithm:
    1. Get all enabled regions from EC2
    2. For each region:
       a. List all SQS queues
       b. Get queue attributes (Policy, QueueArn)
       c. Skip queues without policies
       d. Parse policy JSON
       e. Extract principal account IDs
       f. Identify wildcard principals
       g. Identify Federated principals (fail-fast if found)
       h. Map actions to account IDs
       i. Filter to third-party accounts (not in org)
    3. Return all results with third-party access or wildcards

    Args:
        session: boto3.Session for the target account
        org_account_ids: Set of organization account IDs to exclude from results

    Returns:
        List of SQSQueuePolicyAnalysis results

    Raises:
        UnsupportedPrincipalTypeError: If Federated principals found in any queue
    """
    ec2_client = session.client("ec2")
    all_results: List[SQSQueuePolicyAnalysis] = []

    regions_response = ec2_client.describe_regions()
    regions = [region["RegionName"] for region in regions_response["Regions"]]

    for region in regions:
        logger.info(f"Analyzing SQS queues in {region}")
        regional_results = _analyze_queues_in_region(session, region, org_account_ids)
        all_results.extend(regional_results)

    logger.info(
        f"Analyzed {len(all_results)} SQS queues with policies "
        f"across {len(regions)} regions"
    )
    return all_results
