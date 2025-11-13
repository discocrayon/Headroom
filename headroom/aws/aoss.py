"""
AWS OpenSearch Serverless (AOSS) analysis functions for Headroom checks.

This module analyzes AOSS data access policies to identify third-party account
access to collections and indexes.
"""

import json
import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Set

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


@dataclass
class AossResourcePolicyAnalysis:
    """
    Analysis of AOSS resource policy for third-party access.

    Attributes:
        resource_name: Collection or index name
        resource_type: Type of resource ("collection" or "index")
        resource_arn: Full ARN of the AOSS resource
        policy_name: Name of the access policy
        third_party_account_ids: Set of account IDs not in the organization
        allowed_actions: List of AOSS actions allowed for third-party accounts
    """
    resource_name: str
    resource_type: str
    resource_arn: str
    policy_name: str
    third_party_account_ids: Set[str]
    allowed_actions: List[str]


def _extract_account_ids_from_principals(principals: List[str]) -> Set[str]:
    """
    Extract AWS account IDs from AOSS policy principals.

    Algorithm:
    1. For each principal string:
       a. Check if it's an ARN format (arn:aws:iam::123456789012:*)
       b. Extract the account ID from the ARN
       c. If not an ARN, check if it's a plain 12-digit account ID
    2. Return set of unique account IDs

    Args:
        principals: List of principal strings from AOSS access policy

    Returns:
        Set of extracted account IDs (12-digit strings)
    """
    account_ids: Set[str] = set()

    for principal in principals:
        if not isinstance(principal, str):
            continue

        # Extract account ID from ARN format: arn:aws:iam::123456789012:*
        arn_match = re.match(r'^arn:aws:iam::(\d{12}):', principal)
        if arn_match:
            account_ids.add(arn_match.group(1))
            continue

        # Check if it's a plain 12-digit account ID
        if re.match(r'^\d{12}$', principal):
            account_ids.add(principal)

    return account_ids


def _analyze_access_policy(
    policy_name: str,
    policy_document: str,
    org_account_ids: Set[str],
    region: str,
    account_id: str,
) -> List[AossResourcePolicyAnalysis]:
    """
    Analyze a single AOSS access policy for third-party access.

    Algorithm:
    1. Parse policy JSON document
    2. For each rule in the policy:
       a. Extract principals (account IDs)
       b. Filter to third-party accounts (not in org)
       c. Extract permissions (actions)
       d. Extract resources (collections, indexes)
       e. Create AossResourcePolicyAnalysis for each resource
    3. Return list of analysis results

    Args:
        policy_name: Name of the access policy
        policy_document: JSON string of the policy document
        org_account_ids: Set of all account IDs in the organization
        region: AWS region
        account_id: AWS account ID being analyzed

    Returns:
        List of AossResourcePolicyAnalysis results

    Raises:
        json.JSONDecodeError: If policy document is invalid JSON
    """
    results: List[AossResourcePolicyAnalysis] = []

    try:
        policy_data = json.loads(policy_document)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse policy document for '{policy_name}': {e}")
        raise

    # AOSS policies are a list of policy statements
    if not isinstance(policy_data, list):
        logger.warning(f"Policy '{policy_name}' is not a list, skipping")
        return results

    for policy_statement in policy_data:
        if not isinstance(policy_statement, dict):
            continue

        # Extract principals
        principals = policy_statement.get("Principal", [])
        if not isinstance(principals, list):
            principals = [principals]

        # Extract account IDs from principals
        all_account_ids = _extract_account_ids_from_principals(principals)

        # Filter to third-party accounts
        third_party_accounts = {
            acc_id for acc_id in all_account_ids
            if acc_id not in org_account_ids
        }

        if not third_party_accounts:
            continue

        # Extract rules
        rules = policy_statement.get("Rules", [])
        if not isinstance(rules, list):
            rules = [rules]

        for rule in rules:
            if not isinstance(rule, dict):
                continue

            # Extract permissions (actions)
            permissions = rule.get("Permission", [])
            if not isinstance(permissions, list):
                permissions = [permissions]

            # Extract resources
            resources = rule.get("Resource", [])
            if not isinstance(resources, list):
                resources = [resources]

            resource_type = rule.get("ResourceType", "unknown")

            # Create result for each resource
            for resource in resources:
                if not isinstance(resource, str):
                    continue

                # Parse resource to determine name and type
                # Format: "collection/my-collection" or "index/my-collection/*"
                resource_name = resource
                if "/" in resource:
                    resource_name = resource.split("/", 1)[1]
                    # Remove wildcards from index paths
                    resource_name = resource_name.rstrip("/*")

                # Build ARN
                resource_arn = (
                    f"arn:aws:aoss:{region}:{account_id}:"
                    f"{resource_type}/{resource_name}"
                )

                results.append(AossResourcePolicyAnalysis(
                    resource_name=resource_name,
                    resource_type=resource_type,
                    resource_arn=resource_arn,
                    policy_name=policy_name,
                    third_party_account_ids=third_party_accounts.copy(),
                    allowed_actions=sorted(permissions),
                ))

    return results


def _analyze_aoss_in_region(
    session: boto3.Session,
    region: str,
    org_account_ids: Set[str],
) -> List[AossResourcePolicyAnalysis]:
    """
    Analyze AOSS resources in a specific region.

    Args:
        session: boto3.Session for the target account
        region: AWS region to analyze
        org_account_ids: Set of all account IDs in the organization

    Returns:
        List of AossResourcePolicyAnalysis results for this region

    Raises:
        ClientError: If AWS API calls fail
    """
    aoss_client = session.client("opensearchserverless", region_name=region)
    results: List[AossResourcePolicyAnalysis] = []

    # Get current account ID for ARN construction
    sts_client = session.client("sts")
    account_id = sts_client.get_caller_identity()["Account"]

    try:
        # List all data access policies
        paginator = aoss_client.get_paginator("list_access_policies")
        for page in paginator.paginate(type="data"):
            for policy_summary in page.get("accessPolicySummaries", []):
                policy_name = policy_summary.get("name")
                if not policy_name:
                    continue

                # Get full policy details
                try:
                    policy_response = aoss_client.get_access_policy(
                        name=policy_name,
                        type="data",
                    )
                    policy_detail = policy_response.get("accessPolicyDetail", {})
                    policy_document = policy_detail.get("policy")

                    if policy_document:
                        policy_results = _analyze_access_policy(
                            policy_name=policy_name,
                            policy_document=policy_document,
                            org_account_ids=org_account_ids,
                            region=region,
                            account_id=account_id,
                        )
                        results.extend(policy_results)

                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "")
                    if error_code == "ResourceNotFoundException":
                        logger.warning(
                            f"Access policy '{policy_name}' not found in {region}"
                        )
                    else:
                        logger.error(
                            f"Failed to get access policy '{policy_name}' "
                            f"in {region}: {e}"
                        )
                        raise

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ["InvalidParameterException", "UnrecognizedClientException"]:
            logger.info(
                f"OpenSearch Serverless not available in region {region}, skipping"
            )
            return results
        logger.error(f"Failed to analyze AOSS in region {region}: {e}")
        raise

    return results


def analyze_aoss_resource_policies(
    session: boto3.Session,
    org_account_ids: Set[str],
) -> List[AossResourcePolicyAnalysis]:
    """
    Analyze AOSS resource policies for third-party account access.

    Algorithm:
    1. Get all enabled regions via describe_regions()
    2. For each region:
       a. List all data access policies via list_access_policies()
       b. Get each policy's details via get_access_policy()
       c. Parse policy JSON to extract principals and permissions
       d. Extract account IDs from principals
       e. Filter to third-party accounts (not in org)
       f. Track which actions are allowed for each third-party account
       g. Create AossResourcePolicyAnalysis for each resource
    3. Return all findings across all regions

    Args:
        session: boto3.Session for the target account
        org_account_ids: Set of all account IDs in the organization

    Returns:
        List of AossResourcePolicyAnalysis results

    Raises:
        ClientError: If AWS API calls fail
    """
    ec2_client = session.client("ec2")
    all_results: List[AossResourcePolicyAnalysis] = []

    # Get all regions (including opt-in regions)
    regions_response = ec2_client.describe_regions()
    regions = [region["RegionName"] for region in regions_response["Regions"]]

    for region in regions:
        logger.info(f"Analyzing AOSS resources in {region}")
        regional_results = _analyze_aoss_in_region(
            session=session,
            region=region,
            org_account_ids=org_account_ids,
        )
        all_results.extend(regional_results)

    logger.info(
        f"Analyzed {len(all_results)} AOSS resources with third-party access "
        f"across {len(regions)} regions"
    )
    return all_results
