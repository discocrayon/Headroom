"""AWS EKS analysis functions for Headroom checks."""

import logging
from dataclasses import dataclass
from typing import Dict, List

from boto3.session import Session
from mypy_boto3_eks.client import EKSClient

from ..constants import EKS_PAVED_ROAD_TAG_KEY, EKS_PAVED_ROAD_TAG_VALUE
from .helpers import find_tag_value_as_iam_matches, get_all_regions

logger = logging.getLogger(__name__)


@dataclass
class DenyEksCreateClusterWithoutTag:
    """
    Data model for EKS cluster tag analysis.

    Attributes:
        cluster_name: Name of the EKS cluster
        cluster_arn: Full ARN of the cluster
        region: AWS region where cluster exists
        tags: Dictionary of all cluster tags
        has_paved_road_tag: True if PavedRoad=true tag exists
    """
    cluster_name: str
    cluster_arn: str
    region: str
    tags: Dict[str, str]
    has_paved_road_tag: bool


def get_eks_cluster_tag_analysis(
    session: Session
) -> List[DenyEksCreateClusterWithoutTag]:
    """
    Analyze EKS clusters for PavedRoad tag presence.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region:
       a. List all EKS clusters via list_clusters()
       b. For each cluster:
          - Call describe_cluster() to get details
          - Extract tags from response
          - Read the PavedRoad tag the way IAM matches the condition key
          - Create DenyEksCreateClusterWithoutTag result
    3. Return all results across all regions

    Args:
        session: boto3.Session for the target account

    Returns:
        List of DenyEksCreateClusterWithoutTag analysis results

    Raises:
        ClientError: If AWS API calls fail
    """
    all_results = []
    regions = get_all_regions(session)

    for region in regions:
        logger.debug(f"Analyzing EKS clusters in {region}")
        regional_results = _analyze_eks_in_region(session, region)
        all_results.extend(regional_results)

    logger.info(
        f"Analyzed {len(all_results)} total EKS clusters "
        f"across {len(regions)} regions"
    )
    return all_results


def _analyze_eks_in_region(
    session: Session,
    region: str
) -> List[DenyEksCreateClusterWithoutTag]:
    """
    Analyze EKS clusters in a specific region.

    Args:
        session: boto3.Session for the target account
        region: AWS region to analyze

    Returns:
        List of DenyEksCreateClusterWithoutTag results for this region

    Raises:
        ClientError: If AWS API calls fail
    """
    eks_client: EKSClient = session.client("eks", region_name=region)
    results = []

    # List all EKS clusters
    cluster_paginator = eks_client.get_paginator("list_clusters")
    for page in cluster_paginator.paginate():
        for cluster_name in page.get("clusters", []):
            result = _analyze_eks_cluster(eks_client, cluster_name, region)
            results.append(result)

    return results


def _analyze_eks_cluster(
    eks_client: EKSClient,
    cluster_name: str,
    region: str
) -> DenyEksCreateClusterWithoutTag:
    """
    Analyze single EKS cluster for PavedRoad tag.

    Args:
        eks_client: Boto3 EKS client
        cluster_name: Name of the EKS cluster
        region: AWS region

    Returns:
        DenyEksCreateClusterWithoutTag result for this cluster

    Raises:
        ClientError: If describe_cluster API call fails
        RuntimeError: If the cluster carries the paved-road tag key more than
            once, in cases that differ
    """
    response = eks_client.describe_cluster(name=cluster_name)
    cluster = response["cluster"]

    cluster_arn = cluster["arn"]
    tags = cluster.get("tags", {})

    tag_value = find_tag_value_as_iam_matches(
        tags, EKS_PAVED_ROAD_TAG_KEY, f"Cluster {cluster_name}"
    )
    has_paved_road_tag = tag_value == EKS_PAVED_ROAD_TAG_VALUE

    return DenyEksCreateClusterWithoutTag(
        cluster_name=cluster_name,
        cluster_arn=cluster_arn,
        region=region,
        tags=tags,
        has_paved_road_tag=has_paved_road_tag
    )
