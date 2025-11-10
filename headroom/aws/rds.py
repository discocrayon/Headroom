"""AWS RDS analysis functions for Headroom checks."""

import logging
import boto3
from dataclasses import dataclass
from typing import List


logger = logging.getLogger(__name__)


@dataclass
class DenyRdsUnencrypted:
    """
    Data model for RDS encryption analysis.

    Attributes:
        db_identifier: Database identifier (instance or cluster)
        db_type: Type of database ("instance" or "cluster")
        region: AWS region where database exists
        engine: Database engine (mysql, postgres, aurora, etc.)
        encrypted: True if storage encryption is enabled
        db_arn: Full ARN of the database resource
    """
    db_identifier: str
    db_type: str
    region: str
    engine: str
    encrypted: bool
    db_arn: str


def get_rds_unencrypted_analysis(
    session: boto3.Session
) -> List[DenyRdsUnencrypted]:
    """
    Analyze RDS instances and clusters for encryption configuration.

    Algorithm:
    1. Get all enabled regions from EC2
    2. For each region:
       a. Analyze RDS instances via describe_db_instances()
       b. Analyze Aurora clusters via describe_db_clusters()
       c. Check encryption status (StorageEncrypted field)
       d. Create DenyRdsUnencrypted results
    3. Return all results across all regions

    Args:
        session: boto3.Session for the target account

    Returns:
        List of DenyRdsUnencrypted analysis results

    Raises:
        ClientError: If AWS API calls fail
    """
    ec2_client = session.client("ec2")
    all_results = []

    # Get all regions (including opt-in regions that may be disabled)
    # We intentionally scan all regions to detect resources in any region
    regions_response = ec2_client.describe_regions()
    regions = [region["RegionName"] for region in regions_response["Regions"]]

    for region in regions:
        logger.info(f"Analyzing RDS resources in {region}")
        regional_results = _analyze_rds_in_region(session, region)
        all_results.extend(regional_results)

    logger.info(
        f"Analyzed {len(all_results)} total RDS resources "
        f"across {len(regions)} regions"
    )
    return all_results


def _analyze_rds_in_region(
    session: boto3.Session,
    region: str
) -> List[DenyRdsUnencrypted]:
    """
    Analyze RDS resources in a specific region.

    Args:
        session: boto3.Session for the target account
        region: AWS region to analyze

    Returns:
        List of DenyRdsUnencrypted results for this region

    Raises:
        ClientError: If AWS API calls fail
    """
    rds_client = session.client("rds", region_name=region)
    results = []

    # Analyze RDS instances
    instance_paginator = rds_client.get_paginator("describe_db_instances")
    for page in instance_paginator.paginate():
        for instance in page.get("DBInstances", []):
            result = _analyze_rds_instance(instance, region)
            results.append(result)

    # Analyze Aurora clusters
    cluster_paginator = rds_client.get_paginator("describe_db_clusters")
    for page in cluster_paginator.paginate():
        for cluster in page.get("DBClusters", []):
            result = _analyze_rds_cluster(cluster, region)
            results.append(result)

    return results


def _analyze_rds_instance(
    instance: dict,
    region: str
) -> DenyRdsUnencrypted:
    """
    Analyze single RDS instance for encryption.

    Args:
        instance: DB instance dict from describe_db_instances
        region: AWS region

    Returns:
        DenyRdsUnencrypted result for this instance
    """
    db_identifier = instance["DBInstanceIdentifier"]
    db_arn = instance["DBInstanceArn"]
    encrypted = instance.get("StorageEncrypted", False)
    engine = instance.get("Engine", "unknown")

    return DenyRdsUnencrypted(
        db_identifier=db_identifier,
        db_type="instance",
        region=region,
        engine=engine,
        encrypted=encrypted,
        db_arn=db_arn
    )


def _analyze_rds_cluster(
    cluster: dict,
    region: str
) -> DenyRdsUnencrypted:
    """
    Analyze single Aurora cluster for encryption.

    Args:
        cluster: DB cluster dict from describe_db_clusters
        region: AWS region

    Returns:
        DenyRdsUnencrypted result for this cluster
    """
    db_identifier = cluster["DBClusterIdentifier"]
    db_arn = cluster["DBClusterArn"]
    encrypted = cluster.get("StorageEncrypted", False)
    engine = cluster.get("Engine", "unknown")

    return DenyRdsUnencrypted(
        db_identifier=db_identifier,
        db_type="cluster",
        region=region,
        engine=engine,
        encrypted=encrypted,
        db_arn=db_arn
    )
