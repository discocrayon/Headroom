"""AWS RDS analysis functions for Headroom checks."""

import logging
from dataclasses import dataclass
from typing import List, Sequence
from typing import cast

from boto3.session import Session
from mypy_boto3_rds.client import RDSClient
from mypy_boto3_rds.type_defs import DBClusterTypeDef, DBInstanceTypeDef

from .helpers import get_all_regions, paginate


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
    session: Session
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
    all_results = []

    # Get all regions (including opt-in regions that may be disabled)
    # We intentionally scan all regions to detect resources in any region
    regions = get_all_regions(session)

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
    session: Session,
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
    rds_client: RDSClient = session.client("rds", region_name=region)
    results = []

    # Analyze RDS instances
    for instance_page in paginate(rds_client, "describe_db_instances"):
        instances = cast(Sequence[DBInstanceTypeDef], instance_page.get("DBInstances", []))
        for instance in instances:
            result = _analyze_rds_instance(instance, region)
            results.append(result)

    # Analyze Aurora clusters
    for cluster_page in paginate(rds_client, "describe_db_clusters"):
        clusters = cast(Sequence[DBClusterTypeDef], cluster_page.get("DBClusters", []))
        for cluster in clusters:
            result = _analyze_rds_cluster(cluster, region)
            results.append(result)

    return results


def _analyze_rds_instance(
    instance: DBInstanceTypeDef,
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
    cluster: DBClusterTypeDef,
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
