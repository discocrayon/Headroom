"""
Tests for headroom.aws.rds module.

Tests for DenyRdsUnencrypted dataclass and get_rds_unencrypted_analysis function.
"""

import pytest
from unittest.mock import MagicMock
from typing import Optional

from botocore.exceptions import ClientError
from headroom.aws.rds import DenyRdsUnencrypted, get_rds_unencrypted_analysis


class TestDenyRdsUnencrypted:
    """Test DenyRdsUnencrypted dataclass with various configurations."""

    def test_deny_rds_unencrypted_instance_encrypted(self) -> None:
        """Test creating DenyRdsUnencrypted for encrypted RDS instance."""
        result = DenyRdsUnencrypted(
            db_identifier="encrypted-db",
            db_type="instance",
            region="us-east-1",
            engine="postgres",
            encrypted=True,
            db_arn="arn:aws:rds:us-east-1:111111111111:db:encrypted-db"
        )

        assert result.db_identifier == "encrypted-db"
        assert result.db_type == "instance"
        assert result.region == "us-east-1"
        assert result.engine == "postgres"
        assert result.encrypted is True
        assert result.db_arn == "arn:aws:rds:us-east-1:111111111111:db:encrypted-db"

    def test_deny_rds_unencrypted_instance_unencrypted(self) -> None:
        """Test creating DenyRdsUnencrypted for unencrypted RDS instance."""
        result = DenyRdsUnencrypted(
            db_identifier="unencrypted-db",
            db_type="instance",
            region="us-west-2",
            engine="mysql",
            encrypted=False,
            db_arn="arn:aws:rds:us-west-2:222222222222:db:unencrypted-db"
        )

        assert result.db_identifier == "unencrypted-db"
        assert result.db_type == "instance"
        assert result.region == "us-west-2"
        assert result.engine == "mysql"
        assert result.encrypted is False
        assert result.db_arn == "arn:aws:rds:us-west-2:222222222222:db:unencrypted-db"

    def test_deny_rds_unencrypted_cluster_encrypted(self) -> None:
        """Test creating DenyRdsUnencrypted for encrypted Aurora cluster."""
        result = DenyRdsUnencrypted(
            db_identifier="aurora-cluster",
            db_type="cluster",
            region="eu-west-1",
            engine="aurora-mysql",
            encrypted=True,
            db_arn="arn:aws:rds:eu-west-1:333333333333:cluster:aurora-cluster"
        )

        assert result.db_identifier == "aurora-cluster"
        assert result.db_type == "cluster"
        assert result.region == "eu-west-1"
        assert result.engine == "aurora-mysql"
        assert result.encrypted is True
        assert result.db_arn == "arn:aws:rds:eu-west-1:333333333333:cluster:aurora-cluster"

    def test_deny_rds_unencrypted_equality(self) -> None:
        """Test DenyRdsUnencrypted equality comparison."""
        result1 = DenyRdsUnencrypted(
            db_identifier="test-db",
            db_type="instance",
            region="us-east-1",
            engine="postgres",
            encrypted=True,
            db_arn="arn:aws:rds:us-east-1:111111111111:db:test-db"
        )

        result2 = DenyRdsUnencrypted(
            db_identifier="test-db",
            db_type="instance",
            region="us-east-1",
            engine="postgres",
            encrypted=True,
            db_arn="arn:aws:rds:us-east-1:111111111111:db:test-db"
        )

        result3 = DenyRdsUnencrypted(
            db_identifier="different-db",
            db_type="instance",
            region="us-east-1",
            engine="postgres",
            encrypted=True,
            db_arn="arn:aws:rds:us-east-1:111111111111:db:different-db"
        )

        assert result1 == result2
        assert result1 != result3

    def test_deny_rds_unencrypted_repr(self) -> None:
        """Test DenyRdsUnencrypted string representation."""
        result = DenyRdsUnencrypted(
            db_identifier="test-db",
            db_type="instance",
            region="us-east-1",
            engine="mysql",
            encrypted=False,
            db_arn="arn:aws:rds:us-east-1:111111111111:db:test-db"
        )

        repr_str = repr(result)
        assert "DenyRdsUnencrypted" in repr_str
        assert "test-db" in repr_str
        assert "us-east-1" in repr_str


class TestGetRdsUnencryptedAnalysis:
    """Test get_rds_unencrypted_analysis function with various scenarios."""

    def create_mock_db_instance(
        self,
        instance_id: str,
        engine: str = "postgres",
        encrypted: bool = True
    ) -> dict:
        """Helper to create mock RDS instance data."""
        return {
            "DBInstanceIdentifier": instance_id,
            "DBInstanceArn": f"arn:aws:rds:us-east-1:111111111111:db:{instance_id}",
            "Engine": engine,
            "StorageEncrypted": encrypted
        }

    def create_mock_db_cluster(
        self,
        cluster_id: str,
        engine: str = "aurora-mysql",
        encrypted: bool = True
    ) -> dict:
        """Helper to create mock Aurora cluster data."""
        return {
            "DBClusterIdentifier": cluster_id,
            "DBClusterArn": f"arn:aws:rds:us-east-1:111111111111:cluster:{cluster_id}",
            "Engine": engine,
            "StorageEncrypted": encrypted
        }

    def test_get_rds_unencrypted_analysis_success(self) -> None:
        """Test successful RDS analysis across regions with mixed encryption status."""
        mock_session = MagicMock()

        # Mock regions response
        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "us-west-2"}
            ]
        }

        # Mock regional RDS clients
        mock_regional_rds_1 = MagicMock()
        mock_regional_rds_2 = MagicMock()

        # Mock paginators for us-east-1
        mock_instance_paginator_1 = MagicMock()
        mock_cluster_paginator_1 = MagicMock()

        instances_page_1 = {
            "DBInstances": [
                self.create_mock_db_instance("encrypted-instance", encrypted=True),
                self.create_mock_db_instance("unencrypted-instance", encrypted=False, engine="mysql")
            ]
        }

        clusters_page_1 = {
            "DBClusters": [
                self.create_mock_db_cluster("encrypted-cluster", encrypted=True),
                self.create_mock_db_cluster("unencrypted-cluster", encrypted=False, engine="aurora-postgresql")
            ]
        }

        mock_instance_paginator_1.paginate.return_value = [instances_page_1]
        mock_cluster_paginator_1.paginate.return_value = [clusters_page_1]

        # Mock paginators for us-west-2
        mock_instance_paginator_2 = MagicMock()
        mock_cluster_paginator_2 = MagicMock()

        instances_page_2 = {
            "DBInstances": [
                self.create_mock_db_instance("west-instance", encrypted=True)
            ]
        }

        clusters_page_2: dict = {"DBClusters": []}

        mock_instance_paginator_2.paginate.return_value = [instances_page_2]
        mock_cluster_paginator_2.paginate.return_value = [clusters_page_2]

        # Mock get_paginator calls
        def get_paginator_1_side_effect(operation: str) -> MagicMock:
            if operation == "describe_db_instances":
                return mock_instance_paginator_1
            return mock_cluster_paginator_1

        def get_paginator_2_side_effect(operation: str) -> MagicMock:
            if operation == "describe_db_instances":
                return mock_instance_paginator_2
            return mock_cluster_paginator_2

        mock_regional_rds_1.get_paginator.side_effect = get_paginator_1_side_effect
        mock_regional_rds_2.get_paginator.side_effect = get_paginator_2_side_effect

        # Mock session.client calls
        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if service == "ec2":
                return mock_ec2
            elif region_name == "us-east-1":
                return mock_regional_rds_1
            return mock_regional_rds_2

        mock_session.client.side_effect = client_side_effect

        # Execute function
        results = get_rds_unencrypted_analysis(mock_session)

        # Verify results
        assert len(results) == 5

        # Check encrypted instance
        encrypted_instances = [r for r in results if r.db_identifier == "encrypted-instance"]
        assert len(encrypted_instances) == 1
        assert encrypted_instances[0].encrypted is True
        assert encrypted_instances[0].db_type == "instance"
        assert encrypted_instances[0].region == "us-east-1"

        # Check unencrypted instance
        unencrypted_instances = [r for r in results if r.db_identifier == "unencrypted-instance"]
        assert len(unencrypted_instances) == 1
        assert unencrypted_instances[0].encrypted is False
        assert unencrypted_instances[0].engine == "mysql"

        # Check encrypted cluster
        encrypted_clusters = [r for r in results if r.db_identifier == "encrypted-cluster"]
        assert len(encrypted_clusters) == 1
        assert encrypted_clusters[0].encrypted is True
        assert encrypted_clusters[0].db_type == "cluster"

        # Check unencrypted cluster
        unencrypted_clusters = [r for r in results if r.db_identifier == "unencrypted-cluster"]
        assert len(unencrypted_clusters) == 1
        assert unencrypted_clusters[0].encrypted is False
        assert unencrypted_clusters[0].engine == "aurora-postgresql"

    def test_get_rds_unencrypted_analysis_no_databases(self) -> None:
        """Test function with no RDS resources in any region."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_rds = MagicMock()
        mock_instance_paginator = MagicMock()
        mock_cluster_paginator = MagicMock()

        # Empty responses
        mock_instance_paginator.paginate.return_value = [{"DBInstances": []}]
        mock_cluster_paginator.paginate.return_value = [{"DBClusters": []}]

        def get_paginator_side_effect(operation: str) -> MagicMock:
            if operation == "describe_db_instances":
                return mock_instance_paginator
            return mock_cluster_paginator

        mock_regional_rds.get_paginator.side_effect = get_paginator_side_effect

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if service == "ec2":
                return mock_ec2
            return mock_regional_rds

        mock_session.client.side_effect = client_side_effect

        # Execute function
        results = get_rds_unencrypted_analysis(mock_session)

        # Verify empty results
        assert len(results) == 0
        assert results == []

    def test_get_rds_unencrypted_analysis_region_failure_raises_error(self) -> None:
        """Test that regional RDS client errors are raised."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_rds = MagicMock()
        mock_instance_paginator = MagicMock()

        # Simulate error during paginate
        mock_instance_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "DescribeDBInstances"
        )

        mock_regional_rds.get_paginator.return_value = mock_instance_paginator

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if service == "ec2":
                return mock_ec2
            return mock_regional_rds

        mock_session.client.side_effect = client_side_effect

        # Execute function - should raise ClientError
        with pytest.raises(ClientError) as exc_info:
            get_rds_unencrypted_analysis(mock_session)

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"

    def test_get_rds_unencrypted_analysis_missing_storage_encrypted_field(self) -> None:
        """Test handling of databases with missing StorageEncrypted field."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_rds = MagicMock()
        mock_instance_paginator = MagicMock()
        mock_cluster_paginator = MagicMock()

        # Instance without StorageEncrypted field (defaults to False)
        instances_page = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "no-encryption-field",
                    "DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:no-encryption-field",
                    "Engine": "postgres"
                    # Note: StorageEncrypted field is missing
                }
            ]
        }

        mock_instance_paginator.paginate.return_value = [instances_page]
        mock_cluster_paginator.paginate.return_value = [{"DBClusters": []}]

        def get_paginator_side_effect(operation: str) -> MagicMock:
            if operation == "describe_db_instances":
                return mock_instance_paginator
            return mock_cluster_paginator

        mock_regional_rds.get_paginator.side_effect = get_paginator_side_effect

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if service == "ec2":
                return mock_ec2
            return mock_regional_rds

        mock_session.client.side_effect = client_side_effect

        # Execute function
        results = get_rds_unencrypted_analysis(mock_session)

        # Verify result defaults to encrypted=False when field is missing
        assert len(results) == 1
        assert results[0].db_identifier == "no-encryption-field"
        assert results[0].encrypted is False

    def test_get_rds_unencrypted_analysis_multiple_pages(self) -> None:
        """Test function with paginated results."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_rds = MagicMock()
        mock_instance_paginator = MagicMock()
        mock_cluster_paginator = MagicMock()

        # Multiple pages of instances
        instances_page_1 = {
            "DBInstances": [
                self.create_mock_db_instance("instance-1"),
                self.create_mock_db_instance("instance-2")
            ]
        }

        instances_page_2 = {
            "DBInstances": [
                self.create_mock_db_instance("instance-3")
            ]
        }

        mock_instance_paginator.paginate.return_value = [instances_page_1, instances_page_2]
        mock_cluster_paginator.paginate.return_value = [{"DBClusters": []}]

        def get_paginator_side_effect(operation: str) -> MagicMock:
            if operation == "describe_db_instances":
                return mock_instance_paginator
            return mock_cluster_paginator

        mock_regional_rds.get_paginator.side_effect = get_paginator_side_effect

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if service == "ec2":
                return mock_ec2
            return mock_regional_rds

        mock_session.client.side_effect = client_side_effect

        # Execute function
        results = get_rds_unencrypted_analysis(mock_session)

        # Verify all instances from all pages are included
        assert len(results) == 3
        instance_ids = [r.db_identifier for r in results]
        assert "instance-1" in instance_ids
        assert "instance-2" in instance_ids
        assert "instance-3" in instance_ids
