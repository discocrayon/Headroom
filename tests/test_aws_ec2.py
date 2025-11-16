"""
Tests for headroom.aws.ec2 module.

Tests for DenyImdsV1Ec2 dataclass and get_imds_v1_ec2_analysis function.
"""

import pytest
from unittest.mock import MagicMock
from typing import List, Optional

from botocore.exceptions import ClientError
from headroom.aws.ec2 import (
    DenyImdsV1Ec2,
    DenyEc2AmiOwner,
    get_imds_v1_ec2_analysis,
    get_ec2_ami_owner_analysis
)


class TestDenyImdsV1Ec2:
    """Test DenyImdsV1Ec2 dataclass with various configurations."""

    def test_deny_ec2_imds_v1_creation(self) -> None:
        """Test creating DenyImdsV1Ec2 with valid data."""
        result = DenyImdsV1Ec2(
            region="us-east-1",
            instance_id="i-1234567890abcdef0",
            imdsv1_allowed=True,
            exemption_tag_present=False
        )

        assert result.region == "us-east-1"
        assert result.instance_id == "i-1234567890abcdef0"
        assert result.imdsv1_allowed is True
        assert result.exemption_tag_present is False

    def test_deny_ec2_imds_v1_with_exemption(self) -> None:
        """Test DenyImdsV1Ec2 with exemption tag present."""
        result = DenyImdsV1Ec2(
            region="us-west-2",
            instance_id="i-0987654321fedcba0",
            imdsv1_allowed=True,
            exemption_tag_present=True
        )

        assert result.region == "us-west-2"
        assert result.instance_id == "i-0987654321fedcba0"
        assert result.imdsv1_allowed is True
        assert result.exemption_tag_present is True

    def test_deny_ec2_imds_v1_imdsv2_enforced(self) -> None:
        """Test DenyImdsV1Ec2 with IMDSv2 enforced."""
        result = DenyImdsV1Ec2(
            region="eu-west-1",
            instance_id="i-abcdef1234567890",
            imdsv1_allowed=False,
            exemption_tag_present=False
        )

        assert result.region == "eu-west-1"
        assert result.instance_id == "i-abcdef1234567890"
        assert result.imdsv1_allowed is False
        assert result.exemption_tag_present is False

    def test_deny_ec2_imds_v1_equality(self) -> None:
        """Test DenyImdsV1Ec2 equality comparison."""
        result1 = DenyImdsV1Ec2(
            region="us-east-1",
            instance_id="i-1234567890abcdef0",
            imdsv1_allowed=True,
            exemption_tag_present=False
        )

        result2 = DenyImdsV1Ec2(
            region="us-east-1",
            instance_id="i-1234567890abcdef0",
            imdsv1_allowed=True,
            exemption_tag_present=False
        )

        result3 = DenyImdsV1Ec2(
            region="us-east-1",
            instance_id="i-different",
            imdsv1_allowed=True,
            exemption_tag_present=False
        )

        assert result1 == result2
        assert result1 != result3

    def test_deny_ec2_imds_v1_repr(self) -> None:
        """Test DenyImdsV1Ec2 string representation."""
        result = DenyImdsV1Ec2(
            region="us-east-1",
            instance_id="i-1234567890abcdef0",
            imdsv1_allowed=True,
            exemption_tag_present=False
        )

        repr_str = repr(result)
        assert "DenyImdsV1Ec2" in repr_str
        assert "us-east-1" in repr_str
        assert "i-1234567890abcdef0" in repr_str


class TestGetImdsV1Ec2Analysis:
    """Test get_imds_v1_ec2_analysis function with various scenarios."""

    def create_mock_instance(
        self,
        instance_id: str,
        state: str = "running",
        http_tokens: str = "optional",
        http_endpoint: str = "enabled",
        tags: Optional[List[dict]] = None
    ) -> dict:
        """Helper to create mock EC2 instance data."""
        if tags is None:
            tags = []

        return {
            "InstanceId": instance_id,
            "State": {"Name": state},
            "MetadataOptions": {
                "HttpTokens": http_tokens,
                "HttpEndpoint": http_endpoint
            },
            "Tags": tags
        }

    def test_get_imds_v1_ec2_analysis_success(self) -> None:
        """Test successful IMDS v1 analysis across regions."""
        mock_session = MagicMock()

        # Mock regions response
        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "us-west-2"},
                {"RegionName": "eu-west-1"}  # This will trigger fallback
            ]
        }

        # Mock regional EC2 clients
        mock_regional_ec2_1 = MagicMock()
        mock_regional_ec2_2 = MagicMock()
        mock_regional_ec2_fallback = MagicMock()

        # Mock paginator responses
        mock_paginator_1 = MagicMock()
        mock_paginator_2 = MagicMock()
        mock_paginator_fallback = MagicMock()

        # Instance data for us-east-1
        instances_page_1 = {
            "Reservations": [
                {
                    "Instances": [
                        self.create_mock_instance(
                            "i-1234567890abcdef0",
                            tags=[{"Key": "Name", "Value": "test-instance-1"}]
                        ),
                        self.create_mock_instance(
                            "i-0987654321fedcba0",
                            http_tokens="required",
                            tags=[{"Key": "ExemptFromIMDSv2", "Value": "true"}]
                        )
                    ]
                }
            ]
        }

        # Instance data for us-west-2
        instances_page_2 = {
            "Reservations": [
                {
                    "Instances": [
                        self.create_mock_instance(
                            "i-abcdef1234567890",
                            http_endpoint="disabled"
                        )
                    ]
                }
            ]
        }

        # Instance data for eu-west-1 (fallback region)
        instances_page_fallback = {
            "Reservations": [
                {
                    "Instances": [
                        self.create_mock_instance(
                            "i-fallback123456789",
                            http_tokens="required"
                        )
                    ]
                }
            ]
        }

        mock_paginator_1.paginate.return_value = [instances_page_1]
        mock_paginator_2.paginate.return_value = [instances_page_2]
        mock_paginator_fallback.paginate.return_value = [instances_page_fallback]

        mock_regional_ec2_1.get_paginator.return_value = mock_paginator_1
        mock_regional_ec2_2.get_paginator.return_value = mock_paginator_2
        mock_regional_ec2_fallback.get_paginator.return_value = mock_paginator_fallback

        # Mock session.client calls
        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            elif region_name == "us-east-1":
                return mock_regional_ec2_1
            elif region_name == "us-west-2":
                return mock_regional_ec2_2
            # This covers the fallback case for eu-west-1
            return mock_regional_ec2_fallback

        mock_session.client.side_effect = client_side_effect
        mock_session.region_name = "us-east-1"

        # Execute function
        results = get_imds_v1_ec2_analysis(mock_session)

        # Verify results
        assert len(results) == 4

        # Check first instance (IMDSv1 allowed, no exemption)
        assert results[0].region == "us-east-1"
        assert results[0].instance_id == "i-1234567890abcdef0"
        assert results[0].imdsv1_allowed is True
        assert results[0].exemption_tag_present is False

        # Check second instance (IMDSv2 required, but has exemption tag)
        assert results[1].region == "us-east-1"
        assert results[1].instance_id == "i-0987654321fedcba0"
        assert results[1].imdsv1_allowed is False
        assert results[1].exemption_tag_present is True

        # Check third instance (IMDS disabled)
        assert results[2].region == "us-west-2"
        assert results[2].instance_id == "i-abcdef1234567890"
        assert results[2].imdsv1_allowed is False
        assert results[2].exemption_tag_present is False

        # Check fourth instance (fallback region, IMDSv2 required)
        assert results[3].region == "eu-west-1"
        assert results[3].instance_id == "i-fallback123456789"
        assert results[3].imdsv1_allowed is False
        assert results[3].exemption_tag_present is False

    def test_get_imds_v1_ec2_analysis_no_regions_raises_error(self) -> None:
        """Test that describe_regions failure raises ClientError."""
        mock_session = MagicMock()
        mock_session.region_name = "us-west-1"

        # Mock EC2 client that fails on describe_regions
        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "DescribeRegions"
        )

        mock_session.client.return_value = mock_ec2

        # Execute function - should raise ClientError
        with pytest.raises(ClientError) as exc_info:
            get_imds_v1_ec2_analysis(mock_session)

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"

    def test_get_imds_v1_ec2_analysis_skips_terminated_instances(self) -> None:
        """Test that terminated instances are skipped."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()

        instances_page = {
            "Reservations": [
                {
                    "Instances": [
                        self.create_mock_instance("i-running", state="running"),
                        self.create_mock_instance("i-terminated", state="terminated"),
                        self.create_mock_instance("i-stopped", state="stopped")
                    ]
                }
            ]
        }

        mock_paginator.paginate.return_value = [instances_page]
        mock_regional_ec2.get_paginator.return_value = mock_paginator

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            return mock_regional_ec2

        mock_session.client.side_effect = client_side_effect
        mock_session.region_name = "us-east-1"

        # Execute function
        results = get_imds_v1_ec2_analysis(mock_session)

        # Verify terminated instance is skipped, but others are included
        assert len(results) == 2
        instance_ids = [r.instance_id for r in results]
        assert "i-running" in instance_ids
        assert "i-stopped" in instance_ids
        assert "i-terminated" not in instance_ids

    def test_get_imds_v1_ec2_analysis_regional_client_error(self) -> None:
        """Test handling of regional client errors."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "us-west-2"},
                {"RegionName": "ap-south-1"}  # This will trigger fallback
            ]
        }

        # First regional client works
        mock_regional_ec2_1 = MagicMock()
        mock_paginator_1 = MagicMock()
        instances_page_1 = {
            "Reservations": [
                {"Instances": [self.create_mock_instance("i-success")]}
            ]
        }
        mock_paginator_1.paginate.return_value = [instances_page_1]
        mock_regional_ec2_1.get_paginator.return_value = mock_paginator_1

        # Second regional client fails
        mock_regional_ec2_2 = MagicMock()
        mock_paginator_2 = MagicMock()
        mock_paginator_2.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "DescribeInstances"
        )
        mock_regional_ec2_2.get_paginator.return_value = mock_paginator_2

        # Third regional client (fallback) works
        mock_regional_ec2_fallback = MagicMock()
        mock_paginator_fallback = MagicMock()
        instances_page_fallback = {
            "Reservations": [
                {"Instances": [self.create_mock_instance("i-fallback-success")]}
            ]
        }
        mock_paginator_fallback.paginate.return_value = [instances_page_fallback]
        mock_regional_ec2_fallback.get_paginator.return_value = mock_paginator_fallback

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            elif region_name == "us-east-1":
                return mock_regional_ec2_1
            return mock_regional_ec2_2

        mock_session.client.side_effect = client_side_effect
        mock_session.region_name = "us-east-1"

        # Execute function - should raise exception on first regional failure
        with pytest.raises(RuntimeError, match="Failed to analyze EC2 instances in region us-west-2"):
            get_imds_v1_ec2_analysis(mock_session)

    def test_get_imds_v1_ec2_analysis_exemption_tag_case_insensitive(self) -> None:
        """Test that exemption tag value is case insensitive."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()

        instances_page = {
            "Reservations": [
                {
                    "Instances": [
                        self.create_mock_instance(
                            "i-true-lower",
                            tags=[{"Key": "ExemptFromIMDSv2", "Value": "true"}]
                        ),
                        self.create_mock_instance(
                            "i-true-upper",
                            tags=[{"Key": "ExemptFromIMDSv2", "Value": "TRUE"}]
                        ),
                        self.create_mock_instance(
                            "i-true-mixed",
                            tags=[{"Key": "ExemptFromIMDSv2", "Value": "True"}]
                        ),
                        self.create_mock_instance(
                            "i-false",
                            tags=[{"Key": "ExemptFromIMDSv2", "Value": "false"}]
                        )
                    ]
                }
            ]
        }

        mock_paginator.paginate.return_value = [instances_page]
        mock_regional_ec2.get_paginator.return_value = mock_paginator

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            return mock_regional_ec2

        mock_session.client.side_effect = client_side_effect
        mock_session.region_name = "us-east-1"

        # Execute function
        results = get_imds_v1_ec2_analysis(mock_session)

        # Verify case insensitive matching
        assert len(results) == 4

        exemptions = {r.instance_id: r.exemption_tag_present for r in results}
        assert exemptions["i-true-lower"] is True
        assert exemptions["i-true-upper"] is True
        assert exemptions["i-true-mixed"] is True
        assert exemptions["i-false"] is False

    def test_get_imds_v1_ec2_analysis_no_instances(self) -> None:
        """Test function with no instances in any region."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()

        # Empty reservations
        instances_page: dict = {"Reservations": []}

        mock_paginator.paginate.return_value = [instances_page]
        mock_regional_ec2.get_paginator.return_value = mock_paginator

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            return mock_regional_ec2

        mock_session.client.side_effect = client_side_effect
        mock_session.region_name = "us-east-1"

        # Execute function
        results = get_imds_v1_ec2_analysis(mock_session)

        # Verify empty results
        assert len(results) == 0
        assert results == []

    def test_get_imds_v1_ec2_analysis_fallback_regions(self) -> None:
        """Test function with regions that need fallback client handling."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "eu-central-1"}  # This will trigger fallback
            ]
        }

        # Mock regional clients
        mock_regional_ec2_1 = MagicMock()
        mock_regional_ec2_fallback = MagicMock()

        mock_paginator_1 = MagicMock()
        mock_paginator_fallback = MagicMock()

        # Instance data for us-east-1
        instances_page_1 = {
            "Reservations": [
                {
                    "Instances": [
                        self.create_mock_instance("i-main")
                    ]
                }
            ]
        }

        # Instance data for fallback region
        instances_page_fallback = {
            "Reservations": [
                {
                    "Instances": [
                        self.create_mock_instance("i-fallback")
                    ]
                }
            ]
        }

        mock_paginator_1.paginate.return_value = [instances_page_1]
        mock_paginator_fallback.paginate.return_value = [instances_page_fallback]

        mock_regional_ec2_1.get_paginator.return_value = mock_paginator_1
        mock_regional_ec2_fallback.get_paginator.return_value = mock_paginator_fallback

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            elif region_name == "us-east-1":
                return mock_regional_ec2_1
            # This exercises the fallback path
            return mock_regional_ec2_fallback

        mock_session.client.side_effect = client_side_effect
        mock_session.region_name = "us-east-1"

        # Execute function
        results = get_imds_v1_ec2_analysis(mock_session)

        # Verify both instances are returned
        assert len(results) == 2
        instance_ids = [r.instance_id for r in results]
        assert "i-main" in instance_ids
        assert "i-fallback" in instance_ids


class TestDenyEc2AmiOwner:
    """Test DenyEc2AmiOwner dataclass with various configurations."""

    def test_deny_ec2_ami_owner_creation(self) -> None:
        """Test creating DenyEc2AmiOwner with valid data."""
        result = DenyEc2AmiOwner(
            instance_id="i-1234567890abcdef0",
            region="us-east-1",
            ami_id="ami-12345678",
            ami_owner="amazon",
            ami_name="Amazon Linux 2"
        )

        assert result.instance_id == "i-1234567890abcdef0"
        assert result.region == "us-east-1"
        assert result.ami_id == "ami-12345678"
        assert result.ami_owner == "amazon"
        assert result.ami_name == "Amazon Linux 2"

    def test_deny_ec2_ami_owner_with_none_ami_name(self) -> None:
        """Test DenyEc2AmiOwner when AMI no longer exists."""
        result = DenyEc2AmiOwner(
            instance_id="i-test",
            region="us-west-2",
            ami_id="ami-unknown",
            ami_owner="unknown",
            ami_name=None
        )

        assert result.ami_owner == "unknown"
        assert result.ami_name is None

    def test_deny_ec2_ami_owner_equality(self) -> None:
        """Test DenyEc2AmiOwner equality comparison."""
        result1 = DenyEc2AmiOwner(
            instance_id="i-test",
            region="us-east-1",
            ami_id="ami-12345678",
            ami_owner="amazon",
            ami_name="AL2"
        )

        result2 = DenyEc2AmiOwner(
            instance_id="i-test",
            region="us-east-1",
            ami_id="ami-12345678",
            ami_owner="amazon",
            ami_name="AL2"
        )

        result3 = DenyEc2AmiOwner(
            instance_id="i-different",
            region="us-east-1",
            ami_id="ami-87654321",
            ami_owner="aws-marketplace",
            ami_name="Marketplace"
        )

        assert result1 == result2
        assert result1 != result3


class TestGetEc2AmiOwnerAnalysis:
    """Test get_ec2_ami_owner_analysis function with various scenarios."""

    def create_mock_instance(
        self,
        instance_id: str,
        ami_id: str,
        owner_id: str = "111111111111",
        state: str = "running"
    ) -> dict:
        """Helper to create mock EC2 instance data."""
        return {
            "InstanceId": instance_id,
            "ImageId": ami_id,
            "OwnerId": owner_id,
            "State": {"Name": state}
        }

    def test_get_ec2_ami_owner_analysis_success(self) -> None:
        """Test successful AMI owner analysis across regions."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "us-west-2"}
            ]
        }

        mock_regional_ec2_1 = MagicMock()
        mock_regional_ec2_2 = MagicMock()

        mock_paginator_1 = MagicMock()
        mock_paginator_2 = MagicMock()

        instances_page_1 = {
            "Reservations": [
                {
                    "Instances": [
                        self.create_mock_instance("i-amazon", "ami-12345678"),
                        self.create_mock_instance("i-marketplace", "ami-87654321")
                    ]
                }
            ]
        }

        instances_page_2 = {
            "Reservations": [
                {
                    "Instances": [
                        self.create_mock_instance("i-custom", "ami-custom123")
                    ]
                }
            ]
        }

        mock_paginator_1.paginate.return_value = [instances_page_1]
        mock_paginator_2.paginate.return_value = [instances_page_2]

        mock_regional_ec2_1.get_paginator.return_value = mock_paginator_1
        mock_regional_ec2_2.get_paginator.return_value = mock_paginator_2

        mock_regional_ec2_1.describe_images.side_effect = [
            {"Images": [{"OwnerId": "amazon", "Name": "Amazon Linux 2"}]},
            {"Images": [{"OwnerId": "aws-marketplace", "Name": "Marketplace AMI"}]}
        ]

        mock_regional_ec2_2.describe_images.return_value = {
            "Images": [{"OwnerId": "222222222222", "Name": "Custom AMI"}]
        }

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            elif region_name == "us-east-1":
                return mock_regional_ec2_1
            return mock_regional_ec2_2

        mock_session.client.side_effect = client_side_effect

        results = get_ec2_ami_owner_analysis(mock_session)

        assert len(results) == 3

        assert results[0].instance_id == "i-amazon"
        assert results[0].ami_id == "ami-12345678"
        assert results[0].ami_owner == "amazon"
        assert results[0].ami_name == "Amazon Linux 2"
        assert results[0].region == "us-east-1"

        assert results[1].instance_id == "i-marketplace"
        assert results[1].ami_id == "ami-87654321"
        assert results[1].ami_owner == "aws-marketplace"
        assert results[1].region == "us-east-1"

        assert results[2].instance_id == "i-custom"
        assert results[2].ami_id == "ami-custom123"
        assert results[2].ami_owner == "222222222222"
        assert results[2].region == "us-west-2"

    def test_get_ec2_ami_owner_analysis_ami_not_found(self) -> None:
        """Test handling when AMI no longer exists - must fail fast."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()

        instances_page = {
            "Reservations": [
                {
                    "Instances": [
                        self.create_mock_instance("i-test", "ami-nonexistent")
                    ]
                }
            ]
        }

        mock_paginator.paginate.return_value = [instances_page]
        mock_regional_ec2.get_paginator.return_value = mock_paginator

        mock_regional_ec2.describe_images.side_effect = ClientError(
            {"Error": {"Code": "InvalidAMIID.NotFound", "Message": "AMI not found"}},
            "DescribeImages"
        )

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            return mock_regional_ec2

        mock_session.client.side_effect = client_side_effect

        # Must fail fast - cannot determine AMI owner
        with pytest.raises(RuntimeError, match="AMI ami-nonexistent no longer exists.*critical security check failure"):
            get_ec2_ami_owner_analysis(mock_session)

    def test_get_ec2_ami_owner_analysis_ami_access_denied(self) -> None:
        """Test handling when describe_images raises AccessDenied error."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()

        instances_page = {
            "Reservations": [
                {
                    "Instances": [
                        self.create_mock_instance("i-test", "ami-accessdenied")
                    ]
                }
            ]
        }

        mock_paginator.paginate.return_value = [instances_page]
        mock_regional_ec2.get_paginator.return_value = mock_paginator

        mock_regional_ec2.describe_images.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "DescribeImages"
        )

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            return mock_regional_ec2

        mock_session.client.side_effect = client_side_effect

        with pytest.raises(RuntimeError, match="Failed to analyze EC2 AMI owners in region us-east-1"):
            get_ec2_ami_owner_analysis(mock_session)

    def test_get_ec2_ami_owner_analysis_ami_caching(self) -> None:
        """Test that AMI information is cached to reduce API calls."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()

        instances_page = {
            "Reservations": [
                {
                    "Instances": [
                        self.create_mock_instance("i-1", "ami-same"),
                        self.create_mock_instance("i-2", "ami-same"),
                        self.create_mock_instance("i-3", "ami-same")
                    ]
                }
            ]
        }

        mock_paginator.paginate.return_value = [instances_page]
        mock_regional_ec2.get_paginator.return_value = mock_paginator

        mock_regional_ec2.describe_images.return_value = {
            "Images": [{"OwnerId": "amazon", "Name": "Amazon Linux"}]
        }

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            return mock_regional_ec2

        mock_session.client.side_effect = client_side_effect

        results = get_ec2_ami_owner_analysis(mock_session)

        assert len(results) == 3
        mock_regional_ec2.describe_images.assert_called_once()

    def test_get_ec2_ami_owner_analysis_skips_terminated_instances(self) -> None:
        """Test that terminated instances are skipped."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()

        instances_page = {
            "Reservations": [
                {
                    "Instances": [
                        self.create_mock_instance("i-running", "ami-1", state="running"),
                        self.create_mock_instance("i-terminated", "ami-2", state="terminated"),
                        self.create_mock_instance("i-stopped", "ami-3", state="stopped")
                    ]
                }
            ]
        }

        mock_paginator.paginate.return_value = [instances_page]
        mock_regional_ec2.get_paginator.return_value = mock_paginator

        mock_regional_ec2.describe_images.return_value = {
            "Images": [{"OwnerId": "amazon", "Name": "AL2"}]
        }

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            return mock_regional_ec2

        mock_session.client.side_effect = client_side_effect

        results = get_ec2_ami_owner_analysis(mock_session)

        assert len(results) == 2
        instance_ids = [r.instance_id for r in results]
        assert "i-running" in instance_ids
        assert "i-stopped" in instance_ids
        assert "i-terminated" not in instance_ids

    def test_get_ec2_ami_owner_analysis_no_ami_id(self) -> None:
        """Test handling of instances without AMI ID."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()

        instances_page = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-no-ami",
                            "OwnerId": "111111111111",
                            "State": {"Name": "running"}
                        }
                    ]
                }
            ]
        }

        mock_paginator.paginate.return_value = [instances_page]
        mock_regional_ec2.get_paginator.return_value = mock_paginator

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            return mock_regional_ec2

        mock_session.client.side_effect = client_side_effect

        results = get_ec2_ami_owner_analysis(mock_session)

        assert len(results) == 0

    def test_get_ec2_ami_owner_analysis_empty_ami_response(self) -> None:
        """Test handling when describe_images returns empty list - must fail fast."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()

        instances_page = {
            "Reservations": [
                {
                    "Instances": [
                        self.create_mock_instance("i-test", "ami-missing")
                    ]
                }
            ]
        }

        mock_paginator.paginate.return_value = [instances_page]
        mock_regional_ec2.get_paginator.return_value = mock_paginator

        mock_regional_ec2.describe_images.return_value = {"Images": []}

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            return mock_regional_ec2

        mock_session.client.side_effect = client_side_effect

        # Must fail fast - cannot determine AMI owner
        with pytest.raises(RuntimeError, match="AMI ami-missing not found.*critical security check failure"):
            get_ec2_ami_owner_analysis(mock_session)

    def test_get_ec2_ami_owner_analysis_ami_without_owner_id(self) -> None:
        """Test handling when AMI has no OwnerId field - must fail fast."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()

        instances_page = {
            "Reservations": [
                {
                    "Instances": [
                        self.create_mock_instance("i-test", "ami-no-owner")
                    ]
                }
            ]
        }

        mock_paginator.paginate.return_value = [instances_page]
        mock_regional_ec2.get_paginator.return_value = mock_paginator

        mock_regional_ec2.describe_images.return_value = {
            "Images": [{
                "ImageId": "ami-no-owner",
                "Name": "Test AMI"
            }]
        }

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            return mock_regional_ec2

        mock_session.client.side_effect = client_side_effect

        # Must fail fast - cannot determine AMI owner
        with pytest.raises(RuntimeError, match="AMI ami-no-owner.*has no OwnerId.*critical security check failure"):
            get_ec2_ami_owner_analysis(mock_session)

    def test_get_ec2_ami_owner_analysis_no_instances(self) -> None:
        """Test function with no instances in any region."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()

        instances_page: dict = {"Reservations": []}

        mock_paginator.paginate.return_value = [instances_page]
        mock_regional_ec2.get_paginator.return_value = mock_paginator

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            return mock_regional_ec2

        mock_session.client.side_effect = client_side_effect

        results = get_ec2_ami_owner_analysis(mock_session)

        assert len(results) == 0
        assert results == []

    def test_get_ec2_ami_owner_analysis_regional_client_error(self) -> None:
        """Test handling of regional client errors."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()

        mock_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "DescribeInstances"
        )

        mock_regional_ec2.get_paginator.return_value = mock_paginator

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            return mock_regional_ec2

        mock_session.client.side_effect = client_side_effect

        with pytest.raises(RuntimeError, match="Failed to analyze EC2 AMI owners in region us-east-1"):
            get_ec2_ami_owner_analysis(mock_session)
