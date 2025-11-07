"""
Tests for headroom.aws.ec2 module.

Tests for DenyImdsV1Ec2 dataclass and get_imds_v1_ec2_analysis function.
"""

import pytest
from unittest.mock import MagicMock
from typing import List, Optional

from botocore.exceptions import ClientError
from headroom.aws.ec2 import DenyImdsV1Ec2, get_imds_v1_ec2_analysis


class TestDenyImdsV1Ec2:
    """Test DenyImdsV1Ec2 dataclass with various configurations."""

    def test_deny_imds_v1_ec2_creation(self) -> None:
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

    def test_deny_imds_v1_ec2_with_exemption(self) -> None:
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

    def test_deny_imds_v1_ec2_imdsv2_enforced(self) -> None:
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

    def test_deny_imds_v1_ec2_equality(self) -> None:
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

    def test_deny_imds_v1_ec2_repr(self) -> None:
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
        metadata_state: str = "enabled",
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
                "State": metadata_state
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
                            metadata_state="disabled"
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

    def test_get_imds_v1_ec2_analysis_no_regions_fallback(self) -> None:
        """Test fallback to current region when describe_regions fails."""
        mock_session = MagicMock()
        mock_session.region_name = "us-west-1"

        # Mock EC2 client that fails on describe_regions
        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "DescribeRegions"
        )

        # Mock regional client
        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()

        instances_page = {
            "Reservations": [
                {
                    "Instances": [
                        self.create_mock_instance("i-fallback123")
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

        # Execute function
        results = get_imds_v1_ec2_analysis(mock_session)

        # Verify fallback worked
        assert len(results) == 1
        assert results[0].region == "us-west-1"
        assert results[0].instance_id == "i-fallback123"

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
