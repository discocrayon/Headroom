"""
Tests for headroom.aws.ec2 module.

Tests for DenyEc2ImdsV1 dataclass and get_ec2_imds_v1_analysis function.
"""

import gc
import logging

import pytest
from unittest.mock import MagicMock
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError
from headroom.aws.ec2 import (
    DenyEc2ImdsV1,
    DenyEc2AmiOwner,
    DenyEc2ImdsHopLimit,
    DenyEc2PublicIp,
    Ec2Instance,
    _INSTANCE_MEMO,
    get_ec2_imds_v1_analysis,
    get_ec2_ami_owner_analysis,
    get_ec2_imds_hop_limit_analysis,
    get_ec2_public_ip_analysis,
    get_instances,
)


class TestDenyEc2ImdsV1:
    """Test DenyEc2ImdsV1 dataclass with various configurations."""

    def test_deny_ec2_imds_v1_creation(self) -> None:
        """Test creating DenyEc2ImdsV1 with valid data."""
        result = DenyEc2ImdsV1(
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
        """Test DenyEc2ImdsV1 with exemption tag present."""
        result = DenyEc2ImdsV1(
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
        """Test DenyEc2ImdsV1 with IMDSv2 enforced."""
        result = DenyEc2ImdsV1(
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
        """Test DenyEc2ImdsV1 equality comparison."""
        result1 = DenyEc2ImdsV1(
            region="us-east-1",
            instance_id="i-1234567890abcdef0",
            imdsv1_allowed=True,
            exemption_tag_present=False
        )

        result2 = DenyEc2ImdsV1(
            region="us-east-1",
            instance_id="i-1234567890abcdef0",
            imdsv1_allowed=True,
            exemption_tag_present=False
        )

        result3 = DenyEc2ImdsV1(
            region="us-east-1",
            instance_id="i-different",
            imdsv1_allowed=True,
            exemption_tag_present=False
        )

        assert result1 == result2
        assert result1 != result3

    def test_deny_ec2_imds_v1_repr(self) -> None:
        """Test DenyEc2ImdsV1 string representation."""
        result = DenyEc2ImdsV1(
            region="us-east-1",
            instance_id="i-1234567890abcdef0",
            imdsv1_allowed=True,
            exemption_tag_present=False
        )

        repr_str = repr(result)
        assert "DenyEc2ImdsV1" in repr_str
        assert "us-east-1" in repr_str
        assert "i-1234567890abcdef0" in repr_str


class TestGetImdsV1Ec2Analysis:
    """Test get_ec2_imds_v1_analysis function with various scenarios."""

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

    def test_get_ec2_imds_v1_analysis_success(self) -> None:
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
        results = get_ec2_imds_v1_analysis(mock_session)

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

    def test_get_ec2_imds_v1_analysis_no_regions_raises_error(self) -> None:
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
            get_ec2_imds_v1_analysis(mock_session)

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"

    def test_get_ec2_imds_v1_analysis_skips_terminated_instances(self) -> None:
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
        results = get_ec2_imds_v1_analysis(mock_session)

        # Verify terminated instance is skipped, but others are included
        assert len(results) == 2
        instance_ids = [r.instance_id for r in results]
        assert "i-running" in instance_ids
        assert "i-stopped" in instance_ids
        assert "i-terminated" not in instance_ids

    def test_get_ec2_imds_v1_analysis_regional_client_error(self) -> None:
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
            get_ec2_imds_v1_analysis(mock_session)

    def test_get_ec2_imds_v1_analysis_exemption_tag_case_insensitive(self) -> None:
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
        results = get_ec2_imds_v1_analysis(mock_session)

        # Verify case insensitive matching
        assert len(results) == 4

        exemptions = {r.instance_id: r.exemption_tag_present for r in results}
        assert exemptions["i-true-lower"] is True
        assert exemptions["i-true-upper"] is True
        assert exemptions["i-true-mixed"] is True
        assert exemptions["i-false"] is False

    def test_get_ec2_imds_v1_analysis_no_instances(self) -> None:
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
        results = get_ec2_imds_v1_analysis(mock_session)

        # Verify empty results
        assert len(results) == 0
        assert results == []

    def test_get_ec2_imds_v1_analysis_fallback_regions(self) -> None:
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
        results = get_ec2_imds_v1_analysis(mock_session)

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
        state: str = "running"
    ) -> dict:
        """Helper to create mock EC2 instance data."""
        return {
            "InstanceId": instance_id,
            "ImageId": ami_id,
            "State": {"Name": state}
        }

    def build_single_region_session(
        self,
        instances: List[dict],
        region: str = "us-east-1",
    ) -> tuple[MagicMock, MagicMock]:
        """
        Build a mock session serving `instances` from a single region.

        Returns:
            Tuple of (session, regional EC2 client) so tests can drive and
            assert on describe_images directly.
        """
        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {"Regions": [{"RegionName": region}]}

        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"Reservations": [{"OwnerId": "111111111111", "Instances": instances}]}
        ]
        mock_regional_ec2.get_paginator.return_value = mock_paginator

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            return mock_regional_ec2

        mock_session = MagicMock()
        mock_session.client.side_effect = client_side_effect
        return mock_session, mock_regional_ec2

    def test_get_ec2_ami_owner_analysis_asks_for_hidden_amis_up_front(self) -> None:
        """The single lookup asks for disabled and deprecated images."""
        mock_session, mock_regional_ec2 = self.build_single_region_session(
            [self.create_mock_instance("i-11111111111111111", "ami-11111111111111111")]
        )
        mock_regional_ec2.describe_images.return_value = {
            "Images": [{"OwnerId": "amazon", "Name": "old-al2"}]
        }

        get_ec2_ami_owner_analysis(mock_session)

        mock_regional_ec2.describe_images.assert_called_once_with(
            ImageIds=["ami-11111111111111111"],
            IncludeDisabled=True,
            IncludeDeprecated=True,
        )

    def resolve_single_ami(
        self,
        image: dict,
        caplog: pytest.LogCaptureFixture,
    ) -> tuple[list, str]:
        """
        Run the analysis against one instance whose AMI describes as `image`.

        Returns:
            Tuple of (results, captured log text)
        """
        mock_session, mock_regional_ec2 = self.build_single_region_session(
            [self.create_mock_instance("i-11111111111111111", "ami-11111111111111111")]
        )
        mock_regional_ec2.describe_images.return_value = {"Images": [image]}

        with caplog.at_level(logging.WARNING):
            results = get_ec2_ami_owner_analysis(mock_session)

        return results, caplog.text

    def test_get_ec2_ami_owner_analysis_resolves_owner_of_disabled_ami(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """An AMI turned off with DisableImage still yields its owner."""
        results, _ = self.resolve_single_ami(
            {"OwnerId": "333333333333", "Name": "golden-base", "State": "disabled"},
            caplog,
        )

        assert results[0].ami_owner == "333333333333"
        assert results[0].ami_name == "golden-base"
        assert results[0].owner_unknown_reason is None

    def test_get_ec2_ami_owner_analysis_warns_that_an_ami_is_disabled(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A non-available AMI state is worth reporting even though the owner resolved."""
        _, log = self.resolve_single_ami(
            {"OwnerId": "333333333333", "Name": "golden-base", "State": "disabled"},
            caplog,
        )

        assert "ami-11111111111111111" in log
        assert "disabled" in log

    def test_get_ec2_ami_owner_analysis_resolves_owner_of_deprecated_ami(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A deprecated AMI resolves to its owner and is not worth a warning."""
        results, log = self.resolve_single_ami(
            {
                "OwnerId": "amazon",
                "Name": "old-al2",
                "State": "available",
                "DeprecationTime": "2024-01-01T00:00:00.000Z",
            },
            caplog,
        )

        assert results[0].ami_owner == "amazon"
        assert results[0].owner_unknown_reason is None
        assert log == ""

    def test_get_ec2_ami_owner_analysis_records_ami_hidden_from_this_account(self) -> None:
        """An AMI the include flags do not surface is recorded, not raised."""
        mock_session, mock_regional_ec2 = self.build_single_region_session(
            [self.create_mock_instance("i-11111111111111111", "ami-11111111111111111")]
        )
        mock_regional_ec2.describe_images.return_value = {"Images": []}

        results = get_ec2_ami_owner_analysis(mock_session)

        assert len(results) == 1
        assert results[0].ami_id == "ami-11111111111111111"
        assert results[0].ami_owner is None
        assert results[0].ami_name is None
        assert results[0].owner_unknown_reason == "not_visible"

    def test_get_ec2_ami_owner_analysis_records_deregistered_ami(self) -> None:
        """InvalidAMIID.NotFound is recorded as a deregistered AMI, not raised."""
        mock_session, mock_regional_ec2 = self.build_single_region_session(
            [self.create_mock_instance("i-11111111111111111", "ami-11111111111111111")]
        )
        mock_regional_ec2.describe_images.side_effect = ClientError(
            {"Error": {"Code": "InvalidAMIID.NotFound", "Message": "AMI not found"}},
            "DescribeImages"
        )

        results = get_ec2_ami_owner_analysis(mock_session)

        assert len(results) == 1
        assert results[0].ami_owner is None
        assert results[0].owner_unknown_reason == "deregistered"

    def test_get_ec2_ami_owner_analysis_records_unavailable_ami_as_deregistered(self) -> None:
        """InvalidAMIID.Unavailable is the deregistration signal AWS returns for some AMIs."""
        mock_session, mock_regional_ec2 = self.build_single_region_session(
            [self.create_mock_instance("i-11111111111111111", "ami-11111111111111111")]
        )
        mock_regional_ec2.describe_images.side_effect = ClientError(
            {"Error": {"Code": "InvalidAMIID.Unavailable", "Message": "AMI unavailable"}},
            "DescribeImages"
        )

        results = get_ec2_ami_owner_analysis(mock_session)

        assert len(results) == 1
        assert results[0].ami_owner is None
        assert results[0].owner_unknown_reason == "deregistered"

    def test_get_ec2_ami_owner_analysis_caches_unresolvable_ami(self) -> None:
        """An unresolvable AMI is looked up once, not once per instance using it."""
        mock_session, mock_regional_ec2 = self.build_single_region_session([
            self.create_mock_instance("i-11111111111111111", "ami-11111111111111111"),
            self.create_mock_instance("i-22222222222222222", "ami-11111111111111111"),
            self.create_mock_instance("i-33333333333333333", "ami-11111111111111111"),
        ])
        mock_regional_ec2.describe_images.return_value = {"Images": []}

        results = get_ec2_ami_owner_analysis(mock_session)

        assert len(results) == 3
        assert all(r.owner_unknown_reason == "not_visible" for r in results)
        assert mock_regional_ec2.describe_images.call_count == 1

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
                    "OwnerId": "111111111111",
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
                    "OwnerId": "111111111111",
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

    def test_get_ec2_ami_owner_analysis_ami_access_denied(self) -> None:
        """
        A describe_images failure propagates as ClientError, not RuntimeError.

        Before the shared collector, get_ec2_ami_owner_analysis wrapped its
        whole body -- describe_instances and describe_images alike -- in one
        try/except ClientError that raised a "Failed to analyze EC2 AMI
        owners" RuntimeError. describe_instances failures now raise from
        inside _describe_instances instead (see
        test_get_ec2_ami_owner_analysis_regional_client_error), and nothing
        in this function wraps describe_images any more, so
        _resolve_ami_owner's documented ClientError (see its docstring)
        reaches the caller unwrapped. The run still aborts either way; what
        changes is the exception type and that the region name is no longer
        folded into the message. Confirmed acceptable for this task -- see
        task-2-report.md.
        """
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
                    "OwnerId": "111111111111",
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

        with pytest.raises(ClientError) as exc_info:
            get_ec2_ami_owner_analysis(mock_session)

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"

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
                    "OwnerId": "111111111111",
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
                    "OwnerId": "111111111111",
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
                    "OwnerId": "111111111111",
                    "Instances": [
                        {
                            "InstanceId": "i-no-ami",
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
                    "OwnerId": "111111111111",
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
        """
        A describe_instances failure still aborts the run with the region named.

        The message text changed from "Failed to analyze EC2 AMI owners" to
        the shared collector's "Failed to analyze EC2 instances": this check
        no longer has its own describe_instances error handling, it reads
        get_instances()'s RuntimeError instead. See _describe_instances in
        ec2.py, and test_client_error_becomes_a_runtime_error_naming_the_region
        in TestGetInstances for the collector-level test this now defers to.
        """
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

        with pytest.raises(RuntimeError, match="Failed to analyze EC2 instances in region us-east-1"):
            get_ec2_ami_owner_analysis(mock_session)


class TestDenyEc2PublicIp:
    """Test DenyEc2PublicIp dataclass with various configurations."""

    def test_deny_ec2_public_ip_creation(self) -> None:
        """Test creating DenyEc2PublicIp with valid data."""
        result = DenyEc2PublicIp(
            instance_id="i-1234567890abcdef0",
            region="us-east-1",
            public_ip_address="54.123.45.67",
            has_public_ip=True,
            instance_arn="arn:aws:ec2:us-east-1:111111111111:instance/i-1234567890abcdef0"
        )

        assert result.instance_id == "i-1234567890abcdef0"
        assert result.region == "us-east-1"
        assert result.public_ip_address == "54.123.45.67"
        assert result.has_public_ip is True
        assert result.instance_arn == "arn:aws:ec2:us-east-1:111111111111:instance/i-1234567890abcdef0"

    def test_deny_ec2_public_ip_without_public_ip(self) -> None:
        """Test DenyEc2PublicIp without public IP address."""
        result = DenyEc2PublicIp(
            instance_id="i-0987654321fedcba0",
            region="us-west-2",
            public_ip_address=None,
            has_public_ip=False,
            instance_arn="arn:aws:ec2:us-west-2:111111111111:instance/i-0987654321fedcba0"
        )

        assert result.instance_id == "i-0987654321fedcba0"
        assert result.region == "us-west-2"
        assert result.public_ip_address is None
        assert result.has_public_ip is False

    def test_deny_ec2_public_ip_equality(self) -> None:
        """Test DenyEc2PublicIp equality comparison."""
        result1 = DenyEc2PublicIp(
            instance_id="i-1234567890abcdef0",
            region="us-east-1",
            public_ip_address="54.123.45.67",
            has_public_ip=True,
            instance_arn="arn:aws:ec2:us-east-1:111111111111:instance/i-1234567890abcdef0"
        )

        result2 = DenyEc2PublicIp(
            instance_id="i-1234567890abcdef0",
            region="us-east-1",
            public_ip_address="54.123.45.67",
            has_public_ip=True,
            instance_arn="arn:aws:ec2:us-east-1:111111111111:instance/i-1234567890abcdef0"
        )

        result3 = DenyEc2PublicIp(
            instance_id="i-different",
            region="us-east-1",
            public_ip_address=None,
            has_public_ip=False,
            instance_arn="arn:aws:ec2:us-east-1:111111111111:instance/i-different"
        )

        assert result1 == result2
        assert result1 != result3


class TestGetEc2PublicIpAnalysis:
    """Test get_ec2_public_ip_analysis function with various scenarios."""

    def create_mock_instance_with_ip(
        self,
        instance_id: str,
        state: str = "running",
        public_ip: Optional[str] = None
    ) -> dict:
        """Helper to create mock EC2 instance data."""
        instance_dict = {
            "InstanceId": instance_id,
            "State": {"Name": state},
        }

        if public_ip is not None:
            instance_dict["PublicIpAddress"] = public_ip

        return instance_dict

    def test_get_ec2_public_ip_analysis_success(self) -> None:
        """Test successful EC2 public IP analysis across regions."""
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
                    "OwnerId": "111111111111",
                    "Instances": [
                        self.create_mock_instance_with_ip(
                            "i-1111111111111111",
                            public_ip="54.123.45.67"
                        ),
                        self.create_mock_instance_with_ip(
                            "i-2222222222222222",
                            public_ip=None
                        )
                    ]
                }
            ]
        }

        instances_page_2 = {
            "Reservations": [
                {
                    "OwnerId": "111111111111",
                    "Instances": [
                        self.create_mock_instance_with_ip(
                            "i-3333333333333333",
                            public_ip="52.98.76.54"
                        )
                    ]
                }
            ]
        }

        mock_paginator_1.paginate.return_value = [instances_page_1]
        mock_paginator_2.paginate.return_value = [instances_page_2]

        mock_regional_ec2_1.get_paginator.return_value = mock_paginator_1
        mock_regional_ec2_2.get_paginator.return_value = mock_paginator_2

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            elif region_name == "us-east-1":
                return mock_regional_ec2_1
            return mock_regional_ec2_2

        mock_session.client.side_effect = client_side_effect

        results = get_ec2_public_ip_analysis(mock_session)

        assert len(results) == 3

        assert results[0].instance_id == "i-1111111111111111"
        assert results[0].region == "us-east-1"
        assert results[0].public_ip_address == "54.123.45.67"
        assert results[0].has_public_ip is True

        assert results[1].instance_id == "i-2222222222222222"
        assert results[1].region == "us-east-1"
        assert results[1].public_ip_address is None
        assert results[1].has_public_ip is False

        assert results[2].instance_id == "i-3333333333333333"
        assert results[2].region == "us-west-2"
        assert results[2].public_ip_address == "52.98.76.54"
        assert results[2].has_public_ip is True

    def test_get_ec2_public_ip_analysis_skips_terminated_instances(self) -> None:
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
                    "OwnerId": "111111111111",
                    "Instances": [
                        self.create_mock_instance_with_ip(
                            "i-running",
                            state="running",
                            public_ip="54.123.45.67"
                        ),
                        self.create_mock_instance_with_ip(
                            "i-terminated",
                            state="terminated",
                            public_ip="52.98.76.54"
                        ),
                        self.create_mock_instance_with_ip(
                            "i-stopped",
                            state="stopped",
                            public_ip=None
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

        results = get_ec2_public_ip_analysis(mock_session)

        assert len(results) == 2
        instance_ids = [r.instance_id for r in results]
        assert "i-running" in instance_ids
        assert "i-stopped" in instance_ids
        assert "i-terminated" not in instance_ids

    def test_get_ec2_public_ip_analysis_no_instances(self) -> None:
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

        results = get_ec2_public_ip_analysis(mock_session)

        assert len(results) == 0
        assert results == []

    def test_get_ec2_public_ip_analysis_regional_client_error(self) -> None:
        """Test handling of regional client errors."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "us-west-2"}
            ]
        }

        mock_regional_ec2_1 = MagicMock()
        mock_paginator_1 = MagicMock()
        instances_page_1 = {
            "Reservations": [
                {
                    "OwnerId": "111111111111",
                    "Instances": [self.create_mock_instance_with_ip("i-success", public_ip="54.123.45.67")],
                }
            ]
        }
        mock_paginator_1.paginate.return_value = [instances_page_1]
        mock_regional_ec2_1.get_paginator.return_value = mock_paginator_1

        mock_regional_ec2_2 = MagicMock()
        mock_paginator_2 = MagicMock()
        mock_paginator_2.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "DescribeInstances"
        )
        mock_regional_ec2_2.get_paginator.return_value = mock_paginator_2

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            elif region_name == "us-east-1":
                return mock_regional_ec2_1
            return mock_regional_ec2_2

        mock_session.client.side_effect = client_side_effect

        with pytest.raises(RuntimeError, match="Failed to analyze EC2 instances in region us-west-2"):
            get_ec2_public_ip_analysis(mock_session)

    def test_get_ec2_public_ip_analysis_constructs_arn_correctly(self) -> None:
        """Test that ARN is constructed correctly."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "eu-west-1"}]
        }

        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()

        instances_page = {
            "Reservations": [
                {
                    "OwnerId": "222222222222",
                    "Instances": [
                        self.create_mock_instance_with_ip(
                            "i-test123456789",
                            public_ip="54.123.45.67"
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

        results = get_ec2_public_ip_analysis(mock_session)

        assert len(results) == 1
        assert results[0].instance_arn == "arn:aws:ec2:eu-west-1:222222222222:instance/i-test123456789"


class TestDenyEc2ImdsHopLimit:
    """Test DenyEc2ImdsHopLimit dataclass."""

    def test_deny_ec2_imds_hop_limit_creation(self) -> None:
        """Test creating DenyEc2ImdsHopLimit with valid data."""
        result = DenyEc2ImdsHopLimit(
            region="us-east-1",
            instance_id="i-1234567890abcdef0",
            hop_limit=2,
            imds_enabled=True
        )

        assert result.region == "us-east-1"
        assert result.instance_id == "i-1234567890abcdef0"
        assert result.hop_limit == 2
        assert result.imds_enabled is True


class TestGetEc2ImdsHopLimitAnalysis:
    """Test get_ec2_imds_hop_limit_analysis function."""

    def create_mock_instance(
        self,
        instance_id: str,
        state: str = "running",
        hop_limit: Optional[int] = 1,
        http_endpoint: str = "enabled"
    ) -> dict:
        """Helper to create mock EC2 instance data with metadata hop limit."""
        metadata_options: dict = {"HttpEndpoint": http_endpoint}
        if hop_limit is not None:
            metadata_options["HttpPutResponseHopLimit"] = hop_limit

        return {
            "InstanceId": instance_id,
            "State": {"Name": state},
            "MetadataOptions": metadata_options,
        }

    def build_session(self, instances: List[dict]) -> MagicMock:
        """Build a mock session serving one region with the given instances."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"Reservations": [{"Instances": instances}]}
        ]
        mock_regional_ec2.get_paginator.return_value = mock_paginator

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            return mock_regional_ec2

        mock_session.client.side_effect = client_side_effect
        return mock_session

    def test_reports_hop_limit_above_one(self) -> None:
        """A hop limit greater than 1 is reported verbatim."""
        mock_session = self.build_session([
            self.create_mock_instance("i-aaa", hop_limit=2)
        ])

        results = get_ec2_imds_hop_limit_analysis(mock_session)

        assert len(results) == 1
        assert results[0].instance_id == "i-aaa"
        assert results[0].hop_limit == 2
        assert results[0].imds_enabled is True
        assert results[0].region == "us-east-1"

    def test_defaults_missing_hop_limit_to_one(self) -> None:
        """An absent HttpPutResponseHopLimit defaults to the AWS default of 1."""
        mock_session = self.build_session([
            self.create_mock_instance("i-bbb", hop_limit=None)
        ])

        results = get_ec2_imds_hop_limit_analysis(mock_session)

        assert len(results) == 1
        assert results[0].hop_limit == 1

    def test_marks_imds_disabled_instances(self) -> None:
        """An instance with IMDS disabled is reported with imds_enabled False."""
        mock_session = self.build_session([
            self.create_mock_instance("i-ccc", hop_limit=3, http_endpoint="disabled")
        ])

        results = get_ec2_imds_hop_limit_analysis(mock_session)

        assert len(results) == 1
        assert results[0].imds_enabled is False
        assert results[0].hop_limit == 3

    def test_skips_terminated_instances(self) -> None:
        """Terminated instances are excluded from results."""
        mock_session = self.build_session([
            self.create_mock_instance("i-ddd", state="terminated", hop_limit=3),
            self.create_mock_instance("i-eee", hop_limit=1),
        ])

        results = get_ec2_imds_hop_limit_analysis(mock_session)

        assert len(results) == 1
        assert results[0].instance_id == "i-eee"

    def test_raises_on_regional_client_error(self) -> None:
        """A regional API failure is surfaced as RuntimeError."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
            "DescribeInstances"
        )
        mock_regional_ec2.get_paginator.return_value = mock_paginator

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if region_name is None:
                return mock_ec2
            return mock_regional_ec2

        mock_session.client.side_effect = client_side_effect

        with pytest.raises(RuntimeError, match="Failed to analyze EC2 instances"):
            get_ec2_imds_hop_limit_analysis(mock_session)


class TestGetInstances:
    """Test the shared per-region instance collector."""

    @staticmethod
    def _session(pages: List[Dict[str, Any]]) -> MagicMock:
        """Build a mock session whose regional EC2 client serves `pages`."""
        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = pages
        mock_regional_ec2.get_paginator.return_value = mock_paginator
        mock_session = MagicMock()
        mock_session.client.return_value = mock_regional_ec2
        return mock_session

    def test_projects_every_field_the_checks_read(self) -> None:
        """
        The projection carries exactly the values the four EC2 checks read.

        Anything else in a describe_instances entry -- BlockDeviceMappings,
        NetworkInterfaces, SecurityGroups, Placement -- is dropped, because
        holding it for an account's whole lifetime is what would make this
        memo expensive.
        """
        session = self._session([{
            "Reservations": [{
                "OwnerId": "111111111111",
                "Instances": [{
                    "InstanceId": "i-11111111111111111",
                    "ImageId": "ami-11111111111111111",
                    "PublicIpAddress": "203.0.113.10",
                    "State": {"Name": "running"},
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpEndpoint": "enabled",
                        "HttpPutResponseHopLimit": 2,
                    },
                    "Tags": [{"Key": "ExemptFromIMDSv2", "Value": "true"}],
                    "BlockDeviceMappings": [{"DeviceName": "/dev/sda1"}],
                }],
            }]
        }])

        instances = get_instances(session, "us-east-1")

        assert instances == [Ec2Instance(
            instance_id="i-11111111111111111",
            region="us-east-1",
            image_id="ami-11111111111111111",
            owner_id="111111111111",
            public_ip_address="203.0.113.10",
            http_tokens="required",
            http_endpoint="enabled",
            hop_limit=2,
            tags={"ExemptFromIMDSv2": "true"},
        )]

    def test_applies_the_aws_metadata_defaults(self) -> None:
        """
        An instance with no MetadataOptions gets the values AWS applies:
        IMDSv1 permitted, endpoint enabled, hop limit 1.
        """
        session = self._session([{
            "Reservations": [{
                "OwnerId": "111111111111",
                "Instances": [{
                    "InstanceId": "i-11111111111111111",
                    "State": {"Name": "running"},
                }],
            }]
        }])

        instance = get_instances(session, "us-east-1")[0]

        assert instance.http_tokens == "optional"
        assert instance.http_endpoint == "enabled"
        assert instance.hop_limit == 1
        assert instance.image_id is None
        assert instance.public_ip_address is None
        assert instance.tags == {}

    def test_terminated_instances_are_dropped_once_here(self) -> None:
        """
        The terminated filter lives in the collector.

        All four checks previously opened with the identical
        `if instance['State']['Name'] == 'terminated': continue`. Stating it
        once is the point of collecting once.
        """
        session = self._session([{
            "Reservations": [{
                "OwnerId": "111111111111",
                "Instances": [
                    {"InstanceId": "i-11111111111111111", "State": {"Name": "terminated"}},
                    {"InstanceId": "i-22222222222222222", "State": {"Name": "running"}},
                ],
            }]
        }])

        instances = get_instances(session, "us-east-1")

        assert [i.instance_id for i in instances] == ["i-22222222222222222"]

    def test_owner_id_comes_from_the_reservation(self) -> None:
        """
        OwnerId lives on the reservation, not the instance.

        InstanceTypeDef has no OwnerId key, so reading it off the instance
        always produced an empty string against real AWS and yielded a
        malformed instance ARN with no account.
        """
        session = self._session([{
            "Reservations": [{
                "OwnerId": "111111111111",
                "Instances": [{
                    "InstanceId": "i-11111111111111111",
                    "State": {"Name": "running"},
                }],
            }]
        }])

        assert get_instances(session, "us-east-1")[0].owner_id == "111111111111"

    def test_a_region_is_described_once_per_session(self) -> None:
        """
        Four checks ask for one region's instances; only the first reaches AWS.

        This is 51 of the 68 describe_instances calls a 17-region account
        makes today.
        """
        session = self._session([{"Reservations": []}])

        for _ in range(4):
            get_instances(session, "us-east-1")

        session.client.return_value.get_paginator.assert_called_once_with("describe_instances")

    def test_each_region_is_described_separately(self) -> None:
        """Two regions are distinct memo entries, not one shared answer."""
        session = self._session([{"Reservations": []}])

        get_instances(session, "us-east-1")
        get_instances(session, "eu-west-1")

        assert session.client.call_count == 2

    def test_each_session_gets_its_own_instances(self) -> None:
        """
        Two sessions never share a memo entry.

        A memo keyed wrongly would report one account's instances as another
        account's, and the results would look entirely plausible.
        """
        session_a = self._session([{
            "Reservations": [{
                "OwnerId": "111111111111",
                "Instances": [{"InstanceId": "i-11111111111111111", "State": {"Name": "running"}}],
            }]
        }])
        session_b = self._session([{
            "Reservations": [{
                "OwnerId": "222222222222",
                "Instances": [{"InstanceId": "i-22222222222222222", "State": {"Name": "running"}}],
            }]
        }])

        assert get_instances(session_a, "us-east-1")[0].instance_id == "i-11111111111111111"
        assert get_instances(session_b, "us-east-1")[0].instance_id == "i-22222222222222222"

    def test_memo_entry_is_released_when_the_session_is_dropped(self) -> None:
        """
        An account's instances die with its session.

        A leading gc.collect() gives a clean baseline: MagicMock objects from
        earlier tests hold internal reference cycles (a mock assigned as
        another mock's return_value gets a strong _mock_new_parent back-link),
        so they linger as uncollected garbage rather than vanishing the
        instant their owning test returns. Without the sweep, this test's
        exact-one-entry assertion counts other tests' debris instead (5
        entries observed, not 1).

        Unlike the equivalent test in test_aws_helpers.py, there is no second
        `del` here: `_session` keeps its regional-client mock as a helper
        local rather than binding it to a name in this test's frame, so
        `del session` alone drops the only reference this frame holds into
        the mock family, and gc.collect() reclaims the rest of the cycle.
        """
        gc.collect()

        session = self._session([{"Reservations": []}])

        get_instances(session, "us-east-1")
        assert len(_INSTANCE_MEMO) == 1

        del session
        gc.collect()

        assert len(_INSTANCE_MEMO) == 0

    def test_client_error_becomes_a_runtime_error_naming_the_region(self) -> None:
        """
        A failed describe_instances aborts the run with the region named.

        Headroom does not tolerate a partial scan: an account skipped for a
        transient error is indistinguishable in the results from an account
        with zero violations.
        """
        session = MagicMock()
        mock_regional_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
            "DescribeInstances",
        )
        mock_regional_ec2.get_paginator.return_value = mock_paginator
        session.client.return_value = mock_regional_ec2

        with pytest.raises(RuntimeError, match="us-east-1"):
            get_instances(session, "us-east-1")
