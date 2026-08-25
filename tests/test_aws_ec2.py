"""
Tests for headroom.aws.ec2 module.

Tests for DenyEc2ImdsV1 dataclass and get_ec2_imds_v1_analysis function.
"""

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
    get_ec2_imds_v1_analysis,
    get_ec2_ami_owner_analysis,
    get_ec2_imds_hop_limit_analysis,
    get_ec2_public_ip_analysis
)


class TestDenyEc2ImdsV1:
    """Test DenyEc2ImdsV1 dataclass with various configurations."""

    def test_deny_ec2_imds_v1_creation(self) -> None:
        """Test creating DenyEc2ImdsV1 with valid data."""
        result = DenyEc2ImdsV1(
            region="us-east-1",
            instance_id="i-1234567890abcdef0",
            imdsv1_allowed=True,
            role_exemption_tag_present=False
        )

        assert result.region == "us-east-1"
        assert result.instance_id == "i-1234567890abcdef0"
        assert result.imdsv1_allowed is True
        assert result.role_exemption_tag_present is False

    def test_deny_ec2_imds_v1_with_exemption(self) -> None:
        """Test DenyEc2ImdsV1 with exemption tag present."""
        result = DenyEc2ImdsV1(
            region="us-west-2",
            instance_id="i-0987654321fedcba0",
            imdsv1_allowed=True,
            role_exemption_tag_present=True
        )

        assert result.region == "us-west-2"
        assert result.instance_id == "i-0987654321fedcba0"
        assert result.imdsv1_allowed is True
        assert result.role_exemption_tag_present is True

    def test_deny_ec2_imds_v1_imdsv2_enforced(self) -> None:
        """Test DenyEc2ImdsV1 with IMDSv2 enforced."""
        result = DenyEc2ImdsV1(
            region="eu-west-1",
            instance_id="i-abcdef1234567890",
            imdsv1_allowed=False,
            role_exemption_tag_present=False
        )

        assert result.region == "eu-west-1"
        assert result.instance_id == "i-abcdef1234567890"
        assert result.imdsv1_allowed is False
        assert result.role_exemption_tag_present is False

    def test_deny_ec2_imds_v1_equality(self) -> None:
        """Test DenyEc2ImdsV1 equality comparison."""
        result1 = DenyEc2ImdsV1(
            region="us-east-1",
            instance_id="i-1234567890abcdef0",
            imdsv1_allowed=True,
            role_exemption_tag_present=False
        )

        result2 = DenyEc2ImdsV1(
            region="us-east-1",
            instance_id="i-1234567890abcdef0",
            imdsv1_allowed=True,
            role_exemption_tag_present=False
        )

        result3 = DenyEc2ImdsV1(
            region="us-east-1",
            instance_id="i-different",
            imdsv1_allowed=True,
            role_exemption_tag_present=False
        )

        assert result1 == result2
        assert result1 != result3

    def test_deny_ec2_imds_v1_repr(self) -> None:
        """Test DenyEc2ImdsV1 string representation."""
        result = DenyEc2ImdsV1(
            region="us-east-1",
            instance_id="i-1234567890abcdef0",
            imdsv1_allowed=True,
            role_exemption_tag_present=False
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
        assert results[0].role_exemption_tag_present is False

        # Check second instance (IMDSv2 required; its instance tag is the
        # wrong dimension and does not exempt)
        assert results[1].region == "us-east-1"
        assert results[1].instance_id == "i-0987654321fedcba0"
        assert results[1].imdsv1_allowed is False
        assert results[1].role_exemption_tag_present is False

        # Check third instance (endpoint disabled, but tokens still optional,
        # which the SCP counts and so does this check)
        assert results[2].region == "us-west-2"
        assert results[2].instance_id == "i-abcdef1234567890"
        assert results[2].imdsv1_allowed is True
        assert results[2].role_exemption_tag_present is False

        # Check fourth instance (fallback region, IMDSv2 required)
        assert results[3].region == "eu-west-1"
        assert results[3].instance_id == "i-fallback123456789"
        assert results[3].imdsv1_allowed is False
        assert results[3].role_exemption_tag_present is False

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

    def test_instance_tags_never_exempt_whatever_their_case(self) -> None:
        """
        The tag on the instance is not the tag the SCP reads.

        This test replaces one that pinned the opposite: it asserted the
        instance tag exempted, and accepted "TRUE" and "True" as well as
        "true". Both halves were wrong. The SCP exempts on
        `aws:PrincipalTag/ExemptFromIMDSv2`, so instance tags are the wrong
        dimension entirely, and it tests that key with StringNotEquals, which
        is case-sensitive, so only the exact value would have exempted even on
        the right dimension. TestImdsV1RoleExemption covers the role tag.
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
                    "Instances": [
                        self.create_mock_instance(
                            f"i-{value.lower()}",
                            tags=[{"Key": "ExemptFromIMDSv2", "Value": value}]
                        )
                        for value in ("true", "TRUE", "True", "false")
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

        results = get_ec2_imds_v1_analysis(mock_session)

        assert len(results) == 4
        assert not any(r.role_exemption_tag_present for r in results)

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
        mock_paginator.paginate.return_value = [{"Reservations": [{"Instances": instances}]}]
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
        account_id: str = "111111111111",
        state: str = "running",
        public_ip: Optional[str] = None
    ) -> dict:
        """Helper to create mock EC2 instance data."""
        instance_dict = {
            "InstanceId": instance_id,
            "OwnerId": account_id,
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
                {"Instances": [self.create_mock_instance_with_ip("i-success", public_ip="54.123.45.67")]}
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
                    "Instances": [
                        self.create_mock_instance_with_ip(
                            "i-test123456789",
                            account_id="222222222222",
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


class TestImdsV1RoleExemption:
    """
    Exemption is read off the instance's IAM role, not the instance.

    The deny_ec2_imds_v1 SCP's DenyRoleDelivery statement exempts callers with
    `aws:PrincipalTag/ExemptFromIMDSv2`, a tag on the role the instance runs
    as. Reading the instance's own tags instead reported accounts as having
    zero violations while enforcement would deny every API call those
    instances made - the scan named the instances that would break as the
    evidence the SCP was safe to attach.
    """

    PROFILE_ARN = "arn:aws:iam::111111111111:instance-profile/app"
    ROLE_ARN = "arn:aws:iam::111111111111:role/app-role"

    def _session(
        self,
        instances_by_region: Dict[str, List[dict]],
        iam_client: Optional[MagicMock] = None,
    ) -> MagicMock:
        """Build a session whose regional EC2 clients return the given instances."""
        session = MagicMock()

        global_ec2 = MagicMock()
        global_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": r} for r in instances_by_region]
        }

        regional: Dict[str, MagicMock] = {}
        for region, instances in instances_by_region.items():
            client = MagicMock()
            paginator = MagicMock()
            paginator.paginate.return_value = [
                {"Reservations": [{"Instances": instances}]}
            ]
            client.get_paginator.return_value = paginator
            regional[region] = client

        def client_side_effect(
            service: str, region_name: Optional[str] = None
        ) -> MagicMock:
            if service == "iam":
                assert iam_client is not None, "IAM client was not expected"
                return iam_client
            if region_name is None:
                return global_ec2
            return regional[region_name]

        session.client.side_effect = client_side_effect
        return session

    def _instance(
        self,
        instance_id: str,
        http_tokens: str = "optional",
        profile_arn: Optional[str] = None,
        tags: Optional[List[dict]] = None,
    ) -> dict:
        """Build one describe_instances instance entry."""
        instance: Dict[str, Any] = {
            "InstanceId": instance_id,
            "State": {"Name": "running"},
            "MetadataOptions": {
                "HttpTokens": http_tokens,
                "HttpEndpoint": "enabled",
            },
            "Tags": tags or [],
        }
        if profile_arn:
            instance["IamInstanceProfile"] = {"Arn": profile_arn}
        return instance

    def _iam(self, role_tags: List[dict]) -> MagicMock:
        """Build an IAM client resolving one profile to a role with these tags."""
        iam = MagicMock()
        iam.get_instance_profile.return_value = {
            "InstanceProfile": {"Roles": [{"RoleName": "app-role"}]}
        }
        iam.get_role.return_value = {
            "Role": {"Arn": self.ROLE_ARN, "Tags": role_tags}
        }
        return iam

    def test_role_tagged_exempt_is_exempt(self) -> None:
        """A role tagged ExemptFromIMDSv2=true exempts the instances using it."""
        session = self._session(
            {"us-east-1": [self._instance("i-aaa", profile_arn=self.PROFILE_ARN)]},
            self._iam([{"Key": "ExemptFromIMDSv2", "Value": "true"}]),
        )

        results = get_ec2_imds_v1_analysis(session)

        assert results[0].imdsv1_allowed is True
        assert results[0].role_exemption_tag_present is True
        assert results[0].role_arn == self.ROLE_ARN
        assert results[0].role_unresolved_reason is None

    def test_instance_tag_does_not_exempt(self) -> None:
        """
        The tag on the instance is the wrong dimension.

        No statement in the deny_ec2_imds_v1 SCP reads instance tags, so an
        instance tagged exempt whose role is not tagged is a violation.
        """
        session = self._session(
            {"us-east-1": [self._instance(
                "i-aaa",
                profile_arn=self.PROFILE_ARN,
                tags=[{"Key": "ExemptFromIMDSv2", "Value": "true"}],
            )]},
            self._iam([]),
        )

        results = get_ec2_imds_v1_analysis(session)

        assert results[0].role_exemption_tag_present is False
        assert results[0].role_arn == self.ROLE_ARN

    @pytest.mark.parametrize("value", ["True", "TRUE", "tRuE"])
    def test_exemption_tag_value_is_case_sensitive(self, value: str) -> None:
        """
        StringNotEquals is case-sensitive, so only the exact value exempts.

        Accepting "True" here would report an account clean while enforcement
        denied every call its instances made.
        """
        session = self._session(
            {"us-east-1": [self._instance("i-aaa", profile_arn=self.PROFILE_ARN)]},
            self._iam([{"Key": "ExemptFromIMDSv2", "Value": value}]),
        )

        results = get_ec2_imds_v1_analysis(session)

        assert results[0].role_exemption_tag_present is False

    @pytest.mark.parametrize(
        "key", ["exemptfromimdsv2", "EXEMPTFROMIMDSV2", "ExemptFromIMDSV2"]
    )
    def test_exemption_tag_key_is_case_insensitive(self, key: str) -> None:
        """
        IAM matches the tag key in aws:PrincipalTag case-insensitively.

        The key and the value pull opposite ways: the key is matched without
        regard to case, the value with StringNotEquals, which is
        case-sensitive. Matching the key exactly would report a role that
        enforcement exempts as a violation.
        """
        session = self._session(
            {"us-east-1": [self._instance("i-aaa", profile_arn=self.PROFILE_ARN)]},
            self._iam([{"Key": key, "Value": "true"}]),
        )

        results = get_ec2_imds_v1_analysis(session)

        assert results[0].role_exemption_tag_present is True

    def test_exemption_tag_key_twice_in_different_cases_aborts(self) -> None:
        """
        A role carrying the key twice has no determinate exemption status.

        AWS documents this as an unexpected condition failure rather than a
        match on one of them, so there is nothing to report, and guessing
        which one IAM lands on would invent the status of a live workload.
        """
        session = self._session(
            {"us-east-1": [self._instance("i-aaa", profile_arn=self.PROFILE_ARN)]},
            self._iam([
                {"Key": "ExemptFromIMDSv2", "Value": "true"},
                {"Key": "exemptfromimdsv2", "Value": "false"},
            ]),
        )

        with pytest.raises(RuntimeError, match=r"more than once in cases that differ"):
            get_ec2_imds_v1_analysis(session)

    def test_unrelated_tags_do_not_exempt(self) -> None:
        """A role tagged with something else entirely is not exempt."""
        session = self._session(
            {"us-east-1": [self._instance("i-aaa", profile_arn=self.PROFILE_ARN)]},
            self._iam([{"Key": "Owner", "Value": "true"}]),
        )

        results = get_ec2_imds_v1_analysis(session)

        assert results[0].role_exemption_tag_present is False

    def test_instance_without_profile_records_the_reason(self) -> None:
        """An instance with no role reaches IAM not at all."""
        session = self._session({"us-east-1": [self._instance("i-aaa")]})

        results = get_ec2_imds_v1_analysis(session)

        assert results[0].role_exemption_tag_present is False
        assert results[0].role_arn is None
        assert results[0].role_unresolved_reason == "no_instance_profile"

    def test_profile_is_resolved_once_across_regions(self) -> None:
        """Instances sharing a profile cost one pair of IAM calls, not one each."""
        iam = self._iam([{"Key": "ExemptFromIMDSv2", "Value": "true"}])
        session = self._session(
            {
                "us-east-1": [
                    self._instance("i-aaa", profile_arn=self.PROFILE_ARN),
                    self._instance("i-bbb", profile_arn=self.PROFILE_ARN),
                ],
                "us-west-2": [self._instance("i-ccc", profile_arn=self.PROFILE_ARN)],
            },
            iam,
        )

        results = get_ec2_imds_v1_analysis(session)

        assert len(results) == 3
        assert all(r.role_exemption_tag_present for r in results)
        assert iam.get_instance_profile.call_count == 1
        assert iam.get_role.call_count == 1

    def test_compliant_instance_still_reports_its_role(self) -> None:
        """
        The role is resolved whatever the instance's IMDS setting.

        Naming the role is what tells an operator where the exemption tag
        would have to go.
        """
        session = self._session(
            {"us-east-1": [self._instance(
                "i-aaa", http_tokens="required", profile_arn=self.PROFILE_ARN
            )]},
            self._iam([]),
        )

        results = get_ec2_imds_v1_analysis(session)

        assert results[0].imdsv1_allowed is False
        assert results[0].role_arn == self.ROLE_ARN

    def test_iam_access_denied_names_the_missing_permissions(self) -> None:
        """
        A missing IAM permission must abort, not read as a fleet of violations.

        Reading AccessDenied as "role not tagged" would turn one permission
        gap into violations that look like real findings.
        """
        iam = MagicMock()
        iam.get_instance_profile.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetInstanceProfile"
        )
        session = self._session(
            {"us-east-1": [self._instance("i-aaa", profile_arn=self.PROFILE_ARN)]},
            iam,
        )

        with pytest.raises(RuntimeError, match=r"iam:GetInstanceProfile and iam:GetRole"):
            get_ec2_imds_v1_analysis(session)


class TestImdsV1EndpointIsNotAnExcuse:
    """
    HttpTokens is counted whether or not the metadata endpoint is enabled.

    The check used to require both - endpoint enabled AND tokens optional -
    which read the running instance correctly, since nothing can reach a
    disabled endpoint. The SCP does not read the instance. It tests
    ec2:MetadataHttpTokens on the launch request, where a request that turns
    the endpoint off carries no HttpTokens at all, leaving the key absent and
    StringNotEquals true. Dry runs against a live account confirm that launch
    is denied.

    So an endpoint-disabled instance whose tokens are optional is a violation.
    Remedying it costs nothing: AWS accepts HttpTokens=required alongside a
    disabled endpoint - also confirmed by dry run, contradicting the EC2 guide -
    and setting it changes no behaviour, because nothing is listening.
    """

    def _one_instance(self, metadata_options: Dict[str, Any]) -> DenyEc2ImdsV1:
        """Run the collector over a single instance with these options."""
        session = MagicMock()

        global_ec2 = MagicMock()
        global_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        regional = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "Reservations": [{"Instances": [{
                "InstanceId": "i-aaa",
                "State": {"Name": "running"},
                "MetadataOptions": metadata_options,
                "Tags": [],
            }]}]
        }]
        regional.get_paginator.return_value = paginator

        def client_side_effect(
            service: str, region_name: Optional[str] = None
        ) -> MagicMock:
            return global_ec2 if region_name is None else regional

        session.client.side_effect = client_side_effect
        return get_ec2_imds_v1_analysis(session)[0]

    def test_endpoint_disabled_with_optional_tokens_is_a_violation(self) -> None:
        """The endpoint being off does not excuse optional tokens."""
        result = self._one_instance(
            {"HttpTokens": "optional", "HttpEndpoint": "disabled"}
        )

        assert result.imdsv1_allowed is True

    def test_endpoint_disabled_with_required_tokens_is_compliant(self) -> None:
        """Setting tokens required is the free remedy, and the check honours it."""
        result = self._one_instance(
            {"HttpTokens": "required", "HttpEndpoint": "disabled"}
        )

        assert result.imdsv1_allowed is False

    def test_endpoint_enabled_still_decided_by_tokens_alone(self) -> None:
        """The enabled case is unchanged."""
        assert self._one_instance(
            {"HttpTokens": "optional", "HttpEndpoint": "enabled"}
        ).imdsv1_allowed is True
        assert self._one_instance(
            {"HttpTokens": "required", "HttpEndpoint": "enabled"}
        ).imdsv1_allowed is False
