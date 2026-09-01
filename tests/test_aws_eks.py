"""
Tests for headroom.aws.eks module.

Tests for DenyEksCreateClusterWithoutTag dataclass and get_eks_cluster_tag_analysis function.
"""

from typing import Dict, List
from unittest.mock import MagicMock

import pytest

from headroom.aws.eks import (
    DenyEksCreateClusterWithoutTag,
    get_eks_cluster_tag_analysis,
)


class TestDenyEksCreateClusterWithoutTag:
    """Test DenyEksCreateClusterWithoutTag dataclass with various configurations."""

    def test_deny_eks_create_cluster_with_paved_road_tag(self) -> None:
        """Test creating DenyEksCreateClusterWithoutTag for cluster with PavedRoad tag."""
        result = DenyEksCreateClusterWithoutTag(
            cluster_name="approved-cluster",
            cluster_arn="arn:aws:eks:us-east-1:111111111111:cluster/approved-cluster",
            region="us-east-1",
            tags={"PavedRoad": "true", "Environment": "prod"},
            has_paved_road_tag=True
        )

        assert result.cluster_name == "approved-cluster"
        assert result.cluster_arn == "arn:aws:eks:us-east-1:111111111111:cluster/approved-cluster"
        assert result.region == "us-east-1"
        assert result.tags == {"PavedRoad": "true", "Environment": "prod"}
        assert result.has_paved_road_tag is True

    def test_deny_eks_create_cluster_without_tag(self) -> None:
        """Test creating DenyEksCreateClusterWithoutTag for cluster without PavedRoad tag."""
        result = DenyEksCreateClusterWithoutTag(
            cluster_name="legacy-cluster",
            cluster_arn="arn:aws:eks:us-west-2:222222222222:cluster/legacy-cluster",
            region="us-west-2",
            tags={"Environment": "dev"},
            has_paved_road_tag=False
        )

        assert result.cluster_name == "legacy-cluster"
        assert result.cluster_arn == "arn:aws:eks:us-west-2:222222222222:cluster/legacy-cluster"
        assert result.region == "us-west-2"
        assert result.tags == {"Environment": "dev"}
        assert result.has_paved_road_tag is False

    def test_deny_eks_create_cluster_empty_tags(self) -> None:
        """Test creating DenyEksCreateClusterWithoutTag with empty tags."""
        result = DenyEksCreateClusterWithoutTag(
            cluster_name="no-tags-cluster",
            cluster_arn="arn:aws:eks:eu-west-1:333333333333:cluster/no-tags-cluster",
            region="eu-west-1",
            tags={},
            has_paved_road_tag=False
        )

        assert result.cluster_name == "no-tags-cluster"
        assert result.tags == {}
        assert result.has_paved_road_tag is False

    def test_deny_eks_create_cluster_equality(self) -> None:
        """Test DenyEksCreateClusterWithoutTag equality comparison."""
        result1 = DenyEksCreateClusterWithoutTag(
            cluster_name="test-cluster",
            cluster_arn="arn:aws:eks:us-east-1:111111111111:cluster/test-cluster",
            region="us-east-1",
            tags={"PavedRoad": "true"},
            has_paved_road_tag=True
        )

        result2 = DenyEksCreateClusterWithoutTag(
            cluster_name="test-cluster",
            cluster_arn="arn:aws:eks:us-east-1:111111111111:cluster/test-cluster",
            region="us-east-1",
            tags={"PavedRoad": "true"},
            has_paved_road_tag=True
        )

        result3 = DenyEksCreateClusterWithoutTag(
            cluster_name="different-cluster",
            cluster_arn="arn:aws:eks:us-east-1:111111111111:cluster/different-cluster",
            region="us-east-1",
            tags={"PavedRoad": "true"},
            has_paved_road_tag=True
        )

        assert result1 == result2
        assert result1 != result3


class TestGetEksClusterTagAnalysis:
    """Test get_eks_cluster_tag_analysis function."""

    def test_get_eks_cluster_tag_analysis_success(self) -> None:
        """Test successful EKS cluster analysis with multiple clusters."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_eks_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "eks": mock_eks_client,
        }.get(service)

        # Mock regions
        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        # Mock EKS cluster list
        cluster_paginator = MagicMock()
        cluster_paginator.paginate.return_value = [
            {"clusters": ["approved-cluster", "legacy-cluster"]}
        ]
        mock_eks_client.get_paginator.return_value = cluster_paginator

        # Mock cluster descriptions
        def describe_cluster_side_effect(name: str) -> dict:
            if name == "approved-cluster":
                return {
                    "cluster": {
                        "name": "approved-cluster",
                        "arn": "arn:aws:eks:us-east-1:111111111111:cluster/approved-cluster",
                        "tags": {"PavedRoad": "true", "Environment": "prod"}
                    }
                }
            return {
                "cluster": {
                    "name": "legacy-cluster",
                    "arn": "arn:aws:eks:us-east-1:111111111111:cluster/legacy-cluster",
                    "tags": {"Environment": "dev"}
                }
            }

        mock_eks_client.describe_cluster.side_effect = describe_cluster_side_effect

        results = get_eks_cluster_tag_analysis(mock_session)

        assert len(results) == 2
        assert results[0].cluster_name == "approved-cluster"
        assert results[0].has_paved_road_tag is True
        assert results[1].cluster_name == "legacy-cluster"
        assert results[1].has_paved_road_tag is False

    def test_get_eks_cluster_tag_analysis_empty_results(self) -> None:
        """Test EKS cluster analysis with no clusters."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_eks_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "eks": mock_eks_client,
        }.get(service)

        # Mock regions
        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        # Mock empty cluster list
        cluster_paginator = MagicMock()
        cluster_paginator.paginate.return_value = [{"clusters": []}]
        mock_eks_client.get_paginator.return_value = cluster_paginator

        results = get_eks_cluster_tag_analysis(mock_session)

        assert len(results) == 0

    def test_get_eks_cluster_tag_analysis_multi_region(self) -> None:
        """Test EKS cluster analysis across multiple regions."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()

        # Mock regions
        mock_ec2_client.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "us-west-2"}
            ]
        }

        # Create separate EKS clients for each region
        mock_eks_us_east_1 = MagicMock()
        mock_eks_us_west_2 = MagicMock()

        def client_side_effect(service: str, **kwargs: str) -> MagicMock:
            if service == "ec2":
                return mock_ec2_client
            region = kwargs.get("region_name")
            if region == "us-east-1":
                return mock_eks_us_east_1
            return mock_eks_us_west_2

        mock_session.client.side_effect = client_side_effect

        # Mock us-east-1 clusters
        paginator_east = MagicMock()
        paginator_east.paginate.return_value = [
            {"clusters": ["east-cluster"]}
        ]
        mock_eks_us_east_1.get_paginator.return_value = paginator_east
        mock_eks_us_east_1.describe_cluster.return_value = {
            "cluster": {
                "name": "east-cluster",
                "arn": "arn:aws:eks:us-east-1:111111111111:cluster/east-cluster",
                "tags": {"PavedRoad": "true"}
            }
        }

        # Mock us-west-2 clusters
        paginator_west = MagicMock()
        paginator_west.paginate.return_value = [
            {"clusters": ["west-cluster"]}
        ]
        mock_eks_us_west_2.get_paginator.return_value = paginator_west
        mock_eks_us_west_2.describe_cluster.return_value = {
            "cluster": {
                "name": "west-cluster",
                "arn": "arn:aws:eks:us-west-2:222222222222:cluster/west-cluster",
                "tags": {}
            }
        }

        results = get_eks_cluster_tag_analysis(mock_session)

        assert len(results) == 2
        assert results[0].cluster_name == "east-cluster"
        assert results[0].region == "us-east-1"
        assert results[0].has_paved_road_tag is True
        assert results[1].cluster_name == "west-cluster"
        assert results[1].region == "us-west-2"
        assert results[1].has_paved_road_tag is False

    def test_get_eks_cluster_tag_analysis_pagination(self) -> None:
        """Test EKS cluster analysis with pagination."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_eks_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "eks": mock_eks_client,
        }.get(service)

        # Mock regions
        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        # Mock paginated cluster list (two pages)
        cluster_paginator = MagicMock()
        cluster_paginator.paginate.return_value = [
            {"clusters": ["cluster-1", "cluster-2"]},
            {"clusters": ["cluster-3"]}
        ]
        mock_eks_client.get_paginator.return_value = cluster_paginator

        # Mock cluster descriptions
        def describe_cluster_side_effect(name: str) -> dict:
            return {
                "cluster": {
                    "name": name,
                    "arn": f"arn:aws:eks:us-east-1:111111111111:cluster/{name}",
                    "tags": {"PavedRoad": "true"}
                }
            }

        mock_eks_client.describe_cluster.side_effect = describe_cluster_side_effect

        results = get_eks_cluster_tag_analysis(mock_session)

        assert len(results) == 3
        assert all(r.has_paved_road_tag for r in results)
        assert [r.cluster_name for r in results] == ["cluster-1", "cluster-2", "cluster-3"]

    def test_get_eks_cluster_tag_analysis_missing_tags_field(self) -> None:
        """Test EKS cluster analysis when tags field is missing from response."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_eks_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "eks": mock_eks_client,
        }.get(service)

        # Mock regions
        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        # Mock cluster list
        cluster_paginator = MagicMock()
        cluster_paginator.paginate.return_value = [
            {"clusters": ["no-tags-cluster"]}
        ]
        mock_eks_client.get_paginator.return_value = cluster_paginator

        # Mock cluster description without tags field
        mock_eks_client.describe_cluster.return_value = {
            "cluster": {
                "name": "no-tags-cluster",
                "arn": "arn:aws:eks:us-east-1:111111111111:cluster/no-tags-cluster"
                # No tags field
            }
        }

        results = get_eks_cluster_tag_analysis(mock_session)

        assert len(results) == 1
        assert results[0].tags == {}
        assert results[0].has_paved_road_tag is False


class TestPavedRoadTagIsMatchedAsIamMatchesIt:
    """
    The cluster's tag is read the way IAM reads the condition key.

    `deny_eks_create_cluster_without_tag` conditions on
    `aws:RequestTag/PavedRoad`. AWS documents that a condition key name is
    matched without regard to case while the value is compared by
    StringNotEquals, which is case-sensitive, so the two halves pull opposite
    ways and the scan has to follow both. This is the rule
    `deny_ec2_imds_v1` already follows for its own tag.
    """

    def _analysis(self, tags: Dict[str, str]) -> List[DenyEksCreateClusterWithoutTag]:
        """Run the analysis over one cluster carrying the given tags."""
        mock_session = MagicMock()
        mock_ec2_client = MagicMock()
        mock_eks_client = MagicMock()

        mock_session.client.side_effect = lambda service, **kwargs: {
            "ec2": mock_ec2_client,
            "eks": mock_eks_client,
        }.get(service)

        mock_ec2_client.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        cluster_paginator = MagicMock()
        cluster_paginator.paginate.return_value = [{"clusters": ["test-cluster"]}]
        mock_eks_client.get_paginator.return_value = cluster_paginator

        mock_eks_client.describe_cluster.return_value = {
            "cluster": {
                "name": "test-cluster",
                "arn": "arn:aws:eks:us-east-1:111111111111:cluster/test-cluster",
                "tags": tags,
            }
        }

        return get_eks_cluster_tag_analysis(mock_session)

    @pytest.mark.parametrize("key", ["pavedroad", "PAVEDROAD", "Pavedroad"])
    def test_tag_key_is_matched_without_regard_to_case(self, key: str) -> None:
        """
        A cluster tagged `pavedroad=true` is compliant, not a violation.

        Matching the key exactly reported it as a violation, which blocked the
        account and withheld the SCP over a cluster whose recreation
        enforcement would have allowed.
        """
        assert self._analysis({key: "true"})[0].has_paved_road_tag is True

    @pytest.mark.parametrize("value", ["True", "TRUE", "tRuE"])
    def test_tag_value_is_matched_exactly(self, value: str) -> None:
        """
        StringNotEquals is case-sensitive, so `PavedRoad=True` is a violation.

        Lowercasing here would clear an account whose cluster enforcement
        would refuse to recreate.
        """
        assert self._analysis({"PavedRoad": value})[0].has_paved_road_tag is False

    def test_key_twice_in_differing_cases_aborts(self) -> None:
        """
        Two spellings both match the condition key; at most one value can.

        AWS documents that a condition on `aws:RequestTag/PavedRoad` matches a
        tag key named `PavedRoad` or `pavedroad`, but not both. Whether this
        cluster's recreation is allowed has no determinate answer, and taking
        whichever tag the dict happens to yield first would invent one.
        """
        with pytest.raises(RuntimeError, match=r"more than once in cases that differ"):
            self._analysis({"PavedRoad": "true", "pavedroad": "false"})
