"""
Tests for headroom.aws.helpers module.
"""

import gc
from typing import Any, Dict, Iterator, List
from unittest.mock import MagicMock

from headroom.aws.helpers import _REGION_MEMO, get_all_regions, paginate


class TestGetAllRegions:
    """Test region discovery."""

    def test_only_enabled_regions_are_requested(self) -> None:
        """
        describe_regions is called with no arguments, so AWS returns only the
        regions that are enabled for the account.

        This is the sole reason Headroom never calls a service API in a disabled
        region. Per the EC2 API, AllRegions "indicates whether to display all
        Regions, including Regions that are disabled for your account". Passing it
        would add not-opted-in regions to this list, and because every caller
        builds a per-region client from the result, each such region would produce
        a doomed API call against a region the account cannot use.

        Asserting the exact call signature rather than just the return value is
        deliberate: it fails the moment anyone adds AllRegions=True.
        """
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
                {"RegionName": "eu-south-1", "OptInStatus": "opted-in"},
            ]
        }

        regions = get_all_regions(mock_session)

        mock_ec2.describe_regions.assert_called_once_with()
        assert regions == ["us-east-1", "eu-south-1"]

    def test_region_names_are_returned_in_response_order(self) -> None:
        """Region names are extracted verbatim, preserving the API's order."""
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "eu-west-1"},
                {"RegionName": "us-west-2"},
                {"RegionName": "us-east-1"},
            ]
        }

        assert get_all_regions(mock_session) == ["eu-west-1", "us-west-2", "us-east-1"]

    def test_no_regions_returns_empty_list(self) -> None:
        """An empty Regions list yields no regions rather than raising."""
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2
        mock_ec2.describe_regions.return_value = {"Regions": []}

        assert get_all_regions(mock_session) == []

    def test_region_list_is_fetched_once_per_session(self) -> None:
        """
        Eleven checks ask for the region list; only the first reaches AWS.

        The other ten calls are pure latency, and the answer cannot change
        within a run.
        """
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2
        mock_ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}

        first = get_all_regions(mock_session)
        second = get_all_regions(mock_session)

        assert first == second == ["us-east-1"]
        mock_ec2.describe_regions.assert_called_once_with()

    def test_each_session_gets_its_own_region_list(self) -> None:
        """
        Two sessions never share a memo entry.

        A memo keyed wrongly does not crash. It serves one account's region
        list to another account, and the resulting results look entirely
        plausible, so this is the failure mode worth pinning.
        """
        session_a, session_b = MagicMock(), MagicMock()
        ec2_a, ec2_b = MagicMock(), MagicMock()
        session_a.client.return_value = ec2_a
        session_b.client.return_value = ec2_b
        ec2_a.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
        ec2_b.describe_regions.return_value = {"Regions": [{"RegionName": "eu-west-1"}]}

        assert get_all_regions(session_a) == ["us-east-1"]
        assert get_all_regions(session_b) == ["eu-west-1"]
        assert get_all_regions(session_a) == ["us-east-1"]

    def test_memo_entry_is_released_when_the_session_is_dropped(self) -> None:
        """
        An account's entry dies with its session, so a 300-account run does
        not accumulate 300 region lists.

        A leading gc.collect() gives a clean baseline: MagicMock objects from
        earlier tests hold internal reference cycles (a mock assigned as
        another mock's return_value gets a strong _mock_new_parent back-link),
        so they linger as uncollected garbage rather than vanishing the
        instant their owning test returns. Without the sweep, this test's
        exact-one-entry assertion would be counting other tests' debris.

        mock_ec2 is deleted alongside mock_session for the same reason: since
        mock_session.client.return_value = mock_ec2 gave mock_ec2 a strong
        back-reference to mock_session, mock_ec2 staying alive would keep
        mock_session reachable and the memo entry would never clear.
        """
        gc.collect()

        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2
        mock_ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}

        get_all_regions(mock_session)
        assert len(_REGION_MEMO) == 1

        del mock_session
        del mock_ec2
        gc.collect()

        assert len(_REGION_MEMO) == 0


class TestPaginate:
    """Test the pagination wrapper."""

    def test_yields_every_page(self) -> None:
        """Each page from the paginator is yielded in order."""
        mock_client = MagicMock()
        paginator = MagicMock()
        pages: List[Dict[str, Any]] = [{"Items": [1]}, {"Items": [2]}]
        paginator.paginate.return_value = pages
        mock_client.get_paginator.return_value = paginator

        result = list(paginate(mock_client, "list_things"))

        mock_client.get_paginator.assert_called_once_with("list_things")
        assert result == pages

    def test_passes_operation_kwargs_through(self) -> None:
        """Operation keyword arguments reach the paginator unchanged."""
        mock_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = []
        mock_client.get_paginator.return_value = paginator

        pages: Iterator[Dict[str, Any]] = paginate(
            mock_client, "list_things", MaxResults=50, Prefix="a"
        )
        assert list(pages) == []

        paginator.paginate.assert_called_once_with(MaxResults=50, Prefix="a")
