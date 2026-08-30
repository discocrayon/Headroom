"""
Tests for headroom.aws.helpers module.
"""

import gc
from typing import Any, Dict, Iterator, List, Set
from unittest.mock import MagicMock

from boto3.session import Session

import pytest

from headroom.aws.ecr import analyze_ecr_policies
from headroom.aws.helpers import (
    _REGION_MEMO,
    get_all_regions,
    memoize_per_session,
    paginate,
)
from headroom.aws.iam.roles import analyze_iam_roles_trust_policies
from headroom.aws.kms import analyze_kms_key_policies
from headroom.aws.s3 import analyze_s3_bucket_policies
from headroom.aws.secretsmanager import analyze_secrets_manager_policies
from headroom.aws.sqs import analyze_sqs_queue_policies


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
        Eleven calls reach this per account; only the first reaches AWS.

        The other ten are pure latency, and the answer cannot change within
        a run.
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
        one-entry assertion would be counting other tests' debris.

        The assertions are on the delta rather than on an absolute count,
        because the memo is module state this test does not own and the sweep
        cannot always clear it: an earlier *failing* test in this file keeps
        its mocks alive through pytest's traceback, out of gc.collect()'s
        reach. An absolute count would then fail too, adding noise to the
        report of an unrelated bug.

        mock_ec2 is deleted alongside mock_session for the same reason: since
        mock_session.client.return_value = mock_ec2 gave mock_ec2 a strong
        back-reference to mock_session, mock_ec2 staying alive would keep
        mock_session reachable and the memo entry would never clear.
        """
        gc.collect()
        before = len(_REGION_MEMO)

        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2
        mock_ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}

        get_all_regions(mock_session)
        assert len(_REGION_MEMO) == before + 1

        del mock_session
        del mock_ec2
        gc.collect()

        assert len(_REGION_MEMO) == before


class TestMemoizePerSession:
    """
    Test the shared per-session memo the resource-policy analyzers carry.

    Six analyzers each have two callers: their own third-party-access check,
    and `deny_service_confused_deputy`, which re-reads the same policies for
    the source guards on them. Four of the six sweep every enabled region, so
    without the memo each account pays 4 x 17 region probes it has already
    paid once.
    """

    @staticmethod
    def _counting_analyzer() -> Any:
        """Build a memoized analyzer that records the calls that reach it."""
        calls: List[Any] = []

        @memoize_per_session
        def analyzer(session: Session, org_account_ids: Set[str], org_id: str) -> List[str]:
            calls.append((org_account_ids, org_id))
            return [f"result-{len(calls)}"]

        setattr(analyzer, "calls", calls)
        return analyzer

    def test_the_analyzer_body_runs_once_per_session(self) -> None:
        """The second caller is served from the memo, not from AWS."""
        analyzer = self._counting_analyzer()
        session = MagicMock()

        first = analyzer(session, {"111111111111"}, "o-11111111")
        second = analyzer(session, {"111111111111"}, "o-11111111")

        assert first == second == ["result-1"]
        assert len(analyzer.calls) == 1

    def test_each_session_runs_the_analyzer_again(self) -> None:
        """
        Two sessions never share a memo entry.

        A memo keyed wrongly does not crash. It serves one account's
        resource policies to another account, and the generated allowlist
        looks entirely plausible, so this is the failure mode worth pinning.
        """
        analyzer = self._counting_analyzer()
        session_a, session_b = MagicMock(), MagicMock()

        assert analyzer(session_a, {"111111111111"}, "o-11111111") == ["result-1"]
        assert analyzer(session_b, {"111111111111"}, "o-11111111") == ["result-2"]
        assert analyzer(session_a, {"111111111111"}, "o-11111111") == ["result-1"]

    def test_differing_organization_arguments_are_rejected(self) -> None:
        """
        The memo is keyed on the session alone, so mismatched args must raise.

        Both arguments are fixed for a whole run today, which is what makes
        the session a sufficient key. Serving the first call's results to a
        second call that asked a different question would be silent and
        plausible; refusing is neither.
        """
        analyzer = self._counting_analyzer()
        session = MagicMock()

        analyzer(session, {"111111111111"}, "o-11111111")

        with pytest.raises(RuntimeError, match="different organization arguments"):
            analyzer(session, {"111111111111", "222222222222"}, "o-11111111")

        with pytest.raises(RuntimeError, match="different organization arguments"):
            analyzer(session, {"111111111111"}, "o-22222222")

    def test_memo_entry_is_released_when_the_session_is_dropped(self) -> None:
        """
        An account's entry dies with its session, so a 300-account run does
        not accumulate 300 accounts' worth of resource policies.

        These entries are far larger than the region list: every bucket
        policy, key policy, and role trust policy the account holds. Retaining
        them past the worker would put the pool's memory ceiling somewhere
        other than where `config.MAX_ACCOUNT_WORKERS` says it is.
        """
        analyzer = self._counting_analyzer()
        gc.collect()

        session = MagicMock()
        analyzer(session, {"111111111111"}, "o-11111111")
        assert len(analyzer.session_memo) == 1

        del session
        gc.collect()

        assert len(analyzer.session_memo) == 0

    def test_every_doubly_called_analyzer_is_memoized(self) -> None:
        """
        All six analyzers `deny_service_confused_deputy` shares carry the memo.

        The check re-invokes each of them after their own check already has,
        so an analyzer that loses the decorator silently doubles that
        account's API calls without failing anything.
        """
        shared = [
            analyze_ecr_policies,
            analyze_iam_roles_trust_policies,
            analyze_kms_key_policies,
            analyze_s3_bucket_policies,
            analyze_secrets_manager_policies,
            analyze_sqs_queue_policies,
        ]

        unmemoized = [
            analyzer.__name__ for analyzer in shared
            if not hasattr(analyzer, "session_memo")
        ]

        assert unmemoized == []


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
