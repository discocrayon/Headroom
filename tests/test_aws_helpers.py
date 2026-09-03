"""
Tests for headroom.aws.helpers module.
"""

import gc
import inspect
from dataclasses import fields, is_dataclass
from types import FunctionType, ModuleType
from typing import Any, Dict, Iterator, List, Set, get_args, get_origin, get_type_hints
from unittest.mock import MagicMock

from boto3.session import Session

import pytest

from headroom.aws import ecr, kms, s3, secretsmanager, sqs
from headroom.aws.helpers import (
    _REGION_MEMO,
    find_tag_value_as_iam_matches,
    get_all_regions,
    memoize_per_session,
    paginate,
)
from headroom.aws.iam import roles


# The one list still kept by hand. Discovery walks these modules for the
# shape; a module carrying `service_principal_sources` that is not listed here
# is invisible to every test that reads this discovery, in this file and in
# tests/test_checks_deny_service_confused_deputy.py.
SHARED_ANALYZER_MODULES: List[ModuleType] = [ecr, roles, kms, s3, secretsmanager, sqs]


def _produces_service_principal_sources(module: ModuleType, name: str, member: FunctionType) -> bool:
    """
    Decide whether one module member is a public analyzer carrying the field.

    The module and name tests come first so that type hints are read only for
    functions the module itself defines. Single-line statements, not early
    returns: a return no real module reaches fails the 100% coverage floor on
    tests/.
    """
    if member.__module__ != module.__name__ or name.startswith("_"):
        return False
    hint = get_type_hints(member)["return"]
    element_types = get_args(hint)
    is_list_of_one_dataclass = get_origin(hint) is list and len(element_types) == 1 and is_dataclass(element_types[0])
    return is_list_of_one_dataclass and "service_principal_sources" in {f.name for f in fields(element_types[0])}


def analyzers_producing_service_principal_sources() -> List[FunctionType]:
    """
    Find every public analyzer whose result carries `service_principal_sources`.

    That field is what `deny_service_confused_deputy` consumes, so an analyzer
    producing it and not read by that check is a source guard nobody reports.
    Discovery is by shape - a public function defined in the module, returning
    a list of one dataclass that carries the field - and deliberately not by
    the memo attribute, so that asserting the memo on what is found is a real
    assertion rather than one true by construction.
    """
    return [
        member
        for module in SHARED_ANALYZER_MODULES
        for name, member in inspect.getmembers(module, inspect.isfunction)
        if _produces_service_principal_sources(module, name, member)
    ]


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

        Both sessions carry the same `region_name` because production does:
        `assume_role` reads the region off the one shared base session and
        hands it to every per-account session it mints. An unconfigured
        MagicMock is the opposite -- each attribute access invents a distinct
        child -- so without that line every attribute of a session looks like
        a usable key and a memo keyed on one would pass this test.

        The membership assertions are what pins the key. Comparing the two
        region lists cannot tell a session-keyed memo from one keyed on any
        value that merely differs between two mocks.
        """
        session_a, session_b = MagicMock(), MagicMock()
        session_a.region_name = session_b.region_name = "us-east-1"
        ec2_a, ec2_b = MagicMock(), MagicMock()
        session_a.client.return_value = ec2_a
        session_b.client.return_value = ec2_b
        ec2_a.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}
        ec2_b.describe_regions.return_value = {"Regions": [{"RegionName": "eu-west-1"}]}

        assert get_all_regions(session_a) == ["us-east-1"]
        assert get_all_regions(session_b) == ["eu-west-1"]
        assert get_all_regions(session_a) == ["us-east-1"]

        assert session_a in _REGION_MEMO
        assert session_b in _REGION_MEMO

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

        first = analyzer(session, {"111111111111"}, "o-11111111111")
        second = analyzer(session, {"111111111111"}, "o-11111111111")

        assert first == second == ["result-1"]
        assert len(analyzer.calls) == 1

    def test_each_session_runs_the_analyzer_again(self) -> None:
        """
        Two sessions never share a memo entry.

        A memo keyed wrongly does not crash. It serves one account's
        resource policies to another account, and the generated allowlist
        looks entirely plausible, so this is the failure mode worth pinning.

        Both sessions carry the same `region_name` because production does:
        `assume_role` reads the region off the one shared base session and
        hands it to every per-account session it mints. An unconfigured
        MagicMock is the opposite -- each attribute access invents a distinct
        child -- so without that line every attribute of a session looks like
        a usable key and a memo keyed on one would pass this test. This memo
        has no incidental cover elsewhere in the suite: re-keying the other
        two makes unrelated tests fail, because a region string cannot be
        weakly referenced, while re-keying this one leaves the suite green.

        The membership assertions are what pins the key. Comparing the three
        results cannot tell a session-keyed memo from one keyed on any value
        that merely differs between two mocks.
        """
        analyzer = self._counting_analyzer()
        session_a, session_b = MagicMock(), MagicMock()
        session_a.region_name = session_b.region_name = "us-east-1"

        assert analyzer(session_a, {"111111111111"}, "o-11111111111") == ["result-1"]
        assert analyzer(session_b, {"111111111111"}, "o-11111111111") == ["result-2"]
        assert analyzer(session_a, {"111111111111"}, "o-11111111111") == ["result-1"]

        assert session_a in analyzer.session_memo
        assert session_b in analyzer.session_memo

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

        analyzer(session, {"111111111111"}, "o-11111111111")

        with pytest.raises(RuntimeError, match="different organization arguments"):
            analyzer(session, {"111111111111", "222222222222"}, "o-11111111111")

        with pytest.raises(RuntimeError, match="different organization arguments"):
            analyzer(session, {"111111111111"}, "o-22222222222")

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
        analyzer(session, {"111111111111"}, "o-11111111111")
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
        shared = analyzers_producing_service_principal_sources()

        unmemoized = [
            analyzer.__name__ for analyzer in shared
            if not hasattr(analyzer, "session_memo")
        ]

        assert unmemoized == []

    def test_discovery_finds_the_six_shared_analyzers(self) -> None:
        """
        The shape-based walk finds exactly the analyzers the check reads today.

        The memo test above and the confused-deputy guard in
        `tests/test_checks_deny_service_confused_deputy.py` both pass on an
        empty or short discovery, so this literal is the only assertion that
        fails when the walk misses one - a renamed field, a return type that
        stops being `List[<dataclass>]`, or a module dropped from the list above.
        """
        assert sorted(
            analyzer.__name__ for analyzer in analyzers_producing_service_principal_sources()
        ) == [
            "analyze_ecr_policies",
            "analyze_iam_roles_trust_policies",
            "analyze_kms_key_policies",
            "analyze_s3_bucket_policies",
            "analyze_secrets_manager_policies",
            "analyze_sqs_queue_policies",
        ]


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


class TestFindTagValueAsIamMatches:
    """
    One rule for reading a tag an `aws:RequestTag` condition names.

    Both tag checks call this. They used to read the same kind of tag by two
    different rules - `deny_ec2_imds_v1` case-insensitively on the key,
    `deny_eks_create_cluster_without_tag` exactly - and only one of them could
    be right. The tests here pin the rule itself; each check's own tests pin
    what it does with the answer.
    """

    def test_the_exact_key_returns_its_value(self) -> None:
        assert find_tag_value_as_iam_matches(
            {"PavedRoad": "true"}, "PavedRoad", "Cluster prod"
        ) == "true"

    @pytest.mark.parametrize("key", ["pavedroad", "PAVEDROAD", "pAvEdRoAd"])
    def test_the_key_matches_without_regard_to_case(self, key: str) -> None:
        """AWS matches a condition key name irrespective of its case."""
        assert find_tag_value_as_iam_matches(
            {key: "true"}, "PavedRoad", "Cluster prod"
        ) == "true"

    def test_the_value_is_returned_verbatim(self) -> None:
        """
        The caller compares the value, and must compare it exactly.

        Normalizing it here would hide the case-sensitive half of the match
        from every caller at once.
        """
        assert find_tag_value_as_iam_matches(
            {"PavedRoad": "TRUE"}, "PavedRoad", "Cluster prod"
        ) == "TRUE"

    def test_an_absent_key_is_none_rather_than_empty(self) -> None:
        """
        None distinguishes "no such tag" from a tag whose value is "".

        A caller comparing against "true" treats both as a violation, but the
        two are different facts and the helper does not merge them.
        """
        assert find_tag_value_as_iam_matches(
            {"Name": "prod"}, "PavedRoad", "Cluster prod"
        ) is None

    def test_an_empty_value_is_returned_as_itself(self) -> None:
        assert find_tag_value_as_iam_matches(
            {"PavedRoad": ""}, "PavedRoad", "Cluster prod"
        ) == ""

    def test_the_key_twice_in_differing_cases_raises(self) -> None:
        """
        Both spellings match the condition key; at most one value can.

        Returning either would invent a verdict for a live workload, so there
        is no answer to give.
        """
        with pytest.raises(RuntimeError, match=r"more than once in cases that differ"):
            find_tag_value_as_iam_matches(
                {"PavedRoad": "true", "pavedroad": "false"}, "PavedRoad", "Cluster prod"
            )

    def test_the_error_names_the_resource_and_every_spelling(self) -> None:
        """The operator has to find the tags, so the message carries them."""
        with pytest.raises(RuntimeError) as exc_info:
            find_tag_value_as_iam_matches(
                {"PavedRoad": "true", "pavedroad": "false"}, "PavedRoad", "Cluster prod"
            )

        assert "Cluster prod" in str(exc_info.value)
        assert "PavedRoad, pavedroad" in str(exc_info.value)
