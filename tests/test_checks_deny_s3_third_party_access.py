"""
Tests for headroom.checks.rcps.deny_s3_third_party_access module.
"""

import json
import pytest
import tempfile
import shutil
from unittest.mock import MagicMock, patch
from typing import Any, Dict, Generator, List

from headroom.checks.rcps.deny_s3_third_party_access import DenyS3ThirdPartyAccessCheck
from headroom.constants import DENY_S3_THIRD_PARTY_ACCESS
from headroom.config import DEFAULT_RESULTS_DIR
from headroom.aws.s3 import S3BucketPolicyAnalysis
from headroom.types import JsonDict
from tests.constants import ORG_ID


class TestDenyS3ThirdPartyAccessCheck:
    """Test deny_s3_third_party_access check with various scenarios."""

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def org_account_ids(self) -> set[str]:
        """Organization account IDs for testing."""
        return {"999999999999", "888888888888"}

    @pytest.fixture
    def sample_s3_results_mixed(self) -> List[S3BucketPolicyAnalysis]:
        """Create sample S3 results with mixed compliance status."""
        return [
            S3BucketPolicyAnalysis(
                bucket_name="compliant-bucket",
                bucket_arn="arn:aws:s3:::compliant-bucket",
                third_party_account_ids={"111111111111"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={"111111111111": {"s3:GetObject", "s3:PutObject"}}
            ),
            S3BucketPolicyAnalysis(
                bucket_name="wildcard-bucket",
                bucket_arn="arn:aws:s3:::wildcard-bucket",
                third_party_account_ids={"222222222222"},
                has_wildcard_principal=True,
                has_non_account_principals=False,
                actions_by_account={"222222222222": {"s3:GetObject"}}
            ),
        ]

    def test_check_deny_s3_third_party_access_mixed_results(
        self,
        sample_s3_results_mixed: List[S3BucketPolicyAnalysis],
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test check function with mixed compliance results."""
        mock_session = MagicMock()
        account_name = "test-account"
        account_id = "111111111111"

        with (
            patch("headroom.checks.rcps.deny_s3_third_party_access.analyze_s3_bucket_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_s3_results_mixed

            check = DenyS3ThirdPartyAccessCheck(
                check_name=DENY_S3_THIRD_PARTY_ACCESS,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            assert mock_write.called
            call_args = mock_write.call_args
            results_data = call_args[1]["results_data"]

            assert len(results_data["buckets_with_wildcards"]) == 1
            assert len(results_data["buckets_third_parties_can_access"]) == 2

            summary = results_data["summary"]
            assert summary["total_buckets_analyzed"] == 2
            assert summary["buckets_with_wildcards"] == 1
            assert summary["buckets_third_parties_can_access"] == 2
            assert summary["violations"] == 1
            assert set(summary["unique_third_party_accounts"]) == {"111111111111", "222222222222"}
            assert summary["third_party_account_count"] == 2

    def test_check_all_compliant(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test check with all buckets compliant."""
        mock_session = MagicMock()

        all_compliant = [
            S3BucketPolicyAnalysis(
                bucket_name="compliant-bucket-1",
                bucket_arn="arn:aws:s3:::compliant-bucket-1",
                third_party_account_ids={"111111111111"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={"111111111111": {"s3:GetObject"}}
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_s3_third_party_access.analyze_s3_bucket_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_compliant

            check = DenyS3ThirdPartyAccessCheck(
                check_name=DENY_S3_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["violations"] == 0
            assert summary["buckets_with_wildcards"] == 0
            assert summary["buckets_third_parties_can_access"] == 1

    def test_check_all_violations(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test check with all buckets having violations."""
        mock_session = MagicMock()

        all_violations = [
            S3BucketPolicyAnalysis(
                bucket_name="wildcard-bucket-1",
                bucket_arn="arn:aws:s3:::wildcard-bucket-1",
                third_party_account_ids=set(),
                has_wildcard_principal=True,
                has_non_account_principals=False,
                actions_by_account={}
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_s3_third_party_access.analyze_s3_bucket_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_violations

            check = DenyS3ThirdPartyAccessCheck(
                check_name=DENY_S3_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["violations"] == 1
            assert summary["buckets_with_wildcards"] == 1

    def test_check_empty_results(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test check with no buckets found."""
        mock_session = MagicMock()

        with (
            patch("headroom.checks.rcps.deny_s3_third_party_access.analyze_s3_bucket_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = []

            check = DenyS3ThirdPartyAccessCheck(
                check_name=DENY_S3_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["total_buckets_analyzed"] == 0
            assert summary["violations"] == 0

    def test_categorize_result_violation(
        self,
        org_account_ids: set[str],
    ) -> None:
        """Test categorization of violation."""
        check = DenyS3ThirdPartyAccessCheck(
            check_name=DENY_S3_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=DEFAULT_RESULTS_DIR,
            org_account_ids=org_account_ids,
            org_id=ORG_ID,
        )

        result = S3BucketPolicyAnalysis(
            bucket_name="wildcard-bucket",
            bucket_arn="arn:aws:s3:::wildcard-bucket",
            third_party_account_ids={"222222222222"},
            has_wildcard_principal=True,
            has_non_account_principals=False,
            actions_by_account={"222222222222": {"s3:*"}}
        )

        category, result_dict = check.categorize_result(result)

        assert category == "violation"
        assert result_dict["has_wildcard_principal"] is True

    def test_categorize_result_compliant(
        self,
        org_account_ids: set[str],
    ) -> None:
        """Test categorization of compliant."""
        check = DenyS3ThirdPartyAccessCheck(
            check_name=DENY_S3_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=DEFAULT_RESULTS_DIR,
            org_account_ids=org_account_ids,
            org_id=ORG_ID,
        )

        result = S3BucketPolicyAnalysis(
            bucket_name="compliant-bucket",
            bucket_arn="arn:aws:s3:::compliant-bucket",
            third_party_account_ids={"333333333333"},
            has_wildcard_principal=False,
            has_non_account_principals=False,
            actions_by_account={"333333333333": {"s3:GetObject"}}
        )

        category, result_dict = check.categorize_result(result)

        assert category == "compliant"
        assert result_dict["has_wildcard_principal"] is False

    def test_actions_by_account_tracking(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test that actions by account are correctly tracked and aggregated."""
        mock_session = MagicMock()

        results = [
            S3BucketPolicyAnalysis(
                bucket_name="bucket-1",
                bucket_arn="arn:aws:s3:::bucket-1",
                third_party_account_ids={"111111111111"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={"111111111111": {"s3:GetObject", "s3:PutObject"}}
            ),
            S3BucketPolicyAnalysis(
                bucket_name="bucket-2",
                bucket_arn="arn:aws:s3:::bucket-2",
                third_party_account_ids={"111111111111"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={"111111111111": {"s3:DeleteObject"}}
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_s3_third_party_access.analyze_s3_bucket_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = results

            check = DenyS3ThirdPartyAccessCheck(
                check_name=DENY_S3_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert "111111111111" in summary["actions_by_third_party_account"]
            actions = set(summary["actions_by_third_party_account"]["111111111111"])
            assert actions == {"s3:GetObject", "s3:PutObject", "s3:DeleteObject"}

    def test_buckets_by_account_tracking(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test that buckets by account are correctly tracked."""
        mock_session = MagicMock()

        results = [
            S3BucketPolicyAnalysis(
                bucket_name="bucket-1",
                bucket_arn="arn:aws:s3:::bucket-1",
                third_party_account_ids={"111111111111"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={"111111111111": {"s3:GetObject"}}
            ),
            S3BucketPolicyAnalysis(
                bucket_name="bucket-2",
                bucket_arn="arn:aws:s3:::bucket-2",
                third_party_account_ids={"111111111111", "222222222222"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={
                    "111111111111": {"s3:PutObject"},
                    "222222222222": {"s3:GetObject"}
                }
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_s3_third_party_access.analyze_s3_bucket_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = results

            check = DenyS3ThirdPartyAccessCheck(
                check_name=DENY_S3_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
                org_id=ORG_ID,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert "111111111111" in summary["buckets_by_third_party_account"]
            buckets = set(summary["buckets_by_third_party_account"]["111111111111"])
            assert buckets == {"arn:aws:s3:::bucket-1", "arn:aws:s3:::bucket-2"}

            assert "222222222222" in summary["buckets_by_third_party_account"]
            buckets = set(summary["buckets_by_third_party_account"]["222222222222"])
            assert buckets == {"arn:aws:s3:::bucket-2"}

    def test_categorize_result_with_non_account_principals(
        self,
        org_account_ids: set[str],
    ) -> None:
        """Test categorization of bucket with non-account principals (violation)."""
        check = DenyS3ThirdPartyAccessCheck(
            check_name=DENY_S3_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=DEFAULT_RESULTS_DIR,
            org_account_ids=org_account_ids,
            org_id=ORG_ID,
        )

        result = S3BucketPolicyAnalysis(
            bucket_name="federated-bucket",
            bucket_arn="arn:aws:s3:::federated-bucket",
            third_party_account_ids=set(),
            has_wildcard_principal=False,
            has_non_account_principals=True,
            actions_by_account={}
        )

        category, result_dict = check.categorize_result(result)

        assert category == "violation"
        assert result_dict["has_non_account_principals"] is True


# One statement whose bare wildcard `aws:PrincipalAccount` bounds to a single
# account outside the organization. Both tests below read the same statement,
# because what varies between them is what the check does with it.
CONFINED_WILDCARD_STATEMENT: JsonDict = {
    "Effect": "Allow",
    "Principal": {"AWS": "*"},
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::vendor-bucket/*",
    "Condition": {"StringEquals": {"aws:PrincipalAccount": ["333333333333"]}},
}


class TestConfinedWildcards:
    """
    A wildcard the Condition block bounds travels the check as the accounts it admits.

    The adapter stops calling such a statement a wildcard, so the check must
    still carry the accounts it named into the allowlist. Clearing the
    violation without carrying the accounts ships an RCP that denies exactly
    the access the bucket policy granted.

    The other tests in this file hand the check a pre-built
    S3BucketPolicyAnalysis, which cannot show whether the adapter read a
    wildcard as confined; these mock the client so analyze_s3_bucket_policies
    itself does the reading.
    """

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @staticmethod
    def _session_holding(policy: JsonDict) -> MagicMock:
        """
        Build a session whose one bucket carries this policy and an owner-only ACL.

        Args:
            policy: Bucket policy document, as the API returns it

        Returns:
            A session the real S3 analyzer can read
        """
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client

        bucket_paginator = MagicMock()
        bucket_paginator.paginate.return_value = [
            {"Buckets": [{"Name": "vendor-bucket"}]}
        ]
        mock_s3_client.get_paginator.return_value = bucket_paginator
        mock_s3_client.get_bucket_acl.return_value = {
            "Owner": {"ID": "a" * 64},
            "Grants": [],
        }
        mock_s3_client.get_bucket_policy.return_value = {"Policy": json.dumps(policy)}
        return mock_session

    @staticmethod
    def _results_data(temp_results_dir: str, mock_session: MagicMock) -> Dict[str, Any]:
        """
        Run the check against a session and return the document it wrote.

        Args:
            temp_results_dir: Directory the check writes results to
            mock_session: Session the analyzer reads

        Returns:
            The whole result document, summary and entries alike
        """
        check = DenyS3ThirdPartyAccessCheck(
            check_name=DENY_S3_THIRD_PARTY_ACCESS,
            account_name="test-account",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids={"111111111111", "222222222222"},
            org_id=ORG_ID,
        )

        with (
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print"),
        ):
            check.execute(mock_session)

        results_data: Dict[str, Any] = mock_write.call_args[1]["results_data"]
        return results_data

    def test_a_wildcard_confined_to_out_of_org_accounts_reaches_the_allowlist(
        self, temp_results_dir: str
    ) -> None:
        """
        Clearing the violation without allowlisting the account is the outage.

        The bucket grants 333333333333 and nobody else, so the RCP may ship -
        but only carrying that account. An RCP that shipped because the
        wildcard was read as confined and then omitted the account it was
        confined to would deny the one caller the policy admits.
        """
        mock_session = self._session_holding(
            {"Version": "2012-10-17", "Statement": [CONFINED_WILDCARD_STATEMENT]}
        )

        summary = self._results_data(temp_results_dir, mock_session)["summary"]

        assert summary["violations"] == 0
        assert summary["unique_third_party_accounts"] == ["333333333333"]

    def test_a_confined_entry_names_the_key_that_confined_it(
        self, temp_results_dir: str
    ) -> None:
        """
        The entry records why the bucket stopped counting as a wildcard.

        Without the key, a reader of the result file sees a bucket with
        `has_wildcard_principal: false` and no way to tell a policy that
        never named a wildcard from one whose wildcard a condition bounded.
        """
        mock_session = self._session_holding(
            {"Version": "2012-10-17", "Statement": [CONFINED_WILDCARD_STATEMENT]}
        )

        results_data = self._results_data(temp_results_dir, mock_session)

        assert results_data["buckets_with_wildcards"] == []
        entry = results_data["buckets_third_parties_can_access"][0]
        assert entry["bucket_name"] == "vendor-bucket"
        assert entry["confined_by"] == ["aws:principalaccount"]
