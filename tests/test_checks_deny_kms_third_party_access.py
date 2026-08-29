"""
Tests for headroom.checks.rcps.deny_kms_third_party_access module.
"""

import pytest
import tempfile
import shutil
from unittest.mock import MagicMock, patch
from typing import List, Generator

from headroom.checks.rcps.deny_kms_third_party_access import DenyKMSThirdPartyAccessCheck
from headroom.constants import DENY_KMS_THIRD_PARTY_ACCESS
from headroom.config import DEFAULT_RESULTS_DIR
from headroom.aws.kms import KMSGrantFinding, KMSKeyPolicyAnalysis


class TestCheckDenyKMSThirdPartyAccess:
    """Test deny_kms_third_party_access check with various scenarios."""

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def org_account_ids(self) -> set[str]:
        """Organization account IDs for testing."""
        return {"111111111111", "222222222222"}

    @pytest.fixture
    def sample_kms_results_mixed(self) -> List[KMSKeyPolicyAnalysis]:
        """Create sample KMS results with mixed compliance status."""
        return [
            KMSKeyPolicyAnalysis(
                key_id="key-compliant",
                key_arn="arn:aws:kms:us-east-1:111111111111:key/key-compliant",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={
                    "999999999999": ["kms:Decrypt", "kms:DescribeKey"]
                },
                has_wildcard_principal=False
            ),
            KMSKeyPolicyAnalysis(
                key_id="key-violation",
                key_arn="arn:aws:kms:us-east-1:111111111111:key/key-violation",
                region="us-east-1",
                third_party_account_ids=set(),
                actions_by_account={},
                has_wildcard_principal=True
            ),
        ]

    def test_check_deny_kms_third_party_access_mixed_results(
        self,
        sample_kms_results_mixed: List[KMSKeyPolicyAnalysis],
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test check function with mixed compliance results."""
        mock_session = MagicMock()
        account_name = "test-account"
        account_id = "111111111111"

        with (
            patch("headroom.checks.rcps.deny_kms_third_party_access.analyze_kms_key_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_kms_results_mixed

            check = DenyKMSThirdPartyAccessCheck(
                check_name=DENY_KMS_THIRD_PARTY_ACCESS,
                account_name=account_name,
                account_id=account_id,
                results_dir=DEFAULT_RESULTS_DIR,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            assert mock_write.called
            results_data = mock_write.call_args[1]["results_data"]

            assert len(results_data["keys_with_wildcards"]) == 1
            assert len(results_data["keys_third_parties_can_access"]) == 2

            summary = results_data["summary"]
            assert summary["total_keys_analyzed"] == 2
            assert summary["keys_third_parties_can_access"] == 1
            assert summary["keys_with_wildcards"] == 1
            assert summary["violations"] == 1
            assert summary["unique_third_party_accounts"] == ["999999999999"]
            assert summary["third_party_account_count"] == 1
            assert "999999999999" in summary["actions_by_account"]
            assert "kms:Decrypt" in summary["actions_by_account"]["999999999999"]
            assert "kms:DescribeKey" in summary["actions_by_account"]["999999999999"]

    def test_check_all_compliant(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test check with all keys compliant."""
        mock_session = MagicMock()

        all_compliant = [
            KMSKeyPolicyAnalysis(
                key_id="key-compliant-1",
                key_arn="arn:aws:kms:us-east-1:111111111111:key/key-compliant-1",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={
                    "999999999999": ["kms:Decrypt"]
                },
                has_wildcard_principal=False
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_kms_third_party_access.analyze_kms_key_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_compliant

            check = DenyKMSThirdPartyAccessCheck(
                check_name=DENY_KMS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=DEFAULT_RESULTS_DIR,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["violations"] == 0
            assert summary["keys_with_wildcards"] == 0
            assert summary["keys_third_parties_can_access"] == 1

    def test_check_all_violations(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test check with all keys as violations."""
        mock_session = MagicMock()

        all_violations = [
            KMSKeyPolicyAnalysis(
                key_id="key-wildcard-1",
                key_arn="arn:aws:kms:us-east-1:111111111111:key/key-wildcard-1",
                region="us-east-1",
                third_party_account_ids=set(),
                actions_by_account={},
                has_wildcard_principal=True
            ),
            KMSKeyPolicyAnalysis(
                key_id="key-wildcard-2",
                key_arn="arn:aws:kms:us-west-2:111111111111:key/key-wildcard-2",
                region="us-west-2",
                third_party_account_ids={"888888888888"},
                actions_by_account={
                    "888888888888": ["kms:*"]
                },
                has_wildcard_principal=True
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_kms_third_party_access.analyze_kms_key_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_violations

            check = DenyKMSThirdPartyAccessCheck(
                check_name=DENY_KMS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=DEFAULT_RESULTS_DIR,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["violations"] == 2
            assert summary["keys_with_wildcards"] == 2
            assert summary["keys_third_parties_can_access"] == 1

    def test_check_empty_results(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test check with no keys found."""
        mock_session = MagicMock()

        with (
            patch("headroom.checks.rcps.deny_kms_third_party_access.analyze_kms_key_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = []

            check = DenyKMSThirdPartyAccessCheck(
                check_name=DENY_KMS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=DEFAULT_RESULTS_DIR,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["total_keys_analyzed"] == 0
            assert summary["violations"] == 0
            assert summary["unique_third_party_accounts"] == []
            assert summary["third_party_account_count"] == 0
            assert summary["actions_by_account"] == {}

    def test_categorize_result_violation(
        self,
        org_account_ids: set[str],
    ) -> None:
        """Test categorization of violation."""
        check = DenyKMSThirdPartyAccessCheck(
            check_name=DENY_KMS_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=DEFAULT_RESULTS_DIR,
            org_account_ids=org_account_ids,
        )

        result = KMSKeyPolicyAnalysis(
            key_id="key-wildcard",
            key_arn="arn:aws:kms:us-east-1:111111111111:key/key-wildcard",
            region="us-east-1",
            third_party_account_ids=set(),
            actions_by_account={},
            has_wildcard_principal=True
        )

        category, result_dict = check.categorize_result(result)

        assert category.value == "violation"
        assert result_dict["has_wildcard_principal"] is True

    def test_categorize_result_compliant(
        self,
        org_account_ids: set[str],
    ) -> None:
        """Test categorization of compliant."""
        check = DenyKMSThirdPartyAccessCheck(
            check_name=DENY_KMS_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=DEFAULT_RESULTS_DIR,
            org_account_ids=org_account_ids,
        )

        result = KMSKeyPolicyAnalysis(
            key_id="key-compliant",
            key_arn="arn:aws:kms:us-east-1:111111111111:key/key-compliant",
            region="us-east-1",
            third_party_account_ids={"999999999999"},
            actions_by_account={
                "999999999999": ["kms:Decrypt"]
            },
            has_wildcard_principal=False
        )

        category, result_dict = check.categorize_result(result)

        assert category.value == "compliant"
        assert result_dict["has_wildcard_principal"] is False
        assert result_dict["third_party_account_ids"] == ["999999999999"]

    def test_actions_aggregation_across_keys(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test that actions are aggregated across multiple keys for same account."""
        mock_session = MagicMock()

        results_with_multiple_keys = [
            KMSKeyPolicyAnalysis(
                key_id="key-1",
                key_arn="arn:aws:kms:us-east-1:111111111111:key/key-1",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={
                    "999999999999": ["kms:Decrypt", "kms:DescribeKey"]
                },
                has_wildcard_principal=False
            ),
            KMSKeyPolicyAnalysis(
                key_id="key-2",
                key_arn="arn:aws:kms:us-east-1:111111111111:key/key-2",
                region="us-east-1",
                third_party_account_ids={"999999999999"},
                actions_by_account={
                    "999999999999": ["kms:Encrypt", "kms:DescribeKey"]
                },
                has_wildcard_principal=False
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_kms_third_party_access.analyze_kms_key_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = results_with_multiple_keys

            check = DenyKMSThirdPartyAccessCheck(
                check_name=DENY_KMS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=DEFAULT_RESULTS_DIR,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            actions = summary["actions_by_account"]["999999999999"]
            assert len(actions) == 3
            assert "kms:Decrypt" in actions
            assert "kms:DescribeKey" in actions
            assert "kms:Encrypt" in actions

    def test_multiple_third_party_accounts(
        self,
        temp_results_dir: str,
        org_account_ids: set[str],
    ) -> None:
        """Test tracking multiple third-party accounts."""
        mock_session = MagicMock()

        results_with_multiple_accounts = [
            KMSKeyPolicyAnalysis(
                key_id="key-multi",
                key_arn="arn:aws:kms:us-east-1:111111111111:key/key-multi",
                region="us-east-1",
                third_party_account_ids={"999999999999", "888888888888"},
                actions_by_account={
                    "999999999999": ["kms:Decrypt"],
                    "888888888888": ["kms:Encrypt"]
                },
                has_wildcard_principal=False
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_kms_third_party_access.analyze_kms_key_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = results_with_multiple_accounts

            check = DenyKMSThirdPartyAccessCheck(
                check_name=DENY_KMS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=DEFAULT_RESULTS_DIR,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["third_party_account_count"] == 2
            assert set(summary["unique_third_party_accounts"]) == {"888888888888", "999999999999"}
            assert "888888888888" in summary["actions_by_account"]
            assert "999999999999" in summary["actions_by_account"]


class TestGrantSourcedResults:
    """
    Results whose third party came from a grant, not the key policy.

    A grant is invisible to GetKeyPolicy, so these are the keys that would
    have shipped an RCP that denied access the account depended on.
    """

    ORG_ACCOUNT = "111111111111"
    THIRD_PARTY = "999999999999"

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @staticmethod
    def _grant_sourced_key(key_id: str = "key-grant") -> KMSKeyPolicyAnalysis:
        """Build a key whose policy is clean but whose grant is not."""
        return KMSKeyPolicyAnalysis(
            key_id=key_id,
            key_arn=(
                f"arn:aws:kms:us-east-1:"
                f"{TestGrantSourcedResults.ORG_ACCOUNT}:key/{key_id}"
            ),
            region="us-east-1",
            third_party_account_ids={TestGrantSourcedResults.THIRD_PARTY},
            actions_by_account={
                TestGrantSourcedResults.THIRD_PARTY: ["kms:Decrypt"]
            },
            has_wildcard_principal=False,
            grants=[
                KMSGrantFinding(
                    grant_id="grant-abc",
                    grantee_account_id=TestGrantSourcedResults.THIRD_PARTY,
                    retiring_principal_account_id=None,
                    operations=["kms:Decrypt"],
                    has_constraints=False,
                )
            ],
        )

    @staticmethod
    def _run(
        results: List[KMSKeyPolicyAnalysis],
        temp_results_dir: str,
    ) -> dict:
        """Execute the check over the given analyses and return results_data."""
        mock_session = MagicMock()

        with (
            patch(
                "headroom.checks.rcps.deny_kms_third_party_access."
                "analyze_kms_key_policies"
            ) as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print"),
        ):
            mock_analysis.return_value = results

            check = DenyKMSThirdPartyAccessCheck(
                check_name=DENY_KMS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id=TestGrantSourcedResults.ORG_ACCOUNT,
                results_dir=temp_results_dir,
                org_account_ids={TestGrantSourcedResults.ORG_ACCOUNT},
            )
            check.execute(mock_session)

            results_data: dict = mock_write.call_args[1]["results_data"]
            return results_data

    def test_grants_are_written_to_the_result(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        The result records which grant produced the third party.

        Without it a reader sees an account in the allowlist, opens the key
        policy, finds nothing, and cannot tell where the entry came from.
        """
        results_data = self._run(
            [self._grant_sourced_key()], temp_results_dir
        )

        key = results_data["keys_third_parties_can_access"][0]
        assert key["grants"] == [
            {
                "grant_id": "grant-abc",
                "grantee_account_id": self.THIRD_PARTY,
                "retiring_principal_account_id": None,
                "operations": ["kms:Decrypt"],
                "has_constraints": False,
            }
        ]

    def test_grant_third_party_reaches_the_allowlist(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        A grantee account flows to the Terraform allowlist like any other.

        Grant principals are ordinary IAM ARNs, so unlike an S3 ACL grantee
        they cost the account no RCP coverage.
        """
        results_data = self._run(
            [self._grant_sourced_key()], temp_results_dir
        )

        summary = results_data["summary"]
        assert summary["unique_third_party_accounts"] == [self.THIRD_PARTY]
        assert summary["actions_by_account"][self.THIRD_PARTY] == ["kms:Decrypt"]

    def test_a_grant_only_key_is_not_a_violation(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        Reading grants can widen the allowlist but never withhold the RCP.

        `violations` is what sets blocks_rcp, so a grant raising it would
        cost the account an RCP it should still get.
        """
        results_data = self._run(
            [self._grant_sourced_key()], temp_results_dir
        )

        assert results_data["summary"]["violations"] == 0
        assert results_data["keys_with_wildcards"] == []

    def test_summary_counts_keys_with_third_party_grants(
        self,
        temp_results_dir: str,
    ) -> None:
        """
        The summary says whether the grant surface found anything.

        A key with a clean policy and a third-party grant is otherwise
        indistinguishable in the summary from one found the usual way.
        """
        policy_sourced_key = KMSKeyPolicyAnalysis(
            key_id="key-policy",
            key_arn=(
                f"arn:aws:kms:us-east-1:{self.ORG_ACCOUNT}:key/key-policy"
            ),
            region="us-east-1",
            third_party_account_ids={"888888888888"},
            actions_by_account={"888888888888": ["kms:DescribeKey"]},
            has_wildcard_principal=False,
        )

        results_data = self._run(
            [self._grant_sourced_key(), policy_sourced_key], temp_results_dir
        )

        summary = results_data["summary"]
        assert summary["total_keys_analyzed"] == 2
        assert summary["keys_with_third_party_grants"] == 1
