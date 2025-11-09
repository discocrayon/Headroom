"""
Tests for headroom.checks.deny_third_party_assumerole module.

Tests for deny_third_party_assumerole function and its integration with IAM analysis.
"""

from unittest.mock import MagicMock, patch
from typing import List, Set
from headroom.checks.rcps.deny_third_party_assumerole import ThirdPartyAssumeRoleCheck
from headroom.constants import THIRD_PARTY_ASSUMEROLE
from headroom.aws.iam import TrustPolicyAnalysis
from headroom.config import DEFAULT_RESULTS_DIR


class TestCheckThirdPartyAssumeRole:
    """Test check_third_party_assumerole function with various scenarios."""

    def test_roles_with_third_party_accounts(self) -> None:
        """Test check with roles having third-party accounts."""
        mock_session = MagicMock()
        account_name = "test-account"
        account_id = "111111111111"
        org_account_ids: Set[str] = {"111111111111", "222222222222"}

        trust_policy_results = [
            TrustPolicyAnalysis(
                role_name="ThirdPartyRole1",
                role_arn="arn:aws:iam::111111111111:role/ThirdPartyRole1",
                third_party_account_ids={"999999999999", "888888888888"},
                has_wildcard_principal=False
            ),
            TrustPolicyAnalysis(
                role_name="ThirdPartyRole2",
                role_arn="arn:aws:iam::111111111111:role/ThirdPartyRole2",
                third_party_account_ids={"777777777777"},
                has_wildcard_principal=False
            )
        ]

        with (
            patch("headroom.checks.rcps.deny_third_party_assumerole.analyze_iam_roles_trust_policies") as mock_analyze,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analyze.return_value = trust_policy_results

            check = ThirdPartyAssumeRoleCheck(
                check_name=THIRD_PARTY_ASSUMEROLE,
                account_name=account_name,
                account_id=account_id,
                results_dir=DEFAULT_RESULTS_DIR,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            mock_analyze.assert_called_once_with(mock_session, org_account_ids)
            mock_write.assert_called_once()

            write_call_args = mock_write.call_args
            assert write_call_args[1]["check_name"] == "third_party_assumerole"
            assert write_call_args[1]["account_name"] == account_name
            assert write_call_args[1]["account_id"] == account_id

            results_data = write_call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["account_name"] == "test-account"
            assert summary["account_id"] == "111111111111"
            assert summary["check"] == "third_party_assumerole"
            assert summary["total_roles_analyzed"] == 2
            assert summary["roles_third_parties_can_access"] == 2
            assert summary["roles_with_wildcards"] == 0
            assert summary["violations"] == 0
            assert summary["third_party_account_count"] == 3
            assert set(summary["unique_third_party_accounts"]) == {"777777777777", "888888888888", "999999999999"}

            assert len(results_data["roles_third_parties_can_access"]) == 2
            assert len(results_data["roles_with_wildcards"]) == 0

            assert check.all_third_party_accounts == {"777777777777", "888888888888", "999999999999"}

    def test_roles_with_wildcards(self) -> None:
        """Test check with roles having wildcard principals."""
        mock_session = MagicMock()
        account_name = "wildcard-account"
        account_id = "222222222222"
        org_account_ids: Set[str] = {"111111111111", "222222222222"}

        trust_policy_results = [
            TrustPolicyAnalysis(
                role_name="PublicRole",
                role_arn="arn:aws:iam::222222222222:role/PublicRole",
                third_party_account_ids=set(),
                has_wildcard_principal=True
            )
        ]

        with (
            patch("headroom.checks.rcps.deny_third_party_assumerole.analyze_iam_roles_trust_policies") as mock_analyze,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analyze.return_value = trust_policy_results

            check = ThirdPartyAssumeRoleCheck(
                check_name=THIRD_PARTY_ASSUMEROLE,
                account_name=account_name,
                account_id=account_id,
                results_dir=DEFAULT_RESULTS_DIR,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            write_call_args = mock_write.call_args
            results_data = write_call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["roles_with_wildcards"] == 1
            assert summary["violations"] == 1
            assert summary["roles_third_parties_can_access"] == 0
            assert summary["third_party_account_count"] == 0

            assert len(results_data["roles_with_wildcards"]) == 1
            assert results_data["roles_with_wildcards"][0]["has_wildcard_principal"] is True

            assert check.all_third_party_accounts == set()

    def test_roles_with_both_wildcard_and_third_party(self) -> None:
        """Test check with role having both wildcard and third-party accounts."""
        mock_session = MagicMock()
        account_name = "mixed-account"
        account_id = "333333333333"
        org_account_ids: Set[str] = {"111111111111", "222222222222", "333333333333"}

        trust_policy_results = [
            TrustPolicyAnalysis(
                role_name="MixedRole",
                role_arn="arn:aws:iam::333333333333:role/MixedRole",
                third_party_account_ids={"999999999999"},
                has_wildcard_principal=True
            )
        ]

        with (
            patch("headroom.checks.rcps.deny_third_party_assumerole.analyze_iam_roles_trust_policies") as mock_analyze,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analyze.return_value = trust_policy_results

            check = ThirdPartyAssumeRoleCheck(
                check_name=THIRD_PARTY_ASSUMEROLE,
                account_name=account_name,
                account_id=account_id,
                results_dir=DEFAULT_RESULTS_DIR,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            write_call_args = mock_write.call_args
            results_data = write_call_args[1]["results_data"]

            assert len(results_data["roles_with_wildcards"]) == 1
            assert len(results_data["roles_third_parties_can_access"]) == 1

            assert check.all_third_party_accounts == {"999999999999"}

    def test_no_roles_with_findings(self) -> None:
        """Test check with no roles having third-party access or wildcards."""
        mock_session = MagicMock()
        account_name = "clean-account"
        account_id = "444444444444"
        org_account_ids: Set[str] = {"111111111111", "222222222222", "444444444444"}

        trust_policy_results: List[TrustPolicyAnalysis] = []

        with (
            patch("headroom.checks.rcps.deny_third_party_assumerole.analyze_iam_roles_trust_policies") as mock_analyze,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analyze.return_value = trust_policy_results

            check = ThirdPartyAssumeRoleCheck(
                check_name=THIRD_PARTY_ASSUMEROLE,
                account_name=account_name,
                account_id=account_id,
                results_dir=DEFAULT_RESULTS_DIR,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            write_call_args = mock_write.call_args
            results_data = write_call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["total_roles_analyzed"] == 0
            assert summary["roles_third_parties_can_access"] == 0
            assert summary["roles_with_wildcards"] == 0
            assert summary["violations"] == 0
            assert summary["third_party_account_count"] == 0

            assert check.all_third_party_accounts == set()

    def test_exclude_account_ids_parameter(self) -> None:
        """Test that exclude_account_ids parameter is passed correctly."""
        mock_session = MagicMock()
        account_name = "test-account"
        account_id = "555555555555"
        org_account_ids: Set[str] = {"111111111111", "555555555555"}

        trust_policy_results = [
            TrustPolicyAnalysis(
                role_name="Role1",
                role_arn="arn:aws:iam::555555555555:role/Role1",
                third_party_account_ids={"999999999999"},
                has_wildcard_principal=False
            )
        ]

        with (
            patch("headroom.checks.rcps.deny_third_party_assumerole.analyze_iam_roles_trust_policies") as mock_analyze,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analyze.return_value = trust_policy_results

            check = ThirdPartyAssumeRoleCheck(
                check_name=THIRD_PARTY_ASSUMEROLE,
                account_name=account_name,
                account_id=account_id,
                results_dir=DEFAULT_RESULTS_DIR,
                org_account_ids=org_account_ids,
                exclude_account_ids=True,
            )
            check.execute(mock_session)

            write_call_args = mock_write.call_args
            assert write_call_args[1]["exclude_account_ids"] is True

    def test_result_data_structure(self) -> None:
        """Test the complete structure of result data."""
        mock_session = MagicMock()
        account_name = "structure-test"
        account_id = "666666666666"
        org_account_ids: Set[str] = {"666666666666"}

        trust_policy_results = [
            TrustPolicyAnalysis(
                role_name="TestRole",
                role_arn="arn:aws:iam::666666666666:role/TestRole",
                third_party_account_ids={"999999999999"},
                has_wildcard_principal=True
            )
        ]

        with (
            patch("headroom.checks.rcps.deny_third_party_assumerole.analyze_iam_roles_trust_policies") as mock_analyze,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analyze.return_value = trust_policy_results

            check = ThirdPartyAssumeRoleCheck(
                check_name=THIRD_PARTY_ASSUMEROLE,
                account_name=account_name,
                account_id=account_id,
                results_dir=DEFAULT_RESULTS_DIR,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            write_call_args = mock_write.call_args
            results_data = write_call_args[1]["results_data"]

            assert set(results_data.keys()) == {"summary", "roles_third_parties_can_access", "roles_with_wildcards"}

            summary = results_data["summary"]
            expected_summary_keys = {
                "account_name", "account_id", "check", "total_roles_analyzed",
                "roles_third_parties_can_access", "roles_with_wildcards",
                "violations", "unique_third_party_accounts", "third_party_account_count"
            }
            assert set(summary.keys()) == expected_summary_keys

            for role in results_data["roles_third_parties_can_access"]:
                expected_keys = {"role_name", "role_arn", "third_party_account_ids", "has_wildcard_principal"}
                assert set(role.keys()) == expected_keys

            for role in results_data["roles_with_wildcards"]:
                expected_keys = {"role_name", "role_arn", "third_party_account_ids", "has_wildcard_principal"}
                assert set(role.keys()) == expected_keys
