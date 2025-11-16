"""
Tests for headroom.checks.rcps.deny_secrets_manager_third_party_access module.
"""

import tempfile
import shutil
from typing import Generator, List, Set
from unittest.mock import MagicMock, patch

import pytest

from headroom.aws.secretsmanager import SecretsPolicyAnalysis
from headroom.checks.rcps.deny_secrets_manager_third_party_access import (
    DenySecretsManagerThirdPartyAccessCheck,
)
from headroom.constants import DENY_SECRETS_MANAGER_THIRD_PARTY_ACCESS


class TestDenySecretsManagerThirdPartyAccessCheck:
    """Test deny_secrets_manager_third_party_access check with various scenarios."""

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def org_account_ids(self) -> Set[str]:
        """Create sample organization account IDs."""
        return {"111111111111", "222222222222"}

    @pytest.fixture
    def sample_secrets_mixed(self) -> List[SecretsPolicyAnalysis]:
        """Create sample secrets with mixed third-party access."""
        return [
            SecretsPolicyAnalysis(
                secret_name="vendor-secret",
                secret_arn="arn:aws:secretsmanager:us-east-1:111111111111:secret:vendor-secret",
                third_party_account_ids={"999999999999"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={
                    "999999999999": {"secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"}
                }
            ),
            SecretsPolicyAnalysis(
                secret_name="public-secret",
                secret_arn="arn:aws:secretsmanager:us-east-1:111111111111:secret:public-secret",
                third_party_account_ids=set(),
                has_wildcard_principal=True,
                has_non_account_principals=False,
                actions_by_account={}
            ),
        ]

    def test_check_mixed_results(
        self,
        sample_secrets_mixed: List[SecretsPolicyAnalysis],
        temp_results_dir: str,
        org_account_ids: Set[str],
    ) -> None:
        """Test check with mixed compliance results."""
        mock_session = MagicMock()
        account_name = "test-account"
        account_id = "111111111111"

        with (
            patch("headroom.checks.rcps.deny_secrets_manager_third_party_access.analyze_secrets_manager_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_secrets_mixed

            check = DenySecretsManagerThirdPartyAccessCheck(
                check_name=DENY_SECRETS_MANAGER_THIRD_PARTY_ACCESS,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            assert mock_write.called
            call_args = mock_write.call_args
            results_data = call_args[0][0]

            assert len(results_data["secrets_with_wildcards"]) == 1
            assert len(results_data["secrets_third_parties_can_access"]) == 2

            summary = results_data["summary"]
            assert summary["total_secrets_analyzed"] == 2
            assert summary["secrets_with_wildcards"] == 1
            assert summary["violations"] == 1
            assert summary["unique_third_party_accounts"] == ["999999999999"]
            assert summary["third_party_account_count"] == 1
            assert "999999999999" in summary["actions_by_third_party_account"]
            assert "secretsmanager:GetSecretValue" in summary["actions_by_third_party_account"]["999999999999"]

    def test_check_all_compliant(
        self,
        temp_results_dir: str,
        org_account_ids: Set[str],
    ) -> None:
        """Test check with all secrets compliant."""
        mock_session = MagicMock()

        all_compliant = [
            SecretsPolicyAnalysis(
                secret_name="vendor-secret",
                secret_arn="arn:aws:secretsmanager:us-east-1:111111111111:secret:vendor-secret",
                third_party_account_ids={"999999999999"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={
                    "999999999999": {"secretsmanager:GetSecretValue"}
                }
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_secrets_manager_third_party_access.analyze_secrets_manager_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_compliant

            check = DenySecretsManagerThirdPartyAccessCheck(
                check_name=DENY_SECRETS_MANAGER_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            assert summary["violations"] == 0
            assert summary["secrets_with_wildcards"] == 0
            assert summary["secrets_third_parties_can_access"] == 1

    def test_check_all_violations(
        self,
        temp_results_dir: str,
        org_account_ids: Set[str],
    ) -> None:
        """Test check with all violations."""
        mock_session = MagicMock()

        all_violations = [
            SecretsPolicyAnalysis(
                secret_name="wildcard-secret",
                secret_arn="arn:aws:secretsmanager:us-east-1:111111111111:secret:wildcard-secret",
                third_party_account_ids=set(),
                has_wildcard_principal=True,
                has_non_account_principals=False,
                actions_by_account={}
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_secrets_manager_third_party_access.analyze_secrets_manager_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_violations

            check = DenySecretsManagerThirdPartyAccessCheck(
                check_name=DENY_SECRETS_MANAGER_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            assert summary["violations"] == 1
            assert summary["secrets_with_wildcards"] == 1
            assert summary["secrets_third_parties_can_access"] == 1

    def test_check_empty_results(
        self,
        temp_results_dir: str,
        org_account_ids: Set[str],
    ) -> None:
        """Test check with no secrets."""
        mock_session = MagicMock()

        with (
            patch("headroom.checks.rcps.deny_secrets_manager_third_party_access.analyze_secrets_manager_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = []

            check = DenySecretsManagerThirdPartyAccessCheck(
                check_name=DENY_SECRETS_MANAGER_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            assert summary["total_secrets_analyzed"] == 0
            assert summary["violations"] == 0
            assert summary["unique_third_party_accounts"] == []

    def test_categorize_result_violation_wildcard(
        self,
        temp_results_dir: str,
        org_account_ids: Set[str],
    ) -> None:
        """Test categorization of violation with wildcard."""
        check = DenySecretsManagerThirdPartyAccessCheck(
            check_name=DENY_SECRETS_MANAGER_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids=org_account_ids,
        )

        result = SecretsPolicyAnalysis(
            secret_name="wildcard-secret",
            secret_arn="arn:aws:secretsmanager:us-east-1:111111111111:secret:wildcard-secret",
            third_party_account_ids=set(),
            has_wildcard_principal=True,
            has_non_account_principals=False,
            actions_by_account={}
        )

        category, result_dict = check.categorize_result(result)

        assert category.value == "violation"
        assert result_dict["has_wildcard_principal"] is True

    def test_categorize_result_compliant(
        self,
        temp_results_dir: str,
        org_account_ids: Set[str],
    ) -> None:
        """Test categorization of compliant secret."""
        check = DenySecretsManagerThirdPartyAccessCheck(
            check_name=DENY_SECRETS_MANAGER_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids=org_account_ids,
        )

        result = SecretsPolicyAnalysis(
            secret_name="vendor-secret",
            secret_arn="arn:aws:secretsmanager:us-east-1:111111111111:secret:vendor-secret",
            third_party_account_ids={"999999999999"},
            has_wildcard_principal=False,
            has_non_account_principals=False,
            actions_by_account={
                "999999999999": {"secretsmanager:GetSecretValue"}
            }
        )

        category, result_dict = check.categorize_result(result)

        assert category.value == "compliant"
        assert result_dict["has_wildcard_principal"] is False
        assert "999999999999" in result_dict["third_party_account_ids"]

    def test_actions_tracking(
        self,
        temp_results_dir: str,
        org_account_ids: Set[str],
    ) -> None:
        """Test that actions are tracked correctly per account."""
        mock_session = MagicMock()

        secrets = [
            SecretsPolicyAnalysis(
                secret_name="secret-1",
                secret_arn="arn:aws:secretsmanager:us-east-1:111111111111:secret:secret-1",
                third_party_account_ids={"999999999999"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={
                    "999999999999": {"secretsmanager:GetSecretValue"}
                }
            ),
            SecretsPolicyAnalysis(
                secret_name="secret-2",
                secret_arn="arn:aws:secretsmanager:us-east-1:111111111111:secret:secret-2",
                third_party_account_ids={"999999999999"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={
                    "999999999999": {"secretsmanager:PutSecretValue"}
                }
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_secrets_manager_third_party_access.analyze_secrets_manager_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = secrets

            check = DenySecretsManagerThirdPartyAccessCheck(
                check_name=DENY_SECRETS_MANAGER_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            actions = set(summary["actions_by_third_party_account"]["999999999999"])
            assert "secretsmanager:GetSecretValue" in actions
            assert "secretsmanager:PutSecretValue" in actions

    def test_secrets_tracking(
        self,
        temp_results_dir: str,
        org_account_ids: Set[str],
    ) -> None:
        """Test that secrets are tracked correctly per account."""
        mock_session = MagicMock()

        secrets = [
            SecretsPolicyAnalysis(
                secret_name="secret-1",
                secret_arn="arn:aws:secretsmanager:us-east-1:111111111111:secret:secret-1",
                third_party_account_ids={"999999999999"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={
                    "999999999999": {"secretsmanager:GetSecretValue"}
                }
            ),
            SecretsPolicyAnalysis(
                secret_name="secret-2",
                secret_arn="arn:aws:secretsmanager:us-east-1:111111111111:secret:secret-2",
                third_party_account_ids={"999999999999"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={
                    "999999999999": {"secretsmanager:GetSecretValue"}
                }
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_secrets_manager_third_party_access.analyze_secrets_manager_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = secrets

            check = DenySecretsManagerThirdPartyAccessCheck(
                check_name=DENY_SECRETS_MANAGER_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[0][0]
            summary = results_data["summary"]

            secrets_arns = summary["secrets_by_third_party_account"]["999999999999"]
            assert len(secrets_arns) == 2
            assert "arn:aws:secretsmanager:us-east-1:111111111111:secret:secret-1" in secrets_arns
            assert "arn:aws:secretsmanager:us-east-1:111111111111:secret:secret-2" in secrets_arns
