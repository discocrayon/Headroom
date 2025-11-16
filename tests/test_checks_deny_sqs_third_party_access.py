"""
Tests for headroom.checks.rcps.deny_sqs_third_party_access module.
"""

import pytest
import tempfile
import shutil
from unittest.mock import MagicMock, patch
from typing import Generator, List

from headroom.checks.rcps.deny_sqs_third_party_access import DenySQSThirdPartyAccessCheck
from headroom.constants import DENY_SQS_THIRD_PARTY_ACCESS
from headroom.aws.sqs import SQSQueuePolicyAnalysis


class TestDenySQSThirdPartyAccessCheck:
    """Test deny_sqs_third_party_access check with various scenarios."""

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
    def sample_sqs_results_mixed(self) -> List[SQSQueuePolicyAnalysis]:
        """Create sample SQS results with mixed compliance status."""
        return [
            SQSQueuePolicyAnalysis(
                queue_url="https://sqs.us-east-1.amazonaws.com/111111111111/compliant-queue",
                queue_arn="arn:aws:sqs:us-east-1:111111111111:compliant-queue",
                region="us-east-1",
                third_party_account_ids={"111111111111"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={"111111111111": {"sqs:SendMessage", "sqs:ReceiveMessage"}}
            ),
            SQSQueuePolicyAnalysis(
                queue_url="https://sqs.us-east-1.amazonaws.com/222222222222/wildcard-queue",
                queue_arn="arn:aws:sqs:us-east-1:222222222222:wildcard-queue",
                region="us-east-1",
                third_party_account_ids={"222222222222"},
                has_wildcard_principal=True,
                has_non_account_principals=False,
                actions_by_account={"222222222222": {"sqs:*"}}
            ),
        ]

    def test_check_deny_sqs_third_party_access_mixed_results(
        self,
        sample_sqs_results_mixed: List[SQSQueuePolicyAnalysis],
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test check function with mixed compliance results."""
        mock_session = MagicMock()
        account_name = "test-account"
        account_id = "111111111111"

        with (
            patch("headroom.checks.rcps.deny_sqs_third_party_access.analyze_sqs_queue_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_sqs_results_mixed

            check = DenySQSThirdPartyAccessCheck(
                check_name=DENY_SQS_THIRD_PARTY_ACCESS,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            assert mock_write.called
            call_args = mock_write.call_args
            results_data = call_args[1]["results_data"]

            assert len(results_data["queues_with_wildcards"]) == 1
            assert len(results_data["queues_third_parties_can_access"]) == 2

            summary = results_data["summary"]
            assert summary["total_queues_analyzed"] == 2
            assert summary["queues_with_wildcards"] == 1
            assert summary["queues_third_parties_can_access"] == 2
            assert summary["violations"] == 1
            assert set(summary["unique_third_party_accounts"]) == {"111111111111", "222222222222"}
            assert summary["third_party_account_count"] == 2

    def test_check_all_compliant(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test check with all queues compliant."""
        mock_session = MagicMock()

        all_compliant = [
            SQSQueuePolicyAnalysis(
                queue_url="https://sqs.us-east-1.amazonaws.com/111111111111/compliant-queue-1",
                queue_arn="arn:aws:sqs:us-east-1:111111111111:compliant-queue-1",
                region="us-east-1",
                third_party_account_ids={"111111111111"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={"111111111111": {"sqs:SendMessage"}}
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_sqs_third_party_access.analyze_sqs_queue_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_compliant

            check = DenySQSThirdPartyAccessCheck(
                check_name=DENY_SQS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["violations"] == 0
            assert summary["queues_with_wildcards"] == 0
            assert summary["queues_third_parties_can_access"] == 1

    def test_check_all_violations(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test check with all queues having violations."""
        mock_session = MagicMock()

        all_violations = [
            SQSQueuePolicyAnalysis(
                queue_url="https://sqs.us-east-1.amazonaws.com/111111111111/wildcard-queue-1",
                queue_arn="arn:aws:sqs:us-east-1:111111111111:wildcard-queue-1",
                region="us-east-1",
                third_party_account_ids=set(),
                has_wildcard_principal=True,
                has_non_account_principals=False,
                actions_by_account={}
            ),
            SQSQueuePolicyAnalysis(
                queue_url="https://sqs.us-west-2.amazonaws.com/111111111111/federated-queue",
                queue_arn="arn:aws:sqs:us-west-2:111111111111:federated-queue",
                region="us-west-2",
                third_party_account_ids=set(),
                has_wildcard_principal=False,
                has_non_account_principals=True,
                actions_by_account={}
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_sqs_third_party_access.analyze_sqs_queue_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_violations

            check = DenySQSThirdPartyAccessCheck(
                check_name=DENY_SQS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["violations"] == 2
            assert summary["queues_with_wildcards"] == 2
            assert summary["queues_third_parties_can_access"] == 2

    def test_check_empty_results(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test check with no queues found."""
        mock_session = MagicMock()

        with (
            patch("headroom.checks.rcps.deny_sqs_third_party_access.analyze_sqs_queue_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = []

            check = DenySQSThirdPartyAccessCheck(
                check_name=DENY_SQS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert summary["total_queues_analyzed"] == 0
            assert summary["violations"] == 0
            assert summary["queues_third_parties_can_access"] == 0

    def test_categorize_result_violation_wildcard(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test categorization of violation with wildcard."""
        check = DenySQSThirdPartyAccessCheck(
            check_name=DENY_SQS_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids=org_account_ids,
        )

        result = SQSQueuePolicyAnalysis(
            queue_url="https://sqs.us-east-1.amazonaws.com/111111111111/wildcard-queue",
            queue_arn="arn:aws:sqs:us-east-1:111111111111:wildcard-queue",
            region="us-east-1",
            third_party_account_ids={"222222222222"},
            has_wildcard_principal=True,
            has_non_account_principals=False,
            actions_by_account={"222222222222": {"sqs:*"}}
        )

        category, result_dict = check.categorize_result(result)

        from headroom.enums import CheckCategory
        assert category == CheckCategory.VIOLATION
        assert result_dict["has_wildcard_principal"] is True

    def test_categorize_result_violation_federated(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test categorization of violation with Federated principal."""
        check = DenySQSThirdPartyAccessCheck(
            check_name=DENY_SQS_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids=org_account_ids,
        )

        result = SQSQueuePolicyAnalysis(
            queue_url="https://sqs.us-east-1.amazonaws.com/111111111111/federated-queue",
            queue_arn="arn:aws:sqs:us-east-1:111111111111:federated-queue",
            region="us-east-1",
            third_party_account_ids=set(),
            has_wildcard_principal=False,
            has_non_account_principals=True,
            actions_by_account={}
        )

        category, result_dict = check.categorize_result(result)

        from headroom.enums import CheckCategory
        assert category == CheckCategory.VIOLATION
        assert result_dict["has_non_account_principals"] is True

    def test_categorize_result_compliant(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test categorization of compliant queue."""
        check = DenySQSThirdPartyAccessCheck(
            check_name=DENY_SQS_THIRD_PARTY_ACCESS,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
            org_account_ids=org_account_ids,
        )

        result = SQSQueuePolicyAnalysis(
            queue_url="https://sqs.us-east-1.amazonaws.com/111111111111/compliant-queue",
            queue_arn="arn:aws:sqs:us-east-1:111111111111:compliant-queue",
            region="us-east-1",
            third_party_account_ids={"222222222222"},
            has_wildcard_principal=False,
            has_non_account_principals=False,
            actions_by_account={"222222222222": {"sqs:SendMessage", "sqs:ReceiveMessage"}}
        )

        category, result_dict = check.categorize_result(result)

        from headroom.enums import CheckCategory
        assert category == CheckCategory.COMPLIANT
        assert result_dict["has_wildcard_principal"] is False
        assert result_dict["has_non_account_principals"] is False

    def test_summary_fields_actions_by_account(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test that actions_by_account is tracked correctly."""
        mock_session = MagicMock()

        results = [
            SQSQueuePolicyAnalysis(
                queue_url="https://sqs.us-east-1.amazonaws.com/111111111111/queue-1",
                queue_arn="arn:aws:sqs:us-east-1:111111111111:queue-1",
                region="us-east-1",
                third_party_account_ids={"222222222222"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={"222222222222": {"sqs:SendMessage", "sqs:GetQueueUrl"}}
            ),
            SQSQueuePolicyAnalysis(
                queue_url="https://sqs.us-west-2.amazonaws.com/111111111111/queue-2",
                queue_arn="arn:aws:sqs:us-west-2:111111111111:queue-2",
                region="us-west-2",
                third_party_account_ids={"222222222222", "333333333333"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={
                    "222222222222": {"sqs:ReceiveMessage"},
                    "333333333333": {"sqs:DeleteMessage"}
                }
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_sqs_third_party_access.analyze_sqs_queue_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = results

            check = DenySQSThirdPartyAccessCheck(
                check_name=DENY_SQS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert "222222222222" in summary["actions_by_third_party_account"]
            assert "333333333333" in summary["actions_by_third_party_account"]

            account_222_actions = set(summary["actions_by_third_party_account"]["222222222222"])
            assert account_222_actions == {"sqs:SendMessage", "sqs:GetQueueUrl", "sqs:ReceiveMessage"}

            account_333_actions = set(summary["actions_by_third_party_account"]["333333333333"])
            assert account_333_actions == {"sqs:DeleteMessage"}

    def test_summary_fields_queues_by_account(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test that queues_by_account is tracked correctly."""
        mock_session = MagicMock()

        results = [
            SQSQueuePolicyAnalysis(
                queue_url="https://sqs.us-east-1.amazonaws.com/111111111111/queue-1",
                queue_arn="arn:aws:sqs:us-east-1:111111111111:queue-1",
                region="us-east-1",
                third_party_account_ids={"222222222222"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={"222222222222": {"sqs:SendMessage"}}
            ),
            SQSQueuePolicyAnalysis(
                queue_url="https://sqs.us-west-2.amazonaws.com/111111111111/queue-2",
                queue_arn="arn:aws:sqs:us-west-2:111111111111:queue-2",
                region="us-west-2",
                third_party_account_ids={"222222222222", "333333333333"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={
                    "222222222222": {"sqs:ReceiveMessage"},
                    "333333333333": {"sqs:DeleteMessage"}
                }
            ),
        ]

        with (
            patch("headroom.checks.rcps.deny_sqs_third_party_access.analyze_sqs_queue_policies") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = results

            check = DenySQSThirdPartyAccessCheck(
                check_name=DENY_SQS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            check.execute(mock_session)

            results_data = mock_write.call_args[1]["results_data"]
            summary = results_data["summary"]

            assert "222222222222" in summary["queues_by_third_party_account"]
            assert "333333333333" in summary["queues_by_third_party_account"]

            account_222_queues = set(summary["queues_by_third_party_account"]["222222222222"])
            assert account_222_queues == {
                "arn:aws:sqs:us-east-1:111111111111:queue-1",
                "arn:aws:sqs:us-west-2:111111111111:queue-2"
            }

            account_333_queues = set(summary["queues_by_third_party_account"]["333333333333"])
            assert account_333_queues == {"arn:aws:sqs:us-west-2:111111111111:queue-2"}

    def test_analyze_filters_results(
        self,
        org_account_ids: set[str],
        temp_results_dir: str,
    ) -> None:
        """Test that analyze method filters results correctly."""
        mock_session = MagicMock()

        all_results = [
            SQSQueuePolicyAnalysis(
                queue_url="https://sqs.us-east-1.amazonaws.com/111111111111/third-party-queue",
                queue_arn="arn:aws:sqs:us-east-1:111111111111:third-party-queue",
                region="us-east-1",
                third_party_account_ids={"222222222222"},
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={"222222222222": {"sqs:SendMessage"}}
            ),
            SQSQueuePolicyAnalysis(
                queue_url="https://sqs.us-east-1.amazonaws.com/111111111111/org-only-queue",
                queue_arn="arn:aws:sqs:us-east-1:111111111111:org-only-queue",
                region="us-east-1",
                third_party_account_ids=set(),
                has_wildcard_principal=False,
                has_non_account_principals=False,
                actions_by_account={}
            ),
        ]

        with patch("headroom.checks.rcps.deny_sqs_third_party_access.analyze_sqs_queue_policies") as mock_analysis:
            mock_analysis.return_value = all_results

            check = DenySQSThirdPartyAccessCheck(
                check_name=DENY_SQS_THIRD_PARTY_ACCESS,
                account_name="test-account",
                account_id="111111111111",
                results_dir=temp_results_dir,
                org_account_ids=org_account_ids,
            )
            filtered_results = check.analyze(mock_session)

            assert len(filtered_results) == 1
            assert filtered_results[0].queue_arn == "arn:aws:sqs:us-east-1:111111111111:third-party-queue"
