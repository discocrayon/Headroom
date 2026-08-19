"""
Tests for headroom.checks.scps.deny_lambda_auth_type_none module.

Tests for DenyLambdaAuthTypeNoneCheck and its integration with Lambda analysis.
"""

import pytest
import tempfile
import shutil
from unittest.mock import MagicMock, patch
from typing import List, Generator

from headroom.checks.scps.deny_lambda_auth_type_none import DenyLambdaAuthTypeNoneCheck
from headroom.constants import DENY_LAMBDA_AUTH_TYPE_NONE
from headroom.aws.lambda_functions import DenyLambdaAuthTypeNone


class TestCheckDenyLambdaAuthTypeNone:
    """Test deny_lambda_auth_type_none check with various scenarios."""

    @pytest.fixture
    def temp_results_dir(self) -> Generator[str, None, None]:
        """Create temporary results directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def sample_lambda_results_mixed(self) -> List[DenyLambdaAuthTypeNone]:
        """Create sample Lambda results with mixed compliance status."""
        return [
            DenyLambdaAuthTypeNone(
                function_name="public-function",
                function_arn="arn:aws:lambda:us-east-1:111111111111:function:public-function",
                region="us-east-1",
                has_function_url=True,
                function_url_auth_type="NONE"
            ),
            DenyLambdaAuthTypeNone(
                function_name="secure-function",
                function_arn="arn:aws:lambda:us-east-1:111111111111:function:secure-function",
                region="us-east-1",
                has_function_url=True,
                function_url_auth_type="AWS_IAM"
            ),
            DenyLambdaAuthTypeNone(
                function_name="no-url-function",
                function_arn="arn:aws:lambda:us-west-2:111111111111:function:no-url-function",
                region="us-west-2",
                has_function_url=False,
                function_url_auth_type=None
            ),
            DenyLambdaAuthTypeNone(
                function_name="another-public-function",
                function_arn="arn:aws:lambda:us-west-2:111111111111:function:another-public-function",
                region="us-west-2",
                has_function_url=True,
                function_url_auth_type="NONE"
            )
        ]

    @pytest.fixture
    def sample_lambda_results_compliant(self) -> List[DenyLambdaAuthTypeNone]:
        """Create sample Lambda results with all compliant functions."""
        return [
            DenyLambdaAuthTypeNone(
                function_name="secure-function-1",
                function_arn="arn:aws:lambda:us-east-1:111111111111:function:secure-function-1",
                region="us-east-1",
                has_function_url=True,
                function_url_auth_type="AWS_IAM"
            ),
            DenyLambdaAuthTypeNone(
                function_name="no-url-function-1",
                function_arn="arn:aws:lambda:us-west-2:111111111111:function:no-url-function-1",
                region="us-west-2",
                has_function_url=False,
                function_url_auth_type=None
            )
        ]

    def test_check_deny_lambda_auth_type_none_mixed_results(
        self,
        sample_lambda_results_mixed: List[DenyLambdaAuthTypeNone],
        temp_results_dir: str,
    ) -> None:
        """Test check function with mixed compliance results."""
        mock_session = MagicMock()
        account_name = "test-account"
        account_id = "111111111111"

        with (
            patch("headroom.checks.scps.deny_lambda_auth_type_none.get_deny_lambda_auth_type_none_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_lambda_results_mixed

            check = DenyLambdaAuthTypeNoneCheck(
                check_name=DENY_LAMBDA_AUTH_TYPE_NONE,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
            )
            check.execute(mock_session)

            # Verify analysis was called
            mock_analysis.assert_called_once_with(mock_session)

            # Verify write_check_results was called
            mock_write.assert_called_once()

            # Verify write_check_results arguments
            write_call_args = mock_write.call_args
            assert write_call_args[1]["check_name"] == "deny_lambda_auth_type_none"
            assert write_call_args[1]["account_name"] == account_name
            assert write_call_args[1]["account_id"] == account_id
            assert write_call_args[1]["results_base_dir"] == temp_results_dir

            # Verify JSON structure
            results_data = write_call_args[1]["results_data"]

            # Check summary
            summary = results_data["summary"]
            assert summary["account_name"] == "test-account"
            assert summary["account_id"] == "111111111111"
            assert summary["check"] == "deny_lambda_auth_type_none"
            assert summary["total_functions"] == 4
            assert summary["violations"] == 2
            assert summary["compliant"] == 2
            assert summary["compliance_percentage"] == 50.0

            # Check violations
            violations = results_data["violations"]
            assert len(violations) == 2
            violation_names = [v["function_name"] for v in violations]
            assert "public-function" in violation_names
            assert "another-public-function" in violation_names

            # Verify violation details
            for violation in violations:
                assert violation["has_function_url"] is True
                assert violation["function_url_auth_type"] == "NONE"
                assert "region" in violation
                assert "function_arn" in violation

            # Check compliant functions
            compliant = results_data["compliant_instances"]
            assert len(compliant) == 2
            compliant_names = [c["function_name"] for c in compliant]
            assert "secure-function" in compliant_names
            assert "no-url-function" in compliant_names

    def test_check_deny_lambda_auth_type_none_all_compliant(
        self,
        sample_lambda_results_compliant: List[DenyLambdaAuthTypeNone],
        temp_results_dir: str,
    ) -> None:
        """Test check function with all compliant functions."""
        mock_session = MagicMock()
        account_name = "compliant-account"
        account_id = "222222222222"

        with (
            patch("headroom.checks.scps.deny_lambda_auth_type_none.get_deny_lambda_auth_type_none_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = sample_lambda_results_compliant

            check = DenyLambdaAuthTypeNoneCheck(
                check_name=DENY_LAMBDA_AUTH_TYPE_NONE,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
            )
            check.execute(mock_session)

            # Verify JSON structure for compliant scenario
            write_call_args = mock_write.call_args
            results_data = write_call_args[1]["results_data"]

            # Check summary for perfect compliance
            summary = results_data["summary"]
            assert summary["violations"] == 0
            assert summary["compliant"] == 2
            assert summary["compliance_percentage"] == 100.0

            # Check empty violations
            assert len(results_data["violations"]) == 0
            assert len(results_data["compliant_instances"]) == 2

    def test_check_deny_lambda_auth_type_none_no_functions(self, temp_results_dir: str) -> None:
        """Test check function with no Lambda functions."""
        mock_session = MagicMock()
        account_name = "empty-account"
        account_id = "333333333333"

        with (
            patch("headroom.checks.scps.deny_lambda_auth_type_none.get_deny_lambda_auth_type_none_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = []

            check = DenyLambdaAuthTypeNoneCheck(
                check_name=DENY_LAMBDA_AUTH_TYPE_NONE,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
            )
            check.execute(mock_session)

            # Verify results for empty account
            write_call_args = mock_write.call_args
            results_data = write_call_args[1]["results_data"]

            summary = results_data["summary"]
            assert summary["total_functions"] == 0
            assert summary["violations"] == 0
            assert summary["compliant"] == 0
            assert summary["compliance_percentage"] == 100.0  # No functions = 100% compliant

            assert len(results_data["violations"]) == 0
            assert len(results_data["compliant_instances"]) == 0

    def test_check_deny_lambda_auth_type_none_all_violations(self, temp_results_dir: str) -> None:
        """Test check function with all functions having NONE auth."""
        mock_session = MagicMock()
        account_name = "violation-account"
        account_id = "444444444444"

        all_public = [
            DenyLambdaAuthTypeNone(
                function_name="public-1",
                function_arn="arn:aws:lambda:us-east-1:444444444444:function:public-1",
                region="us-east-1",
                has_function_url=True,
                function_url_auth_type="NONE"
            ),
            DenyLambdaAuthTypeNone(
                function_name="public-2",
                function_arn="arn:aws:lambda:us-west-2:444444444444:function:public-2",
                region="us-west-2",
                has_function_url=True,
                function_url_auth_type="NONE"
            )
        ]

        with (
            patch("headroom.checks.scps.deny_lambda_auth_type_none.get_deny_lambda_auth_type_none_analysis") as mock_analysis,
            patch("headroom.checks.base.write_check_results") as mock_write,
            patch("builtins.print")
        ):
            mock_analysis.return_value = all_public

            check = DenyLambdaAuthTypeNoneCheck(
                check_name=DENY_LAMBDA_AUTH_TYPE_NONE,
                account_name=account_name,
                account_id=account_id,
                results_dir=temp_results_dir,
            )
            check.execute(mock_session)

            # Verify results for all violations scenario
            write_call_args = mock_write.call_args
            results_data = write_call_args[1]["results_data"]

            summary = results_data["summary"]
            assert summary["total_functions"] == 2
            assert summary["violations"] == 2
            assert summary["compliant"] == 0
            assert summary["compliance_percentage"] == 0.0

            assert len(results_data["violations"]) == 2
            assert len(results_data["compliant_instances"]) == 0

    def test_categorize_result_violation(self, temp_results_dir: str) -> None:
        """Test categorize_result returns violation for NONE auth."""
        check = DenyLambdaAuthTypeNoneCheck(
            check_name=DENY_LAMBDA_AUTH_TYPE_NONE,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
        )

        result = DenyLambdaAuthTypeNone(
            function_name="public-function",
            function_arn="arn:aws:lambda:us-east-1:111111111111:function:public-function",
            region="us-east-1",
            has_function_url=True,
            function_url_auth_type="NONE"
        )

        category, result_dict = check.categorize_result(result)

        assert category.value == "violation"
        assert result_dict["function_name"] == "public-function"
        assert result_dict["has_function_url"] is True
        assert result_dict["function_url_auth_type"] == "NONE"

    def test_categorize_result_compliant_aws_iam(self, temp_results_dir: str) -> None:
        """Test categorize_result returns compliant for AWS_IAM auth."""
        check = DenyLambdaAuthTypeNoneCheck(
            check_name=DENY_LAMBDA_AUTH_TYPE_NONE,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
        )

        result = DenyLambdaAuthTypeNone(
            function_name="secure-function",
            function_arn="arn:aws:lambda:us-east-1:111111111111:function:secure-function",
            region="us-east-1",
            has_function_url=True,
            function_url_auth_type="AWS_IAM"
        )

        category, result_dict = check.categorize_result(result)

        assert category.value == "compliant"
        assert result_dict["function_name"] == "secure-function"
        assert result_dict["has_function_url"] is True
        assert result_dict["function_url_auth_type"] == "AWS_IAM"

    def test_categorize_result_compliant_no_url(self, temp_results_dir: str) -> None:
        """Test categorize_result returns compliant for function without URL."""
        check = DenyLambdaAuthTypeNoneCheck(
            check_name=DENY_LAMBDA_AUTH_TYPE_NONE,
            account_name="test",
            account_id="111111111111",
            results_dir=temp_results_dir,
        )

        result = DenyLambdaAuthTypeNone(
            function_name="no-url-function",
            function_arn="arn:aws:lambda:us-east-1:111111111111:function:no-url-function",
            region="us-east-1",
            has_function_url=False,
            function_url_auth_type=None
        )

        category, result_dict = check.categorize_result(result)

        assert category.value == "compliant"
        assert result_dict["function_name"] == "no-url-function"
        assert result_dict["has_function_url"] is False
        assert result_dict["function_url_auth_type"] is None
