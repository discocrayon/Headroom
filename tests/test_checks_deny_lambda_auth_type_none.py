"""
Tests for headroom.checks.scps.deny_lambda_auth_type_none module.

Tests for DenyLambdaAuthTypeNoneCheck and its integration with Lambda analysis.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch
from typing import List, Generator

from boto3.session import Session

from headroom.checks.scps.deny_lambda_auth_type_none import DenyLambdaAuthTypeNoneCheck
from headroom.constants import DENY_LAMBDA_AUTH_TYPE_NONE
from headroom.aws.lambda_functions import DenyLambdaAuthTypeNone
from headroom.parse_results import parse_scp_result_files
from tests.hierarchies import make_single_account_hierarchy


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
        """
        Sample Lambda results with public, IAM-authenticated, and URL-less functions.

        `another-public-function` carries two public URLs, one on $LATEST and
        one on the `prod` alias, so the summary's allowlist is a flattening
        across functions rather than one value per function.
        """
        return [
            DenyLambdaAuthTypeNone(
                function_name="public-function",
                function_arn="arn:aws:lambda:us-east-1:111111111111:function:public-function",
                region="us-east-1",
                has_function_url=True,
                function_url_auth_type="NONE",
                public_function_url_arns=["arn:aws:lambda:us-east-1:111111111111:function:public-function"]
            ),
            DenyLambdaAuthTypeNone(
                function_name="secure-function",
                function_arn="arn:aws:lambda:us-east-1:111111111111:function:secure-function",
                region="us-east-1",
                has_function_url=True,
                function_url_auth_type="AWS_IAM",
                public_function_url_arns=[]
            ),
            DenyLambdaAuthTypeNone(
                function_name="no-url-function",
                function_arn="arn:aws:lambda:us-west-2:111111111111:function:no-url-function",
                region="us-west-2",
                has_function_url=False,
                function_url_auth_type=None,
                public_function_url_arns=[]
            ),
            DenyLambdaAuthTypeNone(
                function_name="another-public-function",
                function_arn="arn:aws:lambda:us-west-2:111111111111:function:another-public-function",
                region="us-west-2",
                has_function_url=True,
                function_url_auth_type="NONE",
                public_function_url_arns=[
                    "arn:aws:lambda:us-west-2:111111111111:function:another-public-function",
                    "arn:aws:lambda:us-west-2:111111111111:function:another-public-function:prod",
                ]
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
                function_url_auth_type="AWS_IAM",
                public_function_url_arns=[]
            ),
            DenyLambdaAuthTypeNone(
                function_name="no-url-function-1",
                function_arn="arn:aws:lambda:us-west-2:111111111111:function:no-url-function-1",
                region="us-west-2",
                has_function_url=False,
                function_url_auth_type=None,
                public_function_url_arns=[]
            )
        ]

    def test_check_deny_lambda_auth_type_none_mixed_results(
        self,
        sample_lambda_results_mixed: List[DenyLambdaAuthTypeNone],
        temp_results_dir: str,
    ) -> None:
        """
        Public URLs are exemptions, and the summary carries their ARNs.

        `violations` is structurally zero and written anyway: placement reads
        the key and cannot tell an absent one from a genuine zero. There is
        no `compliance_percentage`: an exemption counts as compliant, so the
        figure would always read 100 and say nothing.
        """
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
            assert summary["violations"] == 0
            assert summary["exemptions"] == 2
            assert summary["compliant"] == 2
            assert "compliance_percentage" not in summary
            assert summary["public_function_urls"] == [
                "arn:aws:lambda:us-east-1:111111111111:function:public-function",
                "arn:aws:lambda:us-west-2:111111111111:function:another-public-function",
                "arn:aws:lambda:us-west-2:111111111111:function:another-public-function:prod",
            ]

            # Nothing is ever a violation
            assert results_data["violations"] == []

            # Check exemptions, ordered by function name
            exemptions = results_data["exemptions"]
            assert [e["function_name"] for e in exemptions] == ["another-public-function", "public-function"]

            # Verify exemption details
            for exemption in exemptions:
                assert exemption["has_function_url"] is True
                assert exemption["function_url_auth_type"] == "NONE"
                assert "region" in exemption
                assert "function_arn" in exemption

            # Check compliant functions
            compliant = results_data["compliant_instances"]
            assert [c["function_name"] for c in compliant] == ["no-url-function", "secure-function"]

    def test_check_deny_lambda_auth_type_none_all_compliant(
        self,
        sample_lambda_results_compliant: List[DenyLambdaAuthTypeNone],
        temp_results_dir: str,
    ) -> None:
        """An account with no public URL writes the allowlist key as an empty list."""
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

            summary = results_data["summary"]
            assert summary["total_functions"] == 2
            assert summary["violations"] == 0
            assert summary["exemptions"] == 0
            assert summary["compliant"] == 2
            assert "compliance_percentage" not in summary
            assert summary["public_function_urls"] == []

            assert results_data["violations"] == []
            assert results_data["exemptions"] == []
            assert len(results_data["compliant_instances"]) == 2

    def test_check_deny_lambda_auth_type_none_no_functions(self, temp_results_dir: str) -> None:
        """
        An account with no Lambda function still writes every summary key.

        The allowlist key is present as `[]`: parsing aborts on an absent
        key, because an absent key and an empty list mean opposite things
        (INV-01).
        """
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
            assert summary["exemptions"] == 0
            assert summary["compliant"] == 0
            assert summary["public_function_urls"] == []

            assert results_data["violations"] == []
            assert results_data["exemptions"] == []
            assert results_data["compliant_instances"] == []

    def test_check_deny_lambda_auth_type_none_all_public(self, temp_results_dir: str) -> None:
        """An account where every function is public is still safe: all are exemptions."""
        mock_session = MagicMock()
        account_name = "public-account"
        account_id = "444444444444"

        all_public = [
            DenyLambdaAuthTypeNone(
                function_name="public-1",
                function_arn="arn:aws:lambda:us-east-1:444444444444:function:public-1",
                region="us-east-1",
                has_function_url=True,
                function_url_auth_type="NONE",
                public_function_url_arns=["arn:aws:lambda:us-east-1:444444444444:function:public-1"]
            ),
            DenyLambdaAuthTypeNone(
                function_name="public-2",
                function_arn="arn:aws:lambda:us-west-2:444444444444:function:public-2",
                region="us-west-2",
                has_function_url=True,
                function_url_auth_type="NONE",
                public_function_url_arns=["arn:aws:lambda:us-west-2:444444444444:function:public-2"]
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

            write_call_args = mock_write.call_args
            results_data = write_call_args[1]["results_data"]

            summary = results_data["summary"]
            assert summary["total_functions"] == 2
            assert summary["violations"] == 0
            assert summary["exemptions"] == 2
            assert summary["compliant"] == 0
            assert summary["public_function_urls"] == [
                "arn:aws:lambda:us-east-1:444444444444:function:public-1",
                "arn:aws:lambda:us-west-2:444444444444:function:public-2",
            ]

            assert results_data["violations"] == []
            assert len(results_data["exemptions"]) == 2
            assert results_data["compliant_instances"] == []

    def test_categorize_result_exemption_for_a_public_url(self, temp_results_dir: str) -> None:
        """
        A NONE URL is an exemption, not a violation: the allowlist spares it.

        The statement's NotResource carries every public URL the scan found,
        so the deny never matches a re-apply of one, and it must not count
        against deployability. The entry names the ARN the statement spares,
        which for a URL on an alias is the qualified ARN rather than the
        function's own.
        """
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
            function_url_auth_type="NONE",
            public_function_url_arns=["arn:aws:lambda:us-east-1:111111111111:function:public-function:prod"]
        )

        category, result_dict = check.categorize_result(result)

        assert category.value == "exemption"
        assert result_dict["function_name"] == "public-function"
        assert result_dict["has_function_url"] is True
        assert result_dict["function_url_auth_type"] == "NONE"
        assert result_dict["public_function_url_arns"] == [
            "arn:aws:lambda:us-east-1:111111111111:function:public-function:prod"
        ]

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
            function_url_auth_type="AWS_IAM",
            public_function_url_arns=[]
        )

        category, result_dict = check.categorize_result(result)

        assert category.value == "compliant"
        assert result_dict["function_name"] == "secure-function"
        assert result_dict["has_function_url"] is True
        assert result_dict["function_url_auth_type"] == "AWS_IAM"
        assert result_dict["public_function_url_arns"] == []

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
            function_url_auth_type=None,
            public_function_url_arns=[]
        )

        category, result_dict = check.categorize_result(result)

        assert category.value == "compliant"
        assert result_dict["function_name"] == "no-url-function"
        assert result_dict["has_function_url"] is False
        assert result_dict["function_url_auth_type"] is None

    def test_a_written_result_parses(self, temp_results_dir: str) -> None:
        """
        The allowlist round trip starts from the file this check writes (INV-07).

        Parsing reads `public_function_urls` off the summary and carries it
        as `allowlist_values`. A public URL is an exemption, so the account
        parses with zero violations and one exemption, and the value carried
        is the alias-qualified ARN the statement has to spare.
        """
        check = DenyLambdaAuthTypeNoneCheck(
            check_name=DENY_LAMBDA_AUTH_TYPE_NONE,
            account_name="test-account",
            account_id="111111111111",
            results_dir=temp_results_dir,
        )
        function = DenyLambdaAuthTypeNone(
            function_name="public-function",
            function_arn="arn:aws:lambda:us-east-1:111111111111:function:public-function",
            region="us-east-1",
            has_function_url=True,
            function_url_auth_type="NONE",
            public_function_url_arns=["arn:aws:lambda:us-east-1:111111111111:function:public-function:prod"],
        )

        with patch(
            "headroom.checks.scps.deny_lambda_auth_type_none.get_deny_lambda_auth_type_none_analysis"
        ) as mock_analysis:
            mock_analysis.return_value = [function]
            check.execute(MagicMock(spec=Session))

        parsed = parse_scp_result_files(temp_results_dir, make_single_account_hierarchy())

        assert [result.violations for result in parsed] == [0]
        assert [result.exemptions for result in parsed] == [1]
        assert [result.allowlist_values for result in parsed] == [
            {"public_function_urls": ["arn:aws:lambda:us-east-1:111111111111:function:public-function:prod"]}
        ]

    def test_a_redacted_result_parses_back_to_the_real_arn(self, temp_results_dir: str) -> None:
        """
        The writer's redaction and the reader's restoration are one round trip.

        `write_check_results` scrubs the account ID from every ARN when
        `exclude_account_ids` is set - a Lambda ARN carries it between the
        region and the resource - and `_read_declared_allowlist` has to
        restore exactly that account ID, or the allowlist names a
        placeholder rather than the account that actually holds the URL.
        """
        check = DenyLambdaAuthTypeNoneCheck(
            check_name=DENY_LAMBDA_AUTH_TYPE_NONE,
            account_name="test-account",
            account_id="111111111111",
            results_dir=temp_results_dir,
            exclude_account_ids=True,
        )
        function = DenyLambdaAuthTypeNone(
            function_name="public-function",
            function_arn="arn:aws:lambda:us-east-1:111111111111:function:public-function",
            region="us-east-1",
            has_function_url=True,
            function_url_auth_type="NONE",
            public_function_url_arns=["arn:aws:lambda:us-east-1:111111111111:function:public-function:prod"],
        )

        with patch(
            "headroom.checks.scps.deny_lambda_auth_type_none.get_deny_lambda_auth_type_none_analysis"
        ) as mock_analysis:
            mock_analysis.return_value = [function]
            check.execute(MagicMock(spec=Session))

        written_files = list((Path(temp_results_dir) / "scps" / "deny_lambda_auth_type_none").glob("*.json"))
        assert len(written_files) == 1
        written = written_files[0].read_text()
        assert "arn:aws:lambda:us-east-1:REDACTED:function:public-function:prod" in written
        assert "111111111111" not in written

        parsed = parse_scp_result_files(temp_results_dir, make_single_account_hierarchy())

        assert [result.allowlist_values for result in parsed] == [
            {"public_function_urls": ["arn:aws:lambda:us-east-1:111111111111:function:public-function:prod"]}
        ]
