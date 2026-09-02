"""
Tests for headroom.aws.lambda_functions module.

Tests for DenyLambdaAuthTypeNone dataclass and get_deny_lambda_auth_type_none_analysis function.
"""

import pytest
from unittest.mock import MagicMock
from typing import Dict, List

from botocore.exceptions import ClientError
from headroom.aws.lambda_functions import DenyLambdaAuthTypeNone, get_deny_lambda_auth_type_none_analysis


class TestDenyLambdaAuthTypeNone:
    """Test DenyLambdaAuthTypeNone dataclass with various configurations."""

    def test_deny_lambda_auth_type_none_with_none_auth(self) -> None:
        """Test creating DenyLambdaAuthTypeNone for function with NONE auth."""
        result = DenyLambdaAuthTypeNone(
            function_name="public-function",
            function_arn="arn:aws:lambda:us-east-1:111111111111:function:public-function",
            region="us-east-1",
            has_function_url=True,
            function_url_auth_type="NONE"
        )

        assert result.function_name == "public-function"
        assert result.function_arn == "arn:aws:lambda:us-east-1:111111111111:function:public-function"
        assert result.region == "us-east-1"
        assert result.has_function_url is True
        assert result.function_url_auth_type == "NONE"

    def test_deny_lambda_auth_type_none_with_aws_iam_auth(self) -> None:
        """Test creating DenyLambdaAuthTypeNone for function with AWS_IAM auth."""
        result = DenyLambdaAuthTypeNone(
            function_name="secure-function",
            function_arn="arn:aws:lambda:us-west-2:222222222222:function:secure-function",
            region="us-west-2",
            has_function_url=True,
            function_url_auth_type="AWS_IAM"
        )

        assert result.function_name == "secure-function"
        assert result.function_arn == "arn:aws:lambda:us-west-2:222222222222:function:secure-function"
        assert result.region == "us-west-2"
        assert result.has_function_url is True
        assert result.function_url_auth_type == "AWS_IAM"

    def test_deny_lambda_auth_type_none_without_url(self) -> None:
        """Test creating DenyLambdaAuthTypeNone for function without URL."""
        result = DenyLambdaAuthTypeNone(
            function_name="no-url-function",
            function_arn="arn:aws:lambda:eu-west-1:333333333333:function:no-url-function",
            region="eu-west-1",
            has_function_url=False,
            function_url_auth_type=None
        )

        assert result.function_name == "no-url-function"
        assert result.function_arn == "arn:aws:lambda:eu-west-1:333333333333:function:no-url-function"
        assert result.region == "eu-west-1"
        assert result.has_function_url is False
        assert result.function_url_auth_type is None

    def test_deny_lambda_auth_type_none_equality(self) -> None:
        """Test DenyLambdaAuthTypeNone equality comparison."""
        result1 = DenyLambdaAuthTypeNone(
            function_name="test-function",
            function_arn="arn:aws:lambda:us-east-1:111111111111:function:test-function",
            region="us-east-1",
            has_function_url=True,
            function_url_auth_type="NONE"
        )

        result2 = DenyLambdaAuthTypeNone(
            function_name="test-function",
            function_arn="arn:aws:lambda:us-east-1:111111111111:function:test-function",
            region="us-east-1",
            has_function_url=True,
            function_url_auth_type="NONE"
        )

        result3 = DenyLambdaAuthTypeNone(
            function_name="different-function",
            function_arn="arn:aws:lambda:us-east-1:111111111111:function:different-function",
            region="us-east-1",
            has_function_url=False,
            function_url_auth_type=None
        )

        assert result1 == result2
        assert result1 != result3

    def test_deny_lambda_auth_type_none_repr(self) -> None:
        """Test DenyLambdaAuthTypeNone string representation."""
        result = DenyLambdaAuthTypeNone(
            function_name="test-function",
            function_arn="arn:aws:lambda:us-east-1:111111111111:function:test-function",
            region="us-east-1",
            has_function_url=True,
            function_url_auth_type="NONE"
        )

        repr_str = repr(result)
        assert "DenyLambdaAuthTypeNone" in repr_str
        assert "test-function" in repr_str
        assert "us-east-1" in repr_str


class TestGetDenyLambdaAuthTypeNoneAnalysis:
    """Test get_deny_lambda_auth_type_none_analysis function with various scenarios."""

    def create_mock_function(
        self,
        function_name: str,
        region: str = "us-east-1",
        account_id: str = "111111111111"
    ) -> dict:
        """Helper to create mock Lambda function data."""
        return {
            "FunctionName": function_name,
            "FunctionArn": f"arn:aws:lambda:{region}:{account_id}:function:{function_name}"
        }

    @staticmethod
    def _no_urls(FunctionName: str) -> List[dict]:
        """URL-config pages for a function that has no function URL."""
        return [{"FunctionUrlConfigs": []}]

    @staticmethod
    def _lambda_client(functions_pages: List[dict], url_pages: object) -> MagicMock:
        """
        Build a regional Lambda client mock with both paginators wired.

        `url_pages` is the URL-config paginator's `paginate` side effect: a
        callable taking FunctionName and returning that function's pages, or
        an exception every call raises.
        """
        functions_paginator = MagicMock()
        functions_paginator.paginate.return_value = functions_pages
        url_paginator = MagicMock()
        url_paginator.paginate.side_effect = url_pages
        client = MagicMock()
        client.get_paginator.side_effect = lambda name: {
            "list_functions": functions_paginator,
            "list_function_url_configs": url_paginator,
        }[name]
        return client

    @staticmethod
    def _session(lambda_clients: Dict[str, MagicMock]) -> MagicMock:
        """Build a session mock serving one Lambda client per region."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": region} for region in lambda_clients]
        }
        mock_session = MagicMock()
        mock_session.client.side_effect = lambda service, region_name=None: (
            mock_ec2 if service == "ec2" else lambda_clients[region_name]
        )
        return mock_session

    def test_get_deny_lambda_auth_type_none_analysis_success(self) -> None:
        """Test successful Lambda analysis across regions with mixed auth types."""
        east = self._lambda_client(
            [{
                "Functions": [
                    self.create_mock_function("function-with-none-auth"),
                    self.create_mock_function("function-with-iam-auth"),
                    self.create_mock_function("function-without-url"),
                ]
            }],
            lambda FunctionName: {
                "function-with-none-auth": [{"FunctionUrlConfigs": [{"AuthType": "NONE"}]}],
                "function-with-iam-auth": [{"FunctionUrlConfigs": [{"AuthType": "AWS_IAM"}]}],
                "function-without-url": [{"FunctionUrlConfigs": []}],
            }[FunctionName],
        )
        west = self._lambda_client(
            [{"Functions": [self.create_mock_function("west-function", region="us-west-2")]}],
            self._no_urls,
        )

        results = get_deny_lambda_auth_type_none_analysis(
            self._session({"us-east-1": east, "us-west-2": west})
        )

        assert len(results) == 4

        none_auth_functions = [r for r in results if r.function_name == "function-with-none-auth"]
        assert len(none_auth_functions) == 1
        assert none_auth_functions[0].has_function_url is True
        assert none_auth_functions[0].function_url_auth_type == "NONE"
        assert none_auth_functions[0].region == "us-east-1"

        iam_auth_functions = [r for r in results if r.function_name == "function-with-iam-auth"]
        assert len(iam_auth_functions) == 1
        assert iam_auth_functions[0].has_function_url is True
        assert iam_auth_functions[0].function_url_auth_type == "AWS_IAM"

        no_url_functions = [r for r in results if r.function_name == "function-without-url"]
        assert len(no_url_functions) == 1
        assert no_url_functions[0].has_function_url is False
        assert no_url_functions[0].function_url_auth_type is None

    def test_get_deny_lambda_auth_type_none_analysis_no_functions(self) -> None:
        """Test function with no Lambda functions in any region."""
        client = self._lambda_client([{"Functions": []}], self._no_urls)

        results = get_deny_lambda_auth_type_none_analysis(
            self._session({"us-east-1": client})
        )

        assert results == []

    def _one_function_session(self, url_pages: object) -> MagicMock:
        """Build a session mock with one region and one function."""
        client = self._lambda_client(
            [{"Functions": [self.create_mock_function("test-function")]}], url_pages
        )
        return self._session({"us-east-1": client})

    def test_a_none_url_on_any_qualifier_is_reported(self) -> None:
        """
        A NONE URL on an alias is found behind an AWS_IAM URL on $LATEST.

        A function URL can sit on $LATEST and on every alias, and the API
        documents no order for the configs it returns. Reading only the first
        would report this function compliant, the SCP would deploy, and the
        next UpdateFunctionUrlConfig on the alias would be denied - the break
        the check exists to prevent.
        """
        mock_session = self._one_function_session(
            lambda FunctionName: [{
                "FunctionUrlConfigs": [{"AuthType": "AWS_IAM"}, {"AuthType": "NONE"}]
            }]
        )

        results = get_deny_lambda_auth_type_none_analysis(mock_session)

        assert results[0].has_function_url is True
        assert results[0].function_url_auth_type == "NONE"

    def test_url_configs_are_read_across_pages(self) -> None:
        """
        A NONE URL on the second page of ListFunctionUrlConfigs is found.

        The API caps a page at 50 configs and returns a marker for the rest,
        so a single unpaginated call reads the first page only and a NONE URL
        beyond it is a clean verdict from evidence never read (INV-01).
        """
        mock_session = self._one_function_session(
            lambda FunctionName: [
                {"FunctionUrlConfigs": [{"AuthType": "AWS_IAM"}]},
                {"FunctionUrlConfigs": [{"AuthType": "NONE"}]},
            ]
        )

        results = get_deny_lambda_auth_type_none_analysis(mock_session)

        url_paginator = mock_session.client(
            "lambda", region_name="us-east-1"
        ).get_paginator("list_function_url_configs")
        url_paginator.paginate.assert_called_once_with(FunctionName="test-function")
        assert results[0].function_url_auth_type == "NONE"

    def test_url_config_read_failure_aborts_the_run(self) -> None:
        """
        A failure reading a function's URL config raises rather than reporting
        the function as having no URL.

        `categorize_result` treats `has_function_url=False` as COMPLIANT, so
        swallowing the error records a clean verdict for a function nobody could
        read - and a function with AuthType NONE would become invisible. The
        result file would state `"has_function_url": false` as though it had been
        observed. Headroom requires its role to be exempt from region-allowlist
        SCPs, so AccessDenied here is a real permissions gap.
        """
        mock_session = self._one_function_session(
            ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
                "ListFunctionUrlConfigs"
            )
        )

        with pytest.raises(ClientError) as exc_info:
            get_deny_lambda_auth_type_none_analysis(mock_session)

        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"

    def test_function_deleted_during_scan_is_reported_without_a_url(self) -> None:
        """
        A function deleted between listing and reading is not fatal.

        This is the one benign reason the read fails: the function is gone, so it
        exposes no URL and cannot violate the policy.
        """
        mock_session = self._one_function_session(
            ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "Gone"}},
                "ListFunctionUrlConfigs"
            )
        )

        results = get_deny_lambda_auth_type_none_analysis(mock_session)

        assert len(results) == 1
        assert results[0].function_name == "test-function"
        assert results[0].has_function_url is False
        assert results[0].function_url_auth_type is None

    def test_get_deny_lambda_auth_type_none_analysis_multiple_pages(self) -> None:
        """Test function with paginated results."""
        client = self._lambda_client(
            [
                {
                    "Functions": [
                        self.create_mock_function("function-1"),
                        self.create_mock_function("function-2"),
                    ]
                },
                {"Functions": [self.create_mock_function("function-3")]},
            ],
            self._no_urls,
        )

        results = get_deny_lambda_auth_type_none_analysis(
            self._session({"us-east-1": client})
        )

        assert len(results) == 3
        function_names = [r.function_name for r in results]
        assert "function-1" in function_names
        assert "function-2" in function_names
        assert "function-3" in function_names
