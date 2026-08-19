"""
Tests for headroom.aws.lambda_functions module.

Tests for DenyLambdaAuthTypeNone dataclass and get_deny_lambda_auth_type_none_analysis function.
"""

from unittest.mock import MagicMock
from typing import Optional

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

    def test_get_deny_lambda_auth_type_none_analysis_success(self) -> None:
        """Test successful Lambda analysis across regions with mixed auth types."""
        mock_session = MagicMock()

        # Mock regions response
        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-east-1"},
                {"RegionName": "us-west-2"}
            ]
        }

        # Mock regional Lambda clients
        mock_regional_lambda_1 = MagicMock()
        mock_regional_lambda_2 = MagicMock()

        # Mock paginators for us-east-1
        mock_functions_paginator_1 = MagicMock()
        functions_page_1 = {
            "Functions": [
                self.create_mock_function("function-with-none-auth"),
                self.create_mock_function("function-with-iam-auth"),
                self.create_mock_function("function-without-url")
            ]
        }
        mock_functions_paginator_1.paginate.return_value = [functions_page_1]

        # Mock list_function_url_configs responses
        def list_function_url_configs_1_side_effect(FunctionName: str) -> dict:
            if FunctionName == "function-with-none-auth":
                return {
                    "FunctionUrlConfigs": [
                        {"AuthType": "NONE"}
                    ]
                }
            elif FunctionName == "function-with-iam-auth":
                return {
                    "FunctionUrlConfigs": [
                        {"AuthType": "AWS_IAM"}
                    ]
                }
            return {"FunctionUrlConfigs": []}

        mock_regional_lambda_1.list_function_url_configs.side_effect = list_function_url_configs_1_side_effect

        # Mock paginators for us-west-2
        mock_functions_paginator_2 = MagicMock()
        functions_page_2 = {
            "Functions": [
                self.create_mock_function("west-function", region="us-west-2")
            ]
        }
        mock_functions_paginator_2.paginate.return_value = [functions_page_2]

        def list_function_url_configs_2_side_effect(FunctionName: str) -> dict:
            return {"FunctionUrlConfigs": []}

        mock_regional_lambda_2.list_function_url_configs.side_effect = list_function_url_configs_2_side_effect

        # Mock get_paginator calls
        mock_regional_lambda_1.get_paginator.return_value = mock_functions_paginator_1
        mock_regional_lambda_2.get_paginator.return_value = mock_functions_paginator_2

        # Mock session.client calls
        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if service == "ec2":
                return mock_ec2
            elif region_name == "us-east-1":
                return mock_regional_lambda_1
            return mock_regional_lambda_2

        mock_session.client.side_effect = client_side_effect

        # Execute function
        results = get_deny_lambda_auth_type_none_analysis(mock_session)

        # Verify results
        assert len(results) == 4

        # Check function with NONE auth
        none_auth_functions = [r for r in results if r.function_name == "function-with-none-auth"]
        assert len(none_auth_functions) == 1
        assert none_auth_functions[0].has_function_url is True
        assert none_auth_functions[0].function_url_auth_type == "NONE"
        assert none_auth_functions[0].region == "us-east-1"

        # Check function with AWS_IAM auth
        iam_auth_functions = [r for r in results if r.function_name == "function-with-iam-auth"]
        assert len(iam_auth_functions) == 1
        assert iam_auth_functions[0].has_function_url is True
        assert iam_auth_functions[0].function_url_auth_type == "AWS_IAM"

        # Check function without URL
        no_url_functions = [r for r in results if r.function_name == "function-without-url"]
        assert len(no_url_functions) == 1
        assert no_url_functions[0].has_function_url is False
        assert no_url_functions[0].function_url_auth_type is None

    def test_get_deny_lambda_auth_type_none_analysis_no_functions(self) -> None:
        """Test function with no Lambda functions in any region."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_lambda = MagicMock()
        mock_functions_paginator = MagicMock()

        # Empty responses
        mock_functions_paginator.paginate.return_value = [{"Functions": []}]
        mock_regional_lambda.get_paginator.return_value = mock_functions_paginator

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if service == "ec2":
                return mock_ec2
            return mock_regional_lambda

        mock_session.client.side_effect = client_side_effect

        # Execute function
        results = get_deny_lambda_auth_type_none_analysis(mock_session)

        # Verify empty results
        assert len(results) == 0
        assert results == []

    def test_get_deny_lambda_auth_type_none_analysis_url_config_error(self) -> None:
        """Test handling of errors when retrieving function URL configs."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_lambda = MagicMock()
        mock_functions_paginator = MagicMock()

        functions_page = {
            "Functions": [
                self.create_mock_function("test-function")
            ]
        }
        mock_functions_paginator.paginate.return_value = [functions_page]
        mock_regional_lambda.get_paginator.return_value = mock_functions_paginator

        # Simulate error when getting URL config
        mock_regional_lambda.list_function_url_configs.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "ListFunctionUrlConfigs"
        )

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if service == "ec2":
                return mock_ec2
            return mock_regional_lambda

        mock_session.client.side_effect = client_side_effect

        # Execute function - should not raise, just log warning
        results = get_deny_lambda_auth_type_none_analysis(mock_session)

        # Verify function is included with no URL
        assert len(results) == 1
        assert results[0].function_name == "test-function"
        assert results[0].has_function_url is False
        assert results[0].function_url_auth_type is None

    def test_get_deny_lambda_auth_type_none_analysis_multiple_pages(self) -> None:
        """Test function with paginated results."""
        mock_session = MagicMock()

        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}]
        }

        mock_regional_lambda = MagicMock()
        mock_functions_paginator = MagicMock()

        # Multiple pages of functions
        functions_page_1 = {
            "Functions": [
                self.create_mock_function("function-1"),
                self.create_mock_function("function-2")
            ]
        }

        functions_page_2 = {
            "Functions": [
                self.create_mock_function("function-3")
            ]
        }

        mock_functions_paginator.paginate.return_value = [functions_page_1, functions_page_2]
        mock_regional_lambda.get_paginator.return_value = mock_functions_paginator

        # All functions have no URL
        mock_regional_lambda.list_function_url_configs.return_value = {"FunctionUrlConfigs": []}

        def client_side_effect(service: str, region_name: Optional[str] = None) -> MagicMock:
            if service == "ec2":
                return mock_ec2
            return mock_regional_lambda

        mock_session.client.side_effect = client_side_effect

        # Execute function
        results = get_deny_lambda_auth_type_none_analysis(mock_session)

        # Verify all functions from all pages are included
        assert len(results) == 3
        function_names = [r.function_name for r in results]
        assert "function-1" in function_names
        assert "function-2" in function_names
        assert "function-3" in function_names
