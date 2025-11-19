"""AWS Lambda analysis functions for Headroom checks."""

import logging
from dataclasses import dataclass
from typing import List, Optional, Sequence, cast

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_lambda.client import LambdaClient
from mypy_boto3_lambda.type_defs import FunctionConfigurationTypeDef, FunctionUrlConfigTypeDef

from .helpers import get_all_regions, paginate


logger = logging.getLogger(__name__)


@dataclass
class DenyLambdaAuthTypeNone:
    """
    Data model for Lambda function URL authentication analysis.

    Attributes:
        function_name: Name of the Lambda function
        function_arn: Full ARN of the Lambda function
        region: AWS region where function exists
        has_function_url: True if function has a function URL configured
        function_url_auth_type: Auth type of the function URL (NONE or AWS_IAM), None if no URL
    """
    function_name: str
    function_arn: str
    region: str
    has_function_url: bool
    function_url_auth_type: Optional[str]


def get_deny_lambda_auth_type_none_analysis(
    session: Session
) -> List[DenyLambdaAuthTypeNone]:
    """
    Analyze Lambda functions for function URL authentication configuration.

    Algorithm:
    1. Get all enabled regions from EC2
    2. For each region:
       a. List Lambda functions via list_functions()
       b. For each function, check for function URL via list_function_url_configs()
       c. Extract auth type from URL config (NONE or AWS_IAM)
       d. Create DenyLambdaAuthTypeNone results
    3. Return all results across all regions

    Args:
        session: boto3.Session for the target account

    Returns:
        List of DenyLambdaAuthTypeNone analysis results
    """
    all_results = []

    regions = get_all_regions(session)

    for region in regions:
        logger.info(f"Analyzing Lambda functions in {region}")
        regional_results = _analyze_lambda_in_region(session, region)
        all_results.extend(regional_results)

    logger.info(
        f"Analyzed {len(all_results)} total Lambda functions "
        f"across {len(regions)} regions"
    )
    return all_results


def _analyze_lambda_in_region(
    session: Session,
    region: str
) -> List[DenyLambdaAuthTypeNone]:
    """
    Analyze Lambda functions in a specific region.

    Args:
        session: boto3.Session for the target account
        region: AWS region to analyze

    Returns:
        List of DenyLambdaAuthTypeNone results for this region
    """
    lambda_client: LambdaClient = session.client("lambda", region_name=region)
    results = []

    for function_page in paginate(lambda_client, "list_functions"):
        functions = cast(Sequence[FunctionConfigurationTypeDef], function_page.get("Functions", []))
        for function in functions:
            result = _analyze_lambda_function(lambda_client, function, region)
            results.append(result)

    return results


def _analyze_lambda_function(
    lambda_client: LambdaClient,
    function: FunctionConfigurationTypeDef,
    region: str
) -> DenyLambdaAuthTypeNone:
    """
    Analyze single Lambda function for function URL authentication.

    Args:
        lambda_client: Lambda client for API calls
        function: Function dict from list_functions
        region: AWS region

    Returns:
        DenyLambdaAuthTypeNone result for this function
    """
    function_name = function["FunctionName"]
    function_arn = function["FunctionArn"]

    has_function_url = False
    function_url_auth_type = None

    try:
        url_configs_response = lambda_client.list_function_url_configs(
            FunctionName=function_name
        )
        url_configs = cast(Sequence[FunctionUrlConfigTypeDef], url_configs_response.get("FunctionUrlConfigs", []))

        if url_configs:
            has_function_url = True
            function_url_auth_type = url_configs[0].get("AuthType")

    except ClientError as e:
        logger.warning(f"Failed to get function URL config for {function_name} in {region}: {e}")

    return DenyLambdaAuthTypeNone(
        function_name=function_name,
        function_arn=function_arn,
        region=region,
        has_function_url=has_function_url,
        function_url_auth_type=function_url_auth_type
    )
