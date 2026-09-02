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

# Error code meaning a function no longer exists.
#
# A function deleted between `list_functions` and `list_function_url_configs` is
# the only benign reason that read fails: it is gone, so it exposes no URL. Every
# other failure leaves the function's URL configuration unknown, and reporting
# `has_function_url=False` would categorize it as COMPLIANT on the strength of a
# read that never succeeded.
FUNCTION_GONE_ERROR_CODE = "ResourceNotFoundException"

# The AuthType a function URL carries when it accepts unauthenticated calls.
#
# A function can hold one URL on $LATEST and one on each alias, and the API
# documents no order for the configs it returns, so the verdict is NONE if any
# config carries it. The other documented value is AWS_IAM.
FUNCTION_URL_AUTH_TYPE_NONE = "NONE"


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
       b. For each function, list every function URL config via
          list_function_url_configs(), paginated: one URL may sit on $LATEST
          and one on each alias
       c. Record the auth type as NONE if any config carries it, otherwise
          the first config's type (AWS_IAM)
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
        logger.debug(f"Analyzing Lambda functions in {region}")
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

    A failed read of the URL configuration aborts the run. `categorize_result`
    treats `has_function_url=False` as COMPLIANT, so swallowing the error would
    record a clean verdict for a function that was never read, hiding any
    function whose URL uses an AuthType of NONE.

    Args:
        lambda_client: Lambda client for API calls
        function: Function dict from list_functions
        region: AWS region

    Returns:
        DenyLambdaAuthTypeNone result for this function

    Raises:
        ClientError: If the function's URL configuration cannot be read for any
            reason other than the function having been deleted mid-scan
    """
    function_name = function["FunctionName"]
    function_arn = function["FunctionArn"]

    has_function_url = False
    function_url_auth_type = None

    try:
        url_configs = [
            config
            for page in paginate(
                lambda_client, "list_function_url_configs", FunctionName=function_name
            )
            for config in cast(
                Sequence[FunctionUrlConfigTypeDef], page.get("FunctionUrlConfigs", [])
            )
        ]

        if url_configs:
            has_function_url = True
            auth_types = [config["AuthType"] for config in url_configs]
            function_url_auth_type = (
                FUNCTION_URL_AUTH_TYPE_NONE
                if FUNCTION_URL_AUTH_TYPE_NONE in auth_types
                else auth_types[0]
            )

    except ClientError as e:
        if e.response.get("Error", {}).get("Code", "") != FUNCTION_GONE_ERROR_CODE:
            logger.error(
                f"Failed to get function URL config for {function_name} in {region}: {e}"
            )
            raise
        logger.debug(
            f"Function {function_name} in {region} was deleted during the scan, "
            "reporting no function URL"
        )

    return DenyLambdaAuthTypeNone(
        function_name=function_name,
        function_arn=function_arn,
        region=region,
        has_function_url=has_function_url,
        function_url_auth_type=function_url_auth_type
    )
