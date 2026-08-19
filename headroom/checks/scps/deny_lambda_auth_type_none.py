"""Check for Lambda functions that violate the deny_lambda_auth_type_none SCP."""

from typing import List

from boto3.session import Session

from ...aws.lambda_functions import DenyLambdaAuthTypeNone, get_deny_lambda_auth_type_none_analysis
from ...constants import DENY_LAMBDA_AUTH_TYPE_NONE
from ...enums import CheckCategory
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("scps", DENY_LAMBDA_AUTH_TYPE_NONE)
class DenyLambdaAuthTypeNoneCheck(BaseCheck[DenyLambdaAuthTypeNone]):
    """
    Check for Lambda functions that would be blocked by deny_lambda_auth_type_none SCP.

    This check identifies:
    - Lambda functions with function URLs using NONE authentication (violations)
    - Functions without URLs or with AWS_IAM authentication (compliant)
    - Overall compliance status for the account
    """

    def analyze(self, session: Session) -> List[DenyLambdaAuthTypeNone]:
        """
        Analyze Lambda functions for function URL authentication configuration.

        Args:
            session: boto3.Session for the target account

        Returns:
            List of DenyLambdaAuthTypeNone analysis results
        """
        return get_deny_lambda_auth_type_none_analysis(session)

    def categorize_result(
        self,
        result: DenyLambdaAuthTypeNone
    ) -> tuple[CheckCategory, JsonDict]:
        """
        Categorize a single Lambda function URL authentication result.

        Args:
            result: Single DenyLambdaAuthTypeNone analysis result

        Returns:
            Tuple of (category, result_dict) where category is a CheckCategory enum value
        """
        result_dict = {
            "function_name": result.function_name,
            "function_arn": result.function_arn,
            "region": result.region,
            "has_function_url": result.has_function_url,
            "function_url_auth_type": result.function_url_auth_type,
        }

        if result.has_function_url and result.function_url_auth_type == "NONE":
            return (CheckCategory.VIOLATION, result_dict)

        return (CheckCategory.COMPLIANT, result_dict)

    def build_summary_fields(
        self,
        check_result: CategorizedCheckResult
    ) -> JsonDict:
        """
        Build Lambda function URL authentication check-specific summary fields.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """
        total = len(check_result.violations) + len(check_result.compliant)
        compliant_count = len(check_result.compliant)
        compliance_pct = (compliant_count / total * 100) if total else 100

        return {
            "total_functions": total,
            "violations": len(check_result.violations),
            "compliant": len(check_result.compliant),
            "compliance_percentage": compliance_pct,
        }
