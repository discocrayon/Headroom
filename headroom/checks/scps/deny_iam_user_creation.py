"""Check for IAM users that exist in accounts with the deny_iam_user_creation SCP."""

from typing import List

import boto3

from ...aws.iam.users import IamUserAnalysis, get_iam_users_analysis
from ...constants import DENY_IAM_USER_CREATION
from ...enums import CheckCategory
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("scps", DENY_IAM_USER_CREATION)
class DenyIamUserCreationCheck(BaseCheck[IamUserAnalysis]):
    """
    Check for IAM users in accounts with the deny_iam_user_creation SCP.

    This check lists all IAM users in the account. The SCP policy determines
    which users are allowed to be created based on the Terraform configuration.
    """

    def analyze(self, session: boto3.Session) -> List[IamUserAnalysis]:
        """
        Analyze IAM users in the account.

        Args:
            session: boto3.Session for the target account

        Returns:
            List of IamUserAnalysis analysis results
        """
        return get_iam_users_analysis(session)

    def categorize_result(self, result: IamUserAnalysis) -> tuple[CheckCategory, JsonDict]:
        """
        Categorize a single IAM user analysis result.

        Args:
            result: Single IamUserAnalysis analysis result

        Returns:
            Tuple of (category, result_dict) where category is CheckCategory.COMPLIANT
            (we're just listing users, not evaluating them)
        """
        result_dict: JsonDict = {
            "user_name": result.user_name,
            "user_arn": result.user_arn,
            "path": result.path,
        }

        return (CheckCategory.COMPLIANT, result_dict)

    def build_summary_fields(self, check_result: CategorizedCheckResult) -> JsonDict:
        """
        Build IAM user check-specific summary fields.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """
        total = len(check_result.compliant)

        return {
            "total_users": total,
            "users": [user["user_arn"] for user in check_result.compliant],
        }
