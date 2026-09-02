"""Check for IAM users that exist in accounts with the deny_iam_user_creation SCP."""

from typing import List

from boto3.session import Session

from ...aws.iam.users import IamUserAnalysis, get_iam_users_analysis
from ...constants import DENY_IAM_USER_CREATION
from ...enums import CheckCategory, TerraformSection
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import Allowlist, register_check


@register_check(
    "scps",
    DENY_IAM_USER_CREATION,
    terraform_section=TerraformSection.IAM,
    allowlist=Allowlist(
        summary_key="users",
        terraform_variable="iam_allowed_users",
        # The values are user ARNs, so `exclude_account_ids` redacts their
        # account field on write. Parsing restores it, and rendering
        # rewrites it to the account's generated local.
        restores_account_ids=True,
        # An empty allowlist renders NotResource: [], and a policy array
        # takes one or more values, so Organizations rejects the document
        # and the entire SCP fails to attach - every other statement in this
        # module with it (INV-06). Covered accounts holding no IAM user is an
        # ordinary fact about them rather than a broken run, so the policy
        # stays off and the rest of the organization still generates.
        empty_allowlist_comment=(
            "deny_iam_user_creation stays off here: no IAM user in the accounts "
            "this module covers, so the allowlist would be empty - and "
            "NotResource: [] is rejected as a malformed policy."
        ),
    ),
)
class DenyIamUserCreationCheck(BaseCheck[IamUserAnalysis]):
    """
    Check for IAM users in accounts with the deny_iam_user_creation SCP.

    This check lists all IAM users in the account. The SCP policy determines
    which users are allowed to be created based on the Terraform configuration.
    """

    def analyze(self, session: Session) -> List[IamUserAnalysis]:
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

        # Zero, and written rather than left out. Every user this check finds is
        # compliant, so the count is always zero - but placement reads this key
        # to decide whether the account is safe, and a reader cannot tell an
        # absent key from a genuine zero. Stating it keeps the distinction.
        return {
            "total_users": total,
            "users": [user["user_arn"] for user in check_result.compliant],
            "violations": len(check_result.violations),
        }
