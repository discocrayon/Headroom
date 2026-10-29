"""Check for the Lambda function URLs the deny_lambda_auth_type_none SCP spares."""

from typing import List

from boto3.session import Session

from ...aws.lambda_functions import (
    DenyLambdaAuthTypeNone,
    FUNCTION_URL_AUTH_TYPE_NONE,
    get_deny_lambda_auth_type_none_analysis,
)
from ...constants import DENY_LAMBDA_AUTH_TYPE_NONE
from ...enums import CheckCategory, TerraformSection
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import Allowlist, register_check


@register_check(
    "scps",
    DENY_LAMBDA_AUTH_TYPE_NONE,
    terraform_section=TerraformSection.LAMBDA,
    allowlists=(
        Allowlist(
            summary_key="public_function_urls",
            terraform_variable="lambda_allowed_public_function_urls",
            # The values are function ARNs - qualified by alias where the URL
            # sits on one - so `exclude_account_ids` redacts their account field
            # on write. Parsing restores it, and rendering rewrites it to the
            # account's generated local. No `empty_allowlist_comment`: with no
            # URL to spare, the module renders Resource: "*" in place of
            # NotResource, and the statement denies every new public URL - the
            # full deny rather than a malformed one (INV-06, the third shape).
            restores_account_ids=True,
        ),
    ),
)
class DenyLambdaAuthTypeNoneCheck(BaseCheck[DenyLambdaAuthTypeNone]):
    """
    Check for Lambda functions whose URL the deny_lambda_auth_type_none SCP spares.

    This check identifies:
    - Lambda functions with function URLs using NONE authentication
      (exemptions: each public URL's ARN goes into the statement's NotResource)
    - Functions without URLs or with AWS_IAM authentication (compliant)
    - The allowlist of public URL ARNs the account relies on
    """

    def __init__(
        self,
        check_name: str,
        account_name: str,
        account_id: str,
        results_dir: str,
        exclude_account_ids: bool = False,
        **kwargs: object,
    ) -> None:
        """
        Initialize the check with an empty public URL allowlist.

        Args:
            check_name: Name of the check
            account_name: Account name
            account_id: Account ID
            results_dir: Base directory for results
            exclude_account_ids: If True, exclude account ID from results
            **kwargs: Additional parameters (ignored)
        """
        super().__init__(
            check_name=check_name,
            account_name=account_name,
            account_id=account_id,
            results_dir=results_dir,
            exclude_account_ids=exclude_account_ids,
            **kwargs,
        )
        # The FunctionArn of every public URL across the account's functions,
        # accumulated as each function is categorized. The summary's allowlist
        # is built from it: an entry carries the same values, but as a JsonDict
        # `object` the summary could not iterate without a cast.
        self.public_function_url_arns: List[str] = []

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
        result_dict: JsonDict = {
            "function_name": result.function_name,
            "function_arn": result.function_arn,
            "region": result.region,
            "has_function_url": result.has_function_url,
            "function_url_auth_type": result.function_url_auth_type,
            "public_function_url_arns": result.public_function_url_arns,
        }

        self.public_function_url_arns.extend(result.public_function_url_arns)

        # An exemption rather than a violation: every public URL the scan
        # finds goes into the statement's NotResource, so the deny spares it
        # and it must not count against deployability. The scan sees the
        # exact dimension the exemption turns on - the ARN it allowlists -
        # so this is the claim EXEMPTION is reserved for.
        if result.has_function_url and result.function_url_auth_type == FUNCTION_URL_AUTH_TYPE_NONE:
            return (CheckCategory.EXEMPTION, result_dict)

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
            Dictionary with check-specific summary fields, where
            `public_function_urls` holds the ARNs the statement's NotResource
            will carry
        """
        total = len(check_result.violations) + len(check_result.exemptions) + len(check_result.compliant)

        # `violations` is zero, and written rather than left out. Every public
        # URL this check finds is an exemption, so the count is always zero -
        # but placement reads this key to decide whether the account is safe,
        # and a reader cannot tell an absent key from a genuine zero. Stating
        # it keeps the distinction.
        #
        # There is no compliance_percentage: an exemption counts as compliant,
        # so the figure would always read 100 and say nothing.
        return {
            "total_functions": total,
            "violations": len(check_result.violations),
            "exemptions": len(check_result.exemptions),
            "compliant": len(check_result.compliant),
            "public_function_urls": sorted(self.public_function_url_arns),
        }
