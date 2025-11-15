"""
Check for IAM roles that allow third-party account AssumeRole access.

This check identifies IAM roles with trust policies that allow principals
from accounts outside the organization to assume them.
"""

from typing import Any, List, Set

import boto3

from ...aws.iam.roles import TrustPolicyAnalysis, analyze_iam_roles_trust_policies
from ...constants import THIRD_PARTY_ASSUMEROLE
from ...enums import CheckCategory
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("rcps", THIRD_PARTY_ASSUMEROLE)
class ThirdPartyAssumeRoleCheck(BaseCheck[TrustPolicyAnalysis]):
    """
    Check for IAM roles that allow third-party account AssumeRole access.

    This check identifies:
    - IAM roles with trust policies allowing accounts outside the organization
    - IAM roles with wildcard principals in trust policies
    - All unique third-party account IDs found
    """

    def __init__(
        self,
        check_name: str,
        account_name: str,
        account_id: str,
        results_dir: str,
        org_account_ids: Set[str],
        exclude_account_ids: bool = False,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the third-party AssumeRole check.

        Args:
            check_name: Name of the check
            account_name: Account name
            account_id: Account ID
            results_dir: Base directory for results
            org_account_ids: Set of all account IDs in the organization
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
        self.org_account_ids = org_account_ids
        self.all_third_party_accounts: Set[str] = set()

    def analyze(self, session: boto3.Session) -> List[TrustPolicyAnalysis]:
        """
        Analyze IAM role trust policies for third-party access.

        Filters to only return roles with wildcards or third-party access.
        Roles with neither are not relevant to this check.

        Args:
            session: boto3.Session for the target account

        Returns:
            List of TrustPolicyAnalysis results with findings
        """
        all_results = analyze_iam_roles_trust_policies(session, self.org_account_ids)
        return [
            result for result in all_results
            if result.has_wildcard_principal or result.third_party_account_ids
        ]

    def categorize_result(self, result: TrustPolicyAnalysis) -> tuple[CheckCategory, JsonDict]:
        """
        Categorize a single trust policy analysis result.

        Args:
            result: Single TrustPolicyAnalysis result

        Returns:
            Tuple of (category, result_dict) where category is a CheckCategory enum value
        """
        result_dict = {
            "role_name": result.role_name,
            "role_arn": result.role_arn,
            "third_party_account_ids": sorted(list(result.third_party_account_ids)),
            "has_wildcard_principal": result.has_wildcard_principal,
        }

        self.all_third_party_accounts.update(result.third_party_account_ids)

        if result.has_wildcard_principal:
            return (CheckCategory.VIOLATION, result_dict)
        return (CheckCategory.COMPLIANT, result_dict)

    def build_summary_fields(self, check_result: CategorizedCheckResult) -> JsonDict:
        """
        Build third-party AssumeRole check-specific summary fields.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """
        total_roles = len(check_result.violations) + len(check_result.exemptions) + len(check_result.compliant)

        roles_with_wildcards_and_third_party = sum(
            1 for role in check_result.violations
            if role.get("third_party_account_ids")
        )
        roles_with_third_party_access = roles_with_wildcards_and_third_party + len(check_result.compliant)

        return {
            "total_roles_analyzed": total_roles,
            "roles_third_parties_can_access": roles_with_third_party_access,
            "roles_with_wildcards": len(check_result.violations),
            "violations": len(check_result.violations),
            "unique_third_party_accounts": sorted(list(self.all_third_party_accounts)),
            "third_party_account_count": len(self.all_third_party_accounts),
        }

    def execute(self, session: boto3.Session) -> None:
        """
        Execute the check.

        Args:
            session: boto3 Session with appropriate permissions
        """
        super().execute(session)

    def _build_results_data(self, check_result: CategorizedCheckResult) -> JsonDict:
        """
        Build results data in the format expected by this check.

        Overrides the base implementation to use custom field names.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with results data
        """
        roles_with_third_party_access = check_result.violations + check_result.compliant

        return {
            "summary": check_result.summary,
            "roles_third_parties_can_access": roles_with_third_party_access,
            "roles_with_wildcards": check_result.violations,
        }
