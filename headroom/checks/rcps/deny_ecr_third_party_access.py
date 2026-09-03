"""
Check for ECR policies that allow third-party account access.

This check identifies ECR resource policies - repository policies and the
per-region registry policy - that allow principals from accounts outside
the organization.
"""

from typing import Any, Dict, List, Set

from boto3.session import Session

from ...aws.ecr import ECRPolicyAnalysis, analyze_ecr_policies
from ...constants import DENY_ECR_THIRD_PARTY_ACCESS
from ...enums import CheckCategory, TerraformSection
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import Allowlist, register_check


@register_check(
    "rcps",
    DENY_ECR_THIRD_PARTY_ACCESS,
    terraform_section=TerraformSection.ECR,
    allowlist=Allowlist(
        summary_key="unique_third_party_accounts",
        terraform_variable="ecr_third_party_access_account_ids_allowlist",
    ),
)
class DenyECRThirdPartyAccessCheck(BaseCheck[ECRPolicyAnalysis]):
    """
    Check for ECR policies that allow third-party account access.

    This check identifies:
    - ECR policies allowing accounts outside the organization
    - ECR policies with wildcard principals
    - All unique third-party account IDs found
    - ECR actions allowed per third-party account

    Both policy surfaces are covered. A repository policy governs one
    repository; a registry policy governs every ECR request in its region,
    so a third party named in one reaches repositories that grant it nothing.
    Each result carries a `scope` saying which it came from.
    """

    def __init__(
        self,
        check_name: str,
        account_name: str,
        account_id: str,
        results_dir: str,
        org_account_ids: Set[str],
        org_id: str,
        exclude_account_ids: bool = False,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the ECR third-party access check.

        Args:
            check_name: Name of the check
            account_name: Account name
            account_id: Account ID
            results_dir: Base directory for results
            org_account_ids: Set of all account IDs in the organization
            org_id: This organization's ID, deciding whether an
                organization scope on a source guard names this organization
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
        self.org_id = org_id
        self.all_third_party_accounts: Set[str] = set()
        self.all_actions_by_account: Dict[str, Set[str]] = {}

    def analyze(self, session: Session) -> List[ECRPolicyAnalysis]:
        """
        Analyze ECR repository and registry policies for third-party access.

        Filters to only return policies with a wildcard principal, a principal
        type carrying no account ID, or third-party account access.
        Policies with none of the three are not relevant to this check.

        Args:
            session: boto3.Session for the target account

        Returns:
            List of ECRPolicyAnalysis results with findings
        """
        all_results = analyze_ecr_policies(session, self.org_account_ids, self.org_id)
        return [
            result for result in all_results
            if result.has_wildcard_principal or result.has_non_account_principals or result.third_party_account_ids
        ]

    def categorize_result(
        self,
        result: ECRPolicyAnalysis
    ) -> tuple[CheckCategory, Dict[str, Any]]:
        """
        Categorize a single ECR policy analysis result.

        Args:
            result: Single ECRPolicyAnalysis result

        Returns:
            Tuple of (category, result_dict) where category is a CheckCategory enum value
        """
        result_dict = {
            "scope": result.scope,
            "repository_name": result.repository_name,
            "repository_arn": result.repository_arn,
            "region": result.region,
            "third_party_account_ids": sorted(list(result.third_party_account_ids)),
            "actions_by_account": {
                account_id: sorted(actions)
                for account_id, actions in result.actions_by_account.items()
            },
            "has_wildcard_principal": result.has_wildcard_principal,
            "has_non_account_principals": result.has_non_account_principals,
        }

        self.all_third_party_accounts.update(result.third_party_account_ids)

        for account_id, actions in result.actions_by_account.items():
            if account_id not in self.all_actions_by_account:
                self.all_actions_by_account[account_id] = set()
            self.all_actions_by_account[account_id].update(actions)

        if result.has_wildcard_principal or result.has_non_account_principals:
            return (CheckCategory.VIOLATION, result_dict)
        return (CheckCategory.COMPLIANT, result_dict)

    def build_summary_fields(
        self,
        check_result: CategorizedCheckResult
    ) -> Dict[str, Any]:
        """
        Build ECR third-party access check-specific summary fields.

        Counts cover both policy scopes. `violations` in particular must,
        since it is what withholds the RCP from the account - a wildcard
        registry policy blocks deployment exactly as a wildcard repository
        policy does.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """
        total_policies = len(check_result.violations) + len(check_result.exemptions) + len(check_result.compliant)

        policies_with_wildcards_and_third_party = sum(
            1 for policy in check_result.violations
            if policy.get("third_party_account_ids")
        )
        policies_third_parties_can_access = (
            policies_with_wildcards_and_third_party + len(check_result.compliant)
        )

        actions_by_account_sorted = {
            account_id: sorted(list(actions))
            for account_id, actions in self.all_actions_by_account.items()
        }

        return {
            "total_policies_analyzed": total_policies,
            "policies_third_parties_can_access": policies_third_parties_can_access,
            "policies_with_wildcards": len(check_result.violations),
            "violations": len(check_result.violations),
            "unique_third_party_accounts": sorted(list(self.all_third_party_accounts)),
            "third_party_account_count": len(self.all_third_party_accounts),
            "actions_by_account": actions_by_account_sorted,
        }

    def execute(self, session: Session) -> None:
        """
        Execute the check.

        Args:
            session: boto3 Session with appropriate permissions
        """
        super().execute(session)

    def _build_results_data(
        self,
        check_result: CategorizedCheckResult
    ) -> Dict[str, Any]:
        """
        Build results data in the format expected by this check.

        Overrides the base implementation to use custom field names.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with results data
        """
        policies_third_parties_can_access = (
            check_result.violations + check_result.compliant
        )

        return {
            "summary": check_result.summary,
            "policies_third_parties_can_access": policies_third_parties_can_access,
            "policies_with_wildcards": check_result.violations,
        }
