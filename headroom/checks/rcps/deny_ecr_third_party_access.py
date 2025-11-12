"""
Check for ECR repositories that allow third-party account access.

This check identifies ECR repositories with resource policies that allow
principals from accounts outside the organization to access them.
"""

from typing import Any, Dict, List, Set

import boto3

from ...aws.ecr import ECRRepositoryPolicyAnalysis, analyze_ecr_repository_policies
from ...constants import DENY_ECR_THIRD_PARTY_ACCESS
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("rcps", DENY_ECR_THIRD_PARTY_ACCESS)
class DenyECRThirdPartyAccessCheck(BaseCheck[ECRRepositoryPolicyAnalysis]):
    """
    Check for ECR repositories that allow third-party account access.

    This check identifies:
    - ECR repositories with policies allowing accounts outside the organization
    - ECR repositories with wildcard principals in policies
    - All unique third-party account IDs found
    - ECR actions allowed per third-party account
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
        Initialize the ECR third-party access check.

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
        self.all_actions_by_account: Dict[str, Set[str]] = {}

    def analyze(self, session: boto3.Session) -> List[ECRRepositoryPolicyAnalysis]:
        """
        Analyze ECR repository policies for third-party access.

        Filters to only return repositories with wildcards or third-party access.
        Repositories with neither are not relevant to this check.

        Args:
            session: boto3.Session for the target account

        Returns:
            List of ECRRepositoryPolicyAnalysis results with findings
        """
        all_results = analyze_ecr_repository_policies(session, self.org_account_ids)
        return [
            result for result in all_results
            if result.has_wildcard_principal or result.third_party_account_ids
        ]

    def categorize_result(
        self,
        result: ECRRepositoryPolicyAnalysis
    ) -> tuple[str, Dict[str, Any]]:
        """
        Categorize a single repository policy analysis result.

        Args:
            result: Single ECRRepositoryPolicyAnalysis result

        Returns:
            Tuple of (category, result_dict) where category is:
            - "violation": Repository has wildcard principal (blocks RCP deployment)
            - "compliant": Repository has third-party access but no wildcard
        """
        result_dict = {
            "repository_name": result.repository_name,
            "repository_arn": result.repository_arn,
            "region": result.region,
            "third_party_account_ids": sorted(list(result.third_party_account_ids)),
            "actions_by_account": {
                account_id: sorted(actions)
                for account_id, actions in result.actions_by_account.items()
            },
            "has_wildcard_principal": result.has_wildcard_principal,
        }

        self.all_third_party_accounts.update(result.third_party_account_ids)

        for account_id, actions in result.actions_by_account.items():
            if account_id not in self.all_actions_by_account:
                self.all_actions_by_account[account_id] = set()
            self.all_actions_by_account[account_id].update(actions)

        if result.has_wildcard_principal:
            return ("violation", result_dict)
        else:
            return ("compliant", result_dict)

    def build_summary_fields(
        self,
        check_result: CategorizedCheckResult
    ) -> Dict[str, Any]:
        """
        Build ECR third-party access check-specific summary fields.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """
        total_repositories = len(check_result.violations) + len(check_result.exemptions) + len(check_result.compliant)

        repositories_with_wildcards_and_third_party = sum(
            1 for repo in check_result.violations
            if repo.get("third_party_account_ids")
        )
        repositories_with_third_party_access = (
            repositories_with_wildcards_and_third_party + len(check_result.compliant)
        )

        actions_by_account_sorted = {
            account_id: sorted(list(actions))
            for account_id, actions in self.all_actions_by_account.items()
        }

        return {
            "total_repositories_analyzed": total_repositories,
            "repositories_third_parties_can_access": repositories_with_third_party_access,
            "repositories_with_wildcards": len(check_result.violations),
            "violations": len(check_result.violations),
            "unique_third_party_accounts": sorted(list(self.all_third_party_accounts)),
            "third_party_account_count": len(self.all_third_party_accounts),
            "actions_by_account": actions_by_account_sorted,
        }

    def execute(self, session: boto3.Session) -> None:
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
        repositories_with_third_party_access = (
            check_result.violations + check_result.compliant
        )

        return {
            "summary": check_result.summary,
            "repositories_third_parties_can_access": repositories_with_third_party_access,
            "repositories_with_wildcards": check_result.violations,
        }
