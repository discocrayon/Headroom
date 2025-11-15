"""
Check for AOSS resources with third-party account access.

This check identifies AOSS (OpenSearch Serverless) collections and indexes
with data access policies that allow principals from accounts outside the
organization.
"""

from collections import defaultdict
from typing import Dict, List, Set

import boto3

from ...aws.aoss import AossResourcePolicyAnalysis, analyze_aoss_resource_policies
from ...constants import DENY_AOSS_THIRD_PARTY_ACCESS
from ...enums import CheckCategory
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("rcps", DENY_AOSS_THIRD_PARTY_ACCESS)
class DenyAossThirdPartyAccessCheck(BaseCheck[AossResourcePolicyAnalysis]):
    """
    Check for AOSS resources with third-party account access.

    This check identifies:
    - AOSS collections and indexes with third-party access
    - Which AOSS actions are allowed for third-party accounts
    - All unique third-party account IDs with AOSS access
    """

    def __init__(
        self,
        check_name: str,
        account_name: str,
        account_id: str,
        results_dir: str,
        org_account_ids: Set[str],
        exclude_account_ids: bool = False,
    ) -> None:
        """
        Initialize the AOSS third-party access check.

        Args:
            check_name: Name of the check
            account_name: Account name
            account_id: Account ID
            results_dir: Base directory for results
            org_account_ids: Set of all account IDs in the organization
            exclude_account_ids: If True, exclude account ID from results
        """
        super().__init__(
            check_name=check_name,
            account_name=account_name,
            account_id=account_id,
            results_dir=results_dir,
            exclude_account_ids=exclude_account_ids,
        )
        self.org_account_ids = org_account_ids
        self.all_third_party_accounts: Set[str] = set()
        self.actions_by_account: Dict[str, Set[str]] = defaultdict(set)

    def analyze(self, session: boto3.Session) -> List[AossResourcePolicyAnalysis]:
        """
        Analyze AOSS resource policies for third-party access.

        Args:
            session: boto3.Session for the target account

        Returns:
            List of AossResourcePolicyAnalysis results with third-party access
        """
        return analyze_aoss_resource_policies(session, self.org_account_ids)

    def categorize_result(
        self,
        result: AossResourcePolicyAnalysis,
    ) -> tuple[CheckCategory, Dict[str, object]]:
        """
        Categorize a single AOSS resource policy result.

        All third-party access is considered compliant because it will
        be captured in the allowlist for the RCP.

        Args:
            result: Single AossResourcePolicyAnalysis result

        Returns:
            Tuple of (category, result_dict) where category is CheckCategory.COMPLIANT
        """
        result_dict: Dict[str, object] = {
            "resource_name": result.resource_name,
            "resource_type": result.resource_type,
            "resource_arn": result.resource_arn,
            "policy_name": result.policy_name,
            "third_party_account_ids": sorted(list(result.third_party_account_ids)),
            "allowed_actions": result.allowed_actions,
        }

        # Track third-party accounts and their allowed actions
        self.all_third_party_accounts.update(result.third_party_account_ids)
        for account_id in result.third_party_account_ids:
            self.actions_by_account[account_id].update(result.allowed_actions)

        return (CheckCategory.COMPLIANT, result_dict)

    def build_summary_fields(
        self,
        check_result: CategorizedCheckResult,
    ) -> Dict[str, object]:
        """
        Build AOSS third-party access check-specific summary fields.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """
        actions_by_account_serializable: Dict[str, List[str]] = {
            account: sorted(list(actions))
            for account, actions in self.actions_by_account.items()
        }

        return {
            "total_resources_with_third_party_access": len(check_result.compliant),
            "unique_third_party_accounts": sorted(list(self.all_third_party_accounts)),
            "third_party_account_count": len(self.all_third_party_accounts),
            "actions_by_third_party_account": actions_by_account_serializable,
        }

    def _build_results_data(
        self,
        check_result: CategorizedCheckResult,
    ) -> Dict[str, object]:
        """
        Build results data in the format expected by this check.

        Overrides the base implementation to use custom field names
        specific to AOSS third-party access.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with results data
        """
        return {
            "summary": check_result.summary,
            "resources_with_third_party_access": check_result.compliant,
        }
