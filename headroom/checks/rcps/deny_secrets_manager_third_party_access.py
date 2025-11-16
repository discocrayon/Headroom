"""
Check for Secrets Manager secrets that allow third-party account access.

This check identifies Secrets Manager secrets with resource policies that allow
principals from accounts outside the organization to access them.
"""

from typing import Dict, List, Set

from boto3.session import Session

from ...aws.secretsmanager import SecretsPolicyAnalysis, analyze_secrets_manager_policies
from ...constants import DENY_SECRETS_MANAGER_THIRD_PARTY_ACCESS
from ...enums import CheckCategory
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("rcps", DENY_SECRETS_MANAGER_THIRD_PARTY_ACCESS)
class DenySecretsManagerThirdPartyAccessCheck(BaseCheck[SecretsPolicyAnalysis]):
    """
    Check for Secrets Manager secrets that allow third-party account access.

    This check identifies:
    - Secrets with policies allowing accounts outside the organization
    - Secrets with wildcard principals in policies
    - All unique third-party account IDs found
    - Which Secrets Manager actions each third-party account can perform
    - Which secrets each third-party account can access
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
        Initialize the Secrets Manager third-party access check.

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
        self.actions_by_account: Dict[str, Set[str]] = {}
        self.secrets_by_account: Dict[str, Set[str]] = {}

    def analyze(self, session: Session) -> List[SecretsPolicyAnalysis]:
        """
        Analyze Secrets Manager resource policies for third-party access.

        Filters to only return secrets with wildcards or third-party access.
        Secrets with neither are not relevant to this check.

        Args:
            session: boto3.Session for the target account

        Returns:
            List of SecretsPolicyAnalysis results with findings
        """
        all_results = analyze_secrets_manager_policies(session, self.org_account_ids)
        return [
            result for result in all_results
            if result.has_wildcard_principal or result.has_non_account_principals or result.third_party_account_ids
        ]

    def categorize_result(self, result: SecretsPolicyAnalysis) -> tuple[CheckCategory, JsonDict]:
        """
        Categorize a single secret policy analysis result.

        Args:
            result: Single SecretsPolicyAnalysis result

        Returns:
            Tuple of (category, result_dict) where category is a CheckCategory enum value
        """
        actions_by_account_serializable = {
            account_id: sorted(list(actions))
            for account_id, actions in result.actions_by_account.items()
        }

        result_dict = {
            "secret_name": result.secret_name,
            "secret_arn": result.secret_arn,
            "third_party_account_ids": sorted(list(result.third_party_account_ids)),
            "has_wildcard_principal": result.has_wildcard_principal,
            "has_non_account_principals": result.has_non_account_principals,
            "actions_by_account": actions_by_account_serializable,
        }

        self.all_third_party_accounts.update(result.third_party_account_ids)

        for account_id, actions in result.actions_by_account.items():
            if account_id not in self.actions_by_account:
                self.actions_by_account[account_id] = set()
            self.actions_by_account[account_id].update(actions)

            if account_id not in self.secrets_by_account:
                self.secrets_by_account[account_id] = set()
            self.secrets_by_account[account_id].add(result.secret_arn)

        if result.has_wildcard_principal or result.has_non_account_principals:
            return (CheckCategory.VIOLATION, result_dict)
        return (CheckCategory.COMPLIANT, result_dict)

    def build_summary_fields(self, check_result: CategorizedCheckResult) -> JsonDict:
        """
        Build Secrets Manager third-party access check-specific summary fields.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """
        total_secrets = len(check_result.violations) + len(check_result.exemptions) + len(check_result.compliant)

        secrets_with_wildcards_and_third_party = sum(
            1 for secret in check_result.violations
            if secret.get("third_party_account_ids")
        )
        secrets_with_third_party_access = secrets_with_wildcards_and_third_party + len(check_result.compliant)

        actions_by_account_serializable = {
            account_id: sorted(list(actions))
            for account_id, actions in self.actions_by_account.items()
        }

        secrets_by_account_serializable = {
            account_id: sorted(list(secrets))
            for account_id, secrets in self.secrets_by_account.items()
        }

        return {
            "total_secrets_analyzed": total_secrets,
            "secrets_third_parties_can_access": secrets_with_third_party_access,
            "secrets_with_wildcards": len(check_result.violations),
            "violations": len(check_result.violations),
            "unique_third_party_accounts": sorted(list(self.all_third_party_accounts)),
            "third_party_account_count": len(self.all_third_party_accounts),
            "actions_by_third_party_account": actions_by_account_serializable,
            "secrets_by_third_party_account": secrets_by_account_serializable,
        }

    def execute(self, session: Session) -> None:
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
        secrets_with_third_party_access = check_result.violations + check_result.compliant

        return {
            "summary": check_result.summary,
            "secrets_third_parties_can_access": secrets_with_third_party_access,
            "secrets_with_wildcards": check_result.violations,
        }
