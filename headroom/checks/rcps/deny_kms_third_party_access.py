"""
Check for KMS keys that allow third-party account access.

This check identifies KMS keys reachable by principals from accounts
outside the organization, through either of the two surfaces that
authorize access to a key - its resource policy and its grants.
"""

from typing import Any, Dict, List, Set

from boto3.session import Session

from ...aws.kms import KMSKeyPolicyAnalysis, analyze_kms_key_policies
from ...constants import DENY_KMS_THIRD_PARTY_ACCESS
from ...enums import CheckCategory, TerraformSection
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import Allowlist, register_check


@register_check(
    "rcps",
    DENY_KMS_THIRD_PARTY_ACCESS,
    terraform_section=TerraformSection.KMS,
    allowlist=Allowlist(
        summary_key="unique_third_party_accounts",
        terraform_variable="kms_third_party_access_account_ids_allowlist",
    ),
)
class DenyKMSThirdPartyAccessCheck(BaseCheck[KMSKeyPolicyAnalysis]):
    """
    Check for KMS keys that allow third-party account access.

    This check identifies:
    - KMS keys with policies allowing accounts outside the organization
    - KMS keys with grants reaching outside the organization
    - KMS keys with wildcard principals in policies
    - All unique third-party account IDs found
    - KMS actions allowed per third-party account

    Both surfaces are covered. A grant is a separate object that
    GetKeyPolicy cannot see, so a key whose policy names nobody outside
    the organization can still hand Decrypt to a vendor. Each result
    carries a `grants` list saying which grants contributed.
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
        Initialize the KMS third-party access check.

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

    def analyze(self, session: Session) -> List[KMSKeyPolicyAnalysis]:
        """
        Analyze KMS key policies for third-party access.

        Filters to only return keys with a wildcard principal, a principal
        type carrying no account ID, or third-party account access.
        Keys with none of the three are not relevant to this check.

        Args:
            session: boto3.Session for the target account

        Returns:
            List of KMSKeyPolicyAnalysis results with findings
        """
        all_results = analyze_kms_key_policies(session, self.org_account_ids, self.org_id)
        return [
            result for result in all_results
            if result.has_wildcard_principal or result.has_non_account_principals or result.third_party_account_ids
        ]

    def categorize_result(
        self,
        result: KMSKeyPolicyAnalysis
    ) -> tuple[CheckCategory, Dict[str, Any]]:
        """
        Categorize a single key policy analysis result.

        Args:
            result: Single KMSKeyPolicyAnalysis result

        Returns:
            Tuple of (category, result_dict) where category is a CheckCategory enum value
        """
        result_dict = {
            "key_id": result.key_id,
            "key_arn": result.key_arn,
            "region": result.region,
            "third_party_account_ids": sorted(list(result.third_party_account_ids)),
            "actions_by_account": {
                account_id: sorted(actions)
                for account_id, actions in result.actions_by_account.items()
            },
            "has_wildcard_principal": result.has_wildcard_principal,
            "has_non_account_principals": result.has_non_account_principals,
            "grants": [
                {
                    "grant_id": grant.grant_id,
                    "grantee_account_id": grant.grantee_account_id,
                    "retiring_principal_account_id": (
                        grant.retiring_principal_account_id
                    ),
                    "operations": grant.operations,
                    "has_constraints": grant.has_constraints,
                }
                for grant in result.grants
            ],
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
        Build KMS third-party access check-specific summary fields.

        Counts cover both surfaces. `keys_with_third_party_grants` is the
        only signal at summary level that the grant surface found anything:
        a key with a clean policy and a third-party grant is otherwise
        indistinguishable here from one found the usual way.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """
        all_keys = check_result.violations + check_result.exemptions + check_result.compliant
        total_keys = len(all_keys)

        keys_with_third_party_grants = sum(
            1 for key in all_keys if key.get("grants")
        )

        keys_with_wildcards_and_third_party = sum(
            1 for key in check_result.violations
            if key.get("third_party_account_ids")
        )
        keys_with_third_party_access = (
            keys_with_wildcards_and_third_party + len(check_result.compliant)
        )

        actions_by_account_sorted = {
            account_id: sorted(list(actions))
            for account_id, actions in self.all_actions_by_account.items()
        }

        return {
            "total_keys_analyzed": total_keys,
            "keys_third_parties_can_access": keys_with_third_party_access,
            "keys_with_wildcards": len(check_result.violations),
            "keys_with_third_party_grants": keys_with_third_party_grants,
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
        keys_with_third_party_access = (
            check_result.violations + check_result.compliant
        )

        return {
            "summary": check_result.summary,
            "keys_third_parties_can_access": keys_with_third_party_access,
            "keys_with_wildcards": check_result.violations,
        }
