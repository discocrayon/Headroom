"""
Check for SQS queues that allow third-party account access.

This check identifies SQS queues with resource policies that allow principals
from accounts outside the organization to access them.
"""

from typing import Dict, List, Set

from boto3.session import Session

from ...aws.sqs import SQSQueuePolicyAnalysis, analyze_sqs_queue_policies
from ...constants import DENY_SQS_THIRD_PARTY_ACCESS
from ...enums import CheckCategory, TerraformSection
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult, sorted_values_by_account
from ..registry import Allowlist, register_check


@register_check(
    "rcps",
    DENY_SQS_THIRD_PARTY_ACCESS,
    terraform_section=TerraformSection.SQS,
    allowlists=(
        Allowlist(
            summary_key="unique_third_party_accounts",
            terraform_variable="sqs_third_party_access_account_ids_allowlist",
        ),
        Allowlist(
            summary_key="exempt_queue_arns",
            terraform_variable="sqs_third_party_access_exempt_queue_arns",
            # A queue ARN carries the account between the region and the queue
            # name, so `exclude_account_ids` redacts it on write. Parsing
            # restores it, and rendering rewrites it to the account's
            # generated local. No `empty_allowlist_comment`: with no queue to
            # spare the module renders `Resource: "*"`, the strongest form of
            # the deny rather than a broken one (INV-06).
            restores_account_ids=True,
        ),
    ),
)
class DenySQSThirdPartyAccessCheck(BaseCheck[SQSQueuePolicyAnalysis]):
    """
    Check for SQS queues that allow third-party account access.

    This check identifies:
    - SQS queues with policies allowing accounts outside the organization
    - SQS queues whose grants no account allowlist can express - a wildcard
      principal, an Allow with NotPrincipal, or a Federated or CanonicalUser
      principal - which the statement spares by ARN
    - All unique third-party account IDs found
    - SQS actions allowed per third-party account
    - SQS queues accessible per third-party account
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
        **kwargs: object,
    ) -> None:
        """
        Initialize the SQS third-party access check.

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
        self.actions_by_account: Dict[str, Set[str]] = {}
        self.queues_by_account: Dict[str, Set[str]] = {}
        self.exempt_queue_arns: List[str] = []

    def analyze(self, session: Session) -> List[SQSQueuePolicyAnalysis]:
        """
        Analyze SQS queue policies for third-party access.

        Filters to only return queues with a wildcard principal, a principal
        type carrying no account ID, or third-party account access.
        Queues with none of the three are not relevant to this check.

        Args:
            session: boto3.Session for the target account

        Returns:
            List of SQSQueuePolicyAnalysis results with findings
        """
        all_results = analyze_sqs_queue_policies(session, self.org_account_ids, self.org_id)
        return [
            result for result in all_results
            if result.has_wildcard_principal or result.has_non_account_principals or result.third_party_account_ids
        ]

    def categorize_result(self, result: SQSQueuePolicyAnalysis) -> tuple[CheckCategory, JsonDict]:
        """
        Categorize a single queue policy analysis result.

        Args:
            result: Single SQSQueuePolicyAnalysis result

        Returns:
            Tuple of (category, result_dict) where category is a CheckCategory enum value
        """
        actions_by_account_serializable = sorted_values_by_account(result.actions_by_account)

        result_dict = {
            "queue_url": result.queue_url,
            "queue_arn": result.queue_arn,
            "region": result.region,
            "third_party_account_ids": sorted(list(result.third_party_account_ids)),
            "has_wildcard_principal": result.has_wildcard_principal,
            "has_non_account_principals": result.has_non_account_principals,
            "actions_by_account": actions_by_account_serializable,
            "confined_by": sorted(result.confined_by),
        }

        self.all_third_party_accounts.update(result.third_party_account_ids)

        for account_id, actions in result.actions_by_account.items():
            if account_id not in self.actions_by_account:
                self.actions_by_account[account_id] = set()
            self.actions_by_account[account_id].update(actions)

            if account_id not in self.queues_by_account:
                self.queues_by_account[account_id] = set()
            self.queues_by_account[account_id].add(result.queue_arn)

        if result.has_wildcard_principal or result.has_non_account_principals:
            # No aws:PrincipalAccount list can express these grants, so the
            # statement spares the queue by ARN instead: it is an exemption,
            # and the ARN is the value NotResource renders (INV-07).
            self.exempt_queue_arns.append(result.queue_arn)
            return (CheckCategory.EXEMPTION, result_dict)
        return (CheckCategory.COMPLIANT, result_dict)

    def build_summary_fields(self, check_result: CategorizedCheckResult) -> JsonDict:
        """
        Build SQS third-party access check-specific summary fields.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """
        total_queues = len(check_result.violations) + len(check_result.exemptions) + len(check_result.compliant)

        # A spared queue counts as third-party access only where its policy
        # also names a third-party account; a public queue naming none is a
        # wildcard finding and nothing more.
        exemptions_with_third_parties = sum(
            1 for queue in check_result.exemptions
            if queue.get("third_party_account_ids")
        )
        queues_with_third_party_access = exemptions_with_third_parties + len(check_result.compliant)

        actions_by_account_serializable = sorted_values_by_account(self.actions_by_account)

        queues_by_account_serializable = sorted_values_by_account(self.queues_by_account)

        return {
            "total_queues_analyzed": total_queues,
            "queues_third_parties_can_access": queues_with_third_party_access,
            "queues_with_wildcards": len(check_result.exemptions),
            "violations": len(check_result.violations),
            "exemptions": len(check_result.exemptions),
            "unique_third_party_accounts": sorted(list(self.all_third_party_accounts)),
            "third_party_account_count": len(self.all_third_party_accounts),
            "exempt_queue_arns": sorted(self.exempt_queue_arns),
            "actions_by_third_party_account": actions_by_account_serializable,
            "queues_by_third_party_account": queues_by_account_serializable,
        }

    def _build_results_data(self, check_result: CategorizedCheckResult) -> JsonDict:
        """
        Build results data in the format expected by this check.

        Overrides the base implementation to use custom field names.
        `queues_with_wildcards` holds the exemptions: every queue the
        statement spares by ARN, whether for a wildcard or a non-account
        principal. `violations` is structurally empty and is not written as
        a list; the summary carries its zero count.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with results data
        """
        queues_with_third_party_access = check_result.exemptions + check_result.compliant

        return {
            "summary": check_result.summary,
            "queues_third_parties_can_access": queues_with_third_party_access,
            "queues_with_wildcards": check_result.exemptions,
        }
