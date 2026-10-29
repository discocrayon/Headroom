"""
Check for S3 buckets that allow third-party account access.

This check identifies S3 buckets with resource policies that allow principals
from accounts outside the organization to access them.
"""

from typing import Dict, List, Set

from boto3.session import Session

from ...aws.s3 import S3BucketPolicyAnalysis, analyze_s3_bucket_policies
from ...constants import DENY_S3_THIRD_PARTY_ACCESS
from ...enums import CheckCategory, TerraformSection
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult, sorted_values_by_account
from ..registry import Allowlist, register_check


@register_check(
    "rcps",
    DENY_S3_THIRD_PARTY_ACCESS,
    terraform_section=TerraformSection.S3,
    allowlists=(
        Allowlist(
            summary_key="unique_third_party_accounts",
            terraform_variable="s3_third_party_access_account_ids_allowlist",
        ),
        Allowlist(
            summary_key="exempt_bucket_arns",
            terraform_variable="s3_third_party_access_exempt_bucket_arns",
        ),
    ),
)
class DenyS3ThirdPartyAccessCheck(BaseCheck[S3BucketPolicyAnalysis]):
    """
    Check for S3 buckets that allow third-party account access.

    This check identifies:
    - S3 buckets with policies allowing accounts outside the organization
    - S3 buckets whose grants no account allowlist can express - a wildcard
      principal, a Federated or CanonicalUser principal, a CloudFront origin
      access identity, or a public ACL - which the statement spares by ARN
    - All unique third-party account IDs found
    - Which S3 actions each third-party account can perform
    - Which S3 buckets each third-party account can access
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
        Initialize the S3 third-party access check.

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
        self.buckets_by_account: Dict[str, Set[str]] = {}
        self.exempt_bucket_arns: List[str] = []

    def analyze(self, session: Session) -> List[S3BucketPolicyAnalysis]:
        """
        Analyze S3 bucket policies for third-party access.

        Filters to only return buckets with a wildcard principal, a principal
        type carrying no account ID, or third-party account access.
        Buckets with none of the three are not relevant to this check.

        Args:
            session: boto3.Session for the target account

        Returns:
            List of S3BucketPolicyAnalysis results with findings
        """
        all_results = analyze_s3_bucket_policies(session, self.org_account_ids, self.org_id)
        return [
            result for result in all_results
            if result.has_wildcard_principal or result.has_non_account_principals or result.third_party_account_ids
        ]

    def categorize_result(self, result: S3BucketPolicyAnalysis) -> tuple[CheckCategory, JsonDict]:
        """
        Categorize a single bucket policy analysis result.

        Args:
            result: Single S3BucketPolicyAnalysis result

        Returns:
            Tuple of (category, result_dict) where category is a CheckCategory enum value
        """
        actions_by_account_serializable = sorted_values_by_account(result.actions_by_account)

        result_dict: JsonDict = {
            "bucket_name": result.bucket_name,
            "bucket_arn": result.bucket_arn,
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

            if account_id not in self.buckets_by_account:
                self.buckets_by_account[account_id] = set()
            self.buckets_by_account[account_id].add(result.bucket_arn)

        if result.has_wildcard_principal or result.has_non_account_principals:
            # No aws:PrincipalAccount list can express these grants, so the
            # statement spares the bucket by ARN instead: it is an exemption,
            # and the ARN is the value NotResource renders (INV-07).
            self.exempt_bucket_arns.append(result.bucket_arn)
            return (CheckCategory.EXEMPTION, result_dict)
        return (CheckCategory.COMPLIANT, result_dict)

    def build_summary_fields(self, check_result: CategorizedCheckResult) -> JsonDict:
        """
        Build S3 third-party access check-specific summary fields.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """
        total_buckets = len(check_result.violations) + len(check_result.exemptions) + len(check_result.compliant)

        exemptions_with_third_parties = sum(
            1 for bucket in check_result.exemptions
            if bucket.get("third_party_account_ids")
        )
        buckets_with_third_party_access = exemptions_with_third_parties + len(check_result.compliant)

        actions_by_account_serializable = sorted_values_by_account(self.actions_by_account)

        buckets_by_account_serializable = sorted_values_by_account(self.buckets_by_account)

        return {
            "total_buckets_analyzed": total_buckets,
            "buckets_third_parties_can_access": buckets_with_third_party_access,
            "buckets_with_wildcards": len(check_result.exemptions),
            "violations": len(check_result.violations),
            "exemptions": len(check_result.exemptions),
            "unique_third_party_accounts": sorted(list(self.all_third_party_accounts)),
            "third_party_account_count": len(self.all_third_party_accounts),
            "exempt_bucket_arns": sorted(self.exempt_bucket_arns),
            "actions_by_third_party_account": actions_by_account_serializable,
            "buckets_by_third_party_account": buckets_by_account_serializable,
        }

    def _build_results_data(self, check_result: CategorizedCheckResult) -> JsonDict:
        """
        Build results data in the format expected by this check.

        Overrides the base implementation to use custom field names.
        `buckets_with_wildcards` holds the exemptions: every bucket the
        statement spares by ARN, whether for a wildcard, a non-account
        principal, or a public ACL. `violations` is structurally empty and
        is not written as a list; the summary carries its zero count.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with results data
        """
        buckets_with_third_party_access = check_result.exemptions + check_result.compliant

        return {
            "summary": check_result.summary,
            "buckets_third_parties_can_access": buckets_with_third_party_access,
            "buckets_with_wildcards": check_result.exemptions,
        }
