"""
Check for IAM SAML providers that violate the deny_iam_saml_provider_not_aws_sso policy.

This SCP check enforces an absolute deny guardrail by identifying accounts that contain
more than one SAML provider or any provider that is not managed by AWS SSO (`AWSSSO_`
prefix). The eventual SCP will deny iam:CreateSAMLProvider unconditionally once all
accounts meet this constraint.
"""

from typing import Any, List

import boto3

from ...aws.iam import SamlProviderAnalysis, get_saml_providers_analysis
from ...constants import DENY_IAM_SAML_PROVIDER_NOT_AWS_SSO
from ...enums import CheckCategory, TerraformSection
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


def _is_awssso_provider(provider_name: str) -> bool:
    """
    Determine whether a provider name matches the AWS SSO naming convention.

    Args:
        provider_name: Derived name component of the SAML provider ARN.

    Returns:
        True if the provider name begins with AWSSSO_, otherwise False.
    """
    return provider_name.startswith("AWSSSO_")


@register_check("scps", DENY_IAM_SAML_PROVIDER_NOT_AWS_SSO, terraform_section=TerraformSection.IAM)
class DenySamlProviderNotAwsSsoCheck(BaseCheck[SamlProviderAnalysis]):
    """
    Check for IAM SAML providers that would violate deny_iam_saml_provider_not_aws_sso.

    Account is considered compliant only when zero providers exist or exactly one
    AWS SSO-managed provider is present. All other combinations produce violations.
    """

    def __init__(
        self,
        check_name: str,
        account_name: str,
        account_id: str,
        results_dir: str,
        exclude_account_ids: bool = False,
        **kwargs: Any,
    ) -> None:
        """Initialize state used during categorization."""
        super().__init__(
            check_name=check_name,
            account_name=account_name,
            account_id=account_id,
            results_dir=results_dir,
            exclude_account_ids=exclude_account_ids,
            **kwargs,
        )
        self._total_providers: int = 0
        self._awssso_provider_arns: List[str] = []
        self._non_awssso_provider_arns: List[str] = []

    def analyze(self, session: boto3.Session) -> List[SamlProviderAnalysis]:
        """
        Analyze IAM SAML providers in the account.

        Args:
            session: boto3.Session for the target account.

        Returns:
            List of SamlProviderAnalysis entries for the account.
        """
        providers = get_saml_providers_analysis(session)
        self._total_providers = len(providers)
        self._awssso_provider_arns = []
        self._non_awssso_provider_arns = []

        for provider in providers:
            if _is_awssso_provider(provider.name):
                self._awssso_provider_arns.append(provider.arn)
                continue
            self._non_awssso_provider_arns.append(provider.arn)

        return providers

    def categorize_result(self, result: SamlProviderAnalysis) -> tuple[CheckCategory, JsonDict]:
        """
        Categorize a single SAML provider analysis result.

        Args:
            result: Single SamlProviderAnalysis entry.

        Returns:
            Tuple containing category and JSON-serializable result data.
        """
        result_dict: JsonDict = {
            "arn": result.arn,
            "name": result.name,
            "create_date": result.create_date.isoformat() if result.create_date else None,
            "valid_until": result.valid_until.isoformat() if result.valid_until else None,
        }

        if not _is_awssso_provider(result.name):
            result_dict["violation_reason"] = "provider_prefix_not_awssso"
            return (CheckCategory.VIOLATION, result_dict)

        if self._total_providers > 1:
            result_dict["violation_reason"] = "multiple_saml_providers_present"
            return (CheckCategory.VIOLATION, result_dict)

        return (CheckCategory.COMPLIANT, result_dict)

    def build_summary_fields(self, check_result: CategorizedCheckResult) -> JsonDict:
        """
        Build summary fields specific to the SAML provider check.

        Args:
            check_result: Categorized check result.

        Returns:
            Dictionary of summary metrics for the check.
        """
        violating_arns = [violation["arn"] for violation in check_result.violations]
        allowed_provider_arn = None
        if self._total_providers == 1 and not self._non_awssso_provider_arns:
            allowed_provider_arn = self._awssso_provider_arns[0]

        # Placement reads summary.violations and nothing else. Reporting the
        # offenders only in violating_provider_arns left every account looking
        # clean, so the deny was recommended at root over organizations this
        # check had just rejected.

        # categorize_result returns VIOLATION or COMPLIANT and nothing else, so
        # exemptions is structurally zero. It is written rather than left out,
        # the way deny_iam_user_creation writes its always-zero violations, so a
        # reader can tell an absent key from a genuine zero. The percentage
        # leaves it out of both terms for the same reason: with no exemption to
        # classify, deny_ec2_imds_v1's question of whether an exemption counts
        # as compliant does not arise here. Adding one to this check means
        # answering that question first.
        compliant_count = len(check_result.compliant)
        total = len(check_result.violations) + compliant_count
        compliance_pct = (compliant_count / total * 100) if total else 100

        return {
            "total_saml_providers": self._total_providers,
            "awssso_provider_count": len(self._awssso_provider_arns),
            "non_awssso_provider_count": len(self._non_awssso_provider_arns),
            "allowed_provider_arn": allowed_provider_arn,
            "violating_provider_arns": violating_arns,
            "violations": len(check_result.violations),
            "exemptions": len(check_result.exemptions),
            "compliant": compliant_count,
            "compliance_percentage": compliance_pct,
        }
