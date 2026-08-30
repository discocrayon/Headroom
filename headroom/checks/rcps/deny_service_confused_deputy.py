"""
Check for AWS services that can act on an out-of-organization caller's behalf.

Every RCP statement Headroom generates exempts AWS service principals,
because a service call carries no aws:PrincipalOrgID and the deny would
otherwise match every service integration in the organization. That
exemption is what the DenyServiceConfusedDeputy statement narrows back
down.

This check finds the accounts outside the organization that legitimately
drive service calls into organization resources, so the statement can
permit them, and the guards that name sources no allowlist can express, so
the statement can be withheld from the accounts holding them.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from boto3.session import Session

from ...aws.ecr import analyze_ecr_policies
from ...aws.iam.roles import analyze_iam_roles_trust_policies
from ...aws.kms import analyze_kms_key_policies
from ...aws.policy_documents import ServicePrincipalSource
from ...aws.s3 import analyze_s3_bucket_policies
from ...aws.secretsmanager import analyze_secrets_manager_policies
from ...aws.sqs import analyze_sqs_queue_policies
from ...constants import DENY_SERVICE_CONFUSED_DEPUTY
from ...enums import CheckCategory
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@dataclass
class ServicePrincipalSourceFinding:
    """
    One service principal a resource trusts, and the guard on it.

    Attributes:
        resource_type: Which analyzer found it - `ecr`, `kms`, `s3`,
            `secretsmanager`, `sqs`, or `iam`
        resource_identifier: The resource's name or ARN, whichever that
            analyzer records
        region: The region the resource lives in, None for global resources
        service_principal: The service the policy trusts, None when the
            source read failed before any principal was resolved
        source_account_ids: Out-of-organization accounts the guard permits
        has_source_condition: True if any source key guards the statement
        has_wildcard_source: True if the guard names sources no allowlist
            can enumerate
        read_failure: Why this resource's source read could not be
            completed, None when it was read in full
    """

    resource_type: str
    resource_identifier: str
    region: Optional[str]
    service_principal: Optional[str]
    source_account_ids: List[str]
    has_source_condition: bool
    has_wildcard_source: bool
    read_failure: Optional[str] = None


def _findings_for_resource(
    sources: List[ServicePrincipalSource],
    resource_type: str,
    resource_identifier: str,
    region: Optional[str],
) -> List[ServicePrincipalSourceFinding]:
    """
    Pair each source with the resource it was found on.

    Args:
        sources: The sources one analysis recorded
        resource_type: Which analyzer found them
        resource_identifier: The resource's name or ARN
        region: The region the resource lives in, None if global

    Returns:
        One finding per source
    """
    return [
        ServicePrincipalSourceFinding(
            resource_type=resource_type,
            resource_identifier=resource_identifier,
            region=region,
            service_principal=source.service_principal,
            source_account_ids=source.source_account_ids,
            has_source_condition=source.has_source_condition,
            has_wildcard_source=source.has_wildcard_source,
            read_failure=source.read_failure,
        )
        for source in sources
    ]


@register_check("rcps", DENY_SERVICE_CONFUSED_DEPUTY)
class DenyServiceConfusedDeputyCheck(BaseCheck[ServicePrincipalSourceFinding]):
    """
    Check for cross-service confused deputy exposure.

    This check identifies:
    - Out-of-organization accounts that drive AWS service calls into
      organization resources, which the allowlist must carry
    - Source guards naming sources no allowlist can express, which withhold
      the statement from the account
    - Resources whose source read failed, which withhold the statement for
      the same reason: an allowlist we could not compute must never be
      deployed as if it were complete

    Service principals trusted with no source guard are dropped rather than
    reported, on volume: every service role trust policy and every log
    bucket in the account carries one, and listing them would bury the
    sources that matter.

    Dropping them is not the same as their being safe. `aws:SourceAccount`
    is populated by the calling service, from the resource that drove the
    call, so an unguarded trust driven by an out-of-organization account is
    within the statement's reach and will be denied. The policy does not
    name that account, so discovery cannot find it - only CloudTrail can.
    This is the check's principal deployment risk; see the rollout guidance
    in documentation/CHECKS.md.
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
        Initialize the service confused deputy check.

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

    def analyze(self, session: Session) -> List[ServicePrincipalSourceFinding]:
        """
        Collect service principal sources from every resource type.

        Unguarded sources are dropped, because returning every service
        role trust policy and every log bucket in the account would bury
        the findings that matter. They are dropped despite being within the
        statement's reach, not because they sit outside it: the calling
        service populates aws:SourceAccount itself, so an account outside
        the organization driving an unguarded trust is denied once the
        statement deploys. Nothing in a resource policy names that account,
        so only CloudTrail can find it.

        They are not counted either. The six analyzers drop an analysis
        that found nothing worth reporting, so any count taken here would
        see only the unguarded sources that happen to sit on a resource
        kept for some other reason. A plausible-looking undercount is worse
        than no number. See the spec's Non-goals.

        A source the shared parser could not read arrives as a finding
        carrying `read_failure` rather than as a raise. Raising inside the
        analyzers would abort the estate run and take down the six
        pre-existing checks that share them, none of which reads a source
        guard.

        Args:
            session: boto3.Session for the target account

        Returns:
            Findings with an out-of-organization source, a wildcard source,
            or a failed read
        """
        findings: List[ServicePrincipalSourceFinding] = []

        for ecr_result in analyze_ecr_policies(session, self.org_account_ids):
            findings.extend(_findings_for_resource(
                ecr_result.service_principal_sources,
                "ecr",
                ecr_result.repository_name or "registry",
                ecr_result.region,
            ))

        for kms_result in analyze_kms_key_policies(session, self.org_account_ids):
            findings.extend(_findings_for_resource(
                kms_result.service_principal_sources,
                "kms",
                kms_result.key_id,
                kms_result.region,
            ))

        for s3_result in analyze_s3_bucket_policies(session, self.org_account_ids):
            findings.extend(_findings_for_resource(
                s3_result.service_principal_sources,
                "s3",
                s3_result.bucket_name,
                None,
            ))

        for secret_result in analyze_secrets_manager_policies(session, self.org_account_ids):
            findings.extend(_findings_for_resource(
                secret_result.service_principal_sources,
                "secretsmanager",
                secret_result.secret_name,
                None,
            ))

        for sqs_result in analyze_sqs_queue_policies(session, self.org_account_ids):
            findings.extend(_findings_for_resource(
                sqs_result.service_principal_sources,
                "sqs",
                sqs_result.queue_arn,
                sqs_result.region,
            ))

        for role_result in analyze_iam_roles_trust_policies(session, self.org_account_ids):
            findings.extend(_findings_for_resource(
                role_result.service_principal_sources,
                "iam",
                role_result.role_name,
                None,
            ))

        return [
            finding for finding in findings
            if finding.source_account_ids or finding.has_wildcard_source or finding.read_failure
        ]

    def categorize_result(
        self,
        result: ServicePrincipalSourceFinding
    ) -> tuple[CheckCategory, Dict[str, Any]]:
        """
        Categorize a single service principal source finding.

        A failed read is a violation for the same reason a wildcard source
        is: the account's allowlist cannot be computed, so the statement
        must be withheld rather than deployed against a guess.

        Args:
            result: One finding

        Returns:
            Tuple of (category, result_dict)
        """
        result_dict = {
            "resource_type": result.resource_type,
            "resource_identifier": result.resource_identifier,
            "region": result.region,
            "service_principal": result.service_principal,
            "source_account_ids": result.source_account_ids,
            "has_source_condition": result.has_source_condition,
            "has_wildcard_source": result.has_wildcard_source,
            "read_failure": result.read_failure,
        }

        self.all_third_party_accounts.update(result.source_account_ids)

        if result.has_wildcard_source or result.read_failure is not None:
            return (CheckCategory.VIOLATION, result_dict)
        return (CheckCategory.COMPLIANT, result_dict)

    def build_summary_fields(
        self,
        check_result: CategorizedCheckResult
    ) -> Dict[str, Any]:
        """
        Build service confused deputy check-specific summary fields.

        `violations` withholds the statement from the account, exactly as it
        does for the other six checks - and a resource whose source read
        failed is one of them, so the statement is never deployed against an
        allowlist that could not be computed.
        `unique_third_party_accounts` becomes the statement's
        aws:SourceAccount allowlist and `third_party_account_count` its
        length.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """
        return {
            "violations": len(check_result.violations),
            "unique_third_party_accounts": sorted(list(self.all_third_party_accounts)),
            "third_party_account_count": len(self.all_third_party_accounts),
        }
