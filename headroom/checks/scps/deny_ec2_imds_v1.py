"""Check for EC2 instances that violate the deny_ec2_imds_v1 SCP."""

from typing import List

from boto3.session import Session

from ...aws.ec2 import DenyEc2ImdsV1, get_ec2_imds_v1_analysis
from ...constants import DENY_EC2_IMDS_V1
from ...enums import CheckCategory
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("scps", DENY_EC2_IMDS_V1)
class DenyEc2ImdsV1Check(BaseCheck[DenyEc2ImdsV1]):
    """
    Check for EC2 instances that would be blocked by the deny_ec2_imds_v1 SCP.

    This check identifies:
    - Instances that have IMDSv1 enabled (potential violations)
    - Instances whose IAM role carries the ExemptFromIMDSv2 tag (exemptions),
      the key matched without regard to case and the value exactly, as IAM
      matches them
    - Overall compliance status for the account

    The exemption is read off the role the instance runs as, because that is
    what the SCP's DenyRoleDelivery statement tests. The SCP's other statement
    exempts a launch request by `aws:RequestTag/ExemptFromIMDSv2`, which no
    scan of running instances can observe; an account reported clean here is
    therefore safe from the first statement, not from the second.
    """

    def analyze(self, session: Session) -> List[DenyEc2ImdsV1]:
        """
        Analyze EC2 instances for IMDS v1 configuration.

        Args:
            session: boto3.Session for the target account

        Returns:
            List of DenyEc2ImdsV1 analysis results
        """
        return get_ec2_imds_v1_analysis(session)

    def categorize_result(self, result: DenyEc2ImdsV1) -> tuple[CheckCategory, JsonDict]:
        """
        Categorize a single IMDS v1 analysis result.

        Args:
            result: Single DenyEc2ImdsV1 analysis result

        Returns:
            Tuple of (category, result_dict) where category is a CheckCategory enum value
        """
        result_dict = {
            "region": result.region,
            "instance_id": result.instance_id,
            "imdsv1_allowed": result.imdsv1_allowed,
            "role_exemption_tag_present": result.role_exemption_tag_present,
            "role_arn": result.role_arn,
            "role_unresolved_reason": result.role_unresolved_reason,
        }

        if result.imdsv1_allowed:
            if result.role_exemption_tag_present:
                return (CheckCategory.EXEMPTION, result_dict)
            else:
                return (CheckCategory.VIOLATION, result_dict)
        else:
            return (CheckCategory.COMPLIANT, result_dict)

    def build_summary_fields(self, check_result: CategorizedCheckResult) -> JsonDict:
        """
        Build IMDS v1 check-specific summary fields.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """
        total = len(check_result.violations) + len(check_result.exemptions) + len(check_result.compliant)
        compliant_count = len(check_result.compliant) + len(check_result.exemptions)
        compliance_pct = (compliant_count / total * 100) if total else 100

        return {
            "total_instances": total,
            "violations": len(check_result.violations),
            "exemptions": len(check_result.exemptions),
            "compliant": len(check_result.compliant),
            "compliance_percentage": compliance_pct,
        }
