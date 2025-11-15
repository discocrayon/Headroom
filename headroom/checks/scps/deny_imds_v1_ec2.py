"""Check for EC2 instances that violate the deny_imds_v1_ec2 SCP."""

from typing import List

import boto3

from ...aws.ec2 import DenyImdsV1Ec2, get_imds_v1_ec2_analysis
from ...constants import DENY_IMDS_V1_EC2
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("scps", DENY_IMDS_V1_EC2)
class DenyImdsV1Ec2Check(BaseCheck[DenyImdsV1Ec2]):
    """
    Check for EC2 instances that would be blocked by the deny_imds_v1_ec2 SCP.

    This check identifies:
    - Instances that have IMDSv1 enabled (potential violations)
    - Instances that are exempt via ExemptFromIMDSv2 tag
    - Overall compliance status for the account
    """

    def analyze(self, session: boto3.Session) -> List[DenyImdsV1Ec2]:
        """
        Analyze EC2 instances for IMDS v1 configuration.

        Args:
            session: boto3.Session for the target account

        Returns:
            List of DenyImdsV1Ec2 analysis results
        """
        return get_imds_v1_ec2_analysis(session)

    def categorize_result(self, result: DenyImdsV1Ec2) -> tuple[str, JsonDict]:
        """
        Categorize a single IMDS v1 analysis result.

        Args:
            result: Single DenyImdsV1Ec2 analysis result

        Returns:
            Tuple of (category, result_dict) where category is:
            - "violation": IMDSv1 allowed without exemption tag
            - "exemption": IMDSv1 allowed but has exemption tag
            - "compliant": IMDSv1 not allowed
        """
        result_dict = {
            "region": result.region,
            "instance_id": result.instance_id,
            "imdsv1_allowed": result.imdsv1_allowed,
            "exemption_tag_present": result.exemption_tag_present,
        }

        if result.imdsv1_allowed:
            if result.exemption_tag_present:
                return ("exemption", result_dict)
            else:
                return ("violation", result_dict)
        else:
            return ("compliant", result_dict)

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
