"""Check for EC2 instances that violate the deny_ec2_public_ip SCP."""

from typing import Any, Dict, List

import boto3

from ...aws.ec2 import DenyEc2PublicIp, get_ec2_public_ip_analysis
from ...constants import DENY_EC2_PUBLIC_IP
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("scps", DENY_EC2_PUBLIC_IP)
class DenyEc2PublicIpCheck(BaseCheck[DenyEc2PublicIp]):
    """
    Check for EC2 instances that would be blocked by deny_ec2_public_ip SCP.

    This check identifies:
    - EC2 instances with public IP addresses (violations)
    - EC2 instances without public IP addresses (compliant)
    - Overall compliance status for the account
    """

    def analyze(self, session: boto3.Session) -> List[DenyEc2PublicIp]:
        """
        Analyze EC2 instances for public IP address assignment.

        Args:
            session: boto3.Session for the target account

        Returns:
            List of DenyEc2PublicIp analysis results
        """
        return get_ec2_public_ip_analysis(session)

    def categorize_result(
        self,
        result: DenyEc2PublicIp
    ) -> tuple[str, Dict[str, Any]]:
        """
        Categorize a single EC2 public IP analysis result.

        Args:
            result: Single DenyEc2PublicIp analysis result

        Returns:
            Tuple of (category, result_dict) where category is:
            - "violation": Instance has public IP address
            - "compliant": Instance does not have public IP address
        """
        result_dict = {
            "instance_id": result.instance_id,
            "region": result.region,
            "public_ip_address": result.public_ip_address,
            "has_public_ip": result.has_public_ip,
            "instance_arn": result.instance_arn,
        }

        if result.has_public_ip:
            return ("violation", result_dict)
        else:
            return ("compliant", result_dict)

    def build_summary_fields(
        self,
        check_result: CategorizedCheckResult
    ) -> Dict[str, Any]:
        """
        Build EC2 public IP check-specific summary fields.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """
        total = len(check_result.violations) + len(check_result.compliant)
        compliant_count = len(check_result.compliant)
        compliance_pct = (compliant_count / total * 100) if total else 100

        return {
            "total_instances": total,
            "violations": len(check_result.violations),
            "compliant": len(check_result.compliant),
            "compliance_percentage": compliance_pct,
        }
