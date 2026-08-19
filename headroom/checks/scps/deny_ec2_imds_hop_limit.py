"""Check for EC2 instances that violate the deny_ec2_imds_hop_limit SCP."""

from typing import Any, Dict, List

import boto3

from ...aws.ec2 import DenyEc2ImdsHopLimit, get_ec2_imds_hop_limit_analysis
from ...constants import DENY_EC2_IMDS_HOP_LIMIT
from ...enums import CheckCategory
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check

# Highest IMDS hop limit the SCP permits at launch
MAX_ALLOWED_HOP_LIMIT = 1


@register_check("scps", DENY_EC2_IMDS_HOP_LIMIT)
class DenyEc2ImdsHopLimitCheck(BaseCheck[DenyEc2ImdsHopLimit]):
    """
    Check for EC2 instances that would be blocked by deny_ec2_imds_hop_limit SCP.

    This check identifies:
    - Instances whose IMDS hop limit exceeds 1 (violations)
    - Instances at hop limit 1, or with IMDS disabled entirely (compliant)
    - Overall compliance status for the account
    """

    def analyze(self, session: boto3.Session) -> List[DenyEc2ImdsHopLimit]:
        """
        Analyze EC2 instances for IMDS hop limit configuration.

        Args:
            session: boto3.Session for the target account

        Returns:
            List of DenyEc2ImdsHopLimit analysis results
        """
        return get_ec2_imds_hop_limit_analysis(session)

    def categorize_result(
        self,
        result: DenyEc2ImdsHopLimit
    ) -> tuple[CheckCategory, Dict[str, Any]]:
        """
        Categorize a single EC2 IMDS hop limit analysis result.

        An instance with the metadata endpoint disabled is compliant whatever
        its hop limit, because there is no reachable IMDS for a hop to cross.

        Args:
            result: Single DenyEc2ImdsHopLimit analysis result

        Returns:
            Tuple of (category, result_dict) where category is:
            - CheckCategory.VIOLATION: IMDS enabled and hop limit above 1
            - CheckCategory.COMPLIANT: hop limit 1, or IMDS disabled
        """
        result_dict = {
            "instance_id": result.instance_id,
            "region": result.region,
            "hop_limit": result.hop_limit,
            "imds_enabled": result.imds_enabled,
        }

        if result.imds_enabled and result.hop_limit > MAX_ALLOWED_HOP_LIMIT:
            return (CheckCategory.VIOLATION, result_dict)
        else:
            return (CheckCategory.COMPLIANT, result_dict)

    def build_summary_fields(
        self,
        check_result: CategorizedCheckResult
    ) -> Dict[str, Any]:
        """
        Build EC2 IMDS hop limit check-specific summary fields.

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
