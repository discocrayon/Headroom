"""Check for EC2 instances using AMIs from untrusted owners."""

from typing import Any, Dict, List

from boto3.session import Session

from ...aws.ec2 import DenyEc2AmiOwner, get_ec2_ami_owner_analysis
from ...constants import DENY_EC2_AMI_OWNER
from ...enums import CheckCategory
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("scps", DENY_EC2_AMI_OWNER)
class DenyEc2AmiOwnerCheck(BaseCheck[DenyEc2AmiOwner]):
    """
    Check for EC2 instances using AMIs from untrusted owners.

    This check identifies:
    - EC2 instances using AMIs from owners not in allowlist (violations)
    - EC2 instances using AMIs from trusted owners (compliant)
    - Overall compliance status for the account
    """

    def analyze(self, session: Session) -> List[DenyEc2AmiOwner]:
        """
        Analyze EC2 instances to determine AMI owner for each.

        Args:
            session: boto3.Session for the target account

        Returns:
            List of DenyEc2AmiOwner analysis results
        """
        return get_ec2_ami_owner_analysis(session)

    def categorize_result(
        self,
        result: DenyEc2AmiOwner
    ) -> tuple[CheckCategory, Dict[str, Any]]:
        """
        Categorize a single EC2 AMI owner result.

        Args:
            result: Single DenyEc2AmiOwner analysis result

        Returns:
            Tuple of (category, result_dict) where category is a CheckCategory enum value
        """
        result_dict = {
            "instance_id": result.instance_id,
            "region": result.region,
            "ami_id": result.ami_id,
            "ami_owner": result.ami_owner,
            "ami_name": result.ami_name,
        }

        return (CheckCategory.COMPLIANT, result_dict)

    def build_summary_fields(
        self,
        check_result: CategorizedCheckResult
    ) -> Dict[str, Any]:
        """
        Build EC2 AMI owner check-specific summary fields.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """
        total = len(check_result.violations) + len(check_result.compliant)
        compliant_count = len(check_result.compliant)
        compliance_pct = (compliant_count / total * 100) if total else 100

        ami_owners = set()
        for item in check_result.violations + check_result.compliant:
            ami_owners.add(item["ami_owner"])

        return {
            "total_instances": total,
            "violations": len(check_result.violations),
            "compliant": len(check_result.compliant),
            "compliance_percentage": compliance_pct,
            "unique_ami_owners": sorted(list(ami_owners)),
        }
