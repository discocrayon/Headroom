"""Check for RDS databases that violate the deny_rds_unencrypted SCP."""

from typing import Any, Dict, List

import boto3

from ...aws.rds import DenyRdsUnencrypted, get_rds_unencrypted_analysis
from ...constants import DENY_RDS_UNENCRYPTED
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("scps", DENY_RDS_UNENCRYPTED)
class DenyRdsUnencryptedCheck(BaseCheck[DenyRdsUnencrypted]):
    """
    Check for RDS databases that would be blocked by deny_rds_unencrypted SCP.

    This check identifies:
    - RDS instances and Aurora clusters without encryption (violations)
    - Encrypted databases (compliant)
    - Overall compliance status for the account
    """

    def analyze(self, session: boto3.Session) -> List[DenyRdsUnencrypted]:
        """
        Analyze RDS databases for encryption configuration.

        Args:
            session: boto3.Session for the target account

        Returns:
            List of DenyRdsUnencrypted analysis results
        """
        return get_rds_unencrypted_analysis(session)

    def categorize_result(
        self,
        result: DenyRdsUnencrypted
    ) -> tuple[str, Dict[str, Any]]:
        """
        Categorize a single RDS encryption result.

        Args:
            result: Single DenyRdsUnencrypted analysis result

        Returns:
            Tuple of (category, result_dict) where category is:
            - "violation": Unencrypted database
            - "compliant": Encryption enabled
        """
        result_dict = {
            "db_identifier": result.db_identifier,
            "db_type": result.db_type,
            "region": result.region,
            "engine": result.engine,
            "encrypted": result.encrypted,
            "db_arn": result.db_arn,
        }

        if not result.encrypted:
            return ("violation", result_dict)

        return ("compliant", result_dict)

    def build_summary_fields(
        self,
        check_result: CategorizedCheckResult
    ) -> Dict[str, Any]:
        """
        Build RDS encryption check-specific summary fields.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """
        total = len(check_result.violations) + len(check_result.compliant)
        compliant_count = len(check_result.compliant)
        compliance_pct = (compliant_count / total * 100) if total else 100

        return {
            "total_databases": total,
            "violations": len(check_result.violations),
            "compliant": len(check_result.compliant),
            "compliance_percentage": compliance_pct,
        }
