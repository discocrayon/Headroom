"""Check for EKS clusters that violate the deny_eks_create_cluster_without_tag SCP."""

from typing import List

import boto3

from ...aws.eks import (
    DenyEksCreateClusterWithoutTag,
    get_eks_cluster_tag_analysis,
)
from ...constants import DENY_EKS_CREATE_CLUSTER_WITHOUT_TAG
from ...enums import CheckCategory
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("scps", DENY_EKS_CREATE_CLUSTER_WITHOUT_TAG)
class DenyEksCreateClusterWithoutTagCheck(BaseCheck[DenyEksCreateClusterWithoutTag]):
    """
    Check for EKS clusters without required PavedRoad tag.

    This check identifies:
    - EKS clusters missing PavedRoad=true tag (violations)
    - EKS clusters with PavedRoad=true tag (compliant)
    - Overall compliance status for the account
    """

    def analyze(
        self,
        session: boto3.Session
    ) -> List[DenyEksCreateClusterWithoutTag]:
        """
        Analyze EKS clusters for PavedRoad tag presence.

        Args:
            session: boto3.Session for the target account

        Returns:
            List of DenyEksCreateClusterWithoutTag analysis results
        """
        return get_eks_cluster_tag_analysis(session)

    def categorize_result(
        self,
        result: DenyEksCreateClusterWithoutTag
    ) -> tuple[CheckCategory, JsonDict]:
        """
        Categorize a single EKS cluster tag result.

        Args:
            result: Single DenyEksCreateClusterWithoutTag analysis result

        Returns:
            Tuple of (category, result_dict) where category is a CheckCategory enum value
        """
        result_dict = {
            "cluster_name": result.cluster_name,
            "cluster_arn": result.cluster_arn,
            "region": result.region,
            "tags": result.tags,
            "has_paved_road_tag": result.has_paved_road_tag,
        }

        if result.has_paved_road_tag:
            return (CheckCategory.COMPLIANT, result_dict)

        return (CheckCategory.VIOLATION, result_dict)

    def build_summary_fields(
        self,
        check_result: CategorizedCheckResult
    ) -> JsonDict:
        """
        Build EKS cluster tag check-specific summary fields.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """
        total = len(check_result.violations) + len(check_result.compliant)
        compliant_count = len(check_result.compliant)
        compliance_pct = (compliant_count / total * 100) if total else 100

        return {
            "total_clusters": total,
            "violations": len(check_result.violations),
            "compliant": len(check_result.compliant),
            "compliance_percentage": compliance_pct,
        }
