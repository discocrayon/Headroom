"""Check for EC2 instances that violate the deny_ec2_imds_v1 SCP."""

from typing import List

from boto3.session import Session

from ...aws.ec2 import DenyEc2ImdsV1, get_ec2_imds_v1_analysis
from ...constants import DENY_EC2_IMDS_V1
from ...enums import CheckCategory, TerraformSection
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("scps", DENY_EC2_IMDS_V1, terraform_section=TerraformSection.EC2)
class DenyEc2ImdsV1Check(BaseCheck[DenyEc2ImdsV1]):
    """
    Decide whether an account can take the deny_ec2_imds_v1 SCP.

    The SCP carries one statement,
    `DenyRunInstancesMetadataHttpTokensOptional`, which denies a
    `RunInstances` request that would leave the instance answering IMDSv1.

    **What this check measures, and what it does not.** It counts instances
    already running with IMDSv1 available. Not one of them can be denied by
    the statement - they have all launched. They are counted as evidence about
    the next launch: an account still running IMDSv1 instances is an account
    whose next launch is likely to be denied, so the SCP is not safe to attach
    there yet.

    **An instance tagged `ExemptFromIMDSv2=true` is an exemption.** The
    statement exempts a launch through `aws:RequestTag/ExemptFromIMDSv2`, and
    the `TagSpecifications` entry that supplies that request tag is the same
    one that puts the tag on the resulting instance. So the instance's tag is
    the observable trace of the exemption, and an exempt-tagged IMDSv1
    instance does not count against deploying the SCP.

    **That proxy can be wrong, and we accept it.** A tag added after launch
    with `CreateTags`, or an instance whose Terraform does not declare the
    tag, wears the tag without its relaunch carrying one - and this check
    will then clear an account whose relaunch enforcement denies. The tag is
    taken as a declaration of intent, not as a prediction; how it gets
    reapplied is the operator's business, not this check's.

    The tag is read off the instance. No role is resolved; `aws:PrincipalTag`
    belonged to a statement this module no longer generates.
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

        An IMDSv1 instance is a violation unless it carries the exemption
        tag, matched the way the condition key is: key without regard to
        case, value exactly.

        Args:
            result: Single DenyEc2ImdsV1 analysis result

        Returns:
            Tuple of (category, result_dict) where category is a CheckCategory enum value
        """
        result_dict = {
            "region": result.region,
            "instance_id": result.instance_id,
            "imdsv1_allowed": result.imdsv1_allowed,
            "exemption_tag_present": result.exemption_tag_present,
        }

        if result.imdsv1_allowed:
            if result.exemption_tag_present:
                return (CheckCategory.EXEMPTION, result_dict)
            return (CheckCategory.VIOLATION, result_dict)
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
        # An exemption counts as compliant: the SCP will spare that launch, so
        # it is no reason to withhold the SCP from this account.
        compliant_count = len(check_result.compliant) + len(check_result.exemptions)
        compliance_pct = (compliant_count / total * 100) if total else 100

        return {
            "total_instances": total,
            "violations": len(check_result.violations),
            "exemptions": len(check_result.exemptions),
            "compliant": len(check_result.compliant),
            "compliance_percentage": compliance_pct,
        }
