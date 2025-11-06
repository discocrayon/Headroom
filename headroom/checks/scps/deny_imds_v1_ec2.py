"""Check for EC2 instances that violate the deny_imds_v1_ec2 SCP."""

import boto3  # type: ignore
from ...aws.ec2 import get_imds_v1_ec2_analysis
from ...write_results import write_check_results
from ...constants import DENY_IMDS_V1_EC2


def check_deny_imds_v1_ec2(
    headroom_session: boto3.Session,
    account_name: str,
    account_id: str,
    results_base_dir: str,
    exclude_account_ids: bool = False,
) -> None:
    """
    Check for EC2 instances that would be blocked by the deny_imds_v1_ec2 SCP.

    This check identifies:
    - Instances that have IMDSv1 enabled (potential violations)
    - Instances that are exempt via ExemptFromIMDSv2 tag
    - Overall compliance status for the account

    Args:
        headroom_session: boto3.Session for the target account
        account_name: Account name
        account_id: Account ID
        results_base_dir: Base directory for results
        exclude_account_ids: If True, exclude account ID from results
    """
    # Get IMDS analysis results
    imds_results = get_imds_v1_ec2_analysis(headroom_session)

    # Process results for SCP compliance
    violations = []
    exemptions = []
    compliant = []

    for result in imds_results:
        result_dict = {
            "region": result.region,
            "instance_id": result.instance_id,
            "imdsv1_allowed": result.imdsv1_allowed,
            "exemption_tag_present": result.exemption_tag_present
        }

        if result.imdsv1_allowed:
            if result.exemption_tag_present:
                exemptions.append(result_dict)
            else:
                violations.append(result_dict)
        else:
            compliant.append(result_dict)

    # Create summary
    summary = {
        "account_name": account_name,
        "account_id": account_id,
        "check": DENY_IMDS_V1_EC2,
        "total_instances": len(imds_results),
        "violations": len(violations),
        "exemptions": len(exemptions),
        "compliant": len(compliant),
        "compliance_percentage": (len(compliant) + len(exemptions)) / len(imds_results) * 100 if imds_results else 100
    }

    # Prepare full results
    results = {
        "summary": summary,
        "violations": violations,
        "exemptions": exemptions,
        "compliant_instances": compliant
    }

    # Write results to JSON file
    write_check_results(
        check_name=DENY_IMDS_V1_EC2,
        account_name=account_name,
        account_id=account_id,
        results_data=results,
        results_base_dir=results_base_dir,
        exclude_account_ids=exclude_account_ids,
    )

    account_identifier = f"{account_name}_{account_id}"
    print(f"IMDS v1 check completed for {account_identifier}: {len(violations)} violations, {len(exemptions)} exemptions, {len(compliant)} compliant")
