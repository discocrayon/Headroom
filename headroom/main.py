import boto3  # type: ignore
from botocore.exceptions import ClientError  # type: ignore

from .usage import load_yaml_config, parse_cli_args, merge_configs
from .analysis import perform_analysis, get_security_analysis_session
from .parse_results import parse_results
from .terraform.generate_scps import generate_scp_terraform
from .aws.organization import analyze_organization_structure


def main() -> None:
    cli_args = parse_cli_args()
    yaml_config = load_yaml_config(cli_args.config)

    try:
        final_config = merge_configs(yaml_config, cli_args)
    except ValueError as e:
        print(f"\n🚨 Configuration Validation Error:\n{e}\n")
        exit(1)
    except TypeError as e:
        print(f"\n🚨 Configuration Type Error:\n{e}\n")
        exit(1)

    print("\n✅ Final Config:")
    print(final_config.model_dump())

    # Perform security analysis
    perform_analysis(final_config)

    # Analyze results and determine SCP placement recommendations
    recommendations = parse_results(final_config)

    # Generate Terraform files for SCP deployment
    if not recommendations:
        return

    # We need to get the organization hierarchy again for Terraform generation
    # This is a temporary solution - in a real implementation, we'd pass it from parse_results
    security_session = get_security_analysis_session(final_config)
    if not final_config.management_account_id:
        return

    role_arn = f"arn:aws:iam::{final_config.management_account_id}:role/OrgAndAccountInfoReader"
    sts = security_session.client("sts")
    try:
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="HeadroomSCPPlacementAnalysisSession"
        )
        creds = resp["Credentials"]
        mgmt_session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
        organization_hierarchy = analyze_organization_structure(mgmt_session)
        generate_scp_terraform(
            recommendations,
            organization_hierarchy,
            final_config.scps_dir,
        )
    except ClientError as e:
        print(f"Failed to generate Terraform files: {e}")
