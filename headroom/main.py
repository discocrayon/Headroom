import boto3  # type: ignore
from botocore.exceptions import ClientError  # type: ignore

from .usage import load_yaml_config, parse_cli_args, merge_configs
from .analysis import perform_analysis, get_security_analysis_session
from .parse_results import parse_results
from .terraform.generate_scps import generate_scp_terraform
from .terraform.generate_rcps import parse_rcp_result_files, determine_rcp_placement, generate_rcp_terraform
from .terraform.generate_org_info import generate_terraform_org_info
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
    scp_recommendations = parse_results(final_config)

    # Get organization hierarchy for Terraform generation
    security_session = get_security_analysis_session(final_config)
    if not final_config.management_account_id:
        return

    role_arn = f"arn:aws:iam::{final_config.management_account_id}:role/OrgAndAccountInfoReader"
    sts = security_session.client("sts")
    try:
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="HeadroomTerraformGenerationSession"
        )
        creds = resp["Credentials"]
        mgmt_session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
        organization_hierarchy = analyze_organization_structure(mgmt_session)

        # Generate shared Terraform organization info file (used by both SCPs and RCPs)
        generate_terraform_org_info(mgmt_session, f"{final_config.scps_dir}/grab_org_info.tf")

        # Generate Terraform files for SCP deployment
        if scp_recommendations:
            generate_scp_terraform(
                scp_recommendations,
                organization_hierarchy,
                final_config.scps_dir,
            )

        # Parse RCP results and generate RCP Terraform
        rcp_parse_result = parse_rcp_result_files(
            final_config.results_dir,
            organization_hierarchy
        )
        if rcp_parse_result.account_third_party_map:
            rcp_recommendations = determine_rcp_placement(
                rcp_parse_result.account_third_party_map,
                organization_hierarchy,
                rcp_parse_result.accounts_with_wildcards
            )

            if rcp_recommendations:
                print("\n" + "=" * 80)
                print("RCP PLACEMENT RECOMMENDATIONS")
                print("=" * 80)
                for rec in rcp_recommendations:
                    print(f"\nRecommended Level: {rec.recommended_level.upper()}")
                    if rec.target_ou_id:
                        ou_info = organization_hierarchy.organizational_units.get(rec.target_ou_id)
                        ou_name = ou_info.name if ou_info else rec.target_ou_id
                        print(f"Target OU: {ou_name} ({rec.target_ou_id})")
                    print(f"Affected Accounts: {len(rec.affected_accounts)}")
                    print(f"Third-Party Accounts: {len(rec.third_party_account_ids)}")
                    print(f"Reasoning: {rec.reasoning}")
                    print("-" * 40)

                generate_rcp_terraform(
                    rcp_recommendations,
                    organization_hierarchy,
                    final_config.rcps_dir,
                    final_config.scps_dir,
                )

    except ClientError as e:
        print(f"Failed to generate Terraform files: {e}")
