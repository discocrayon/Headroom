from typing import Any, Callable, Dict, List, Union
import argparse
import boto3
from botocore.exceptions import ClientError

from .config import HeadroomConfig
from .usage import load_yaml_config, parse_cli_args, merge_configs
from .analysis import perform_analysis, get_security_analysis_session, get_management_account_session
from .parse_results import parse_scp_results, print_policy_recommendations
from .terraform.generate_scps import generate_scp_terraform
from .terraform.generate_rcps import parse_rcp_result_files, determine_rcp_placement, generate_rcp_terraform
from .terraform.generate_org_info import generate_terraform_org_info
from .aws.organization import analyze_organization_structure
from .types import OrganizationHierarchy
from .constants import ORG_INFO_FILENAME


def setup_configuration(cli_args: argparse.Namespace, yaml_config: Dict) -> HeadroomConfig:
    """
    Merge and validate configuration from YAML and CLI arguments.

    Args:
        cli_args: Parsed command line arguments
        yaml_config: Configuration loaded from YAML file

    Returns:
        Validated HeadroomConfig object

    Raises:
        SystemExit: If configuration validation fails
    """
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

    return final_config


def process_policy_recommendations(
    recommendations: Union[Dict[Any, Any], List[Any]],
    org_hierarchy: OrganizationHierarchy,
    title: str,
    terraform_generator: Callable[..., None],
    *generator_args: str
) -> None:
    """
    Process policy recommendations by printing and generating Terraform.

    Args:
        recommendations: Policy recommendations dictionary or list
        org_hierarchy: Organization hierarchy structure
        title: Title to display for the recommendations
        terraform_generator: Function to call to generate Terraform files
        *generator_args: Additional arguments to pass to terraform_generator
    """
    if not recommendations:
        return

    print_policy_recommendations(recommendations, org_hierarchy, title)  # type: ignore[arg-type]
    terraform_generator(recommendations, org_hierarchy, *generator_args)


def setup_organization_context(
    final_config: HeadroomConfig,
    security_session: boto3.Session
) -> tuple[boto3.Session, OrganizationHierarchy]:
    """
    Set up organization context for Terraform generation.

    Args:
        final_config: Validated Headroom configuration
        security_session: boto3 Session with security analysis access

    Returns:
        Tuple of (management_session, organization_hierarchy)

    Raises:
        ValueError: If management account configuration is missing
        RuntimeError: If role assumption fails
        ClientError: If AWS API calls fail
    """
    mgmt_session = get_management_account_session(final_config, security_session)
    organization_hierarchy = analyze_organization_structure(mgmt_session)

    generate_terraform_org_info(mgmt_session, f"{final_config.scps_dir}/{ORG_INFO_FILENAME}")

    return mgmt_session, organization_hierarchy


def handle_scp_workflow(final_config: HeadroomConfig, org_hierarchy: OrganizationHierarchy) -> None:
    """
    Parse SCP results and generate SCP Terraform files.

    Args:
        final_config: Validated Headroom configuration
        org_hierarchy: Organization hierarchy structure
    """
    scp_recommendations = parse_scp_results(final_config)

    if not scp_recommendations:
        return

    process_policy_recommendations(
        scp_recommendations,
        org_hierarchy,
        "SCP PLACEMENT RECOMMENDATIONS",
        generate_scp_terraform,
        final_config.scps_dir,
    )


def handle_rcp_workflow(final_config: HeadroomConfig, org_hierarchy: OrganizationHierarchy) -> None:
    """
    Parse RCP results and generate RCP Terraform files.

    Args:
        final_config: Validated Headroom configuration
        org_hierarchy: Organization hierarchy structure
    """
    rcp_parse_result = parse_rcp_result_files(final_config.results_dir, org_hierarchy)

    if not rcp_parse_result.account_third_party_map:
        return

    rcp_recommendations = determine_rcp_placement(
        rcp_parse_result.account_third_party_map,
        org_hierarchy,
        rcp_parse_result.accounts_with_wildcards
    )

    if not rcp_recommendations:
        return

    process_policy_recommendations(
        rcp_recommendations,
        org_hierarchy,
        "RCP PLACEMENT RECOMMENDATIONS",
        generate_rcp_terraform,
        final_config.rcps_dir,
        final_config.scps_dir,
    )


def main() -> None:
    """Main entry point for Headroom security analysis."""
    cli_args = parse_cli_args()
    yaml_config = load_yaml_config(cli_args.config)

    final_config = setup_configuration(cli_args, yaml_config)

    perform_analysis(final_config)

    security_session = get_security_analysis_session(final_config)

    try:
        mgmt_session, org_hierarchy = setup_organization_context(final_config, security_session)

        handle_scp_workflow(final_config, org_hierarchy)
        handle_rcp_workflow(final_config, org_hierarchy)

    except (ValueError, RuntimeError, ClientError) as e:
        print(f"\n🚨 Terraform Generation Error:\n{e}\n")
        exit(1)
