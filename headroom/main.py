from typing import Any, Callable, Dict, List, Union
import argparse
import logging
from pathlib import Path

from boto3.session import Session
from botocore.exceptions import ClientError

from .config import HeadroomConfig
from .usage import load_yaml_config, parse_cli_args, merge_configs
from .analysis import perform_analysis, get_security_analysis_session, get_management_account_session
from .parse_results import analyze_scp_compliance, print_policy_recommendations
from .terraform.generate_scps import generate_scp_terraform
from .terraform.generate_rcps import parse_rcp_result_files, determine_rcp_placement, generate_rcp_terraform, _create_org_info_symlink
from .terraform.generate_org_info import generate_terraform_org_info
from .aws.organization import analyze_organization_structure
from .types import OrganizationHierarchy
from .constants import ORG_INFO_FILENAME
from .output import OutputHandler

logger = logging.getLogger(__name__)


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
    except (ValueError, TypeError) as e:
        OutputHandler.error("Configuration Error", e)
        exit(1)

    OutputHandler.success("Final Config", final_config.model_dump())

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
    security_session: Session
) -> tuple[Session, OrganizationHierarchy]:
    """
    Set up organization context for policy analysis.

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
    return mgmt_session, organization_hierarchy


def ensure_org_info_symlink(rcps_dir: str, scps_dir: str) -> None:
    """
    Create symlink from rcps/grab_org_info.tf to scps/grab_org_info.tf.

    The grab_org_info.tf file contains shared organization structure data sources
    needed by both SCP and RCP modules. This function ensures the symlink exists
    in the RCP directory.

    Args:
        rcps_dir: RCP directory path where symlink should be created
        scps_dir: SCP directory path (contains the actual grab_org_info.tf file)
    """
    rcps_path = Path(rcps_dir)
    rcps_path.mkdir(parents=True, exist_ok=True)
    _create_org_info_symlink(rcps_path, scps_dir)


def handle_scp_workflow(final_config: HeadroomConfig, org_hierarchy: OrganizationHierarchy) -> None:
    """
    Parse SCP results and generate SCP Terraform files.

    Args:
        final_config: Validated Headroom configuration
        org_hierarchy: Organization hierarchy structure
    """
    scp_recommendations = analyze_scp_compliance(final_config, org_hierarchy)

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

        # Generate Terraform organization info file (needed by both SCP and RCP workflows)
        generate_terraform_org_info(mgmt_session, f"{final_config.scps_dir}/{ORG_INFO_FILENAME}")

        # Create symlink from RCP directory to SCP grab_org_info.tf (needed for RCP Terraform)
        ensure_org_info_symlink(final_config.rcps_dir, final_config.scps_dir)

        handle_scp_workflow(final_config, org_hierarchy)
        handle_rcp_workflow(final_config, org_hierarchy)

    except ValueError as e:
        OutputHandler.error("Configuration Error", e)
        logger.error(f"Invalid configuration: {e}", exc_info=True)
        exit(1)
    except RuntimeError as e:
        OutputHandler.error("Runtime Error", e)
        logger.error(f"Runtime error during Terraform generation: {e}", exc_info=True)
        exit(1)
    except ClientError as e:
        error_code = e.response['Error']['Code']
        OutputHandler.error(f"AWS API Error ({error_code})", e)
        logger.error(f"AWS API error: {e}", exc_info=True)
        exit(1)
