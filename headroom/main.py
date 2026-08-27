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
from .terraform.models import TerraformPlan
from .terraform.reconcile import reconcile_generated_terraform
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
    terraform_generator: Callable[..., TerraformPlan],
    *generator_args: str
) -> TerraformPlan:
    """
    Process policy recommendations by printing and generating Terraform.

    Empty recommendations still reach the generator. Its plan is what the
    directory is reconciled against, and an empty plan is the instruction to
    remove every policy file a previous run left there.

    Args:
        recommendations: Policy recommendations dictionary or list
        org_hierarchy: Organization hierarchy structure
        title: Title to display for the recommendations
        terraform_generator: Function to call to generate Terraform files
        *generator_args: Additional arguments to pass to terraform_generator

    Returns:
        The files the generator wants the output directory to hold
    """
    print_policy_recommendations(recommendations, org_hierarchy, title)  # type: ignore[arg-type]
    return terraform_generator(recommendations, org_hierarchy, *generator_args)


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


def handle_scp_workflow(
    final_config: HeadroomConfig,
    org_hierarchy: OrganizationHierarchy
) -> TerraformPlan:
    """
    Parse SCP results and generate SCP Terraform files.

    Args:
        final_config: Validated Headroom configuration
        org_hierarchy: Organization hierarchy structure

    Returns:
        The files this run wants the SCP directory to hold

    Raises:
        RuntimeError: If no SCP result files were parsed
    """
    scp_recommendations = analyze_scp_compliance(final_config, org_hierarchy)

    return process_policy_recommendations(
        scp_recommendations,
        org_hierarchy,
        "SCP PLACEMENT RECOMMENDATIONS",
        generate_scp_terraform,
        final_config.scps_dir,
    )


def handle_rcp_workflow(
    final_config: HeadroomConfig,
    org_hierarchy: OrganizationHierarchy
) -> TerraformPlan:
    """
    Parse RCP results and generate RCP Terraform files.

    Args:
        final_config: Validated Headroom configuration
        org_hierarchy: Organization hierarchy structure

    Returns:
        The files this run wants the RCP directory to hold

    Raises:
        RuntimeError: If no RCP result files were parsed
    """
    parse_results = parse_rcp_result_files(final_config.results_dir, org_hierarchy)

    # A check whose directory is missing is already rejected during parsing.
    # What is left is directories that exist and hold nothing: no account
    # cleared for the policy and none blocked from it, which means no file was
    # read. That is the absence of evidence, and it must not be reconciled into
    # deleting every RCP the organization currently deploys. An account that
    # blocks a check is evidence, and it leaves accounts_with_blockers non-empty.
    if not any(
        parsed.account_third_party_map or parsed.accounts_with_blockers
        for parsed in parse_results
    ):
        raise RuntimeError(
            f"No RCP result files were parsed from {final_config.results_dir}/rcps. "
            "Every generated policy file is deleted when a run places nothing, so "
            "a run that read nothing cannot be told apart from an organization "
            "that needs no policies. Check that the analysis wrote results to "
            "this directory before generating Terraform."
        )

    rcp_recommendations = determine_rcp_placement(parse_results, org_hierarchy)

    return process_policy_recommendations(
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
        org_info_path = Path(final_config.scps_dir) / ORG_INFO_FILENAME
        generate_terraform_org_info(mgmt_session, str(org_info_path))

        # Create symlink from RCP directory to SCP grab_org_info.tf (needed for RCP Terraform)
        ensure_org_info_symlink(final_config.rcps_dir, final_config.scps_dir)

        expected = {org_info_path}
        expected |= set(handle_scp_workflow(final_config, org_hierarchy))
        expected |= set(handle_rcp_workflow(final_config, org_hierarchy))

        # Both workflows have succeeded, so this run's plan is complete and
        # anything generated but unaccounted for belongs to a previous one. A
        # raise above skips this and leaves the previous output whole.
        reconcile_generated_terraform(
            [Path(final_config.scps_dir), Path(final_config.rcps_dir)],
            expected,
        )

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
