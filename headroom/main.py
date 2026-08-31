from typing import Dict, Iterator, List
import argparse
from contextlib import contextmanager
import logging
from pathlib import Path

from botocore.exceptions import ClientError
from mypy_boto3_organizations.client import OrganizationsClient

from .config import HeadroomConfig
from .log_context import configure_logging
from .usage import load_yaml_config, parse_cli_args, merge_configs
from .analysis import perform_analysis, get_security_analysis_session, get_management_account_session
from .parse_results import analyze_scp_compliance, print_policy_recommendations
from .terraform.generate_scps import generate_scp_terraform
from .terraform.generate_rcps import parse_rcp_result_files, determine_rcp_placement, generate_rcp_terraform, _create_org_info_symlink
from .terraform.generate_org_info import generate_terraform_org_info
from .terraform.reconcile import reconcile_generated_terraform
from .aws.organization_snapshot import discover_organization
from .types import OrganizationHierarchy, RCPPlacementRecommendations, SCPPlacementRecommendations
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
) -> List[SCPPlacementRecommendations]:
    """
    Parse SCP results, place them, and report them.

    Nothing is written here. The caller compiles every recommendation into one
    plan before any of it reaches the filesystem.

    Args:
        final_config: Validated Headroom configuration
        org_hierarchy: Organization hierarchy structure

    Returns:
        This run's SCP placement recommendations

    Raises:
        RuntimeError: If no SCP result files were parsed
    """
    scp_recommendations = analyze_scp_compliance(final_config, org_hierarchy)
    print_policy_recommendations(
        scp_recommendations, org_hierarchy, "SCP PLACEMENT RECOMMENDATIONS"
    )
    return scp_recommendations


def handle_rcp_workflow(
    final_config: HeadroomConfig,
    org_hierarchy: OrganizationHierarchy
) -> List[RCPPlacementRecommendations]:
    """
    Parse RCP results, place them, and report them.

    Nothing is written here. The caller compiles every recommendation into one
    plan before any of it reaches the filesystem.

    Args:
        final_config: Validated Headroom configuration
        org_hierarchy: Organization hierarchy structure

    Returns:
        This run's RCP placement recommendations

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
    print_policy_recommendations(
        rcp_recommendations, org_hierarchy, "RCP PLACEMENT RECOMMENDATIONS"
    )
    return rcp_recommendations


@contextmanager
def _failures_reported(phase: str) -> Iterator[None]:
    """
    Report the wrapped phase's failure to the operator, then exit.

    Organization discovery, the scan, and Terraform generation each end a run
    the same way, so they share one reporter rather than each growing its own
    copy of these handlers: one format, whichever phase failed. The phase
    names itself in every line, because the exception rarely does -- a
    ClientError says which API refused and never says which phase called it,
    and a denied AssumeRole is both discovery's first step and the scan's
    per-account one.

    Only the first two phases reach AWS, so only they can raise the
    ClientError arm; generation reads result files and writes Terraform. The
    handler stays shared anyway, because a phase's set of failure modes is
    not what decides how its failure is reported.

    Only the scan reaches an account; a failure there has already printed one
    ERROR line per failed account, and what this adds is the summary that
    ended the run.
    """
    try:
        yield
    except ValueError as e:
        OutputHandler.error(f"Configuration Error during {phase}", e)
        logger.error(f"Invalid configuration during {phase}: {e}", exc_info=True)
        exit(1)
    except RuntimeError as e:
        OutputHandler.error(f"Runtime Error during {phase}", e)
        logger.error(f"Runtime error during {phase}: {e}", exc_info=True)
        exit(1)
    except ClientError as e:
        error_code = e.response['Error']['Code']
        OutputHandler.error(f"AWS API Error ({error_code}) during {phase}", e)
        logger.error(f"AWS API error during {phase}: {e}", exc_info=True)
        exit(1)


def main() -> None:
    """Main entry point for Headroom security analysis."""
    configure_logging()
    cli_args = parse_cli_args()
    yaml_config = load_yaml_config(cli_args.config)

    final_config = setup_configuration(cli_args, yaml_config)

    with _failures_reported("organization discovery"):
        security_session = get_security_analysis_session(final_config)
        mgmt_session = get_management_account_session(final_config, security_session)
        org_client: OrganizationsClient = mgmt_session.client("organizations")
        snapshot = discover_organization(final_config, org_client)

    with _failures_reported("the scan"):
        perform_analysis(final_config, security_session, snapshot)

    with _failures_reported("Terraform generation"):
        # Everything that can fail on bad input runs first. A raise here has
        # written nothing, so the previous run's output is still whole.
        scp_recommendations = handle_scp_workflow(final_config, snapshot.hierarchy)
        rcp_recommendations = handle_rcp_workflow(final_config, snapshot.hierarchy)

        org_info_path = Path(final_config.scps_dir) / ORG_INFO_FILENAME
        generate_terraform_org_info(snapshot.hierarchy, str(org_info_path))
        ensure_org_info_symlink(final_config.rcps_dir, final_config.scps_dir)

        expected = {org_info_path}
        expected |= set(generate_scp_terraform(
            scp_recommendations, snapshot.hierarchy, final_config.scps_dir
        ))
        expected |= set(generate_rcp_terraform(
            rcp_recommendations, snapshot.hierarchy, final_config.rcps_dir
        ))

        # Both workflows have succeeded, so this run's plan is complete and
        # anything generated but unaccounted for belongs to a previous one.
        reconcile_generated_terraform(
            [Path(final_config.scps_dir), Path(final_config.rcps_dir)],
            expected,
        )
