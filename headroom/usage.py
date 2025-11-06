import argparse
import yaml
from typing import Any, Dict
from .config import HeadroomConfig


def load_yaml_config(path: str) -> Dict[str, Any]:
    """
    Load configuration from a YAML file.

    Args:
        path: Path to the YAML configuration file

    Returns:
        Dictionary containing the loaded configuration, or empty dict if file not found
    """
    try:
        with open(path, 'r') as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(f"Config file '{path}' not found. Continuing without it.")
        return {}


def parse_cli_args() -> argparse.Namespace:
    """
    Parse command line arguments for the headroom tool.

    Returns:
        Parsed command line arguments namespace
    """
    parser = argparse.ArgumentParser(
        prog="headroom",
        description="Headroom - analyze AWS org and generate SCP Terraform"
    )

    parser.add_argument(
        '--config',
        required=True,
        type=str,
        help='Path to config YAML'
    )

    # Paths (override YAML if provided)
    parser.add_argument(
        '--results-dir',
        dest='results_dir',
        type=str,
        help='Directory containing headroom results (default test_environment/headroom_results)'
    )
    parser.add_argument(
        '--scps-dir',
        dest='scps_dir',
        type=str,
        help='Directory to output SCP Terraform (default test_environment/scps)'
    )
    parser.add_argument(
        '--rcps-dir',
        dest='rcps_dir',
        type=str,
        help='Directory to output RCP Terraform (default test_environment/rcps)'
    )

    # Account IDs
    parser.add_argument(
        '--security-analysis-account-id',
        dest='security_analysis_account_id',
        type=str,
        help='AWS Account ID where security analysis role is located'
    )
    parser.add_argument(
        '--management-account-id',
        dest='management_account_id',
        type=str,
        help='AWS Organization management account ID'
    )

    # Privacy options
    parser.add_argument(
        '--exclude-account-ids',
        dest='exclude_account_ids',
        action='store_true',
        default=argparse.SUPPRESS,
        help='Exclude account IDs from result files and filenames'
    )

    return parser.parse_args()


def merge_configs(yaml_config: Dict[str, Any], cli_args: argparse.Namespace) -> HeadroomConfig:
    """
    Merge YAML configuration with CLI arguments and validate the result.

    Args:
        yaml_config: Configuration loaded from YAML file
        cli_args: Parsed command line arguments

    Returns:
        Validated HeadroomConfig object

    Raises:
        ValueError: If configuration validation fails
        TypeError: If configuration has type errors
    """
    # Start with YAML
    merged = yaml_config.copy()

    # Apply CLI overrides (only if CLI provided them)
    cli_dict = {
        k: v for k, v in vars(cli_args).items()
        if k in HeadroomConfig.model_fields and v is not None
    }
    merged.update(cli_dict)

    # Validate and return final config (will raise if required fields missing or wrong types)
    return HeadroomConfig(**merged)
