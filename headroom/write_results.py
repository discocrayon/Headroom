"""
Result Writing Module

Handles writing compliance check results to JSON files.
Provides centralized functionality for result file management,
mirroring the parse_results.py module for reading results.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict

# Set up logging
logger = logging.getLogger(__name__)


def write_check_results(
    check_name: str,
    account_name: str,
    account_id: str,
    results_data: Dict[str, Any],
    results_base_dir: str,
    exclude_account_ids: bool = False,
) -> None:
    """
    Write check results to a JSON file.

    Creates the necessary directory structure and writes results in a
    standardized format that can be parsed by parse_results.py.

    Args:
        check_name: Name of the check (e.g., 'deny_imds_v1_ec2')
        account_name: Account name
        account_id: Account ID
        results_data: Dictionary containing summary, violations, exemptions, etc.
        results_base_dir: Base directory for results
        exclude_account_ids: If True, exclude account ID from filename and JSON

    Creates file at:
        {results_base_dir}/{check_name}/{account_name}_{account_id}.json
        or {results_base_dir}/{check_name}/{account_name}.json if exclude_account_ids=True
    """
    results_dir = get_results_dir(check_name, results_base_dir)
    os.makedirs(results_dir, exist_ok=True)

    output_file = get_results_path(
        check_name,
        account_name,
        account_id,
        results_base_dir,
        exclude_account_ids,
    )

    # If excluding account IDs, remove account_id from the results data
    data_to_write = results_data
    if exclude_account_ids and "summary" in results_data:
        data_to_write = results_data.copy()
        data_to_write["summary"] = results_data["summary"].copy()
        data_to_write["summary"].pop("account_id", None)

    try:
        with open(output_file, 'w') as f:
            json.dump(data_to_write, f, indent=2, default=str)
            f.write('\n')
        logger.info(f"Wrote results to {output_file}")
    except IOError as e:
        logger.error(f"Failed to write results to {output_file}: {e}")
        raise


def get_results_dir(check_name: str, results_base_dir: str) -> str:
    """
    Get the directory path where results for a check should be stored.

    Args:
        check_name: Name of the check (e.g., 'deny_imds_v1_ec2')
        results_base_dir: Base directory for results

    Returns:
        Path to the check's results directory
    """
    return f"{results_base_dir}/{check_name}"


def get_results_path(
    check_name: str,
    account_name: str,
    account_id: str,
    results_base_dir: str,
    exclude_account_ids: bool = False,
) -> Path:
    """
    Get the file path where results for a specific account should be written.

    Args:
        check_name: Name of the check (e.g., 'deny_imds_v1_ec2')
        account_name: Account name
        account_id: Account ID
        results_base_dir: Base directory for results
        exclude_account_ids: If True, use only account name in filename

    Returns:
        Path object for the results file
    """
    results_dir = get_results_dir(check_name, results_base_dir)
    if exclude_account_ids:
        account_identifier = account_name
    else:
        account_identifier = f"{account_name}_{account_id}"
    return Path(results_dir) / f"{account_identifier}.json"


def results_exist(
    check_name: str,
    account_name: str,
    account_id: str,
    results_base_dir: str,
    exclude_account_ids: bool = False,
) -> bool:
    """
    Check if results file already exists for a given check and account.

    Checks for both filename formats to handle backward compatibility.

    Args:
        check_name: Name of the check (e.g., 'deny_imds_v1_ec2')
        account_name: Account name
        account_id: Account ID
        results_base_dir: Base directory for results
        exclude_account_ids: If True, check for filename without account ID

    Returns:
        True if results file exists, False otherwise
    """
    results_file = get_results_path(
        check_name,
        account_name,
        account_id,
        results_base_dir,
        exclude_account_ids,
    )
    if results_file.exists():
        return True

    # Check alternate format for backward compatibility
    alternate_file = get_results_path(
        check_name,
        account_name,
        account_id,
        results_base_dir,
        not exclude_account_ids,
    )
    return alternate_file.exists()
