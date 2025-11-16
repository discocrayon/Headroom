"""
Result Writing Module

Handles writing compliance check results to JSON files.
Provides centralized functionality for result file management,
mirroring the parse_results.py module for reading results.
"""

import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Union, cast

from .constants import get_check_type_map
from .utils import format_account_identifier

# Set up logging
logger = logging.getLogger(__name__)


@dataclass
class ResultFilePathResolver:
    """
    Resolves file paths for check results with backward compatibility.

    Centralizes all path resolution logic to eliminate duplication across
    write_check_results(), get_results_dir(), get_results_path(), and
    results_exist() functions.

    Attributes:
        check_name: Name of the check (e.g., 'deny_imds_v1_ec2')
        results_base_dir: Base directory for results
        account_name: Account name (optional, defaults to empty string)
        account_id: Account ID (optional, defaults to empty string)
        exclude_account_ids: If True, exclude account ID from filename
    """

    check_name: str
    results_base_dir: str
    account_name: str = ""
    account_id: str = ""
    exclude_account_ids: bool = False

    def get_check_directory(self) -> str:
        """
        Get directory for this check type.

        Returns:
            Path to the check's results directory

        Raises:
            ValueError: If check_name is not recognized
        """
        check_type_map = get_check_type_map()
        check_type = check_type_map.get(self.check_name)
        if not check_type:
            raise ValueError(
                f"Unknown check name: {self.check_name}. "
                f"Must be one of {list(check_type_map.keys())}"
            )
        return f"{self.results_base_dir}/{check_type}/{self.check_name}"

    def get_file_path(self) -> Path:
        """
        Get file path for results.

        Returns:
            Path object for the results file
        """
        results_dir = self.get_check_directory()
        filename = self._build_filename()
        return Path(results_dir) / filename

    def exists(self) -> bool:
        """
        Check if result file exists.

        Checks both current and alternate formats for backward compatibility.

        Returns:
            True if file exists in either format, False otherwise
        """
        if self.get_file_path().exists():
            return True
        return self._get_alternate_path().exists()

    def _build_filename(self) -> str:
        """
        Build filename based on configuration.

        Returns:
            Filename string (e.g., 'account_123456789012.json' or 'account.json')
        """
        if self.exclude_account_ids:
            account_identifier = self.account_name
        else:
            account_identifier = format_account_identifier(
                self.account_name,
                self.account_id
            )
        return f"{account_identifier}.json"

    def _get_alternate_path(self) -> Path:
        """
        Get alternate format path for backward compatibility.

        Returns alternate filename format to check if file exists under
        the opposite naming convention.

        Returns:
            Path object for the alternate format file
        """
        alternate = ResultFilePathResolver(
            check_name=self.check_name,
            results_base_dir=self.results_base_dir,
            account_name=self.account_name,
            account_id=self.account_id,
            exclude_account_ids=not self.exclude_account_ids
        )
        return alternate.get_file_path()


def _redact_account_ids_from_arns(data: Union[Dict[str, Any], List[Any], str, Any]) -> Union[Dict[str, Any], List[Any], str, Any]:
    """
    Recursively redact account IDs from ARNs in data structures.

    Replaces 12-digit account IDs in ARNs with "REDACTED".
    ARN formats:
    - arn:aws:service::111111111111:resource -> arn:aws:service::REDACTED:resource
    - arn:aws:service:region:111111111111:resource -> arn:aws:service:region:REDACTED:resource

    Args:
        data: Data structure to process (dict, list, str, or primitive)

    Returns:
        Data structure with account IDs redacted from ARNs
    """
    if isinstance(data, dict):
        return {key: _redact_account_ids_from_arns(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [_redact_account_ids_from_arns(item) for item in data]
    elif isinstance(data, str):
        return re.sub(r'(arn:aws:[^:]+:[^:]*:)(\d{12})(:)', r'\1REDACTED\3', data)
    else:
        return data


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
        {results_base_dir}/{check_type}/{check_name}/{account_name}_{account_id}.json
        or {results_base_dir}/{check_type}/{check_name}/{account_name}.json if exclude_account_ids=True
    """
    results_resolver = ResultFilePathResolver(
        check_name=check_name,
        results_base_dir=results_base_dir,
        account_name=account_name,
        account_id=account_id,
        exclude_account_ids=exclude_account_ids
    )

    results_dir = results_resolver.get_check_directory()
    os.makedirs(results_dir, exist_ok=True)

    output_file = results_resolver.get_file_path()

    # If excluding account IDs, remove account_id from the results data
    # and redact account IDs from ARNs
    data_to_write = results_data
    if exclude_account_ids:
        data_to_write = cast(Dict[str, Any], _redact_account_ids_from_arns(results_data))
        if "summary" in data_to_write:
            data_to_write["summary"] = data_to_write["summary"].copy()
            data_to_write["summary"].pop("account_id", None)

    with open(output_file, 'w') as f:
        json.dump(data_to_write, f, indent=2, default=str)
        f.write('\n')
    logger.info(f"Wrote results to {output_file}")


def get_results_dir(check_name: str, results_base_dir: str) -> str:
    """
    Get the directory path where results for a check should be stored.

    Results are organized by check type (scps/rcps) and then by check name.

    Args:
        check_name: Name of the check (e.g., 'deny_imds_v1_ec2')
        results_base_dir: Base directory for results

    Returns:
        Path to the check's results directory (e.g., '{results_base_dir}/scps/deny_imds_v1_ec2')
    """
    results_resolver = ResultFilePathResolver(
        check_name=check_name,
        results_base_dir=results_base_dir
    )
    return results_resolver.get_check_directory()


def get_results_path(
    check_name: str,
    account_name: str,
    account_id: str,
    results_base_dir: str,
    exclude_account_ids: bool = False,
) -> Path:
    """
    Get the file path where results for a specific account should be written.

    Results are organized by check type, then check name, then account.

    Args:
        check_name: Name of the check (e.g., 'deny_imds_v1_ec2')
        account_name: Account name
        account_id: Account ID
        results_base_dir: Base directory for results
        exclude_account_ids: If True, use only account name in filename

    Returns:
        Path object for the results file (e.g., '{results_base_dir}/scps/deny_imds_v1_ec2/account.json')
    """
    results_resolver = ResultFilePathResolver(
        check_name=check_name,
        results_base_dir=results_base_dir,
        account_name=account_name,
        account_id=account_id,
        exclude_account_ids=exclude_account_ids
    )
    return results_resolver.get_file_path()


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
    results_resolver = ResultFilePathResolver(
        check_name=check_name,
        results_base_dir=results_base_dir,
        account_name=account_name,
        account_id=account_id,
        exclude_account_ids=exclude_account_ids
    )
    return results_resolver.exists()
