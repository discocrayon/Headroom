"""
Terraform Utility Functions

Shared utility functions used across the Terraform generation modules.
"""

import logging
from pathlib import Path

from ..utils import make_safe_variable_name

logger = logging.getLogger(__name__)

__all__ = ["make_safe_variable_name", "write_terraform_file"]


def write_terraform_file(filepath: Path, content: str, policy_type: str) -> None:
    """
    Write Terraform content to a file with logging.

    Args:
        filepath: Path object for the file to write
        content: Terraform content to write
        policy_type: Type of policy being written (e.g., "SCP", "RCP")
    """
    with open(filepath, 'w') as f:
        f.write(content)
    logger.info(f"Generated {policy_type} Terraform file: {filepath}")
