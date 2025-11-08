"""
Terraform Utility Functions

Shared utility functions used across the Terraform generation modules.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def make_safe_variable_name(name: str) -> str:
    """
    Convert a name to a safe Terraform variable name.

    Args:
        name: Original name

    Returns:
        Safe variable name with special characters replaced
    """
    # Replace spaces and special characters with underscores
    safe_name = name.lower().replace(" ", "_").replace("-", "_")
    # Remove any remaining special characters except underscores
    safe_name = "".join(c if c.isalnum() or c == "_" else "_" for c in safe_name)
    # Remove multiple consecutive underscores
    while "__" in safe_name:
        safe_name = safe_name.replace("__", "_")
    # Remove leading/trailing underscores
    safe_name = safe_name.strip("_")
    # Ensure it starts with a letter
    if safe_name and not safe_name[0].isalpha():
        safe_name = "ou_" + safe_name
    return safe_name


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
