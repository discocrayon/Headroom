"""
Utility functions used across the Headroom codebase.

This module contains general-purpose utility functions that are used
by multiple modules throughout the application.
"""


def format_account_identifier(account_name: str, account_id: str) -> str:
    """
    Format a consistent account identifier string.

    Args:
        account_name: Account name
        account_id: Account ID

    Returns:
        Formatted identifier string in format: name_id
    """
    return f"{account_name}_{account_id}"


def make_safe_variable_name(name: str) -> str:
    """
    Convert a name to a safe Terraform variable name.

    Replaces spaces and special characters with underscores, ensures the name
    starts with a letter, and removes consecutive underscores.

    Args:
        name: Original name (e.g., "My Account-123")

    Returns:
        Safe variable name (e.g., "my_account_123")
    """
    safe_name = name.lower().replace(" ", "_").replace("-", "_")
    safe_name = "".join(c if c.isalnum() or c == "_" else "_" for c in safe_name)
    while "__" in safe_name:
        safe_name = safe_name.replace("__", "_")
    safe_name = safe_name.strip("_")
    if safe_name and not safe_name[0].isalpha():
        safe_name = "ou_" + safe_name
    return safe_name
