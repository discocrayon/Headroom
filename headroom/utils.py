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
