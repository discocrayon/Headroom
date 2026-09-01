"""
Utility functions used across the Headroom codebase.

This module contains general-purpose utility functions that are used
by multiple modules throughout the application.
"""

from pathlib import Path


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


def delete_and_rerun_remedy(result_file: Path, check_name: str) -> str:
    """
    Name the one action that makes a stale result file regenerate.

    `results_exist` makes a check skip any account whose result file is
    already present, so an instruction to re-run without deleting the file
    repeats the same failure. Both result readers prescribe this remedy, so
    both build the sentence here rather than wording it twice.

    Args:
        result_file: The result file the caller could not use
        check_name: Check whose skip must be cleared

    ResultFilePathResolver.exists() accepts either filename format, so
    naming only the file the reader tripped on can send an operator round the
    same loop. The sentence names the directory for the other form.

    Returns:
        The remedy sentence, for appending to a reader's error
    """
    return (
        f"Delete {result_file} and re-run: the {check_name} check skips any "
        f"account whose result file already exists, so re-running without "
        f"deleting it changes nothing. The skip matches both filename "
        f"formats, with and without the account ID, so if the account still "
        f"skips, delete the other form of its name in {result_file.parent} "
        f"too."
    )
