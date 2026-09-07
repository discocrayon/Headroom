"""
Centralized output handling with consistent formatting.

This module provides a single point of control for all user-facing output,
ensuring consistent formatting and making it easy to modify output behavior.
"""

import json
import logging
from typing import Dict, Optional

from .types import JsonDict

logger = logging.getLogger(__name__)


class OutputHandler:
    """Centralized output handling with consistent formatting."""

    @staticmethod
    def check_completed(check_name: str, account: str, stats: Dict[str, int]) -> None:
        """
        Log check completion with statistics.

        Args:
            check_name: Name of the check
            account: Account identifier
            stats: Dictionary with 'violations', 'exemptions', 'compliant' keys
        """
        logger.info(
            f"{check_name} completed for {account}: "
            f"{stats.get('violations', 0)} violations, "
            f"{stats.get('exemptions', 0)} exemptions, "
            f"{stats.get('compliant', 0)} compliant"
        )

    @staticmethod
    def error(title: str, error: Exception) -> None:
        """
        Print formatted error message.

        Args:
            title: Error title
            error: Exception that occurred
        """
        print(f"\n🚨 {title}:\n{error}\n")

    @staticmethod
    def success(title: str, data: Optional[JsonDict] = None) -> None:
        """
        Print formatted success message.

        Args:
            title: Success message title
            data: Optional dictionary to display, JSON formatted
        """
        print(f"\n✅ {title}")
        if not data:
            return

        print(json.dumps(data, indent=2, default=str))

    @staticmethod
    def section_header(title: str) -> None:
        """
        Print section header with divider.

        Args:
            title: Section title
        """
        print("\n" + "=" * 80)
        print(title)
        print("=" * 80)
