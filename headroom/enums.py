"""
Enumerations for Headroom application.

This module contains all enum types used throughout the application
to replace magic strings and improve type safety.
"""

from enum import Enum


class CheckType(str, Enum):
    """Types of compliance checks."""
    SCPS = "scps"
    RCPS = "rcps"


class PlacementLevel(str, Enum):
    """Policy placement levels in organization hierarchy."""
    ROOT = "root"
    OU = "ou"
    ACCOUNT = "account"
    NONE = "none"


class CheckCategory(str, Enum):
    """Categorization of check results."""
    VIOLATION = "violation"
    EXEMPTION = "exemption"
    COMPLIANT = "compliant"
