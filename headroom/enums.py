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


class AmiOwnerUnknownReason(str, Enum):
    """Reasons an EC2 instance's AMI owner cannot be determined."""
    # DescribeImages does not surface the AMI to this account even when asked
    # for disabled and deprecated images: an Allowed AMIs setting filters it,
    # or it was shared and then unshared.
    NOT_VISIBLE = "not_visible"
    # The AMI ID no longer resolves at all, which is what deregistration leaves
    # behind on a long-lived instance.
    DEREGISTERED = "deregistered"
