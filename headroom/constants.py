"""
Constants module for check names and type mappings.

This module serves as the single source of truth for all check-related
constants used throughout the Headroom codebase.
"""

# Check name constants
DENY_IMDS_V1_EC2 = "deny_imds_v1_ec2"
THIRD_PARTY_ASSUMEROLE = "third_party_assumerole"

# Map check names to their types (scp or rcp)
CHECK_TYPE_MAP = {
    DENY_IMDS_V1_EC2: "scps",
    THIRD_PARTY_ASSUMEROLE: "rcps",
}

# Derived sets for convenience
SCP_CHECK_NAMES = {name for name, check_type in CHECK_TYPE_MAP.items() if check_type == "scps"}
RCP_CHECK_NAMES = {name for name, check_type in CHECK_TYPE_MAP.items() if check_type == "rcps"}
