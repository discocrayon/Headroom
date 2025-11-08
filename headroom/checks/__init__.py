"""
Compliance checks for Headroom security analysis.

Imports all check modules to ensure they register themselves via the
@register_check decorator.
"""

from .scps import deny_imds_v1_ec2
from .rcps import check_third_party_assumerole

# Import modules to trigger registration
# Check classes are accessed via registry, not direct imports
__all__ = []
