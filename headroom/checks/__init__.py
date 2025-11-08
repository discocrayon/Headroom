"""
Compliance checks for Headroom security analysis.

Imports all check modules to ensure they register themselves via the
@register_check decorator.
"""

# These imports are required to trigger decorator execution and register checks.
# The @register_check decorator only runs when the module is imported, so without
# these imports, the checks would never register themselves in _CHECK_REGISTRY.
from .rcps import check_third_party_assumerole  # noqa: F401
from .scps import deny_imds_v1_ec2  # noqa: F401

# Check classes are accessed via registry, not direct imports
__all__ = []
