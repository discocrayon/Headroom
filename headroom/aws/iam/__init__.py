"""
AWS IAM analysis module.

This module provides functions for analyzing IAM resources:
- Trust policy analysis for IAM roles (RCP checks)
- User enumeration for IAM users (SCP checks)
"""

# Trust policy analysis (RCP checks)
from .roles import (
    InvalidFederatedPrincipalError,
    TrustPolicyAnalysis,
    UnknownPrincipalTypeError,
    analyze_iam_roles_trust_policies,
)

# User enumeration (SCP checks)
from .users import (
    IamUserAnalysis,
    get_iam_users_analysis,
)

__all__ = [
    # Roles (RCP)
    "TrustPolicyAnalysis",
    "UnknownPrincipalTypeError",
    "InvalidFederatedPrincipalError",
    "analyze_iam_roles_trust_policies",
    # Users (SCP)
    "IamUserAnalysis",
    "get_iam_users_analysis",
]
