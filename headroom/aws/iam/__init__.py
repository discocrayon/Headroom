"""
AWS IAM analysis module.

This module provides functions for analyzing IAM resources:
- Trust policy analysis for IAM roles (RCP checks)
- User enumeration for IAM users (SCP checks)
- SAML provider enumeration for AWS SSO guardrails (SCP checks)
- Instance profile role resolution for EC2 instances (SCP checks)
"""

# Trust policy analysis (RCP checks)
from .roles import (
    InvalidFederatedPrincipalError,
    MalformedStatementError,
    TrustPolicyAnalysis,
    UnknownPrincipalTypeError,
    analyze_iam_roles_trust_policies,
)

# Instance profile role resolution (SCP checks)
from .instance_profiles import (
    ResolvedInstanceRole,
    resolve_instance_profile_role,
    unresolved_instance_role,
)

# User enumeration (SCP checks)
from .users import (
    IamUserAnalysis,
    get_iam_users_analysis,
)

# SAML provider enumeration (SCP checks)
from .saml_providers import (
    SamlProviderAnalysis,
    get_saml_providers_analysis,
)

__all__ = [
    # Roles (RCP)
    "TrustPolicyAnalysis",
    "UnknownPrincipalTypeError",
    "InvalidFederatedPrincipalError",
    "MalformedStatementError",
    "analyze_iam_roles_trust_policies",
    # Instance profiles (SCP)
    "ResolvedInstanceRole",
    "resolve_instance_profile_role",
    "unresolved_instance_role",
    # Users (SCP)
    "IamUserAnalysis",
    "get_iam_users_analysis",
    # SAML providers (SCP)
    "SamlProviderAnalysis",
    "get_saml_providers_analysis",
]
