"""AWS integration library for Headroom security analysis."""

from .iam import (
    UnknownPrincipalTypeError,
    InvalidFederatedPrincipalError,
    TrustPolicyAnalysis,
    analyze_iam_roles_trust_policies
)

__all__ = [
    "UnknownPrincipalTypeError",
    "InvalidFederatedPrincipalError",
    "TrustPolicyAnalysis",
    "analyze_iam_roles_trust_policies"
]
