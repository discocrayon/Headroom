"""AWS integration library for Headroom security analysis."""

from .iam import (
    InvalidFederatedPrincipalError,
    TrustPolicyAnalysis,
    analyze_iam_roles_trust_policies
)

__all__ = [
    "InvalidFederatedPrincipalError",
    "TrustPolicyAnalysis",
    "analyze_iam_roles_trust_policies"
]
