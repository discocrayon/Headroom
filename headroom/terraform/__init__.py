"""
Terraform Generation Module

This module contains all Terraform generation functionality for Headroom.
It provides clean separation between analysis/parsing logic and infrastructure
code generation.

Modules:
- generate_org_info: Generates Terraform data sources for AWS Organizations structure
- generate_scp: Generates Terraform configurations for SCP deployment
"""

from .generate_org_info import generate_terraform_org_info
from .generate_scps import generate_scp_terraform

__all__ = [
    "generate_terraform_org_info",
    "generate_scp_terraform",
]
