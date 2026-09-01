"""
Terraform Generation Module

This module contains all Terraform generation functionality for Headroom.
It provides clean separation between analysis/parsing logic and infrastructure
code generation.

Modules:
- generate_org_info, generate_scps, generate_rcps: render Terraform content
  for the organization data sources, the SCPs, and the RCPs. Each returns
  what it rendered and writes nothing.
- plan: merges the three into one validated whole-run TerraformPlan
- apply: the only code in Headroom that writes, links, or deletes Terraform
"""

from .apply import apply_terraform_plan
from .generate_org_info import render_terraform_org_info
from .generate_rcps import render_rcp_terraform
from .generate_scps import render_scp_terraform
from .plan import compile_terraform_plan
from .utils import make_safe_variable_name

__all__ = [
    "apply_terraform_plan",
    "compile_terraform_plan",
    "make_safe_variable_name",
    "render_rcp_terraform",
    "render_scp_terraform",
    "render_terraform_org_info",
]
