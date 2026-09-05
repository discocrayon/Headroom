"""
Terraform Generation Module

This module contains all Terraform generation functionality for Headroom.
It provides clean separation between analysis/parsing logic and infrastructure
code generation.

Modules:
- generate_org_info, generate_scps, generate_rcps: render Terraform content
  for the organization data sources, the SCPs, and the RCPs. Each returns
  what it rendered and writes nothing.
- parameters: the one renderer both policy generators call for a module
  call's check booleans and allowlists
- disabled_reasons: says, for one target, why each check rendering false
  is false, from the placements and the coverage map
- models: the elements the renderers emit - parameters, comments, module
  calls - with HCL escaping and comment wrapping
- utils: the Terraform identifiers that name each OU and account, and the
  path a rendered file claims in the plan
- plan: merges the three renderers' output into one validated whole-run
  TerraformPlan
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
