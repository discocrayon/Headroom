"""
Regression tests for Terraform SCP module fixtures in test_environment.
"""

from pathlib import Path


def test_scps_module_guards_root_from_leaving_organization() -> None:
    """
    Ensure the SCP module always blocks organizations:LeaveOrganization for root targets.
    """
    locals_path = Path("test_environment/modules/scps/locals.tf")
    locals_content = locals_path.read_text(encoding="utf-8")

    expected_snippet = (
        'include = startswith(var.target_id, "r-"),\n'
        "        statement = {\n"
        '          Action   = "organizations:LeaveOrganization"'
    )
    assert expected_snippet in locals_content
