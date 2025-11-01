"""
Tests for terraform.generate_scps module.

Covers early returns, warnings for missing targets, and name normalization edges.
"""

from pathlib import Path

import pytest

from headroom.types import (
    OrganizationHierarchy,
    SCPPlacementRecommendations,
)
from headroom.terraform import make_safe_variable_name
from headroom.terraform.generate_scps import (
    generate_scp_terraform,
)


def make_org_empty() -> OrganizationHierarchy:
    return OrganizationHierarchy(root_id="r-root", organizational_units={}, accounts={})


def test_generate_scp_terraform_no_recommendations(tmp_path: Path) -> None:
    org = make_org_empty()

    generate_scp_terraform([], org, str(tmp_path))
    assert not any(tmp_path.iterdir())


def test_generate_scp_terraform_warn_missing_account(tmp_path: Path) -> None:
    org = make_org_empty()
    rec = SCPPlacementRecommendations(
        check_name="deny-imds-v1-ec2",
        recommended_level="account",
        target_ou_id=None,
        affected_accounts=["999999999999"],
        compliance_percentage=100.0,
        reasoning="test",
    )

    # Should raise exception for missing account
    with pytest.raises(RuntimeError, match="Account \\(999999999999\\) not found in organization hierarchy"):
        generate_scp_terraform([rec], org, str(tmp_path))


def test_generate_scp_terraform_warn_missing_ou(tmp_path: Path) -> None:
    org = make_org_empty()
    rec = SCPPlacementRecommendations(
        check_name="deny-imds-v1-ec2",
        recommended_level="ou",
        target_ou_id="ou-unknown",
        affected_accounts=[],
        compliance_percentage=100.0,
        reasoning="test",
    )

    # Should raise exception for missing OU
    with pytest.raises(RuntimeError, match="OU ou-unknown not found in organization hierarchy"):
        generate_scp_terraform([rec], org, str(tmp_path))


def test_make_safe_variable_name_edge_cases() -> None:
    assert make_safe_variable_name("My  Name--X") == "my_name_x"
    assert make_safe_variable_name("a__b---c  d") == "a_b_c_d"
    # Starts with digit -> prefixed
    assert make_safe_variable_name("123bad-name") == "ou_123bad_name"
