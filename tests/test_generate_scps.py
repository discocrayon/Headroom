"""
Tests for terraform.generate_scps module.

Covers early returns, warnings for missing targets, and name normalization edges.
"""

from pathlib import Path

import pytest

from headroom.types import (
    AccountOrgPlacement,
    OrganizationHierarchy,
    OrganizationalUnit,
    SCPPlacementRecommendations,
)
from headroom.terraform import make_safe_variable_name
from headroom.terraform.generate_scps import (
    _build_scp_terraform_module,
    _generate_account_scp_terraform,
    _generate_ou_scp_terraform,
    _generate_root_scp_terraform,
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


# Tests for _build_scp_terraform_module()
def test_build_scp_terraform_module_single_check_100_percent_compliant() -> None:
    """Should include SCP flag when compliance is 100%."""
    org = make_org_empty()
    rec = SCPPlacementRecommendations(
        check_name="deny-imds-v1-ec2",
        recommended_level="root",
        target_ou_id=None,
        affected_accounts=[],
        compliance_percentage=100.0,
        reasoning="test",
    )
    result = _build_scp_terraform_module(
        module_name="scps_root",
        target_id_reference="local.root_ou_id",
        recommendations=[rec],
        comment="Organization Root",
        organization_hierarchy=org
    )
    assert "deny_imds_v1_ec2 = true" in result
    assert "deny_iam_user_creation = false" in result
    assert "deny_rds_unencrypted = false" in result
    assert "allowed_iam_users" not in result
    assert 'module "scps_root"' in result
    assert "target_id = local.root_ou_id" in result


def test_build_scp_terraform_module_multiple_checks_all_compliant() -> None:
    """Should include all SCP flags when all checks are 100% compliant."""
    org = make_org_empty()
    recs = [
        SCPPlacementRecommendations(
            check_name="deny-imds-v1-ec2",
            recommended_level="root",
            target_ou_id=None,
            affected_accounts=[],
            compliance_percentage=100.0,
            reasoning="test",
        ),
        SCPPlacementRecommendations(
            check_name="deny-iam-user-creation",
            recommended_level="root",
            target_ou_id=None,
            affected_accounts=[],
            compliance_percentage=100.0,
            reasoning="test",
        ),
    ]
    result = _build_scp_terraform_module(
        module_name="scps_test",
        target_id_reference="local.test_id",
        recommendations=recs,
        comment="Test",
        organization_hierarchy=org
    )
    assert "deny_imds_v1_ec2 = true" in result
    assert "deny_iam_user_creation = true" in result
    assert "deny_rds_unencrypted = false" in result
    assert "allowed_iam_users = []" in result


def test_build_scp_terraform_module_with_iam_user_arns() -> None:
    """Should include IAM user ARNs with account ID replaced by local variable reference."""
    org = OrganizationHierarchy(
        root_id="r-root",
        organizational_units={},
        accounts={
            "111111111111": AccountOrgPlacement(
                account_id="111111111111",
                account_name="test-account-1",
                parent_ou_id="ou-test",
                ou_path=["r-root", "ou-test"]
            ),
            "222222222222": AccountOrgPlacement(
                account_id="222222222222",
                account_name="test-account-2",
                parent_ou_id="ou-test",
                ou_path=["r-root", "ou-test"]
            )
        }
    )
    recs = [
        SCPPlacementRecommendations(
            check_name="deny-iam-user-creation",
            recommended_level="root",
            target_ou_id=None,
            affected_accounts=[],
            compliance_percentage=100.0,
            reasoning="test",
            allowed_iam_user_arns=[
                "arn:aws:iam::111111111111:user/terraform-user",
                "arn:aws:iam::222222222222:user/github-actions"
            ]
        ),
    ]
    result = _build_scp_terraform_module(
        module_name="scps_test",
        target_id_reference="local.test_id",
        recommendations=recs,
        comment="Test",
        organization_hierarchy=org
    )
    assert "deny_iam_user_creation = true" in result
    assert "allowed_iam_users = [" in result
    assert '"arn:aws:iam::${local.test_account_1_account_id}:user/terraform-user",' in result
    assert '"arn:aws:iam::${local.test_account_2_account_id}:user/github-actions",' in result


def test_build_scp_terraform_module_with_iam_user_arns_unknown_account() -> None:
    """Should keep ARN unchanged when account ID is not in organization hierarchy."""
    org = OrganizationHierarchy(
        root_id="r-root",
        organizational_units={},
        accounts={
            "111111111111": AccountOrgPlacement(
                account_id="111111111111",
                account_name="test-account-1",
                parent_ou_id="ou-test",
                ou_path=["r-root", "ou-test"]
            )
        }
    )
    recs = [
        SCPPlacementRecommendations(
            check_name="deny-iam-user-creation",
            recommended_level="root",
            target_ou_id=None,
            affected_accounts=[],
            compliance_percentage=100.0,
            reasoning="test",
            allowed_iam_user_arns=[
                "arn:aws:iam::111111111111:user/terraform-user",
                "arn:aws:iam::999999999999:user/unknown-account"
            ]
        ),
    ]
    result = _build_scp_terraform_module(
        module_name="scps_test",
        target_id_reference="local.test_id",
        recommendations=recs,
        comment="Test",
        organization_hierarchy=org
    )
    assert "deny_iam_user_creation = true" in result
    assert "allowed_iam_users = [" in result
    assert '"arn:aws:iam::${local.test_account_1_account_id}:user/terraform-user",' in result
    assert '"arn:aws:iam::999999999999:user/unknown-account",' in result


def test_build_scp_terraform_module_partial_compliance_skips_check() -> None:
    """Should set SCP flag to false when compliance is less than 100%."""
    org = make_org_empty()
    rec = SCPPlacementRecommendations(
        check_name="deny-imds-v1-ec2",
        recommended_level="root",
        target_ou_id=None,
        affected_accounts=[],
        compliance_percentage=80.0,
        reasoning="test",
    )
    result = _build_scp_terraform_module(
        module_name="scps_root",
        target_id_reference="local.root_ou_id",
        recommendations=[rec],
        comment="Organization Root",
        organization_hierarchy=org
    )
    assert "deny_imds_v1_ec2 = false" in result
    assert "deny_iam_user_creation = false" in result
    assert "allowed_iam_users" not in result
    assert 'module "scps_root"' in result


def test_build_scp_terraform_module_mixed_compliance_includes_only_100_percent() -> None:
    """Should only set to true checks that are 100% compliant."""
    org = make_org_empty()
    recs = [
        SCPPlacementRecommendations(
            check_name="deny-imds-v1-ec2",
            recommended_level="root",
            target_ou_id=None,
            affected_accounts=[],
            compliance_percentage=100.0,
            reasoning="test",
        ),
        SCPPlacementRecommendations(
            check_name="deny-iam-user-creation",
            recommended_level="root",
            target_ou_id=None,
            affected_accounts=[],
            compliance_percentage=75.0,
            reasoning="test",
        ),
    ]
    result = _build_scp_terraform_module(
        module_name="scps_root",
        target_id_reference="local.root_ou_id",
        recommendations=recs,
        comment="Organization Root",
        organization_hierarchy=org
    )
    assert "deny_imds_v1_ec2 = true" in result
    assert "deny_iam_user_creation = false" in result
    assert "allowed_iam_users" not in result


def test_build_scp_terraform_module_check_name_with_hyphens_converts_to_underscores() -> None:
    """Should convert hyphens in check names to underscores for Terraform."""
    org = make_org_empty()
    rec = SCPPlacementRecommendations(
        check_name="deny-imds-v1-ec2",
        recommended_level="root",
        target_ou_id=None,
        affected_accounts=[],
        compliance_percentage=100.0,
        reasoning="test",
    )
    result = _build_scp_terraform_module(
        module_name="scps_root",
        target_id_reference="local.root_ou_id",
        recommendations=[rec],
        comment="Organization Root",
        organization_hierarchy=org
    )
    assert "deny_imds_v1_ec2 = true" in result
    assert "deny_iam_user_creation = false" in result
    assert "allowed_iam_users" not in result
    assert "deny-imds-v1-ec2" not in result


# Tests for _generate_account_scp_terraform()
def test_generate_account_scp_terraform_creates_file_with_correct_name() -> None:
    """Should create Terraform file with account name."""
    org = OrganizationHierarchy(
        root_id="r-root",
        organizational_units={},
        accounts={
            "123456789012": AccountOrgPlacement(
                account_id="123456789012",
                account_name="Test Account",
                parent_ou_id="ou-test",
                ou_path=["r-root", "ou-test"]
            )
        }
    )
    rec = SCPPlacementRecommendations(
        check_name="deny-imds-v1-ec2",
        recommended_level="account",
        target_ou_id=None,
        affected_accounts=["123456789012"],
        compliance_percentage=100.0,
        reasoning="test",
    )
    output_path = Path("/tmp/test_scps")
    output_path.mkdir(parents=True, exist_ok=True)

    _generate_account_scp_terraform("123456789012", [rec], org, output_path)

    expected_file = output_path / "test_account_scps.tf"
    assert expected_file.exists()
    content = expected_file.read_text()
    assert "scps_test_account" in content
    assert "local.test_account_account_id" in content
    assert "deny_imds_v1_ec2 = true" in content
    expected_file.unlink()


def test_generate_account_scp_terraform_raises_error_for_missing_account() -> None:
    """Should raise RuntimeError when account is not in organization hierarchy."""
    org = make_org_empty()
    rec = SCPPlacementRecommendations(
        check_name="deny-imds-v1-ec2",
        recommended_level="account",
        target_ou_id=None,
        affected_accounts=["999999999999"],
        compliance_percentage=100.0,
        reasoning="test",
    )
    output_path = Path("/tmp/test_scps")

    with pytest.raises(RuntimeError, match="Account \\(999999999999\\) not found in organization hierarchy"):
        _generate_account_scp_terraform("999999999999", [rec], org, output_path)


# Tests for _generate_ou_scp_terraform()
def test_generate_ou_scp_terraform_creates_file_with_correct_name() -> None:
    """Should create Terraform file with OU name."""
    org = OrganizationHierarchy(
        root_id="r-root",
        organizational_units={
            "ou-test": OrganizationalUnit(
                ou_id="ou-test",
                name="Test OU",
                parent_ou_id="r-root",
                child_ous=[],
                accounts=[]
            )
        },
        accounts={}
    )
    rec = SCPPlacementRecommendations(
        check_name="deny-imds-v1-ec2",
        recommended_level="ou",
        target_ou_id="ou-test",
        affected_accounts=[],
        compliance_percentage=100.0,
        reasoning="test",
    )
    output_path = Path("/tmp/test_scps")
    output_path.mkdir(parents=True, exist_ok=True)

    _generate_ou_scp_terraform("ou-test", [rec], org, output_path)

    expected_file = output_path / "test_ou_ou_scps.tf"
    assert expected_file.exists()
    content = expected_file.read_text()
    assert "scps_test_ou_ou" in content
    assert "local.top_level_test_ou_ou_id" in content
    assert "deny_imds_v1_ec2 = true" in content
    expected_file.unlink()


def test_generate_ou_scp_terraform_raises_error_for_missing_ou() -> None:
    """Should raise RuntimeError when OU is not in organization hierarchy."""
    org = make_org_empty()
    rec = SCPPlacementRecommendations(
        check_name="deny-imds-v1-ec2",
        recommended_level="ou",
        target_ou_id="ou-missing",
        affected_accounts=[],
        compliance_percentage=100.0,
        reasoning="test",
    )
    output_path = Path("/tmp/test_scps")

    with pytest.raises(RuntimeError, match="OU ou-missing not found in organization hierarchy"):
        _generate_ou_scp_terraform("ou-missing", [rec], org, output_path)


# Tests for _generate_root_scp_terraform()
def test_generate_root_scp_terraform_creates_file() -> None:
    """Should create root_scps.tf file with correct content."""
    org = make_org_empty()
    rec = SCPPlacementRecommendations(
        check_name="deny-imds-v1-ec2",
        recommended_level="root",
        target_ou_id=None,
        affected_accounts=[],
        compliance_percentage=100.0,
        reasoning="test",
    )
    output_path = Path("/tmp/test_scps")
    output_path.mkdir(parents=True, exist_ok=True)

    _generate_root_scp_terraform([rec], org, output_path)

    expected_file = output_path / "root_scps.tf"
    assert expected_file.exists()
    content = expected_file.read_text()
    assert "scps_root" in content
    assert "local.root_ou_id" in content
    assert "deny_imds_v1_ec2 = true" in content
    expected_file.unlink()


def test_generate_root_scp_terraform_no_recommendations_returns_early() -> None:
    """Should return early and not create file when no recommendations."""
    org = make_org_empty()
    output_path = Path("/tmp/test_scps")
    output_path.mkdir(parents=True, exist_ok=True)

    _generate_root_scp_terraform([], org, output_path)

    expected_file = output_path / "root_scps.tf"
    assert not expected_file.exists()


def test_generate_root_scp_terraform_multiple_checks() -> None:
    """Should include all checks in root_scps.tf."""
    org = make_org_empty()
    recs = [
        SCPPlacementRecommendations(
            check_name="deny-imds-v1-ec2",
            recommended_level="root",
            target_ou_id=None,
            affected_accounts=[],
            compliance_percentage=100.0,
            reasoning="test",
        ),
        SCPPlacementRecommendations(
            check_name="deny-iam-user-creation",
            recommended_level="root",
            target_ou_id=None,
            affected_accounts=[],
            compliance_percentage=100.0,
            reasoning="test",
        ),
    ]
    output_path = Path("/tmp/test_scps")
    output_path.mkdir(parents=True, exist_ok=True)

    _generate_root_scp_terraform(recs, org, output_path)

    expected_file = output_path / "root_scps.tf"
    content = expected_file.read_text()
    assert "deny_imds_v1_ec2 = true" in content
    assert "deny_iam_user_creation = true" in content
    assert "deny_rds_unencrypted = false" in content
    assert "allowed_iam_users = []" in content
    expected_file.unlink()


def test_build_scp_terraform_module_with_rds_check_enabled() -> None:
    """Should include deny_rds_unencrypted flag when check is enabled."""
    org = make_org_empty()
    rec = SCPPlacementRecommendations(
        check_name="deny-rds-unencrypted",
        recommended_level="root",
        target_ou_id=None,
        affected_accounts=[],
        compliance_percentage=100.0,
        reasoning="test",
    )
    result = _build_scp_terraform_module(
        module_name="scps_root",
        target_id_reference="local.root_ou_id",
        recommendations=[rec],
        comment="Organization Root",
        organization_hierarchy=org
    )
    assert "deny_imds_v1_ec2 = false" in result
    assert "deny_iam_user_creation = false" in result
    assert "deny_rds_unencrypted = true" in result
    assert "allowed_iam_users" not in result


def test_build_scp_terraform_module_with_ec2_ami_owner_check_with_allowed_owners() -> None:
    """Should include allowed_ami_owners when deny_ec2_ami_owner is enabled."""
    org = make_org_empty()
    rec = SCPPlacementRecommendations(
        check_name="deny-ec2-ami-owner",
        recommended_level="root",
        target_ou_id=None,
        affected_accounts=[],
        compliance_percentage=100.0,
        reasoning="test",
        allowed_ami_owners=["amazon", "aws-marketplace"]
    )
    result = _build_scp_terraform_module(
        module_name="scps_root",
        target_id_reference="local.root_ou_id",
        recommendations=[rec],
        comment="Organization Root",
        organization_hierarchy=org
    )
    assert "deny_ec2_ami_owner = true" in result
    assert '"amazon"' in result
    assert '"aws-marketplace"' in result
    assert "allowed_ami_owners = [" in result


def test_build_scp_terraform_module_with_ec2_ami_owner_check_without_allowed_owners() -> None:
    """Should include empty allowed_ami_owners when deny_ec2_ami_owner is enabled without owners."""
    org = make_org_empty()
    rec = SCPPlacementRecommendations(
        check_name="deny-ec2-ami-owner",
        recommended_level="root",
        target_ou_id=None,
        affected_accounts=[],
        compliance_percentage=100.0,
        reasoning="test",
    )
    result = _build_scp_terraform_module(
        module_name="scps_root",
        target_id_reference="local.root_ou_id",
        recommendations=[rec],
        comment="Organization Root",
        organization_hierarchy=org
    )
    assert "deny_ec2_ami_owner = true" in result
    assert "allowed_ami_owners = []" in result
