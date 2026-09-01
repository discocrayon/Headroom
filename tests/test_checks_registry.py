"""Tests for headroom.checks.registry module."""

import pytest
from headroom.checks.registry import (
    _CHECK_REGISTRY,
    get_check_class,
    get_all_check_classes,
    get_check_names,
    get_check_type_map,
)


class TestGetCheckClass:
    """Test get_check_class function."""

    def test_get_check_class_deny_ec2_imds_v1(self) -> None:
        """Test retrieving DenyEc2ImdsV1Check class."""
        check_class = get_check_class("deny_ec2_imds_v1")
        assert check_class is not None
        assert check_class.CHECK_NAME == "deny_ec2_imds_v1"
        assert check_class.CHECK_TYPE == "scps"

    def test_get_check_class_deny_sts_third_party_assumerole(self) -> None:
        """Test retrieving ThirdPartyAssumeRoleCheck class."""
        check_class = get_check_class("deny_sts_third_party_assumerole")
        assert check_class is not None
        assert check_class.CHECK_NAME == "deny_sts_third_party_assumerole"
        assert check_class.CHECK_TYPE == "rcps"

    def test_get_check_class_unknown_raises_value_error(self) -> None:
        """Test that unknown check name raises ValueError."""
        with pytest.raises(ValueError, match="Unknown check: nonexistent_check"):
            get_check_class("nonexistent_check")


class TestGetAllCheckClasses:
    """Test get_all_check_classes function."""

    def test_get_all_check_classes_no_filter(self) -> None:
        """Test getting all check classes without filter."""
        all_checks = get_all_check_classes()
        assert len(all_checks) == 16
        check_names = {cls.CHECK_NAME for cls in all_checks}
        assert "deny_ec2_imds_v1" in check_names
        assert "deny_ec2_imds_hop_limit" in check_names
        assert "deny_ec2_ami_owner" in check_names
        assert "deny_ec2_public_ip" in check_names
        assert "deny_eks_create_cluster_without_tag" in check_names
        assert "deny_iam_user_creation" in check_names
        assert "deny_lambda_auth_type_none" in check_names
        assert "deny_rds_unencrypted" in check_names
        assert "deny_iam_saml_provider_not_aws_sso" in check_names
        assert "deny_ecr_third_party_access" in check_names
        assert "deny_sts_third_party_assumerole" in check_names
        assert "deny_s3_third_party_access" in check_names
        assert "deny_secrets_manager_third_party_access" in check_names
        assert "deny_sqs_third_party_access" in check_names

    def test_get_all_check_classes_filter_by_scps(self) -> None:
        """Test getting check classes filtered by scps."""
        scp_checks = get_all_check_classes("scps")
        assert len(scp_checks) == 9
        check_names = {cls.CHECK_NAME for cls in scp_checks}
        assert "deny_ec2_imds_v1" in check_names
        assert "deny_ec2_imds_hop_limit" in check_names
        assert "deny_ec2_ami_owner" in check_names
        assert "deny_ec2_public_ip" in check_names
        assert "deny_eks_create_cluster_without_tag" in check_names
        assert "deny_iam_user_creation" in check_names
        assert "deny_lambda_auth_type_none" in check_names
        assert "deny_rds_unencrypted" in check_names
        assert "deny_iam_saml_provider_not_aws_sso" in check_names
        for check in scp_checks:
            assert check.CHECK_TYPE == "scps"

    def test_get_all_check_classes_filter_by_rcps(self) -> None:
        """Test getting check classes filtered by rcps."""
        rcp_checks = get_all_check_classes("rcps")
        assert len(rcp_checks) == 7
        check_names = {cls.CHECK_NAME for cls in rcp_checks}
        assert "deny_sts_third_party_assumerole" in check_names
        assert "deny_s3_third_party_access" in check_names
        assert "deny_ecr_third_party_access" in check_names
        assert "deny_secrets_manager_third_party_access" in check_names
        assert "deny_sqs_third_party_access" in check_names
        for check in rcp_checks:
            assert check.CHECK_TYPE == "rcps"


class TestGetCheckTypeMap:
    """Test get_check_type_map function."""

    def test_get_check_type_map_returns_correct_mapping(self) -> None:
        """Test that get_check_type_map returns correct check name to type mapping."""
        type_map = get_check_type_map()
        assert isinstance(type_map, dict)
        assert type_map["deny_ec2_imds_v1"] == "scps"
        assert type_map["deny_ec2_ami_owner"] == "scps"
        assert type_map["deny_ec2_imds_hop_limit"] == "scps"
        assert type_map["deny_ec2_public_ip"] == "scps"
        assert type_map["deny_eks_create_cluster_without_tag"] == "scps"
        assert type_map["deny_iam_user_creation"] == "scps"
        assert type_map["deny_lambda_auth_type_none"] == "scps"
        assert type_map["deny_rds_unencrypted"] == "scps"
        assert type_map["deny_iam_saml_provider_not_aws_sso"] == "scps"
        assert type_map["deny_ecr_third_party_access"] == "rcps"
        assert type_map["deny_kms_third_party_access"] == "rcps"
        assert type_map["deny_sts_third_party_assumerole"] == "rcps"
        assert type_map["deny_s3_third_party_access"] == "rcps"
        assert type_map["deny_secrets_manager_third_party_access"] == "rcps"
        assert type_map["deny_sqs_third_party_access"] == "rcps"
        assert type_map["deny_service_confused_deputy"] == "rcps"
        assert len(type_map) == 16


def test_every_registry_key_matches_its_class_check_name() -> None:
    """
    The decorator's key and the class attribute must agree.

    @register_check keys the registry by its check_name argument, while
    get_check_names reads CHECK_NAME off the class. A check whose two names
    differ is listed under one and retrievable only under the other, so
    get_check_class(name) raises for a name get_check_names just returned.
    """
    mismatched = {
        key: cls.CHECK_NAME
        for key, cls in _CHECK_REGISTRY.items()
        if key != cls.CHECK_NAME
    }

    assert mismatched == {}


def test_every_listed_check_name_is_retrievable() -> None:
    """The two registry projections must round trip."""
    for check_name in get_check_names():
        assert get_check_class(check_name).CHECK_NAME == check_name
