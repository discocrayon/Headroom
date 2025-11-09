"""Tests for headroom.checks.registry module."""

import pytest
from headroom.checks.registry import (
    get_check_class,
    get_all_check_classes,
    get_check_type_map,
)


class TestGetCheckClass:
    """Test get_check_class function."""

    def test_get_check_class_deny_imds_v1_ec2(self) -> None:
        """Test retrieving DenyImdsV1Ec2Check class."""
        check_class = get_check_class("deny_imds_v1_ec2")
        assert check_class is not None
        assert check_class.CHECK_NAME == "deny_imds_v1_ec2"
        assert check_class.CHECK_TYPE == "scps"

    def test_get_check_class_third_party_assumerole(self) -> None:
        """Test retrieving ThirdPartyAssumeRoleCheck class."""
        check_class = get_check_class("third_party_assumerole")
        assert check_class is not None
        assert check_class.CHECK_NAME == "third_party_assumerole"
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
        assert len(all_checks) == 3
        check_names = {cls.CHECK_NAME for cls in all_checks}
        assert "deny_imds_v1_ec2" in check_names
        assert "deny_iam_user_creation" in check_names
        assert "third_party_assumerole" in check_names

    def test_get_all_check_classes_filter_by_scps(self) -> None:
        """Test getting check classes filtered by scps."""
        scp_checks = get_all_check_classes("scps")
        assert len(scp_checks) == 2
        check_names = {cls.CHECK_NAME for cls in scp_checks}
        assert "deny_imds_v1_ec2" in check_names
        assert "deny_iam_user_creation" in check_names
        for check in scp_checks:
            assert check.CHECK_TYPE == "scps"

    def test_get_all_check_classes_filter_by_rcps(self) -> None:
        """Test getting check classes filtered by rcps."""
        rcp_checks = get_all_check_classes("rcps")
        assert len(rcp_checks) == 1
        assert rcp_checks[0].CHECK_NAME == "third_party_assumerole"
        assert rcp_checks[0].CHECK_TYPE == "rcps"


class TestGetCheckTypeMap:
    """Test get_check_type_map function."""

    def test_get_check_type_map_returns_correct_mapping(self) -> None:
        """Test that get_check_type_map returns correct check name to type mapping."""
        type_map = get_check_type_map()
        assert isinstance(type_map, dict)
        assert type_map["deny_imds_v1_ec2"] == "scps"
        assert type_map["deny_iam_user_creation"] == "scps"
        assert type_map["third_party_assumerole"] == "rcps"
        assert len(type_map) == 3
