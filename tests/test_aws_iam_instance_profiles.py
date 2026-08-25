"""
Tests for headroom.aws.iam.instance_profiles.

The deny_ec2_imds_v1 SCP exempts by role tag, so these tests pin the
instance-profile-to-role-tags resolution the exemption check depends on.
"""

from typing import Any, Dict, List, Optional

import pytest
from botocore.exceptions import ClientError
from unittest.mock import MagicMock

from headroom.aws.iam.instance_profiles import (
    ResolvedInstanceRole,
    resolve_instance_profile_role,
)
from headroom.enums import InstanceRoleUnresolvedReason

PROFILE_ARN = "arn:aws:iam::111111111111:instance-profile/app-server"
ROLE_ARN = "arn:aws:iam::111111111111:role/app-server-role"


def _client(
    profile_roles: Optional[List[Dict[str, Any]]] = None,
    role_tags: Optional[List[Dict[str, str]]] = None,
    profile_error: Optional[str] = None,
    role_error: Optional[str] = None,
) -> MagicMock:
    """Build an IAM client mock for one profile and its role."""
    client = MagicMock()

    if profile_error:
        client.get_instance_profile.side_effect = ClientError(
            {"Error": {"Code": profile_error, "Message": "x"}}, "GetInstanceProfile"
        )
    else:
        roles = [{"RoleName": "app-server-role", "Arn": ROLE_ARN}] \
            if profile_roles is None else profile_roles
        client.get_instance_profile.return_value = {
            "InstanceProfile": {"Arn": PROFILE_ARN, "Roles": roles}
        }

    if role_error:
        client.get_role.side_effect = ClientError(
            {"Error": {"Code": role_error, "Message": "x"}}, "GetRole"
        )
    else:
        client.get_role.return_value = {
            "Role": {"Arn": ROLE_ARN, "Tags": role_tags or []}
        }

    return client


class TestResolveInstanceProfileRole:
    """Resolution of an instance profile to its role's tags."""

    def test_returns_role_arn_and_tags(self) -> None:
        """A profile with a role returns that role's ARN and tags."""
        client = _client(role_tags=[{"Key": "ExemptFromIMDSv2", "Value": "true"}])

        resolved = resolve_instance_profile_role(client, PROFILE_ARN)

        assert resolved == ResolvedInstanceRole(
            role_arn=ROLE_ARN,
            tags={"ExemptFromIMDSv2": "true"},
            unresolved_reason=None,
        )

    def test_looks_up_profile_by_name_not_arn(self) -> None:
        """GetInstanceProfile takes the profile name, which the ARN carries last."""
        client = _client()

        resolve_instance_profile_role(
            client, "arn:aws:iam::111111111111:instance-profile/eng/team/app-server"
        )

        client.get_instance_profile.assert_called_once_with(
            InstanceProfileName="app-server"
        )

    def test_reads_tags_from_get_role_not_the_embedded_role(self) -> None:
        """
        Tags come from GetRole.

        The role embedded in a GetInstanceProfile response declares Tags as
        optional and AWS does not promise to populate it, so trusting it would
        read an untagged role as unexempt whenever AWS omits the field.
        """
        client = _client(
            profile_roles=[{
                "RoleName": "app-server-role",
                "Arn": ROLE_ARN,
                "Tags": [{"Key": "ExemptFromIMDSv2", "Value": "true"}],
            }],
            role_tags=[],
        )

        resolved = resolve_instance_profile_role(client, PROFILE_ARN)

        client.get_role.assert_called_once_with(RoleName="app-server-role")
        assert resolved.tags == {}

    def test_missing_profile_is_reported_not_raised(self) -> None:
        """A profile deleted mid-scan is a data condition, not a run-ending error."""
        client = _client(profile_error="NoSuchEntity")

        resolved = resolve_instance_profile_role(client, PROFILE_ARN)

        assert resolved.role_arn is None
        assert resolved.tags == {}
        assert resolved.unresolved_reason == InstanceRoleUnresolvedReason.PROFILE_NOT_FOUND.value

    def test_missing_role_is_reported_not_raised(self) -> None:
        """A role deleted between the two calls is reported the same way."""
        client = _client(role_error="NoSuchEntity")

        resolved = resolve_instance_profile_role(client, PROFILE_ARN)

        assert resolved.role_arn is None
        assert resolved.unresolved_reason == InstanceRoleUnresolvedReason.ROLE_NOT_FOUND.value

    def test_profile_with_no_roles_is_reported(self) -> None:
        """An instance profile can exist with no role attached."""
        client = _client(profile_roles=[])

        resolved = resolve_instance_profile_role(client, PROFILE_ARN)

        assert resolved.role_arn is None
        assert resolved.unresolved_reason == InstanceRoleUnresolvedReason.PROFILE_HAS_NO_ROLE.value

    @pytest.mark.parametrize("operation", ["get_instance_profile", "get_role"])
    def test_other_client_errors_propagate(self, operation: str) -> None:
        """
        AccessDenied must not read as an unexempt role.

        Swallowing it would turn a missing permission into a fleet-wide set of
        violations that look like real findings.
        """
        client = (
            _client(profile_error="AccessDenied")
            if operation == "get_instance_profile"
            else _client(role_error="AccessDenied")
        )

        with pytest.raises(ClientError):
            resolve_instance_profile_role(client, PROFILE_ARN)
