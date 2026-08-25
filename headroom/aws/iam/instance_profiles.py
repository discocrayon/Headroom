"""
Resolve the IAM role an EC2 instance runs as, and read that role's tags.

The deny_ec2_imds_v1 SCP exempts callers by role tag - its DenyRoleDelivery
statement tests `aws:PrincipalTag/ExemptFromIMDSv2` - so deciding whether that
SCP is safe to attach means reading tags off the role behind an instance's
instance profile. Tags on the instance itself are a different dimension that
no statement in that policy reads.
"""

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

from botocore.exceptions import ClientError
from mypy_boto3_iam.client import IAMClient
from mypy_boto3_iam.type_defs import TagTypeDef

from ...enums import InstanceRoleUnresolvedReason

logger = logging.getLogger(__name__)

# IAM's error code for a named entity that does not exist. Both calls in this
# module can hit it: an instance profile or a role can be deleted between
# describing the instance and looking the role up.
NO_SUCH_ENTITY_ERROR_CODE = "NoSuchEntity"


@dataclass
class ResolvedInstanceRole:
    """
    Outcome of resolving the IAM role behind an EC2 instance profile.

    Either `role_arn` is populated and `tags` holds that role's tags, or
    `unresolved_reason` records why no role could be reached and `tags` is
    empty. An empty `tags` on a resolved role means the role genuinely carries
    no tags; the two states are distinguished by `role_arn`.
    """
    role_arn: Optional[str]
    tags: Dict[str, str]
    unresolved_reason: Optional[str]


def unresolved_instance_role(
    reason: InstanceRoleUnresolvedReason
) -> ResolvedInstanceRole:
    """Build the empty result carrying why the role could not be reached."""
    return ResolvedInstanceRole(role_arn=None, tags={}, unresolved_reason=reason.value)


def _is_no_such_entity(error: ClientError) -> bool:
    """Report whether a ClientError is IAM's missing-entity error."""
    return error.response['Error']['Code'] == NO_SUCH_ENTITY_ERROR_CODE


def _tags_to_dict(tags: List[TagTypeDef]) -> Dict[str, str]:
    """Flatten IAM's list-of-pairs tag shape into a mapping."""
    return {tag['Key']: tag['Value'] for tag in tags}


def resolve_instance_profile_role(
    iam_client: IAMClient,
    instance_profile_arn: str,
) -> ResolvedInstanceRole:
    """
    Resolve an instance profile to its role's tags.

    Tags are read with GetRole rather than taken from the role embedded in the
    GetInstanceProfile response. That embedded role declares Tags as optional
    and AWS documents its resource-listing operations as omitting tags, so
    trusting it would silently read a tagged role as untagged - which for an
    exemption check means reporting a violation that enforcement would not
    produce.

    A profile or role that has been deleted is reported rather than raised.
    An instance outlives neither for long, but a scan sweeping every region of
    every account will meet one eventually, and aborting the run over a single
    torn-down instance would strand every account queued behind it. Any other
    ClientError propagates: AccessDenied in particular must not be mistaken for
    an unexempt role, because that turns one missing permission into a fleet of
    violations that look like real findings.

    Args:
        iam_client: IAM client for the account being analyzed
        instance_profile_arn: ARN of the instance profile attached to the
            instance, as `describe_instances` reports it

    Returns:
        The role's ARN and tags, or the reason no role could be reached

    Raises:
        ClientError: If IAM fails for any reason other than a missing entity
    """
    # The profile name is the last ARN segment; the segments before it are the
    # IAM path, which GetInstanceProfile does not take.
    profile_name = instance_profile_arn.rsplit('/', 1)[-1]

    try:
        profile = iam_client.get_instance_profile(
            InstanceProfileName=profile_name
        )['InstanceProfile']
    except ClientError as e:
        if not _is_no_such_entity(e):
            raise
        logger.warning(
            f"Instance profile {profile_name} no longer exists, so the role "
            f"behind it cannot be checked for an exemption tag. It was deleted "
            f"while an instance was still using it."
        )
        return unresolved_instance_role(InstanceRoleUnresolvedReason.PROFILE_NOT_FOUND)

    roles = profile['Roles']
    if not roles:
        logger.warning(
            f"Instance profile {profile_name} carries no role, so no role tag "
            f"can exempt the instances using it."
        )
        return unresolved_instance_role(InstanceRoleUnresolvedReason.PROFILE_HAS_NO_ROLE)

    # An instance profile can hold exactly one role, so the first is the only.
    role_name = roles[0]['RoleName']

    try:
        role = iam_client.get_role(RoleName=role_name)['Role']
    except ClientError as e:
        if not _is_no_such_entity(e):
            raise
        logger.warning(
            f"Role {role_name}, named by instance profile {profile_name}, no "
            f"longer exists, so its tags cannot be read."
        )
        return unresolved_instance_role(InstanceRoleUnresolvedReason.ROLE_NOT_FOUND)

    return ResolvedInstanceRole(
        role_arn=role['Arn'],
        tags=_tags_to_dict(role.get('Tags', [])),
        unresolved_reason=None,
    )
