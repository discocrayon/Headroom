"""EC2-related security analysis functions for Headroom."""

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_ec2.client import EC2Client
from mypy_boto3_ec2.type_defs import ImageTypeDef
from mypy_boto3_iam.client import IAMClient

from ..constants import IMDS_EXEMPTION_TAG_KEY, IMDS_EXEMPTION_TAG_VALUE
from ..enums import AmiOwnerUnknownReason, InstanceRoleUnresolvedReason
from .helpers import get_all_regions
from .iam.instance_profiles import (
    ResolvedInstanceRole,
    resolve_instance_profile_role,
    unresolved_instance_role,
)

logger = logging.getLogger(__name__)


@dataclass
class DenyEc2ImdsV1:
    """
    Data model for EC2 IMDSv1 analysis.

    Attributes:
        region: AWS region where the instance runs
        instance_id: EC2 instance identifier
        imdsv1_allowed: True when the metadata endpoint is enabled and does not
            require a session token, so IMDSv1 can be used
        role_exemption_tag_present: True when the IAM role the instance runs as
            carries the exemption tag with the exact value the SCP tests for.
            The tag is read off the role, not the instance: the SCP exempts
            through `aws:PrincipalTag/ExemptFromIMDSv2`, and no statement in it
            reads instance tags
        role_arn: The role whose tags were read, or None when no role could be
            reached
        role_unresolved_reason: Why no role could be reached, or None when
            `role_arn` is populated
    """
    region: str
    instance_id: str
    imdsv1_allowed: bool
    role_exemption_tag_present: bool
    role_arn: Optional[str] = None
    role_unresolved_reason: Optional[str] = None


@dataclass
class _ImdsInstance:
    """One instance's IMDS configuration, before its role has been resolved."""
    region: str
    instance_id: str
    imdsv1_allowed: bool
    instance_profile_arn: Optional[str]


@dataclass
class DenyEc2AmiOwner:
    """
    Data model for EC2 AMI owner analysis.

    Attributes:
        instance_id: EC2 instance identifier
        region: AWS region where instance exists
        ami_id: AMI identifier used to launch instance
        ami_owner: AMI owner account ID or alias, or None when the AMI's owner
            cannot be determined
        ami_name: AMI name (may be None if the AMI no longer exists)
        owner_unknown_reason: Why the owner could not be determined, or None
            when `ami_owner` is populated
    """
    instance_id: str
    region: str
    ami_id: str
    ami_owner: Optional[str]
    ami_name: Optional[str]
    owner_unknown_reason: Optional[str] = None


@dataclass
class DenyEc2ImdsHopLimit:
    """
    Data model for EC2 IMDS hop limit analysis.

    Attributes:
        region: AWS region where instance exists
        instance_id: EC2 instance identifier
        hop_limit: IMDS HttpPutResponseHopLimit (AWS defaults to 1 when unset)
        imds_enabled: True if the instance metadata endpoint is enabled
    """
    region: str
    instance_id: str
    hop_limit: int
    imds_enabled: bool


@dataclass
class DenyEc2PublicIp:
    """
    Data model for EC2 public IP analysis.

    Attributes:
        instance_id: EC2 instance identifier
        region: AWS region where instance exists
        public_ip_address: Public IP address if assigned (None otherwise)
        has_public_ip: True if instance has a public IP address
        instance_arn: Full ARN of the EC2 instance
    """
    instance_id: str
    region: str
    public_ip_address: Optional[str]
    has_public_ip: bool
    instance_arn: str


def _describe_imds_instances(session: Session) -> List[_ImdsInstance]:
    """
    Read every non-terminated instance's IMDS configuration, in every region.

    Args:
        session: boto3.Session with appropriate permissions

    Returns:
        One `_ImdsInstance` per live instance, roles not yet resolved

    Raises:
        RuntimeError: If DescribeInstances fails in any region
    """
    instances = []
    regions = get_all_regions(session)

    for region in regions:
        try:
            regional_ec2: EC2Client = session.client('ec2', region_name=region)
            paginator = regional_ec2.get_paginator('describe_instances')

            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        # Skip terminated instances
                        if instance['State']['Name'] == 'terminated':
                            continue

                        metadata_options = instance.get('MetadataOptions', {})
                        http_tokens = metadata_options.get('HttpTokens', 'optional')
                        http_endpoint = metadata_options.get('HttpEndpoint', 'enabled')

                        # IMDSv1 is reachable only when the endpoint is on and a
                        # session token is not required. Either one closes it.
                        imdsv1_allowed = (
                            http_endpoint == 'enabled' and http_tokens == 'optional'
                        )

                        instances.append(_ImdsInstance(
                            region=region,
                            instance_id=instance['InstanceId'],
                            imdsv1_allowed=imdsv1_allowed,
                            instance_profile_arn=instance.get(
                                'IamInstanceProfile', {}
                            ).get('Arn'),
                        ))

        except ClientError as e:
            raise RuntimeError(f"Failed to analyze EC2 instances in region {region}: {e}")

    return instances


def _resolve_profile_roles(
    session: Session,
    instances: List[_ImdsInstance],
) -> Dict[str, ResolvedInstanceRole]:
    """
    Resolve every distinct instance profile in the fleet to its role's tags.

    Instance profiles are global, so one lookup serves every region and every
    instance behind that profile: a thousand instances sharing a profile cost
    one pair of IAM calls. A fleet with no instance profiles reaches IAM not at
    all.

    Args:
        session: boto3.Session for the target account
        instances: Live instances and their IMDS configuration

    Returns:
        Mapping of instance profile ARN to the role behind it

    Raises:
        RuntimeError: If IAM fails for any reason other than a deleted profile
            or role
    """
    profile_arns = sorted({
        instance.instance_profile_arn
        for instance in instances
        if instance.instance_profile_arn
    })
    if not profile_arns:
        return {}

    iam_client: IAMClient = session.client('iam')
    resolved_by_profile = {}

    for profile_arn in profile_arns:
        try:
            resolved_by_profile[profile_arn] = resolve_instance_profile_role(
                iam_client, profile_arn
            )
        except ClientError as e:
            raise RuntimeError(
                f"Failed to resolve the IAM role behind instance profile "
                f"{profile_arn}: {e}. The deny_ec2_imds_v1 SCP exempts by role "
                f"tag, so this check cannot report compliance without reading "
                f"role tags, and treating the failure as an untagged role would "
                f"turn one permission gap into a fleet of violations that look "
                f"real. The Headroom role needs iam:GetInstanceProfile and "
                f"iam:GetRole."
            )

    return resolved_by_profile


def _find_exemption_tag_value(
    tags: Dict[str, str],
    role_arn: Optional[str],
) -> Optional[str]:
    """
    Find the exemption tag's value the way IAM matches the condition key.

    The two halves of the match pull opposite ways, and the scanner has to
    follow both. IAM matches the tag key in `aws:PrincipalTag/<key>`
    case-insensitively, so matching it exactly here would report a role tagged
    `exemptfromimdsv2` as a violation that enforcement exempts. The value is
    compared with StringNotEquals, which is case-sensitive, so lowercasing it
    would report a role tagged "True" as exempt when enforcement denies it.

    A role carrying the key twice in cases that differ has no determinate
    answer. AWS documents that as an unexpected condition failure rather than a
    match on one of them, so there is nothing to report, and guessing which one
    IAM lands on would invent the exemption status of a live workload.

    Args:
        tags: The role's tags
        role_arn: The role the tags came from, named in the error

    Returns:
        The tag's value, or None when the role does not carry it

    Raises:
        RuntimeError: If the role carries the key more than once, in cases that
            differ
    """
    wanted_key = IMDS_EXEMPTION_TAG_KEY.lower()
    matches = {
        key: value for key, value in tags.items() if key.lower() == wanted_key
    }

    if len(matches) > 1:
        raise RuntimeError(
            f"Role {role_arn} carries {IMDS_EXEMPTION_TAG_KEY} more than once "
            f"in cases that differ ({', '.join(sorted(matches))}). IAM matches "
            f"the tag key in aws:PrincipalTag without regard to case, so every "
            f"one of them matches the SCP's condition key while at most one "
            f"value can - which AWS documents as an unexpected condition "
            f"failure. Whether this role is exempt cannot be determined, and "
            f"guessing would misreport whether the SCP is safe to attach here."
        )

    return next(iter(matches.values()), None)


def _build_imds_results(
    instances: List[_ImdsInstance],
    resolved_by_profile: Dict[str, ResolvedInstanceRole],
) -> List[DenyEc2ImdsV1]:
    """
    Pair each instance's IMDS configuration with its role's exemption tag.

    Args:
        instances: Live instances and their IMDS configuration
        resolved_by_profile: Roles behind the fleet's instance profiles

    Returns:
        One DenyEc2ImdsV1 per instance
    """
    no_profile = unresolved_instance_role(
        InstanceRoleUnresolvedReason.NO_INSTANCE_PROFILE
    )

    results = []
    for instance in instances:
        resolved = (
            resolved_by_profile[instance.instance_profile_arn]
            if instance.instance_profile_arn
            else no_profile
        )

        exemption_value = _find_exemption_tag_value(
            resolved.tags, resolved.role_arn
        )

        results.append(DenyEc2ImdsV1(
            region=instance.region,
            instance_id=instance.instance_id,
            imdsv1_allowed=instance.imdsv1_allowed,
            role_exemption_tag_present=exemption_value == IMDS_EXEMPTION_TAG_VALUE,
            role_arn=resolved.role_arn,
            role_unresolved_reason=resolved.unresolved_reason,
        ))

    return results


def get_ec2_imds_v1_analysis(session: Session) -> List[DenyEc2ImdsV1]:
    """
    Analyze EC2 instances for IMDS v1 configuration across all regions.

    Algorithm:
    1. Describe every non-terminated instance in every enabled region, reading
       its MetadataOptions and the instance profile attached to it
    2. Resolve each distinct instance profile to its role and that role's tags
    3. Report each instance's IMDS setting alongside its role's exemption

    The exemption is a property of the role, not of the instance. The SCP this
    check gates exempts callers through `aws:PrincipalTag/ExemptFromIMDSv2`,
    which reads tags on the role an instance runs as; its other statement
    exempts through `aws:RequestTag/ExemptFromIMDSv2`, a property of a future
    launch request that no scan of running instances can observe. Reading the
    instance's own tags matched neither, and reported accounts as violation-free
    while enforcement would have denied every API call those instances made.

    Args:
        session: boto3.Session with appropriate permissions

    Returns:
        List of DenyEc2ImdsV1 objects containing analysis results

    Raises:
        RuntimeError: If DescribeInstances fails in any region, or if IAM
            fails for any reason other than a deleted profile or role
    """
    instances = _describe_imds_instances(session)
    return _build_imds_results(instances, _resolve_profile_roles(session, instances))


# DescribeImages error codes that mean the AMI ID no longer resolves at all.
# AWS returns NotFound for a deregistered AMI and Unavailable for one that is
# deregistered but not yet fully torn down. Neither leaves an owner to read.
# AMI state set by DisableImage. A disabled image keeps its owner but cannot
# launch, and DescribeImages omits it unless IncludeDisabled is set.
DISABLED_AMI_STATE = "disabled"

DEREGISTERED_AMI_ERROR_CODES = frozenset({
    "InvalidAMIID.NotFound",
    "InvalidAMIID.Unavailable",
})


@dataclass
class _ResolvedAmi:
    """
    Outcome of resolving one AMI's owner.

    Either `owner` is populated and `unknown_reason` is None, or the reverse.
    """
    owner: Optional[str]
    name: Optional[str]
    unknown_reason: Optional[str]


def _describe_ami(regional_ec2: EC2Client, ami_id: str) -> Optional[ImageTypeDef]:
    """
    Describe one AMI, returning None when DescribeImages does not surface it.

    DescribeImages filters its results rather than erroring, so an AMI that a
    running instance was launched from can come back as an empty list. The two
    categories AWS hides by default are asked for up front: images turned off
    with DisableImage, and images past their deprecation date that this account
    does not own. Both still carry the owner this check needs, and asking for
    them once costs less than discovering their absence and asking again.

    Args:
        regional_ec2: EC2 client for the region the instance runs in
        ami_id: AMI identifier to describe

    Returns:
        The AMI description, or None if it is not in the response
    """
    response = regional_ec2.describe_images(
        ImageIds=[ami_id],
        IncludeDisabled=True,
        IncludeDeprecated=True,
    )
    images = response['Images']
    return images[0] if images else None


def _resolve_ami_owner(
    regional_ec2: EC2Client,
    ami_id: str,
    region: str,
    instance_id: str,
) -> _ResolvedAmi:
    """
    Resolve an AMI's owner, recording why when it cannot be determined.

    An instance outlives the visibility of the AMI it was launched from, so an
    unresolvable AMI is a data condition to report rather than a reason to abort
    the run. The check that consumes this treats an unresolved owner as a
    violation, which keeps the account out of any org-wide policy placement
    without stopping every account queued behind it.

    An AMI that DescribeImages returns without an OwnerId still raises, because
    that is the API breaking its own contract rather than a fact about this
    account, and it would be wrong for every AMI rather than for this one.

    Args:
        regional_ec2: EC2 client for the region the instance runs in
        ami_id: AMI identifier the instance was launched from
        region: Region name, used for logging
        instance_id: Instance identifier, used for logging

    Returns:
        The resolved owner, or the reason it is unknown

    Raises:
        RuntimeError: If AWS returns the AMI without an OwnerId
        ClientError: If DescribeImages fails for any reason other than the AMI
            no longer resolving
    """
    try:
        image = _describe_ami(regional_ec2, ami_id)

        if image is None:
            logger.warning(
                f"AMI {ami_id} in {region} is not visible to this account even "
                f"with IncludeDisabled and IncludeDeprecated, so the owner of "
                f"instance {instance_id} cannot be determined. An Allowed AMIs "
                f"setting is filtering it, or it was shared and then unshared."
            )
            return _ResolvedAmi(
                owner=None,
                name=None,
                unknown_reason=AmiOwnerUnknownReason.NOT_VISIBLE.value,
            )
    except ClientError as e:
        if e.response['Error']['Code'] not in DEREGISTERED_AMI_ERROR_CODES:
            raise
        logger.warning(
            f"AMI {ami_id} in {region} no longer resolves, so the owner of instance "
            f"{instance_id} cannot be determined. The AMI was deregistered while the "
            f"instance kept running."
        )
        return _ResolvedAmi(
            owner=None,
            name=None,
            unknown_reason=AmiOwnerUnknownReason.DEREGISTERED.value,
        )

    owner_id = image.get('OwnerId')
    if not owner_id:
        raise RuntimeError(
            f"AMI {ami_id} in {region} has no OwnerId - "
            f"cannot determine owner for instance {instance_id}. "
            f"This is a critical security check failure."
        )

    if image.get('State') == DISABLED_AMI_STATE:
        logger.warning(
            f"AMI {ami_id} in {region}, used by instance {instance_id}, has been "
            f"disabled. Its owner still resolves, but the image cannot launch."
        )

    return _ResolvedAmi(owner=owner_id, name=image.get('Name'), unknown_reason=None)


def get_ec2_ami_owner_analysis(session: Session) -> List[DenyEc2AmiOwner]:
    """
    Analyze EC2 instances to determine AMI owner for each instance.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region:
       a. Describe all EC2 instances via paginator
       b. For each instance, extract AMI ID
       c. Resolve the AMI's owner via _resolve_ami_owner(), which records why
          the owner is unknown when the AMI cannot be resolved
       d. Create DenyEc2AmiOwner result with instance and AMI details
    3. Return all results across all regions

    AMIs are resolved once per region and cached, including the ones that do
    not resolve, so a dead AMI shared by many instances costs one lookup.

    Args:
        session: boto3.Session for the target account

    Returns:
        List of DenyEc2AmiOwner analysis results, each carrying either an
        `ami_owner` or an `owner_unknown_reason`

    Raises:
        RuntimeError: If AWS API calls fail, or if AWS returns an AMI with no
            OwnerId
    """
    results = []
    regions = get_all_regions(session)

    for region in regions:
        try:
            regional_ec2: EC2Client = session.client('ec2', region_name=region)
            logger.info(f"Analyzing EC2 AMI owners in {region}")

            ami_cache: Dict[str, _ResolvedAmi] = {}

            paginator = regional_ec2.get_paginator('describe_instances')
            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        if instance['State']['Name'] == 'terminated':
                            continue

                        instance_id = instance['InstanceId']
                        ami_id = instance.get('ImageId')

                        if not ami_id:
                            logger.warning(
                                f"Instance {instance_id} in {region} has no AMI ID, skipping"
                            )
                            continue

                        if ami_id not in ami_cache:
                            ami_cache[ami_id] = _resolve_ami_owner(
                                regional_ec2, ami_id, region, instance_id
                            )

                        resolved = ami_cache[ami_id]

                        results.append(DenyEc2AmiOwner(
                            instance_id=instance_id,
                            region=region,
                            ami_id=ami_id,
                            ami_owner=resolved.owner,
                            ami_name=resolved.name,
                            owner_unknown_reason=resolved.unknown_reason
                        ))

        except ClientError as e:
            raise RuntimeError(
                f"Failed to analyze EC2 AMI owners in region {region}: {e}"
            )

    logger.info(
        f"Analyzed {len(results)} EC2 instances across {len(regions)} regions"
    )
    return results


def get_ec2_public_ip_analysis(session: Session) -> List[DenyEc2PublicIp]:
    """
    Analyze EC2 instances for public IP address assignment across all regions.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region:
       a. Analyze EC2 instances via describe_instances() (paginated)
       b. Check for public IP address in network interfaces
       c. Skip terminated instances
       d. Create DenyEc2PublicIp results
    3. Return all results across all regions

    Args:
        session: boto3.Session for the target account

    Returns:
        List of DenyEc2PublicIp analysis results

    Raises:
        RuntimeError: If AWS API calls fail
    """
    results = []
    regions = get_all_regions(session)

    for region in regions:
        try:
            regional_ec2: EC2Client = session.client('ec2', region_name=region)
            paginator = regional_ec2.get_paginator('describe_instances')

            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        if instance['State']['Name'] == 'terminated':
                            continue

                        instance_id = instance['InstanceId']
                        account_id = instance.get('OwnerId', '')

                        instance_arn = (
                            f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
                        )

                        public_ip_address = instance.get('PublicIpAddress')
                        has_public_ip = public_ip_address is not None

                        results.append(DenyEc2PublicIp(
                            instance_id=instance_id,
                            region=region,
                            public_ip_address=public_ip_address,
                            has_public_ip=has_public_ip,
                            instance_arn=instance_arn
                        ))

        except ClientError as e:
            raise RuntimeError(f"Failed to analyze EC2 instances in region {region}: {e}")

    return results


def get_ec2_imds_hop_limit_analysis(session: Session) -> List[DenyEc2ImdsHopLimit]:
    """
    Analyze EC2 instances for IMDS hop limit configuration across all regions.

    A hop limit above 1 lets the metadata response cross an extra network hop,
    which is what allows a container or a downstream proxy on the instance to
    reach IMDS. This function reports the configured limit; deciding what
    counts as a violation is the check's job.

    Args:
        session: boto3.Session with appropriate permissions

    Returns:
        List of DenyEc2ImdsHopLimit objects containing analysis results
    """
    results = []
    regions = get_all_regions(session)

    for region in regions:
        try:
            regional_ec2: EC2Client = session.client('ec2', region_name=region)
            paginator = regional_ec2.get_paginator('describe_instances')

            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        # Skip terminated instances
                        if instance['State']['Name'] == 'terminated':
                            continue

                        metadata_options = instance.get('MetadataOptions', {})
                        # AWS defaults the hop limit to 1 when it is not set
                        hop_limit = metadata_options.get('HttpPutResponseHopLimit', 1)
                        imds_enabled = metadata_options.get('HttpEndpoint', 'enabled') == 'enabled'

                        results.append(DenyEc2ImdsHopLimit(
                            region=region,
                            instance_id=instance['InstanceId'],
                            hop_limit=hop_limit,
                            imds_enabled=imds_enabled
                        ))

        except ClientError as e:
            raise RuntimeError(f"Failed to analyze EC2 instances in region {region}: {e}")

    return results
