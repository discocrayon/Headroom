"""EC2-related security analysis functions for Headroom."""

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_ec2.client import EC2Client
from mypy_boto3_ec2.type_defs import ImageTypeDef

from ..enums import AmiOwnerUnknownReason
from .helpers import get_all_regions

logger = logging.getLogger(__name__)


@dataclass
class DenyEc2ImdsV1:
    """Data class for EC2 IMDS v1 analysis results."""
    region: str
    instance_id: str
    imdsv1_allowed: bool  # Compliance status
    exemption_tag_present: bool  # Exemption via `ExemptFromIMDSv2` tag


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


def get_ec2_imds_v1_analysis(session: Session) -> List[DenyEc2ImdsV1]:
    """
    Analyze EC2 instances for IMDS v1 configuration across all regions.

    This function calls describe_instances in a paginated, performant way
    and returns a list of DenyEc2ImdsV1 with the relevant attributes filled in.

    Args:
        session: boto3.Session with appropriate permissions

    Returns:
        List of DenyEc2ImdsV1 objects containing analysis results
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

                        instance_id = instance['InstanceId']

                        # Check IMDS configuration
                        metadata_options = instance.get('MetadataOptions', {})
                        http_tokens = metadata_options.get('HttpTokens', 'optional')
                        http_endpoint = metadata_options.get('HttpEndpoint', 'enabled')

                        # Determine if IMDSv1 is allowed
                        # IMDSv1 is allowed if IMDS is enabled and HttpTokens is 'optional'
                        # IMDSv1 is blocked if HttpTokens is 'required' or IMDS is disabled
                        imdsv1_allowed = (http_endpoint == 'enabled' and http_tokens == 'optional')

                        # Check for exemption tag
                        exemption_tag_present = False
                        for tag in instance.get('Tags', []):
                            if tag['Key'] == 'ExemptFromIMDSv2' and tag['Value'].lower() == 'true':
                                exemption_tag_present = True
                                break

                        results.append(DenyEc2ImdsV1(
                            region=region,
                            instance_id=instance_id,
                            imdsv1_allowed=imdsv1_allowed,
                            exemption_tag_present=exemption_tag_present
                        ))

        except ClientError as e:
            raise RuntimeError(f"Failed to analyze EC2 instances in region {region}: {e}")

    return results


# DescribeImages error codes that mean the AMI ID no longer resolves at all.
# AWS returns NotFound for a deregistered AMI and Unavailable for one that is
# deregistered but not yet fully torn down. Neither leaves an owner to read.
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


def _describe_ami(
    regional_ec2: EC2Client,
    ami_id: str,
    include_hidden: bool = False,
) -> Optional[ImageTypeDef]:
    """
    Describe one AMI, returning None when DescribeImages does not surface it.

    DescribeImages filters its results rather than erroring, so an AMI that a
    running instance was launched from can come back as an empty list. Setting
    `include_hidden` asks for the two categories AWS hides by default: images
    turned off with DisableImage, and images past their deprecation date that
    this account does not own.

    Args:
        regional_ec2: EC2 client for the region the instance runs in
        ami_id: AMI identifier to describe
        include_hidden: Whether to ask for disabled and deprecated images

    Returns:
        The AMI description, or None if it is not in the response
    """
    if include_hidden:
        response = regional_ec2.describe_images(
            ImageIds=[ami_id],
            IncludeDisabled=True,
            IncludeDeprecated=True,
        )
    else:
        response = regional_ec2.describe_images(ImageIds=[ami_id])

    images = response['Images']
    return images[0] if images else None


def _hidden_ami_description(image: ImageTypeDef) -> str:
    """
    Name why DescribeImages hides an AMI that the include flags recovered.

    Both causes leave a running instance untouched, so they surface only here.
    An AMI that fits neither is described without a cause rather than guessed at.

    Args:
        image: AMI description returned by the include-flag retry

    Returns:
        A phrase naming the cause, for use in a log message
    """
    if image.get('State') == 'disabled':
        return "disabled"
    if image.get('DeprecationTime'):
        return "deprecated"
    return "hidden"


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
            image = _describe_ami(regional_ec2, ami_id, include_hidden=True)

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

            logger.warning(
                f"AMI {ami_id} in {region}, used by instance {instance_id}, is "
                f"{_hidden_ami_description(image)} and so is absent from the "
                f"default DescribeImages view."
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
