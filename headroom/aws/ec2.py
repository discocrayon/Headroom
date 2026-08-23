"""EC2-related security analysis functions for Headroom."""

import logging
from dataclasses import dataclass
from threading import Lock
from typing import Dict, List, Optional
from weakref import WeakKeyDictionary

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_ec2.client import EC2Client
from mypy_boto3_ec2.type_defs import ImageTypeDef, InstanceTypeDef

from ..enums import AmiOwnerUnknownReason
from .helpers import get_all_regions, paginate

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


@dataclass
class Ec2Instance:
    """
    The subset of a describe_instances entry that Headroom's EC2 checks read.

    Four checks previously swept every region independently for the same data.
    They now share one collection pass, and this is its output: the nine values
    those checks actually consume. Everything else in the API response --
    BlockDeviceMappings, NetworkInterfaces, SecurityGroups, Placement -- is
    dropped, because the memo holds this for an account's whole lifetime and
    the full entries are what would make that expensive.

    Attributes:
        instance_id: EC2 instance identifier
        region: AWS region the instance runs in
        image_id: AMI the instance was launched from, None if the API omits it
        owner_id: Account that owns the reservation
        public_ip_address: Public IP if one is assigned, None otherwise
        http_tokens: MetadataOptions HttpTokens; AWS defaults to 'optional'
        http_endpoint: MetadataOptions HttpEndpoint; AWS defaults to 'enabled'
        hop_limit: MetadataOptions HttpPutResponseHopLimit; AWS defaults to 1
        tags: Instance tags as a key to value mapping
    """
    instance_id: str
    region: str
    image_id: Optional[str]
    owner_id: str
    public_ip_address: Optional[str]
    http_tokens: str
    http_endpoint: str
    hop_limit: int
    tags: Dict[str, str]


_INSTANCE_MEMO: WeakKeyDictionary[Session, Dict[str, List[Ec2Instance]]] = WeakKeyDictionary()
_INSTANCE_MEMO_LOCK = Lock()


def _project_instance(
    instance: InstanceTypeDef,
    owner_id: str,
    region: str
) -> Ec2Instance:
    """
    Reduce one describe_instances entry to the values the checks read.

    Args:
        instance: Instance dictionary from describe_instances
        owner_id: Owner of the reservation the instance belongs to
        region: AWS region being collected

    Returns:
        The projected instance
    """
    metadata_options = instance.get('MetadataOptions', {})
    return Ec2Instance(
        instance_id=instance['InstanceId'],
        region=region,
        image_id=instance.get('ImageId'),
        owner_id=owner_id,
        public_ip_address=instance.get('PublicIpAddress'),
        http_tokens=metadata_options.get('HttpTokens', 'optional'),
        http_endpoint=metadata_options.get('HttpEndpoint', 'enabled'),
        hop_limit=metadata_options.get('HttpPutResponseHopLimit', 1),
        tags={tag['Key']: tag['Value'] for tag in instance.get('Tags', [])},
    )


def _describe_instances(session: Session, region: str) -> List[Ec2Instance]:
    """
    Read every non-terminated instance in one region and project it.

    The terminated filter lives here rather than in each check. All four EC2
    checks previously opened with the identical test, and collecting once is
    the opportunity to state it once.

    Args:
        session: boto3.Session for the target account
        region: AWS region to read

    Returns:
        Projected instances, terminated ones excluded

    Raises:
        RuntimeError: If describe_instances fails
    """
    regional_ec2: EC2Client = session.client('ec2', region_name=region)
    instances = []

    try:
        for page in paginate(regional_ec2, 'describe_instances'):
            for reservation in page['Reservations']:
                owner_id = reservation.get('OwnerId', '')
                for instance in reservation['Instances']:
                    if instance['State']['Name'] == 'terminated':
                        continue
                    instances.append(_project_instance(instance, owner_id, region))
    except ClientError as e:
        raise RuntimeError(f"Failed to analyze EC2 instances in region {region}: {e}")

    return instances


def get_instances(session: Session, region: str) -> List[Ec2Instance]:
    """
    Return one region's non-terminated instances, reading AWS at most once.

    Four checks -- IMDSv1, AMI owner, public IP, and IMDS hop limit -- each
    need every instance in every region. Sweeping separately cost four
    identical describe_instances passes per region, 51 of the 68 calls a
    17-region account made.

    The memo is keyed on the session object itself, never on an account ID or
    name, which is what keeps one account's instances out of another account's
    results. Entries live in a WeakKeyDictionary and are released when the
    worker drops the session.

    The lock is released across the API call rather than held; see
    `get_all_regions` in helpers.py for why.

    Args:
        session: boto3.Session for the target account
        region: AWS region to read

    Returns:
        Projected instances for that region

    Raises:
        RuntimeError: If describe_instances fails
    """
    with _INSTANCE_MEMO_LOCK:
        by_region = _INSTANCE_MEMO.get(session)
        if by_region is None:
            by_region = {}
            _INSTANCE_MEMO[session] = by_region
        cached = by_region.get(region)

    if cached is not None:
        return cached

    instances = _describe_instances(session, region)

    with _INSTANCE_MEMO_LOCK:
        by_region[region] = instances

    return instances


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
        for instance in get_instances(session, region):
            # IMDSv1 is allowed when IMDS is enabled and tokens are optional;
            # it is blocked when HttpTokens is 'required' or IMDS is disabled.
            imdsv1_allowed = (
                instance.http_endpoint == 'enabled' and instance.http_tokens == 'optional'
            )
            exemption_tag_present = instance.tags.get('ExemptFromIMDSv2', '').lower() == 'true'

            results.append(DenyEc2ImdsV1(
                region=region,
                instance_id=instance.instance_id,
                imdsv1_allowed=imdsv1_allowed,
                exemption_tag_present=exemption_tag_present
            ))

    return results


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
        instances = get_instances(session, region)
        if not instances:
            continue

        try:
            regional_ec2: EC2Client = session.client('ec2', region_name=region)
            logger.debug(f"Analyzing EC2 AMI owners in {region}")
            ami_cache: Dict[str, _ResolvedAmi] = {}

            for instance in instances:
                if not instance.image_id:
                    logger.warning(
                        f"Instance {instance.instance_id} in {region} has no AMI ID, skipping"
                    )
                    continue

                if instance.image_id not in ami_cache:
                    ami_cache[instance.image_id] = _resolve_ami_owner(
                        regional_ec2, instance.image_id, region, instance.instance_id
                    )

                resolved = ami_cache[instance.image_id]

                results.append(DenyEc2AmiOwner(
                    instance_id=instance.instance_id,
                    region=region,
                    ami_id=instance.image_id,
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
        for instance in get_instances(session, region):
            instance_arn = (
                f"arn:aws:ec2:{region}:{instance.owner_id}:instance/{instance.instance_id}"
            )

            results.append(DenyEc2PublicIp(
                instance_id=instance.instance_id,
                region=region,
                public_ip_address=instance.public_ip_address,
                has_public_ip=instance.public_ip_address is not None,
                instance_arn=instance_arn
            ))

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
        for instance in get_instances(session, region):
            results.append(DenyEc2ImdsHopLimit(
                region=region,
                instance_id=instance.instance_id,
                hop_limit=instance.hop_limit,
                imds_enabled=instance.http_endpoint == 'enabled'
            ))

    return results
