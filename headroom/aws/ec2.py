"""EC2-related security analysis functions for Headroom."""

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_ec2.client import EC2Client
from mypy_boto3_ec2.type_defs import ImageTypeDef

from ..constants import IMDS_EXEMPTION_TAG_KEY, IMDS_EXEMPTION_TAG_VALUE
from ..enums import AmiOwnerUnknownReason
from .helpers import get_all_regions

logger = logging.getLogger(__name__)


@dataclass
class DenyEc2ImdsV1:
    """
    Data model for EC2 IMDSv1 analysis.

    Attributes:
        region: AWS region where the instance runs
        instance_id: EC2 instance identifier
        imdsv1_allowed: True when the instance does not require a session
            token. The metadata endpoint's state does not enter it: the SCP
            tests HttpTokens on the launch request either way, so an instance
            with the endpoint off and tokens optional is still counted.
            Remedying it costs nothing, because nothing reads HttpTokens while
            the endpoint is off
        exemption_tag_present: True when the INSTANCE carries the exemption
            tag with the exact value the SCP tests for. Read off the instance,
            not off any role: the statement exempts through
            `aws:RequestTag/ExemptFromIMDSv2`, and the instance's tag is the
            observable trace of that request tag

    An instance answering IMDSv1 is read as evidence about launches, not as a
    finding against the instance. `deny_ec2_imds_v1` gates one statement,
    `DenyRunInstancesMetadataHttpTokensOptional`, and the fleet already running
    is deliberately outside what this check governs - see
    `get_ec2_imds_v1_analysis`.
    """
    region: str
    instance_id: str
    imdsv1_allowed: bool
    exemption_tag_present: bool


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
        hop_limit: IMDS HttpPutResponseHopLimit (AWS defaults to 1 when unset,
            but an AMI carrying imds-support=v2.0 supplies a higher default)
        imds_enabled: True if the instance metadata endpoint is enabled.
            Reported for context only - it does not affect whether a hop limit
            counts as a violation, because the SCP counts it either way
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


def _find_exemption_tag_value(
    tags: Dict[str, str],
    instance_id: str,
) -> Optional[str]:
    """
    Find the exemption tag's value the way IAM matches the condition key.

    The two halves of the match pull opposite ways, and the scanner has to
    follow both. IAM matches the tag key in `aws:RequestTag/<key>` without
    regard to case, so matching it exactly here would report an instance
    tagged `exemptfromimdsv2` as a violation that enforcement exempts. The
    value is compared with StringNotEquals, which is case-sensitive, so
    lowercasing it would report an instance tagged "True" as exempt when
    enforcement denies its relaunch.

    An instance carrying the key twice in cases that differ has no
    determinate answer. AWS documents that as an unexpected condition failure
    rather than a match on one of them, so there is nothing to report, and
    guessing which one IAM lands on would invent the exemption status of a
    live workload.

    Args:
        tags: The instance's tags
        instance_id: The instance the tags came from, named in the error

    Returns:
        The tag's value, or None when the instance does not carry it

    Raises:
        RuntimeError: If the instance carries the key more than once, in
            cases that differ
    """
    wanted_key = IMDS_EXEMPTION_TAG_KEY.lower()
    matches = {
        key: value for key, value in tags.items() if key.lower() == wanted_key
    }

    if len(matches) > 1:
        raise RuntimeError(
            f"Instance {instance_id} carries {IMDS_EXEMPTION_TAG_KEY} more "
            f"than once in cases that differ ({', '.join(sorted(matches))}). "
            f"IAM matches the tag key in aws:RequestTag without regard to "
            f"case, so every one of them matches the SCP's condition key "
            f"while at most one value can - which AWS documents as an "
            f"unexpected condition failure. Whether a relaunch of this "
            f"instance is exempt cannot be determined, and guessing would "
            f"misreport whether the SCP is safe to attach here."
        )

    return next(iter(matches.values()), None)


def get_ec2_imds_v1_analysis(session: Session) -> List[DenyEc2ImdsV1]:
    """
    Report every live instance's IMDS token setting and exemption tag.

    **The fleet already running is out of scope, deliberately.**
    `deny_ec2_imds_v1` gates exactly one statement,
    `DenyRunInstancesMetadataHttpTokensOptional`, which AWS evaluates against
    a `RunInstances` request. Nothing this function reads can be denied by it:
    every instance it sees has already launched. What an IMDSv1 instance
    provides is evidence about the *next* launch in this account, and that is
    the only thing the check does with it.

    **The exemption is read off the instance, as a proxy for the request.**
    The statement exempts a launch carrying `ExemptFromIMDSv2=true` in
    `aws:RequestTag`, which is populated from the `TagSpecifications` that
    also put the tag on the instance the launch creates. So an instance
    wearing the tag today is the observable trace of a request tag, and good
    evidence its relaunch will carry the same one. Measured against a live
    account with `RunInstances --dry-run`, under the shipped statement:

        tokens=optional, no tag                       DENY
        tokens=optional, ExemptFromIMDSv2=true        allow
        tokens=optional, ExemptFromIMDSv2=True        DENY
        tokens=required, no tag                       allow

    **The proxy is imperfect, and that is accepted.** A tag applied after
    launch with `CreateTags` leaves an instance wearing it whose relaunch
    carries nothing, and so does an instance whose Terraform or launch
    template does not declare the tag. In both cases this scan reports an
    exemption for a relaunch enforcement would deny. Headroom takes the tag as
    a declaration of intent and does not second-guess how it will be
    reapplied; an operator who tags an instance `ExemptFromIMDSv2` is saying
    this workload is meant to keep IMDSv1, and that is the answer this check
    reports.

    No role is resolved and IAM is never called. `aws:PrincipalTag` belonged
    to `DenyRoleDeliveryLessThan2`, a statement this module no longer
    generates.

    Args:
        session: boto3.Session with appropriate permissions

    Returns:
        One DenyEc2ImdsV1 per live instance

    Raises:
        RuntimeError: If DescribeInstances fails in any region, or if an
            instance carries the exemption tag key twice in differing cases
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
                        http_tokens = metadata_options.get('HttpTokens', 'optional')

                        # HttpTokens alone decides, whether or not the metadata
                        # endpoint is enabled. A disabled endpoint does make
                        # IMDSv1 unreachable on the running instance, but the
                        # SCP reads the launch request, where a request turning
                        # the endpoint off carries no HttpTokens, leaving
                        # ec2:MetadataHttpTokens absent and StringNotEquals
                        # true. Excusing those instances cleared accounts whose
                        # relaunches the SCP denies.
                        imdsv1_allowed = http_tokens == 'optional'

                        instance_id = instance['InstanceId']
                        tags = {
                            tag['Key']: tag['Value']
                            for tag in instance.get('Tags', [])
                        }
                        exemption_value = _find_exemption_tag_value(
                            tags, instance_id
                        )

                        results.append(DenyEc2ImdsV1(
                            region=region,
                            instance_id=instance_id,
                            imdsv1_allowed=imdsv1_allowed,
                            exemption_tag_present=(
                                exemption_value == IMDS_EXEMPTION_TAG_VALUE
                            ),
                        ))

        except ClientError as e:
            raise RuntimeError(f"Failed to analyze EC2 instances in region {region}: {e}")

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
