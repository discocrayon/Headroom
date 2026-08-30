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

from ..constants import IMDS_EXEMPTION_TAG_KEY, IMDS_EXEMPTION_TAG_VALUE
from ..enums import AmiOwnerUnknownReason
from .helpers import get_all_regions, paginate

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
        ami_owner: AMI owner account ID, or None when the AMI's owner cannot
            be determined
        ami_owner_alias: The AMI's owner alias when AWS publishes one, else
            None. This is what `ec2:Owner` resolves to - see EC2_OWNER_ALIASES
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
    ami_owner_alias: Optional[str] = None


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


@dataclass(frozen=True)
class Ec2Instance:
    """
    The subset of a describe_instances entry that Headroom's EC2 checks read.

    Frozen, because `get_instances` hands every check the same object rather
    than a copy: an unfrozen field assignment in one check would be visible to
    the next three.

    Four checks previously swept every region independently for the same data.
    They now share one collection pass, and this is its output: the eight values
    those checks actually consume. Everything else in the API response --
    BlockDeviceMappings, NetworkInterfaces, SecurityGroups, Placement -- is
    dropped, because the memo holds this for an account's whole lifetime and
    the full entries are what would make that expensive.

    Attributes:
        instance_id: EC2 instance identifier
        image_id: AMI the instance was launched from, None if the API omits it
        owner_id: Account that owns the reservation
        public_ip_address: Public IP if one is assigned, None otherwise
        http_tokens: MetadataOptions HttpTokens; AWS defaults to 'optional'
        http_endpoint: MetadataOptions HttpEndpoint; AWS defaults to 'enabled'
        hop_limit: MetadataOptions HttpPutResponseHopLimit; AWS defaults to 1
        tags: Instance tags as a key to value mapping
    """
    instance_id: str
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
    owner_id: str
) -> Ec2Instance:
    """
    Reduce one describe_instances entry to the values the checks read.

    The region is not among them. Every check already has it as the loop
    variable it passed to get_instances, and it is the memo's dict key, so
    carrying it on each instance would be a field with no reader.

    Args:
        instance: Instance dictionary from describe_instances
        owner_id: Owner of the reservation the instance belongs to

    Returns:
        The projected instance
    """
    metadata_options = instance.get('MetadataOptions', {})
    return Ec2Instance(
        instance_id=instance['InstanceId'],
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
                owner_id = reservation['OwnerId']
                for instance in reservation['Instances']:
                    if instance['State']['Name'] == 'terminated':
                        continue
                    instances.append(_project_instance(instance, owner_id))
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
    worker drops the session. The region is a key of the nested dictionary
    rather than half of a `(session, region)` tuple key, because a tuple
    cannot be weakly referenced at all -- `WeakKeyDictionary` raises TypeError
    on the first write. Flattening the key would therefore mean giving up the
    weak dictionary, and with it the release that keeps 300 accounts' instance
    lists from accumulating.

    The lock is released across the API call rather than held; see
    `get_all_regions` in helpers.py for why. What makes the `by_region`
    reference safe to hold across that window is narrower than one worker per
    session: the entry for a live session is only ever created, never
    replaced, so the dictionary written to at the end is still the one the
    memo holds. Adding eviction would break that while leaving one worker per
    session true, and the write would land in an orphaned dictionary and be
    silently dropped.

    Callers must not mutate what this returns. It is the cached list itself,
    not a copy, so appending to it or removing from it changes what the next
    check for this account and region sees. `Ec2Instance` is frozen; the list
    is not, and no check has any reason to write to either.

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

    Instances come from `get_instances`, which reads each region once per
    session and has already dropped the terminated ones.

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
        for instance in get_instances(session, region):
            # HttpTokens alone decides, whether or not the metadata endpoint
            # is enabled. A disabled endpoint does make IMDSv1 unreachable on
            # the running instance, but the SCP reads the launch request,
            # where a request turning the endpoint off carries no HttpTokens,
            # leaving ec2:MetadataHttpTokens absent and StringNotEquals true.
            # Excusing those instances cleared accounts whose relaunches the
            # SCP denies.
            imdsv1_allowed = instance.http_tokens == 'optional'

            exemption_value = _find_exemption_tag_value(
                instance.tags, instance.instance_id
            )

            results.append(DenyEc2ImdsV1(
                region=region,
                instance_id=instance.instance_id,
                imdsv1_allowed=imdsv1_allowed,
                exemption_tag_present=(
                    exemption_value == IMDS_EXEMPTION_TAG_VALUE
                ),
            ))

    return results


# DescribeImages error codes that mean the AMI ID no longer resolves at all.
# AWS returns NotFound for a deregistered AMI and Unavailable for one that is
# deregistered but not yet fully torn down. Neither leaves an owner to read.
# AMI state set by DisableImage. A disabled image keeps its owner but cannot
# launch, and DescribeImages omits it unless IncludeDisabled is set.
# ec2:Owner resolves to the AMI's owner ALIAS when DescribeImages returns one,
# and to the numeric OwnerId only when it does not. Measured with
# RunInstances --dry-run against the Deny statement this repo generates:
#
#   AMI                            allowlist              result
#   Amazon Linux 2023              [numeric OwnerId]      DENY
#   (ImageOwnerAlias "amazon")     ["amazon"]             ALLOW
#                                  [numeric, "amazon"]    ALLOW
#   Rocky Linux                    [numeric OwnerId]      ALLOW
#   (no ImageOwnerAlias)           ["amazon"]             DENY
#
# "aws-marketplace" is inferred from the "amazon" rows rather than measured:
# every Marketplace AMI reachable for the test needed a subscription, and EC2
# returns OptInRequired before it evaluates the statement, so the dry run
# cannot tell an allow from a deny there.
#
# Recording only the numeric owner therefore builds an allowlist that denies
# the very AMI a clean scan observed, because StringNotEquals matches whenever
# the key holds anything other than a listed value.
EC2_OWNER_ALIASES = frozenset({"amazon", "aws-marketplace"})

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
    `owner_alias` is set only when AWS publishes one for the image.
    """
    owner: Optional[str]
    name: Optional[str]
    unknown_reason: Optional[str]
    owner_alias: Optional[str] = None


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
    account, and it would be wrong for every AMI rather than for this one. An
    owner alias outside EC2_OWNER_ALIASES raises for the same reason.

    Args:
        regional_ec2: EC2 client for the region the instance runs in
        ami_id: AMI identifier the instance was launched from
        region: Region name, used for logging
        instance_id: Instance identifier, used for logging

    Returns:
        The resolved owner, or the reason it is unknown

    Raises:
        RuntimeError: If AWS returns the AMI without an OwnerId, or with an
            owner alias outside EC2_OWNER_ALIASES
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

    owner_alias = image.get('ImageOwnerAlias')
    if owner_alias is not None and owner_alias not in EC2_OWNER_ALIASES:
        raise RuntimeError(
            f"AMI {ami_id} in {region}, used by instance {instance_id}, has the "
            f"unrecognised owner alias '{owner_alias}'. ec2:Owner takes one of "
            f"{sorted(EC2_OWNER_ALIASES)} or an account ID, so an alias outside "
            f"that set cannot be turned into an allowlist entry, and guessing "
            f"one would deny every launch in the accounts this covers."
        )

    if image.get('State') == DISABLED_AMI_STATE:
        logger.warning(
            f"AMI {ami_id} in {region}, used by instance {instance_id}, has been "
            f"disabled. Its owner still resolves, but the image cannot launch."
        )

    return _ResolvedAmi(
        owner=owner_id,
        name=image.get('Name'),
        unknown_reason=None,
        owner_alias=owner_alias,
    )


def get_ec2_ami_owner_analysis(session: Session) -> List[DenyEc2AmiOwner]:
    """
    Analyze EC2 instances to determine AMI owner for each instance.

    Algorithm:
    1. Get all enabled regions via get_all_regions()
    2. For each region:
       a. Get the region's instances via get_instances(), which reads each
          region once per session and has already dropped terminated ones
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
            OwnerId or an unrecognised owner alias
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
                    owner_unknown_reason=resolved.unknown_reason,
                    ami_owner_alias=resolved.owner_alias
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
       a. Get the region's instances via get_instances(), which reads each
          region once per session and has already dropped terminated ones
       b. Check for public IP address in network interfaces
       c. Create DenyEc2PublicIp results
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
