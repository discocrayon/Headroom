"""EC2-related security analysis functions for Headroom."""

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

from boto3.session import Session
from botocore.exceptions import ClientError
from mypy_boto3_ec2.client import EC2Client

logger = logging.getLogger(__name__)


@dataclass
class DenyImdsV1Ec2:
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
        ami_owner: AMI owner account ID or alias
        ami_name: AMI name (may be None if AMI no longer exists)
    """
    instance_id: str
    region: str
    ami_id: str
    ami_owner: str
    ami_name: Optional[str]


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


def get_imds_v1_ec2_analysis(session: Session) -> List[DenyImdsV1Ec2]:
    """
    Analyze EC2 instances for IMDS v1 configuration across all regions.

    This function calls describe_instances in a paginated, performant way
    and returns a list of DenyImdsV1Ec2 with the relevant attributes filled in.

    Args:
        session: boto3.Session with appropriate permissions

    Returns:
        List of DenyImdsV1Ec2 objects containing analysis results
    """
    results = []
    ec2_client: EC2Client = session.client('ec2')

    # Get all available regions
    regions_response = ec2_client.describe_regions()
    regions = [region['RegionName'] for region in regions_response['Regions']]

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

                        results.append(DenyImdsV1Ec2(
                            region=region,
                            instance_id=instance_id,
                            imdsv1_allowed=imdsv1_allowed,
                            exemption_tag_present=exemption_tag_present
                        ))

        except ClientError as e:
            raise RuntimeError(f"Failed to analyze EC2 instances in region {region}: {e}")

    return results


def get_ec2_ami_owner_analysis(session: Session) -> List[DenyEc2AmiOwner]:
    """
    Analyze EC2 instances to determine AMI owner for each instance.

    Algorithm:
    1. Get all enabled regions from EC2
    2. For each region:
       a. Describe all EC2 instances via paginator
       b. For each instance, extract AMI ID
       c. Describe the AMI to get owner information
       d. Create DenyEc2AmiOwner result with instance and AMI details
    3. Return all results across all regions

    Args:
        session: boto3.Session for the target account

    Returns:
        List of DenyEc2AmiOwner analysis results

    Raises:
        RuntimeError: If AWS API calls fail
    """
    results = []
    ec2_client: EC2Client = session.client('ec2')

    regions_response = ec2_client.describe_regions()
    regions = [region['RegionName'] for region in regions_response['Regions']]

    for region in regions:
        try:
            regional_ec2: EC2Client = session.client('ec2', region_name=region)
            logger.info(f"Analyzing EC2 AMI owners in {region}")

            ami_cache: Dict[str, Dict[str, Optional[str]]] = {}

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
                            try:
                                ami_response = regional_ec2.describe_images(ImageIds=[ami_id])
                                if ami_response['Images']:
                                    ami_info = ami_response['Images'][0]
                                    owner_id = ami_info.get('OwnerId')
                                    if not owner_id:
                                        raise RuntimeError(
                                            f"AMI {ami_id} in {region} has no OwnerId - "
                                            f"cannot determine owner for instance {instance_id}. "
                                            f"This is a critical security check failure."
                                        )
                                    ami_cache[ami_id] = {
                                        'owner': owner_id,
                                        'name': ami_info.get('Name')
                                    }
                                else:
                                    raise RuntimeError(
                                        f"AMI {ami_id} not found in {region} for instance {instance_id}. "
                                        f"Cannot determine AMI owner. This is a critical security check failure."
                                    )
                            except ClientError as e:
                                if e.response['Error']['Code'] == 'InvalidAMIID.NotFound':
                                    raise RuntimeError(
                                        f"AMI {ami_id} no longer exists in {region} for instance {instance_id}. "
                                        f"Cannot determine AMI owner. This is a critical security check failure."
                                    ) from e
                                else:
                                    raise

                        ami_owner = ami_cache[ami_id]['owner']
                        ami_name = ami_cache[ami_id]['name']

                        # ami_owner is always a string in cache (never None)
                        assert ami_owner is not None

                        results.append(DenyEc2AmiOwner(
                            instance_id=instance_id,
                            region=region,
                            ami_id=ami_id,
                            ami_owner=ami_owner,
                            ami_name=ami_name
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
    1. Get all available regions from EC2
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
    ec2_client: EC2Client = session.client('ec2')

    regions_response = ec2_client.describe_regions()
    regions = [region['RegionName'] for region in regions_response['Regions']]

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
