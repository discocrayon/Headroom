"""EC2-related security analysis functions for Headroom."""

import boto3  # type: ignore
from dataclasses import dataclass
from typing import List
from botocore.exceptions import ClientError  # type: ignore


@dataclass
class DenyImdsV1Ec2:
    """Data class for EC2 IMDS v1 analysis results."""
    region: str
    instance_id: str
    imdsv1_allowed: bool  # Compliance status
    exemption_tag_present: bool  # Exemption via `ExemptFromIMDSv2` tag


def get_imds_v1_ec2_analysis(session: boto3.Session) -> List[DenyImdsV1Ec2]:
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
    ec2_client = session.client('ec2')

    try:
        # Get all available regions
        regions_response = ec2_client.describe_regions()
        regions = [region['RegionName'] for region in regions_response['Regions']]
    except ClientError:
        # If we can't get regions, fall back to current region
        regions = [session.region_name or 'us-east-1']

    for region in regions:
        try:
            regional_ec2 = session.client('ec2', region_name=region)
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
                        state = metadata_options.get('State', 'enabled')

                        # Determine if IMDSv1 is allowed
                        # IMDSv1 is allowed if IMDS is enabled and HttpTokens is 'optional'
                        # IMDSv1 is blocked if HttpTokens is 'required' or IMDS is disabled
                        imdsv1_allowed = (state == 'enabled' and http_tokens == 'optional')

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
