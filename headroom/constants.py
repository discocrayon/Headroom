"""
Constants module for check names and type mappings.

This module contains check name constants used throughout the Headroom codebase.
"""

from typing import Dict

# Check name constants

# SCP Checks (alphabetical by service)
# EC2
DENY_EC2_AMI_OWNER = "deny_ec2_ami_owner"
DENY_IMDS_V1_EC2 = "deny_imds_v1_ec2"
# EKS
DENY_EKS_CREATE_CLUSTER_WITHOUT_TAG = "deny_eks_create_cluster_without_tag"
# IAM
DENY_IAM_USER_CREATION = "deny_iam_user_creation"
# RDS
DENY_RDS_UNENCRYPTED = "deny_rds_unencrypted"

# RCP Checks (alphabetical by service)
# ECR
DENY_ECR_THIRD_PARTY_ACCESS = "deny_ecr_third_party_access"
# IAM
THIRD_PARTY_ASSUMEROLE = "third_party_assumerole"

# Terraform file generation constants
ORG_INFO_FILENAME = "grab_org_info.tf"

# Check type mapping - updated by checks when they register
# This avoids circular imports while allowing checks to self-register
_CHECK_TYPE_MAP: Dict[str, str] = {}


def register_check_type(check_name: str, check_type: str) -> None:
    """
    Register a check's type.

    Called by checks during registration to populate the type map.

    Args:
        check_name: Name of the check
        check_type: Type of the check (scps, rcps)
    """
    _CHECK_TYPE_MAP[check_name] = check_type


def get_check_type_map() -> Dict[str, str]:
    """
    Get the check type map.

    Returns:
        Dictionary mapping check names to check types
    """
    return _CHECK_TYPE_MAP
