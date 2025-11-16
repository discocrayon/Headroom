"""
Constants module for check names and type mappings.

This module contains check name constants used throughout the Headroom codebase.
"""

from typing import Dict

# AWS IAM Policy Principal Types
# Base types supported in both IAM trust policies and S3 bucket policies
# Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
BASE_PRINCIPAL_TYPES = frozenset({"AWS", "Service", "Federated"})

# AWS ARN Regex Pattern
# Pattern to extract 12-digit account ID from AWS ARN
# Format: arn:aws:service:region:account-id:resource
AWS_ARN_ACCOUNT_ID_PATTERN = r'^arn:aws:[^:]+:[^:]*:(\d{12}):'

# Check name constants

# SCP Checks (alphabetical by service)
# EC2
DENY_EC2_AMI_OWNER = "deny_ec2_ami_owner"
DENY_EC2_IMDS_V1 = "deny_ec2_imds_v1"
DENY_EC2_PUBLIC_IP = "deny_ec2_public_ip"
# EKS
DENY_EKS_CREATE_CLUSTER_WITHOUT_TAG = "deny_eks_create_cluster_without_tag"
# IAM
DENY_IAM_USER_CREATION = "deny_iam_user_creation"
# IAM SAML
DENY_IAM_SAML_PROVIDER_NOT_AWS_SSO = "deny_iam_saml_provider_not_aws_sso"
# RDS
DENY_RDS_UNENCRYPTED = "deny_rds_unencrypted"

# RCP Checks (alphabetical by service)
# AOSS
DENY_AOSS_THIRD_PARTY_ACCESS = "deny_aoss_third_party_access"
# ECR
DENY_ECR_THIRD_PARTY_ACCESS = "deny_ecr_third_party_access"
# KMS
DENY_KMS_THIRD_PARTY_ACCESS = "deny_kms_third_party_access"
# S3
DENY_S3_THIRD_PARTY_ACCESS = "deny_s3_third_party_access"
# Secrets Manager
DENY_SECRETS_MANAGER_THIRD_PARTY_ACCESS = "deny_secrets_manager_third_party_access"
# SQS
DENY_SQS_THIRD_PARTY_ACCESS = "deny_sqs_third_party_access"
# STS
DENY_STS_THIRD_PARTY_ASSUMEROLE = "deny_sts_third_party_assumerole"

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
