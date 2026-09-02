"""
Enumerations for Headroom application.

This module contains all enum types used throughout the application
to replace magic strings and improve type safety.
"""

from enum import Enum


class CheckType(str, Enum):
    """Types of compliance checks."""
    SCPS = "scps"
    RCPS = "rcps"


class TerraformSection(Enum):
    """
    The section comment a check's module parameters render under.

    Declaration order is render order, for SCP and RCP modules alike: a
    module's parameters are grouped by section in this order and sorted by
    check name within a section, so neither import order nor registration
    order can change generated Terraform (INV-13). Services run
    alphabetically; a cross-service statement sits after that run rather
    than inside it.

    A new check in an existing service touches only its own module. A new
    service adds one member here, in alphabetical position.
    """
    EC2 = "EC2"
    ECR = "ECR"
    EKS = "EKS"
    IAM = "IAM"
    KMS = "KMS"
    LAMBDA = "Lambda"
    RDS = "RDS"
    S3 = "S3"
    SECRETS_MANAGER = "Secrets Manager"
    SQS = "SQS"
    STS = "STS"
    SERVICE_CONFUSED_DEPUTY = "Service confused deputy"


class PlacementLevel(str, Enum):
    """Policy placement levels in organization hierarchy."""
    ROOT = "root"
    OU = "ou"
    ACCOUNT = "account"
    NONE = "none"


class CheckCategory(str, Enum):
    """
    Categorization of check results.

    EXEMPTION means the resource matches the deny's condition but the policy
    will spare it, so it must not count against deployability. Only claim it
    where the scan can see the dimension the exemption turns on, or something
    that reliably stands in for it - `deny_ec2_imds_v1` is the sole producer,
    and it reads an instance tag as a proxy for the launch request's tag. See
    AP-011 in HOW_TO_ADD_A_CHECK.md for the shape of that argument.
    """
    VIOLATION = "violation"
    EXEMPTION = "exemption"
    COMPLIANT = "compliant"


class AmiOwnerUnknownReason(str, Enum):
    """Reasons an EC2 instance's AMI owner cannot be determined."""
    # DescribeImages does not surface the AMI to this account even when asked
    # for disabled and deprecated images: an Allowed AMIs setting filters it,
    # or it was shared and then unshared.
    NOT_VISIBLE = "not_visible"
    # The AMI ID no longer resolves at all, which is what deregistration leaves
    # behind on a long-lived instance.
    DEREGISTERED = "deregistered"
