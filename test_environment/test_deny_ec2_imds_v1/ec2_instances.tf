# EC2 Test Instances for IMDSv1/v2 Testing
#
# These instances are used to test the deny_ec2_imds_v1 SCP check.
# They should be destroyed when not actively being used for testing.
#
# An instance answering IMDSv1 is a violation unless it carries
# ExemptFromIMDSv2 = "true". That tag is read off the INSTANCE as a proxy for
# aws:RequestTag on its relaunch - the TagSpecifications entry that exempts
# the launch is the same one that puts the tag here. No role tag is read.
# See documentation/CHECKS.md for what the proxy costs and why it is accepted.

# Instance 1: IMDSv1 enabled (should be flagged by the check)
resource "aws_instance" "test_imdsv1_enabled" {
  provider      = aws.shared_foo_bar
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.nano"

  metadata_options {
    http_tokens   = "optional"
    http_endpoint = "enabled"
  }

  tags = {
    Name = "test-imdsv1-enabled"
  }
}

# Instance 2: IMDSv2 required, IMDSv1 disabled (should pass the check)
resource "aws_instance" "test_imdsv2_only" {
  provider      = aws.acme_co
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.nano"

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  tags = {
    Name = "test-imdsv2-only"
  }
}

# Instance 3: IMDSv1 enabled, exempt by its own tag (should pass)
#
# Measured with RunInstances --dry-run under the shipped statement: a launch
# carrying ExemptFromIMDSv2=true in its TagSpecifications is allowed even with
# http_tokens = "optional". That same TagSpecifications entry is what puts the
# tag on the instance, so the tag visible here is the trace of the request tag
# that exempted the launch - and of the one its relaunch will carry.
#
# An earlier revision put this tag on the instance's IAM ROLE instead, for a
# DenyRoleDeliveryLessThan2 statement that is no longer generated. The role
# and its instance profile are gone.
resource "aws_instance" "test_imdsv1_exempt" {
  provider      = aws.fort_knox
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.nano"

  metadata_options {
    http_tokens   = "optional"
    http_endpoint = "enabled"
  }

  tags = {
    Name             = "test-imdsv1-exempt"
    ExemptFromIMDSv2 = "true"
  }
}

# Instance 4: IMDSv1 enabled, tag value in the wrong case (a violation)
#
# StringNotEquals is case-sensitive, so "True" does not exempt. Measured: the
# same launch tagged "true" is allowed and tagged "True" is denied. A scanner
# that lowercased the value would report this instance exempt and clear an
# account whose relaunch enforcement denies.
#
# The tag KEY is the opposite - IAM matches condition key names without regard
# to case, so exemptfromimdsv2 would exempt. Only the value is exact.
resource "aws_instance" "test_imdsv1_tag_value_wrong_case" {
  provider      = aws.shared_foo_bar
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.nano"

  metadata_options {
    http_tokens   = "optional"
    http_endpoint = "enabled"
  }

  tags = {
    Name             = "test-imdsv1-tag-value-wrong-case"
    ExemptFromIMDSv2 = "True"
  }
}

# Instance 5: metadata endpoint disabled, tokens still optional (a violation)
#
# Nothing can reach IMDS here, but neither the check nor the SCP looks at the
# endpoint - http_tokens decides on its own, matching how the hop limit is
# counted. The remedy costs nothing: http_tokens = "required" is accepted
# alongside a disabled endpoint and changes no behaviour, because nothing is
# listening.
#
# http_tokens is named explicitly because this AMI sets imds-support=v2.0,
# whose "required" default would otherwise make this instance compliant and
# leave the case untested.
resource "aws_instance" "test_imds_disabled_tokens_optional" {
  provider      = aws.acme_co
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.nano"

  metadata_options {
    http_endpoint = "disabled"
    http_tokens   = "optional"
  }

  tags = {
    Name = "test-imds-disabled-tokens-optional"
  }
}
