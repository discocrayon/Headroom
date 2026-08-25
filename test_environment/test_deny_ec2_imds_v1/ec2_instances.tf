# EC2 Test Instances for IMDSv1/v2 Testing
#
# These instances are used to test the deny_ec2_imds_v1 SCP check.
# They should be destroyed when not actively being used for testing.

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

# Instance 3: IMDSv1 enabled, exempt through its ROLE's tag (should pass)
#
# The exemption tag is on aws_iam_role.imdsv1_exempt, not on this instance.
# That is the dimension the SCP reads. The Name tag here is only a label.
resource "aws_instance" "test_imdsv1_exempt" {
  provider             = aws.fort_knox
  ami                  = data.aws_ami.amazon_linux_2023.id
  instance_type        = "t2.nano"
  iam_instance_profile = aws_iam_instance_profile.imdsv1_exempt.name

  metadata_options {
    http_tokens   = "optional"
    http_endpoint = "enabled"
  }

  tags = {
    Name = "test-imdsv1-exempt"
  }
}

# Instance 4: IMDSv1 enabled, instance tagged exempt, role NOT tagged
#
# This is the case that used to read as exempt and is now a violation. It is
# the shape that made a clean scan meaningless: the check reported zero
# violations while the SCP would have denied every API call this instance made.
resource "aws_instance" "test_imdsv1_instance_tagged_only" {
  provider      = aws.shared_foo_bar
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.nano"

  metadata_options {
    http_tokens   = "optional"
    http_endpoint = "enabled"
  }

  tags = {
    Name             = "test-imdsv1-instance-tagged-only"
    ExemptFromIMDSv2 = "true"
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
