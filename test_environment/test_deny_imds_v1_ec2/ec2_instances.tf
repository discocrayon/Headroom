# EC2 Test Instances for IMDSv1/v2 Testing
#
# These instances are used to test the deny_imds_v1_ec2 SCP check.
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

# Instance 3: IMDSv1 enabled but tagged as exempt (should pass the check)
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
