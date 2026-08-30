# EC2 Test Instances for IMDS Hop Limit Testing
#
# These instances are used to test the deny_ec2_imds_hop_limit SCP check.
# They should be destroyed when not actively being used for testing.

# Instance 1: hop limit 2 (should be flagged by the check)
resource "aws_instance" "test_hop_limit_two" {
  provider      = aws.shared_foo_bar
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.nano"

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 2
  }

  tags = {
    Name = "test-imds-hop-limit-two"
  }
}

# Instance 2: hop limit 1 (should pass the check)
resource "aws_instance" "test_hop_limit_one" {
  provider      = aws.acme_co
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.nano"

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  tags = {
    Name = "test-imds-hop-limit-one"
  }
}

# Instance 3: IMDS disabled entirely (should pass the check regardless of hop limit)
resource "aws_instance" "test_imds_disabled" {
  provider      = aws.fort_knox
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.nano"

  metadata_options {
    http_endpoint = "disabled"
  }

  tags = {
    Name = "test-imds-disabled"
  }
}

# Instance: hop limit above 1 with the metadata endpoint disabled
#
# The regression case. The hop limit is inert on this running instance - no
# IMDS is listening for a hop to cross - but the SCP is evaluated against the
# launch request, and AWS accepts a request naming both. A dry run against a
# live account confirms MaxImdsHopLimit denies exactly this shape, so the check
# must report it a violation. Reporting it compliant, which it used to, cleared
# accounts whose relaunches the SCP would deny.
resource "aws_instance" "test_hop_limit_high_imds_disabled" {
  provider      = aws.shared_foo_bar
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.nano"

  metadata_options {
    http_endpoint               = "disabled"
    http_put_response_hop_limit = 3
  }

  tags = {
    Name = "test-hop-limit-high-imds-disabled"
  }
}
