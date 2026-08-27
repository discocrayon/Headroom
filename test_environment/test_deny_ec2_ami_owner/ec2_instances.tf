# EC2 Test Instances for AMI Owner Testing
#
# These instances are used to test the deny_ec2_ami_owner SCP check.
# They demonstrate different AMI ownership scenarios.
# Destroy when not actively being used for testing.
#
# What the check records is the value ec2:Owner will hold when the instance
# relaunches, NOT the AMI's OwnerId. Those differ: DescribeImages returns
# OwnerId (always the publishing account) and ImageOwnerAlias (only for
# Amazon and Marketplace images) as separate fields, and ec2:Owner takes the
# alias whenever there is one. Measured with RunInstances --dry-run against
# the shipped statement: an allowlist of Amazon Linux 2023's numeric OwnerId
# DENIES its own relaunch, while ["amazon"] allows it. An alias-free AMI is
# the opposite - its numeric OwnerId allows and "amazon" denies.
#
# Allowlisting an alias is broader than the AMI observed: ec2:Owner offers no
# narrower form, so "amazon" permits every Amazon-published AMI. That is the
# cost of a working policy, not a choice between broad and narrow.

# Instance 1: Amazon-owned AMI (trusted owner)
#
# Recorded as "amazon" - Amazon Linux 2023 carries ImageOwnerAlias = amazon,
# so its publishing account never appears in the allowlist.
resource "aws_instance" "test_amazon_ami" {
  provider      = aws.acme_co
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.nano"

  tags = {
    Name    = "test-amazon-ami"
    Purpose = "Headroom AMI owner test - Amazon Linux"
  }
}

# Instance 2: Canonical-published Ubuntu, listed through AWS Marketplace
#
# Recorded as "aws-marketplace", not Canonical's account. Measured by survey:
# every Canonical image DescribeImages returned carried the Marketplace
# alias, as did every Debian one. Rocky Linux, AlmaLinux and Fedora/CentOS
# publish directly and carry no alias at all.
resource "aws_instance" "test_marketplace_ami" {
  provider      = aws.shared_foo_bar
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t2.nano"

  tags = {
    Name    = "test-marketplace-ami"
    Purpose = "Headroom AMI owner test - Ubuntu from Canonical"
  }
}

# Instance 3: Custom account-owned AMI
#
# This is the only instance here that would exercise the alias-free branch,
# where ec2:Owner is the numeric OwnerId - the golden-image case most real
# organizations hit. Instances 1 and 2 both resolve to aliases, so as written
# this environment tests only half the rule.
#
# Note: This requires creating a custom AMI first
# Uncomment after creating a custom AMI in the account
# resource "aws_instance" "test_custom_ami" {
#   provider      = aws.fort_knox
#   ami           = "ami-custom123456"  # Replace with actual custom AMI
#   instance_type = "t2.nano"
#
#   tags = {
#     Name    = "test-custom-ami"
#     Purpose = "Headroom AMI owner test - Custom AMI"
#   }
# }
