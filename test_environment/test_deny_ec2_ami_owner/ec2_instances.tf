# EC2 Test Instances for AMI Owner Testing
#
# These instances are used to test the deny_ec2_ami_owner SCP check.
# They demonstrate different AMI ownership scenarios.
# Destroy when not actively being used for testing.

# Instance 1: Amazon-owned AMI (trusted owner)
resource "aws_instance" "test_amazon_ami" {
  provider      = aws.acme_co
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t2.nano"

  tags = {
    Name    = "test-amazon-ami"
    Purpose = "Headroom AMI owner test - Amazon Linux"
  }
}

# Instance 2: Canonical-owned AMI (Ubuntu, from AWS Marketplace)
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
