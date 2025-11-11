# EC2 Test Instances for Public IP Testing
#
# These instances are used to test the deny_ec2_public_ip SCP check.
# They should be destroyed when not actively being used for testing.
#
# ⚠️ COST WARNING: EC2 instances incur charges (~$3-5/month for t2.nano)
# Remember to destroy these resources after testing!

# Instance 1: With public IP (violation)
resource "aws_instance" "test_public_ip_violation" {
  provider               = aws.shared_foo_bar
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.nano"
  subnet_id              = data.aws_subnets.default_shared_foo_bar.ids[0]
  associate_public_ip_address = true

  tags = {
    Name    = "test-public-ip-violation"
    Purpose = "Headroom test - EC2 with public IP (violation)"
  }
}

# Instance 2: Without public IP (compliant)
resource "aws_instance" "test_no_public_ip_compliant" {
  provider               = aws.acme_co
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.nano"
  subnet_id              = data.aws_subnets.default_acme_co.ids[0]
  associate_public_ip_address = false

  tags = {
    Name    = "test-no-public-ip-compliant"
    Purpose = "Headroom test - EC2 without public IP (compliant)"
  }
}

# Instance 3: With public IP in different account (violation)
resource "aws_instance" "test_public_ip_violation_2" {
  provider               = aws.fort_knox
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "t2.nano"
  subnet_id              = data.aws_subnets.default_fort_knox.ids[0]
  associate_public_ip_address = true

  tags = {
    Name    = "test-public-ip-violation-2"
    Purpose = "Headroom test - EC2 with public IP (violation)"
  }
}
