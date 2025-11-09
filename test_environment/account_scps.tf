# Headroom SCPs
# Attaches SCPs to accounts through module

# Headroom SCPs in Fort Knox account
module "scps_fort_knox" {
  source = "./modules/scps"
  target_id = aws_organizations_account.fort_knox.id

  # EC2
  deny_imds_v1_ec2 = true

  # IAM
  deny_iam_user_creation = false
}
