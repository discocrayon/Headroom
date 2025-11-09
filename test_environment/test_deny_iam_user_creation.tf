# Test IAM users for deny_iam_user_creation SCP functionality testing
# These users test various edge cases for the IAM user creation check

# User 1: User in acme-co with default path (/)
resource "aws_iam_user" "terraform_user" {
  provider = aws.acme_co
  name     = "terraform-user"
  path     = "/"

  tags = {
    Purpose = "Terraform automation"
  }
}

# User 2: User in fort-knox with service path
resource "aws_iam_user" "github_actions" {
  provider = aws.fort_knox
  name     = "github-actions"
  path     = "/service/"

  tags = {
    Purpose = "CI/CD automation"
  }
}

# User 3: User in shared-foo-bar with default path
resource "aws_iam_user" "legacy_developer" {
  provider = aws.shared_foo_bar
  name     = "legacy-developer"
  path     = "/"

  tags = {
    Purpose = "Development access"
  }
}

# User 4: User in security-tooling with automation path
resource "aws_iam_user" "cicd_deployer" {
  provider = aws.security_tooling
  name     = "cicd-deployer"
  path     = "/automation/"

  tags = {
    Purpose = "CI/CD deployments"
  }
}

# User 5: User in acme-co with contractors path
resource "aws_iam_user" "temp_contractor" {
  provider = aws.acme_co
  name     = "temp-contractor"
  path     = "/contractors/"

  tags = {
    Purpose = "Contractor access"
  }
}
