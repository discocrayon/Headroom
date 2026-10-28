# Plans this module with the real provider and no credentials, and asserts
# on the policy document the provider renders: aws_iam_policy_document is
# computed locally, and nothing in this module reads AWS.
# tests/test_terraform_module_plans.py runs this file under tox. Every
# identifier here is a placeholder.
#
# A plan rather than a validate, because the resource clause the Lambda
# statement builds from conditionals is typed only once the list is known:
# `terraform validate` accepts a single conditional whose arms are objects
# keyed NotResource and Resource, and `terraform plan` refuses it.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "mock"
  secret_key                  = "mock"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

variables {
  target_id                           = "r-1111"
  deny_ec2_ami_owner                  = true
  ec2_allowed_ami_owners              = ["111111111111"]
  deny_ec2_imds_hop_limit             = true
  deny_ec2_imds_v1                    = true
  deny_ec2_public_ip                  = true
  deny_eks_create_cluster_without_tag = true
  deny_iam_saml_provider_not_aws_sso  = true
  deny_iam_user_creation              = true
  iam_allowed_users                   = ["arn:aws:iam::111111111111:user/breakglass"]
  deny_lambda_auth_type_none          = true
  deny_rds_unencrypted                = true
}

run "empty_public_url_list_renders_resource_star" {
  command = plan

  assert {
    condition = one([
      for statement in jsondecode(aws_organizations_policy.scp_1[0].content).Statement :
      statement.Resource == "*" && try(statement.NotResource, null) == null
      if contains(flatten([statement.Action]), "lambda:CreateFunctionUrlConfig")
    ])
    error_message = "With no public URL to spare, the Lambda statement must carry Resource \"*\" and no NotResource."
  }
}

run "populated_public_url_list_renders_not_resource" {
  command = plan

  variables {
    lambda_allowed_public_function_urls = ["arn:aws:lambda:us-east-1:111111111111:function:webhook:prod"]
  }

  assert {
    condition = one([
      for statement in jsondecode(aws_organizations_policy.scp_1[0].content).Statement :
      flatten([statement.NotResource]) == ["arn:aws:lambda:us-east-1:111111111111:function:webhook:prod"] && try(statement.Resource, null) == null
      if contains(flatten([statement.Action]), "lambda:CreateFunctionUrlConfig")
    ])
    error_message = "The Lambda statement must spare the alias-qualified ARN under NotResource and carry no Resource."
  }
}

run "function_arn_without_the_function_segment_is_rejected" {
  command = plan

  variables {
    lambda_allowed_public_function_urls = ["arn:aws:lambda:us-east-1:111111111111:webhook"]
  }

  expect_failures = [var.lambda_allowed_public_function_urls]
}
