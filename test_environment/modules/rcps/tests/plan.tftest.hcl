# Plans this module with the real provider and no credentials, and asserts
# on the policy document the provider renders. aws_iam_policy_document is
# computed locally; aws_organizations_organization is the one read that
# would call AWS, and is overridden below. tests/test_terraform_module_plans.py
# runs this file under tox. Every identifier here is a placeholder.
#
# A plan rather than a validate, because the resource clauses the S3 and
# SQS statements build from conditionals are typed only once the list is
# known: `terraform validate` accepted a single conditional whose arms were
# objects keyed NotResource and Resource, and `terraform plan` refused it.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "mock"
  secret_key                  = "mock"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}

override_data {
  target = data.aws_organizations_organization.current
  values = {
    id = "o-1111111111"
  }
}

variables {
  target_id                               = "r-1111"
  deny_ecr_third_party_access             = true
  deny_kms_third_party_access             = true
  deny_s3_third_party_access              = true
  deny_secrets_manager_third_party_access = true
  deny_sqs_third_party_access             = true
  deny_sts_third_party_assumerole         = true
  deny_service_confused_deputy            = true
}

run "empty_exempt_lists_render_resource_star" {
  command = plan

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_organizations_policy.rcp_1.content).Statement :
      statement.Resource == "*" && try(statement.NotResource, null) == null
    ])
    error_message = "With no bucket or queue to spare, every statement must carry Resource \"*\" and no NotResource."
  }

  assert {
    condition     = length(jsondecode(aws_organizations_policy.rcp_1.content).Statement) == 7
    error_message = "Every registered RCP check is enabled, so the document must carry seven statements."
  }
}

run "populated_exempt_lists_render_not_resource" {
  command = plan

  variables {
    s3_third_party_access_exempt_bucket_arns = ["arn:aws:s3:::bucket-111111111111"]
    sqs_third_party_access_exempt_queue_arns = ["arn:aws:sqs:us-east-1:111111111111:queue-1"]
  }

  assert {
    condition = flatten([one([
      for statement in jsondecode(aws_organizations_policy.rcp_1.content).Statement :
      statement.NotResource if statement.Sid == "DenyS3ThirdPartyAccess"
    ])]) == ["arn:aws:s3:::bucket-111111111111", "arn:aws:s3:::bucket-111111111111/*"]
    error_message = "The S3 statement must spare the bucket and its objects under NotResource."
  }

  assert {
    condition = flatten([one([
      for statement in jsondecode(aws_organizations_policy.rcp_1.content).Statement :
      statement.NotResource if statement.Sid == "DenySQSThirdPartyAccess"
    ])]) == ["arn:aws:sqs:us-east-1:111111111111:queue-1"]
    error_message = "The SQS statement must spare the queue ARN as recorded under NotResource."
  }

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_organizations_policy.rcp_1.content).Statement :
      try(statement.Resource, null) == null
      if contains(["DenyS3ThirdPartyAccess", "DenySQSThirdPartyAccess"], statement.Sid)
    ])
    error_message = "A statement sparing by NotResource must not also carry Resource."
  }
}

run "bucket_arn_with_object_key_is_rejected" {
  command = plan

  variables {
    s3_third_party_access_exempt_bucket_arns = ["arn:aws:s3:::bucket-111111111111/key"]
  }

  expect_failures = [var.s3_third_party_access_exempt_bucket_arns]
}

run "queue_arn_without_account_is_rejected" {
  command = plan

  variables {
    sqs_third_party_access_exempt_queue_arns = ["arn:aws:sqs:us-east-1:queue-1"]
  }

  expect_failures = [var.sqs_third_party_access_exempt_queue_arns]
}
