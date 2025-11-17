locals {
  possible_rcp_1_statements = [
    # var.deny_aoss_third_party_access
    # -->
    # Sid: DenyAossThirdPartyAccess
    # Restricts AOSS access to organization accounts and allowlisted third-party accounts
    # Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonopensearchserverless.html
    {
      include = var.deny_aoss_third_party_access,
      statement = {
        "Sid"       = "DenyAossThirdPartyAccess"
        "Principal" = "*"
        "Action" = [
          "aoss:*",
        ]
        "Resource" = "*"
        "Condition" = {
          "StringNotEqualsIfExists" = {
            "aws:PrincipalOrgID"                  = data.aws_organizations_organization.current.id
            "aws:PrincipalAccount"                = var.aoss_third_party_access_account_ids_allowlist
            "aws:ResourceTag/dp:exclude:identity" = "true"
          }
          "BoolIfExists" = {
            "aws:PrincipalIsAWSService" = "false"
          }
        }
      }
    },
    # var.deny_ecr_third_party_access
    # -->
    # Sid: DenyECRThirdPartyAccess
    # Restricts ECR access to organization accounts and allowlisted third parties
    {
      include = var.deny_ecr_third_party_access,
      statement = {
        "Sid"       = "DenyECRThirdPartyAccess"
        "Principal" = "*"
        "Action" = [
          "ecr:*",
        ]
        "Resource" = "*"
        "Condition" = {
          "StringNotEqualsIfExists" = {
            "aws:PrincipalOrgID"                  = data.aws_organizations_organization.current.id
            "aws:PrincipalAccount"                = var.ecr_third_party_access_account_ids_allowlist
            "aws:ResourceTag/dp:exclude:identity" = "true"
          }
          "BoolIfExists" = {
            "aws:PrincipalIsAWSService" = "false"
          }
        }
      }
    },
    # var.deny_kms_third_party_access
    # -->
    # Sid: DenyKMSThirdPartyAccess
    # Restricts KMS access to organization accounts and allowlisted third parties
    # Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_awskeymanagementservice.html
    {
      include = var.deny_kms_third_party_access,
      statement = {
        "Sid"       = "DenyKMSThirdPartyAccess"
        "Principal" = "*"
        "Action" = [
          "kms:*",
        ]
        "Resource" = "*"
        "Condition" = {
          "StringNotEqualsIfExists" = {
            "aws:PrincipalOrgID"                  = data.aws_organizations_organization.current.id
            "aws:PrincipalAccount"                = var.kms_third_party_access_account_ids_allowlist
            "aws:ResourceTag/dp:exclude:identity" = "true"
          }
          "BoolIfExists" = {
            "aws:PrincipalIsAWSService" = "false"
          }
        }
      }
    },
    # var.deny_s3_third_party_access
    # -->
    # Sid: DenyS3ThirdPartyAccess
    # Restricts S3 access to organization accounts and allowlisted third-party accounts
    {
      include = var.deny_s3_third_party_access,
      statement = {
        "Sid"       = "DenyS3ThirdPartyAccess"
        "Principal" = "*"
        "Action"    = "s3:*"
        "Resource"  = "*"
        "Condition" = {
          "StringNotEqualsIfExists" = {
            "aws:PrincipalOrgID"                  = data.aws_organizations_organization.current.id
            "aws:PrincipalAccount"                = var.s3_third_party_access_account_ids_allowlist
            "aws:ResourceTag/dp:exclude:identity" = "true"
          }
          "BoolIfExists" = {
            "aws:PrincipalIsAWSService" = "false"
          }
        }
      }
    },
    # var.deny_secrets_manager_third_party_access
    # -->
    # Sid: DenySecretsManagerThirdPartyAccess
    # Restricts Secrets Manager access to organization accounts and allowlisted third-party accounts
    # Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_awssecretsmanager.html
    {
      include = var.deny_secrets_manager_third_party_access,
      statement = {
        "Sid"       = "DenySecretsManagerThirdPartyAccess"
        "Principal" = "*"
        "Action" = [
          "secretsmanager:*",
        ]
        "Resource" = "*"
        "Condition" = {
          "StringNotEqualsIfExists" = {
            "aws:PrincipalOrgID"                  = data.aws_organizations_organization.current.id
            "aws:PrincipalAccount"                = var.secrets_manager_third_party_account_ids_allowlist
            "aws:ResourceTag/dp:exclude:identity" = "true"
          }
          "BoolIfExists" = {
            "aws:PrincipalIsAWSService" = "false"
          }
        }
      }
    },
    # var.deny_sqs_third_party_access
    # -->
    # Sid: DenySQSThirdPartyAccess
    # Restricts SQS access to organization accounts and allowlisted third-party accounts
    # Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonsqs.html
    {
      include = var.deny_sqs_third_party_access,
      statement = {
        "Sid"       = "DenySQSThirdPartyAccess"
        "Principal" = "*"
        "Action" = [
          "sqs:*",
        ]
        "Resource" = "*"
        "Condition" = {
          "StringNotEqualsIfExists" = {
            "aws:PrincipalOrgID"                  = data.aws_organizations_organization.current.id
            "aws:PrincipalAccount"                = var.sqs_third_party_access_account_ids_allowlist
            "aws:ResourceTag/dp:exclude:identity" = "true"
          }
          "BoolIfExists" = {
            "aws:PrincipalIsAWSService" = "false"
          }
        }
      }
    },
    # var.deny_sts_third_party_assumerole
    # -->
    # Sid: DenySTSThirdPartyAssumeRole
    # Restricts STS AssumeRole to organization identities and specified third-party accounts
    {
      include = var.deny_sts_third_party_assumerole,
      statement = {
        "Sid"       = "DenySTSThirdPartyAssumeRole"
        "Principal" = "*"
        "Action" = [
          "sts:AssumeRole",
        ]
        "Resource" = "*"
        "Condition" = {
          "StringNotEqualsIfExists" = {
            "aws:PrincipalOrgID"                  = data.aws_organizations_organization.current.id
            "aws:PrincipalAccount"                = var.sts_third_party_assumerole_account_ids_allowlist
            "aws:ResourceTag/dp:exclude:identity" = "true"
          }
          "BoolIfExists" = {
            "aws:PrincipalIsAWSService" = "false"
          }
        }
      }
    },
  ]
  # Included RCP 1 Deny Statements
  included_rcp_1_deny_statements = [
    for rcp_1_deny_statement in local.possible_rcp_1_statements :
    rcp_1_deny_statement.statement if rcp_1_deny_statement.include
  ]
  # This was done to meet the following constraints:
  # - Conditionally include statements depending on variables
  # - Conditionally include `Action`/`Condition`/`NotAction`/`NotResource` etc. inside of statements
  rcp_1_policy = {
    "Version" = "2012-10-17"
    "Statement" = [
      for statement in local.included_rcp_1_deny_statements :
      merge(statement, { Effect = "Deny" })
    ]
  }
  # See https://ramimac.me/terraform-minimized-scps for why jsonencode() is needed
  rcp_1_content = jsonencode(
    jsondecode(data.aws_iam_policy_document.rcp_1.json)
  )
  #
  # This is for validating RCP maximum length at plan time, rather than apply time
  #
  rcp_length_1 = length(local.rcp_1_content)
  # See https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html#min-max-values
  validation_check_1 = (local.rcp_length_1 <= 5120) ? "All good. This is a no-op." : error("[Error] String length exceeds 5120 characters, right now it is ${local.rcp_length_1}")
}

#
# Data sources
#

data "aws_iam_policy_document" "rcp_1" {
  source_policy_documents = [jsonencode(local.rcp_1_policy)]
}
