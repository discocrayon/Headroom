locals {
  possible_scp_1_denies = [
    # var.deny_imds_v1_ec2
    # -->
    # Sid: DenyRoleDeliveryLessThan2
    # Exempts IAM roles tagged with {"ExemptFromIMDSv2": "true"}
    {
      include = var.deny_imds_v1_ec2,
      statement = {
        Action   = "*"
        Resource = "*"
        Condition = {
          "NumericLessThan" = {
            "ec2:RoleDelivery" = "2.0"
          },
          "StringNotEquals" = {
            "aws:PrincipalTag/ExemptFromIMDSv2" = "true"
          }
        }
      }
    },
    # var.deny_imds_v1_ec2
    # -->
    # Sid: DenyRunInstancesMetadataHttpTokensOptional
    # Exempts requests tagged with {"ExemptFromIMDSv2": "true"}
    {
      include = var.deny_imds_v1_ec2,
      statement = {
        Action   = "ec2:RunInstances"
        Resource = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          "StringNotEquals" = {
            "ec2:MetadataHttpTokens"          = "required",
            "aws:RequestTag/ExemptFromIMDSv2" = "true"
          },
        }
      }
    },
    # var.deny_iam_user_creation
    # -->
    # Sid: DenyIamUserCreation
    # Denies creation of IAM users not on the allowed list
    {
      include = var.deny_iam_user_creation,
      statement = {
        Action      = "iam:CreateUser"
        NotResource = var.allowed_iam_users
      }
    },
    # var.deny_saml_provider_not_aws_sso
    # -->
    # Sid: DenyCreateSamlProvider
    # Prevents creation of custom IAM SAML providers so only AWS SSO-managed providers remain.
    # AWSServiceRoleForSSO provisions the required provider in new accounts and is not affected by SCPs,
    # so a blanket deny is safe for all other principals.
    {
      include = var.deny_saml_provider_not_aws_sso,
      statement = {
        Action   = "iam:CreateSAMLProvider"
        Resource = "*"
      }
    },
    # var.deny_rds_unencrypted
    # -->
    # Sid: DenyRdsUnencrypted
    # Denies creation of unencrypted RDS databases and clusters
    # Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonrds.html
    #
    # Actions confirmed in AWS Service Authorization Reference to support rds:StorageEncrypted:
    # - rds:CreateDBCluster ✓ (create Aurora/DocumentDB cluster)
    # - rds:RestoreDBClusterFromS3 ✓ (restore cluster from S3 backup)
    # - rds:CreateBlueGreenDeployment ✓ (create blue-green deployment)
    #
    # Special exception - NOT documented but included anyway:
    # - rds:CreateDBInstance ⚠️ (create standalone RDS instance)
    #   Rationale: Critical for protecting standalone RDS instances. If condition key is not
    #   supported, the "Bool" operator will evaluate to false (key missing), causing the Deny
    #   to NOT apply, allowing the action through. If it IS supported but undocumented, we get
    #   the protection. Including it is worth the attempt.
    #   ✅ MANUALLY TESTED: Confirmed this DOES block unencrypted CreateDBInstance despite not
    #   being documented in the Service Authorization Reference. The condition key is supported.
    {
      include = var.deny_rds_unencrypted,
      statement = {
        Action = [
          "rds:CreateDBInstance",
          "rds:CreateDBCluster",
          "rds:RestoreDBClusterFromS3",
          "rds:CreateBlueGreenDeployment"
        ]
        Resource = "*"
        Condition = {
          "Bool" = {
            "rds:StorageEncrypted" = "false"
          }
        }
      }
    },
  ]
  # Included SCP 1 Deny Statements
  included_scp_1_deny_statements = [
    for scp_1_deny_statement in local.possible_scp_1_denies :
    scp_1_deny_statement.statement if scp_1_deny_statement.include
  ]
  # This was done to meet the following constraints:
  # - Conditionally include statements depending on variables
  # - Conditionally include `Action`/`Condition`/`NotAction`/`NotResource` etc. inside of statements
  scp_1_denies = {
    "Version" = "2012-10-17"
    "Statement" = [
      for statement in local.included_scp_1_deny_statements :
      merge(statement, { Effect = "Deny" })
    ]
  }
}
