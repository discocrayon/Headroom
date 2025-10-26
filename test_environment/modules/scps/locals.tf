locals {
  possible_scp_1_denies = [
    # var.deny_imds_v1_ec2
    # -->
    # Sid: DenyRoleDeliveryLessThan2
    # Exempts IAM roles tagged with {"ExemptFromIMDSv2": "true"}
    {
      include   = var.deny_imds_v1_ec2,
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
        Action = "ec2:RunInstances"
        Resource = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          "StringNotEquals" = {
            "ec2:MetadataHttpTokens" = "required",
            "aws:RequestTag/ExemptFromIMDSv2" = "true"
          },
        }
      }
    },
  ]
  # Included SCP 1 Deny Statements
  included_scp_1_deny_statements = [
      for scp_1_deny_statement in local.possible_scp_1_denies:
      scp_1_deny_statement.statement if scp_1_deny_statement.include
  ]
  # This was done to meet the following constraints:
  # - Conditionally include statements depending on variables
  # - Conditionally include `Action`/`Condition`/`NotAction`/`NotResource` etc. inside of statements
  scp_1_denies = {
    "Version"   = "2012-10-17"
    "Statement" = [
      for statement in local.included_scp_1_deny_statements :
        merge(statement, { Effect = "Deny" })
    ]
  }
}
