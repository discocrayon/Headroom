locals {
  possible_scp_1_denies = [
    # var.deny_ec2_ami_owner
    # -->
    # Sid: DenyEc2AmiOwner
    # Denies launching EC2 instances unless AMI owner is in allowlist
    # Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html
    # Uses ec2:Owner condition key which contains the AMI owner account ID or alias
    #
    # The resource is the AMI, not the instance. RunInstances is authorized
    # against every resource it touches - instance, volume, network interface,
    # image - and ec2:Owner exists only on the image. Scoped to instance/*, the
    # key is absent from the request context, StringNotEquals on an absent key
    # is true, and the Deny matches every launch regardless of AMI.
    #
    # StringNotEquals is deliberately not StringNotEqualsIfExists: should AWS
    # ever stop populating ec2:Owner, denying the launch is the safe direction
    # for a Deny statement.
    #
    # The image ARN has an empty account field: AMIs are region-scoped.
    #
    # The actions are launch paths AWS authorizes against the image resource
    # with ec2:Owner, taken from the machine-readable service reference at
    # https://servicereference.us-east-1.amazonaws.com/v1/ec2/ec2.json
    #
    # ec2:ModifyFleet supports the key too - raising a fleet's target capacity
    # launches from its launch template's AMI - and is left out as a
    # deliberate scope decision, not an oversight.
    #
    # Absent for a different reason: ec2:RunScheduledInstances,
    # ec2:ModifySpotFleetRequest and ec2:CreateLaunchTemplateVersion list no
    # image resource at all, so a statement scoped to image/* never matches
    # them. Adding them would read as coverage while denying nothing.
    {
      include = var.deny_ec2_ami_owner,
      statement = {
        Action = [
          "ec2:CreateFleet",
          "ec2:RequestSpotFleet",
          "ec2:RequestSpotInstances",
          "ec2:RunInstances",
        ]
        Resource = "arn:aws:ec2:*::image/*"
        Condition = {
          "StringNotEquals" = {
            "ec2:Owner" = var.ec2_allowed_ami_owners
          }
        }
      }
    },
    # var.deny_ec2_imds_hop_limit
    # -->
    # Sid: MaxImdsHopLimit
    # Denies launching EC2 instances whose IMDS hop limit exceeds 1
    # Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html
    # A hop limit above 1 lets the metadata response cross an extra network hop
    #
    # Deliberately NO ec2:MetadataHttpEndpoint clause, matching
    # DenyRunInstancesMetadataHttpTokensOptional below. Both statements ignore
    # the endpoint, and both scanners count their key whether the endpoint is
    # on or off. Adding a clause to either would be a reasonable-looking change
    # and is not wanted: it would put policy and scan back out of step, in the
    # direction where the policy is looser than the scan rather than stricter.
    #
    # Measured against a live account with RunInstances --dry-run:
    #
    #   hop=3, endpoint=enabled                    DENY
    #   hop=1, endpoint=enabled                    allow
    #   hop=3, endpoint=disabled                   DENY   <- counted, so the
    #                                                        scanner counts it
    #   endpoint=disabled, no hop                  allow  (key absent, and
    #                                                        NumericGreaterThan
    #                                                        on an absent key
    #                                                        is false)
    #   no MetadataOptions, AMI imds-support=v2.0  DENY   <- the AMI supplies a
    #                                                        hop limit above 1
    #   no MetadataOptions, AMI without it         allow
    #
    # Two documented claims this disproves. AWS does NOT require HttpEndpoint
    # enabled when HttpPutResponseHopLimit is specified, whatever the EC2 guide
    # says about modify-instance-metadata-options; RunInstances accepts the
    # combination. And a modern AMI defaults above this threshold, so this
    # statement denies a default Amazon Linux 2023 launch - whether a threshold
    # of 1 is right for such a fleet is an operator decision, not one this
    # module makes.
    {
      include = var.deny_ec2_imds_hop_limit,
      statement = {
        Action   = "ec2:RunInstances"
        Resource = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          "NumericGreaterThan" = {
            "ec2:MetadataHttpPutResponseHopLimit" = "1"
          }
        }
      }
    },
    # var.deny_ec2_imds_v1
    # -->
    # Sid: DenyRunInstancesMetadataHttpTokensOptional
    # Denies launching an EC2 instance that would answer IMDSv1
    # Exempts requests tagged with {"ExemptFromIMDSv2": "true"}
    #
    # Keys within one operator block are ANDed, so the launch is denied unless
    # it either requires tokens or carries the exemption tag.
    #
    # This is the whole of var.deny_ec2_imds_v1. It governs launches and
    # nothing else: an instance already running with IMDSv1 available is
    # outside what this variable denies, and stays reachable over IMDSv1 for
    # as long as it lives. That is a scope decision, not a gap - such
    # instances are expected to be migrated, and the SCP's job is to stop new
    # ones appearing while that happens.
    #
    # A DenyRoleDeliveryLessThan2 statement used to sit above this one, on the
    # same variable, denying every API call made with credentials fetched over
    # IMDSv1 and exempting by aws:PrincipalTag/ExemptFromIMDSv2 on the calling
    # role. It was removed rather than split. One variable gating two
    # statements meant one scan verdict licensing two different pieces of
    # evidence, and a role-tagged IMDSv1 instance was reported as a clean
    # exemption while this statement - which reads no role tag - would have
    # denied that account's next launch.
    #
    # Deliberately NO ec2:MetadataHttpEndpoint clause, matching MaxImdsHopLimit
    # above. A launch that turns IMDS off usually names no HttpTokens, so
    # ec2:MetadataHttpTokens is absent, StringNotEquals on an absent key is
    # true, and the deny fires - such a launch has to say HttpTokens=required
    # to get through. That is accepted: AWS does NOT reject HttpTokens
    # alongside HttpEndpoint=disabled at RunInstances, whatever the EC2 guide
    # says about modify-instance-metadata-options, and the extra parameter
    # changes no behaviour because nothing is listening. Requiring it keeps
    # this statement and its scanner reading one thing, HttpTokens, instead of
    # two.
    #
    # Measured against a live account with RunInstances --dry-run:
    #
    #   AMI without imds-support=v2.0 (Amazon Linux 2)
    #     tokens=required, endpoint=enabled    allow
    #     tokens=optional, endpoint=enabled    DENY
    #     endpoint=disabled, no tokens         DENY   <- must set tokens
    #     no MetadataOptions at all            DENY
    #
    #   AMI with imds-support=v2.0 (Amazon Linux 2023)
    #     every row                            allow, except tokens=optional
    #
    # That second block is the surprise: ec2:MetadataHttpTokens resolves from
    # the EFFECTIVE metadata configuration, not only from literal request
    # parameters. An AMI carrying imds-support=v2.0 populates it as "required"
    # even when the request names no MetadataOptions, so a modern-AMI fleet
    # never reaches this deny. Whether an account-level default does the same
    # is untested - the probe account had none set - but the AMI result makes
    # it likely.
    #
    # The absent-key direction is deliberate: StringNotEquals rather than the
    # IfExists form, so a request leaving the key absent with nothing supplying
    # a default is denied. The AL2 rows above are that case.
    {
      include = var.deny_ec2_imds_v1,
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
    # var.deny_ec2_public_ip
    # -->
    # Sid: DenyEc2PublicIp
    # Denies creation of EC2 instances with public IP addresses
    # Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html
    {
      include = var.deny_ec2_public_ip,
      statement = {
        Action   = "ec2:RunInstances"
        Resource = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          "Bool" = {
            "ec2:AssociatePublicIpAddress" = "true"
          }
        }
      }
    },
    # var.deny_eks_create_cluster_without_tag
    # -->
    # Sid: DenyEksCreateClusterWithoutTag
    # Denies EKS cluster creation unless PavedRoad=true tag is present
    # Encourages use of approved automation (paved road approach)
    # Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonelastickubernetesservice.html
    {
      include = var.deny_eks_create_cluster_without_tag,
      statement = {
        Action   = "eks:CreateCluster"
        Resource = "*"
        Condition = {
          "StringNotEquals" = {
            "aws:RequestTag/PavedRoad" = "true"
          }
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
        NotResource = var.iam_allowed_users
      }
    },
    # var.deny_iam_saml_provider_not_aws_sso
    # -->
    # Sid: DenyCreateSamlProvider
    # Prevents creation of custom IAM SAML providers so only AWS SSO-managed providers remain.
    # AWSServiceRoleForSSO provisions the required provider in new accounts and is not affected by SCPs,
    # so a blanket deny is safe for all other principals.
    {
      include = var.deny_iam_saml_provider_not_aws_sso,
      statement = {
        Action   = "iam:CreateSAMLProvider"
        Resource = "*"
      }
    },
    # var.deny_lambda_auth_type_none
    # -->
    # Sid: DenyPublicFunctionUrls
    # Denies Lambda function URLs with no authentication (auth type NONE)
    # Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_awslambda.html
    {
      include = var.deny_lambda_auth_type_none,
      statement = {
        Action = [
          "lambda:CreateFunctionUrlConfig",
          "lambda:UpdateFunctionUrlConfig",
          "lambda:AddPermission"
        ]
        Resource = "*"
        Condition = {
          "StringEquals" = {
            "lambda:FunctionUrlAuthType" = "NONE"
          }
        }
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
    # Automatic root guardrail
    # -->
    # Sid: DenyRootLeaveOrganization
    # Applies when module target is the root (IDs prefixed with r-)
    {
      include = startswith(var.target_id, "r-"),
      statement = {
        Action   = "organizations:LeaveOrganization"
        Resource = "*"
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
