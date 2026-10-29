terraform {
  # tests/plan.tftest.hcl overrides the organization data source, which
  # `terraform test` first supported in 1.7.0.
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # The first release whose aws_organizations_policy accepts
      # RESOURCE_CONTROL_POLICY. No lock file is committed, so the provider
      # floats above this floor.
      version = ">= 5.77.0"
    }
  }
}
