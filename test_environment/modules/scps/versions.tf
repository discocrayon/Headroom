terraform {
  # tests/test_terraform_module_plans.py plans this module and the RCP module
  # under one binary, and the RCP module's tests/plan.tftest.hcl overrides a
  # data source, which `terraform test` first supported in 1.7.0.
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # The floor the RCP module needs, shared so one gate runs both modules
      # against one provider range. No lock file is committed, so the
      # provider floats above it.
      version = ">= 5.77.0"
    }
  }
}
