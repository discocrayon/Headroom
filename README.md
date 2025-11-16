# Headroom

[![Python Version](https://img.shields.io/badge/python-3.13%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Code Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](tests/)

**Audit mode for AWS SCPs and RCPs** - Analyze your AWS Organization, identify policy violations, and auto-generate enforcement policies that won't disrupt operations.

> ⚠️ **Status**: Proof-of-concept. Review all output before deploying to production.

## What is Headroom?

Headroom scans your AWS Organization to:
1. **Prevent new violations** by deploying SCPs/RCPs at the optimal level (root, OU, or account)
2. **Identify existing violations** with detailed reports
3. **Generate Terraform** with smart allowlists (e.g., approved IAM users, third-party accounts)

Think "audit mode" for AWS policy enforcement - see what *would* break before you enforce anything.

## Quick Example

```bash
# Scan your AWS Organization
$ python -m headroom --config config.yaml

# Get placement recommendations
Check: deny_imds_v1_ec2
Recommended Level: ROOT
Affected Accounts: 4
Compliance: 100.0%
Reasoning: All accounts have zero violations - safe to deploy at root level

# Review auto-generated Terraform
$ cat test_environment/scps/root_scps.tf
```

**What you get**:
- JSON violation reports for every account
- Terraform SCP/RCP configurations ready to deploy
- Intelligent placement recommendations (root/OU/account level)

## Installation

```bash
# Clone and install
git clone https://github.com/discocrayon/Headroom
cd headroom
pip install -r requirements.txt
```

**Requirements**:
- Python 3.13+
- AWS CLI configured
- IAM roles deployed ([see detailed setup](documentation/SETUP.md))

## Quick Start

### 1. Deploy IAM Roles

Deploy two types of roles in your AWS Organization:
- `Headroom` role in all accounts you want to scan
- `OrgAndAccountInfoReader` role in management account

See [detailed setup guide](documentation/SETUP.md) for Terraform examples.

### 2. Create Configuration

```yaml
# config.yaml
management_account_id: '222222222222'

# Optional - only needed if running from management account
# security_analysis_account_id: '111111111111'

exclude_account_ids: false
use_account_name_from_tags: false

account_tag_layout:
  environment: 'Environment'
  name: 'Name'
  owner: 'Owner'
```

### 3. Run Analysis

```bash
python -m headroom --config config.yaml
```

### 4. Review Results

**JSON reports** in `test_environment/headroom_results/`:
- `scps/deny_imds_v1_ec2/{account}.json` - EC2 IMDSv1 violations
- `scps/deny_iam_user_creation/{account}.json` - IAM users found
- `rcps/third_party_assumerole/{account}.json` - External account access
- `rcps/deny_s3_third_party_access/{account}.json` - S3 third-party access
- And more...

**Terraform configs** in `test_environment/scps/` and `test_environment/rcps/`:
- `root_scps.tf` - Organization-wide policies
- `{ou_name}_rcps.tf` - OU-level policies
- `grab_org_info.tf` - Organization structure

See [full examples](documentation/EXAMPLES.md).

## Features

### SCP Checks
- **EC2 IMDSv1**: Enforce IMDSv2 on all instances (supports exemption tags)
- **EKS Paved Road**: Require `PavedRoad=true` tag on clusters
- **IAM User Creation**: Restrict to approved users (auto-generates allowlists)
- **RDS Encryption**: Block unencrypted databases

### RCP Checks
- **Third-Party AssumeRole**: Control external AWS account access
- **S3 Third-Party Access**: Manage cross-account S3 permissions
- **AOSS Third-Party Access**: OpenSearch Serverless access control
- **ECR Third-Party Access**: Container registry sharing controls

[View detailed check documentation](documentation/CHECKS.md)

### Key Capabilities
- **Multi-region scanning** for comprehensive coverage
- **Smart placement logic** recommends root/OU/account-level deployment
- **Allowlist generation** for IAM users and third-party accounts
- **Exemption support** via resource tags
- **100% test coverage** with type safety

## How It Works

Headroom uses a hub-and-spoke model:

```
Security Analysis Account
    ├─> Management Account (read org structure)
    ├─> Production Account 1 (scan resources)
    ├─> Production Account 2 (scan resources)
    └─> Development Accounts... (scan resources)
```

**Execution flow**:
1. Assume role in management account to get org structure
2. Assume role in each member account to scan resources
3. Analyze compliance and determine optimal policy placement
4. Generate Terraform with smart allowlists

[View detailed architecture](documentation/ARCHITECTURE.md)

## Sample Output

### CLI Output
```
================================================================================
SCP/RCP PLACEMENT RECOMMENDATIONS
================================================================================

Check: deny_iam_user_creation
Recommended Level: ROOT
Compliance: 100.0%
Reasoning: All existing IAM users added to allowlist - safe for root deployment
```

### Generated Terraform
```hcl
module "scps_root" {
  source = "../modules/scps"
  target_id = local.root_ou_id

  deny_iam_user_creation = true
  allowed_iam_users = [
    "arn:aws:iam::${local.security_account_id}:user/automation/cicd",
    "arn:aws:iam::${local.prod_account_id}:user/terraform-user",
  ]
}
```

[View more examples](documentation/EXAMPLES.md)

## Current Status

✅ **Working**:
- Multi-account AWS Organizations scanning
- SCP checks: EC2 IMDSv1, IAM users, EKS tags, RDS encryption
- RCP checks: IAM trust policies, S3/AOSS/ECR third-party access
- Terraform auto-generation with allowlists
- JSON violation reports
- Smart placement recommendations

🚧 **Coming Soon** ([see roadmap](ROADMAP.md)):
- CloudTrail integration for wildcard principal analysis
- Terraform auto-remediation
- Detection of policy-blocked activity
- Configurable exemption handling

## Documentation

- **[Setup Guide](documentation/SETUP.md)** - Detailed IAM role setup and configuration
- **[Architecture](documentation/ARCHITECTURE.md)** - Module structure and execution flow
- **[Check Reference](documentation/CHECKS.md)** - Detailed documentation of all checks
- **[Examples](documentation/EXAMPLES.md)** - Full Terraform and JSON output examples
- **[Adding Checks](HOW_TO_ADD_A_CHECK.md)** - Guide for contributing new checks
- **[Roadmap](ROADMAP.md)** - Future plans and ideas

## Testing

```bash
# Run full test suite with coverage
tox

# Run specific tests
pytest tests/test_analysis.py

# Type checking
mypy headroom/ tests/
```

**Quality standards**:
- 100% test coverage required
- Strict mypy type checking
- Pre-commit hooks for formatting

## CLI Reference

```bash
python -m headroom --help

Options:
  --config CONFIG              Path to config YAML (required)
  --results-dir RESULTS_DIR    Results output directory
  --scps-dir SCPS_DIR         SCP Terraform output directory
  --rcps-dir RCPS_DIR         RCP Terraform output directory
```

## Test Environment

The [`test_environment/`](test_environment/) contains:
- Complete Terraform for a sample AWS Organization
- All required IAM roles
- Example SCPs and RCPs
- Sample test resources

Apply this Terraform from your management account to create a working demo environment.

## Contributing

We welcome contributions! Here's how to get started:

1. Read [CONTRIBUTING.md](CONTRIBUTING.md) for general guidelines
2. Check out [HOW_TO_ADD_A_CHECK.md](HOW_TO_ADD_A_CHECK.md) to add new policy checks
3. Review our [plugin system](documentation/CHECKS.md) for extensibility
4. Ensure 100% test coverage and run `tox` before submitting

**Good first issues**: Look for checks that follow similar patterns to existing ones.

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## Acknowledgments

Created to enable teams to safely roll out AWS policy enforcement without breaking existing workloads. Inspired by the need for "audit mode" in cloud security.
