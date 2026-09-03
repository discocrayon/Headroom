# Test environment

A complete, reproducible AWS Organization for testing Headroom against real AWS.
Everything here is real infrastructure with real cost, and nothing runs it for
you: it is not a `tox` step, and the repository has no `.github/` directory and
no workflow. Standing it up is always a deliberate act. See
[`../spec/verification/strategy.md`](../spec/verification/strategy.md) for what
does run.

This document is operational. The normative behavior it exercises is specified in
[`../spec/README.md`](../spec/README.md).

## What it is for

| Purpose | |
|---|---|
| Live integration testing | Confirm a generated policy actually denies what its check predicted |
| Reproducible demo | Anyone with an AWS Organization can stand up the same scenarios |
| Example outputs | `headroom_results/`, `scps/`, and `rcps/` are committed as worked examples |

A live result is evidence about **AWS**, not about Headroom. Where the two
disagree, the finding belongs in the affected check's specification under
[`../spec/checks/`](../spec/checks/index.md), measured with a `--dry-run` probe
and cited there.

## Topology

Four member accounts across three OUs, plus the management account:

```
Organization root
├── high_value_assets/     fort-knox, security-tooling
├── shared_services/       shared-foo-bar
└── acme_acquisition/      acme-co
```

Account emails are derived from a single `base_email` variable using plus
addressing, so one mailbox stands up the whole organization.

| File | Creates |
|---|---|
| `organizational_units.tf` | The three OUs |
| `accounts.tf` | The four member accounts |
| `headroom_roles.tf`, `modules/headroom_role/` | The `Headroom` role in each account |
| `org_and_account_info_reader.tf` | The `OrgAndAccountInfoReader` role in the management account |
| `providers.tf`, `data.tf`, `variables.tf` | Provider and input plumbing |

The `Headroom` role is granted the `ViewOnlyAccess` and `SecurityAudit` managed
policies. Role setup for a real organization is documented in
[`../documentation/SETUP.md`](../documentation/SETUP.md).

## Scenarios

Each scenario deliberately creates violations, exemptions, and compliant
resources for one check, so a run has something to find. Scenarios are either a
bare `.tf` file or a directory with its own `README.md`.

| Check | Scenario |
|---|---|
| `deny_ec2_ami_owner` | `test_deny_ec2_ami_owner/` |
| `deny_ec2_imds_hop_limit` | `test_deny_ec2_imds_hop_limit/` |
| `deny_ec2_imds_v1` | `test_deny_ec2_imds_v1/` |
| `deny_ec2_public_ip` | `test_deny_ec2_public_ip/` |
| `deny_iam_saml_provider_not_aws_sso` | `test_deny_iam_saml_provider_not_aws_sso.tf` |
| `deny_iam_user_creation` | `test_deny_iam_user_creation.tf` |
| `deny_lambda_auth_type_none` | `test_deny_lambda_auth_type_none.tf`, `test_deny_lambda_auth_type_none/` |
| `deny_rds_unencrypted` | `test_deny_rds_unencrypted/` |
| `deny_ecr_third_party_access` | `test_deny_ecr_third_party_access.tf` |
| `deny_kms_third_party_access` | `test_deny_kms_third_party_access.tf`, `test_deny_kms_third_party_access/` |
| `deny_s3_third_party_access` | `test_deny_s3_third_party_access.tf` |
| `deny_secrets_manager_third_party_access` | `test_deny_secrets_manager_third_party_access.tf`, `test_deny_secrets_manager_third_party_access/` |
| `deny_sqs_third_party_access` | `test_deny_sqs_third_party_access.tf` |
| `deny_sts_third_party_assumerole` | `test_deny_sts_third_party_assumerole.tf` |

Two of the sixteen registered checks have no live scenario, for different
reasons, and both are covered by unit tests only.

`deny_eks_create_cluster_without_tag` would need an EKS control plane, the most
expensive resource any check requires.

`deny_service_confused_deputy` issues no AWS call of its own. It re-runs the six
analyzers the other RCP checks use and reads `service_principal_sources` off
each result, so giving it something to find means a resource policy that grants
a service principal under a source guard. None of the six resource-policy
scenarios above carries either, so the check runs against this organization and
correctly finds nothing.

With no scenario directory applied, the five checks those directories cover —
`deny_ec2_ami_owner`, `deny_ec2_imds_hop_limit`, `deny_ec2_imds_v1`,
`deny_ec2_public_ip`, and `deny_rds_unencrypted` — run against an organization
holding none of their resources and correctly report nothing, so a clean result
from those five is evidence about the environment rather than about the checks.

## Running it

Apply from the **management account**, which is the only identity that can create
organization accounts and OUs.

```bash
cd test_environment
cp terraform.tfvars.example terraform.tfvars   # set base_email
terraform init && terraform apply          # organization, OUs, accounts, roles, and the nine bare-file scenarios
```

`terraform.tfvars` holds a real email address — every account created here needs
a unique one, so it is typically a personal address with plus-addressing. It is
gitignored and must stay that way. Only `terraform.tfvars.example` is committed.

`terraform validate` currently fails against this root configuration, and so do
`plan`, `apply`, and `destroy`: several bare scenario files redeclare provider
aliases, `aws_caller_identity` data sources, and local values that another file
in the same root module already declares. Terraform rejects each duplicate while
loading the configuration, before any command reaches a plan — so the
`terraform apply` above and the `terraform destroy` under Cleanup cannot complete
either. Fixing the `.tf` files is a separate change, out of scope for this
document.

This root configuration reaches the top-level `.tf` files and the four `module`
blocks in `headroom_roles.tf`, all of which point at `./modules/headroom_role`.
It reaches nothing else: Terraform loads a subdirectory only when a `module`
block names it, and none names a `test_deny_*/` directory. So the root apply
creates the organization, the OUs, the four accounts, the roles, and the nine
bare-file scenarios named in the Scenarios table above.

A `test_deny_*/` directory holding `.tf` files is therefore its own root
configuration, applied from inside that directory:

```bash
cd test_deny_ec2_imds_v1                   # one scenario, applied on its own
terraform init && terraform apply
cd ..
```

The `test_deny_*/` directories the Scenarios table pairs with a bare `.tf` file
hold no `.tf` files of their own, so there is nothing to apply inside any of
them. Each holds a `README.md` walkthrough of the scenario that bare file
creates at the root; `test_deny_lambda_auth_type_none/` additionally holds the
Lambda deployment package that `test_deny_lambda_auth_type_none.tf` reads via
`path.module`, not a `module` block.

Whether or not a scenario directory was applied, return to the repository root
before running Headroom:

```bash
cd ..
```

Then run Headroom against it from the security analysis account:

```bash
python -m headroom --config config.yaml
```

Results land in `test_environment/headroom_results/`, and generated Terraform in
`test_environment/scps/` and `test_environment/rcps/`. Both directories are
reconciled to the current run — a target that drops out of the recommendations
loses its file — so a diff there is the run's output, not an accumulation. See
[`../spec/contracts/terraform.md`](../spec/contracts/terraform.md).

To re-run a check, delete its result file. Existing results are treated as done
and are never refreshed on their own; see
[`../spec/contracts/results.md`](../spec/contracts/results.md).

## Cost

Organizations, OUs, IAM roles, IAM users, KMS aliases, and data sources are free.
The billable resources are:

| Resource | Count | Class |
|---|---|---|
| EC2 instances | 14 | `t2.nano` |
| RDS instances | 2 | `db.t3.micro` (`mysql`, `postgres`) |
| Aurora clusters | 2 | `aurora-mysql`, `aurora-postgresql` |
| Aurora cluster instances | 2 | `db.t3.medium` |
| KMS customer-managed keys | see `test_deny_kms_third_party_access.tf` | — |
| Secrets Manager secrets | see `test_deny_secrets_manager_third_party_access.tf` | — |

No dollar figure is quoted here on purpose: it depends on region and on which
scenarios are applied, and four different figures in the old specification had
all gone stale. Price the table above with the
[AWS Pricing Calculator](https://calculator.aws/) for your region before applying.

The databases dominate. `db.t3.medium` Aurora instances and always-on RDS
instances cost substantially more than the EC2 fleet.

## Cleanup

```bash
terraform destroy
```

Run from `test_environment`, this destroys the organization, the OUs, the
accounts, the roles, and the nine bare-file scenarios — everything the root
`terraform apply` creates.

Two things `destroy` will not do:

1. **Member accounts are not deleted.** AWS Organizations accounts cannot be
   destroyed by Terraform. Closing one is a manual, ~90-day process from the
   console. Plan to reuse the accounts rather than recreate them.
2. **Secrets are not removed immediately.** Secrets Manager applies a recovery
   window; a secret continues to incur cost until it elapses, and its name cannot
   be reused before then.

`terraform destroy -target=module.<name>` cannot reach a separate root
configuration — there is no such module. Stopping the cost means running
`terraform destroy` inside each scenario directory that was applied. The
scenario directories that create billable resources are
`test_deny_ec2_ami_owner`, `test_deny_ec2_imds_hop_limit`,
`test_deny_ec2_imds_v1`, `test_deny_ec2_public_ip`, and
`test_deny_rds_unencrypted`.

## Committed outputs

`headroom_results/`, `scps/`, and `rcps/` are committed deliberately, as worked
examples of what a run produces. They are illustrative, not normative: where they
disagree with [`../spec/`](../spec/README.md), the specification is right and the
committed output is stale.

**One real AWS account ID is committed here**: the operating-system publisher
that owns the public Ubuntu images, named as the owner filter in
`test_deny_ec2_ami_owner/data.tf`. That lookup is live, so a fabricated owner
resolves to no AMI and the scenario launches nothing. Every other twelve-digit
identifier under this directory is a placeholder — the third-party vendors the
RCP scenarios grant access to, the operator's own account, and the accounts
recorded in `headroom_results/` alike.

This is the standing exception to INV-15, recorded at the invariant itself
([`../spec/invariants.md`](../spec/invariants.md)) — this file describes where
the identifier is, not whether it is allowed. No new one may be added, and
nothing outside `test_environment/` is covered. Nor is the directory itself a
blanket exemption: the exception is granted for that one account ID and for no
other kind of identifier, so an instance ID, an AMI ID, a KMS key ID, or an
Organizations root, OU, or organization ID committed here is held to INV-15
exactly as it would be anywhere else, and
`test_no_identifier_of_a_non_account_kind_reads_as_real_anywhere` fails on it.

**The operator's own account IDs are a different matter, and are not covered.**
Buckets here are named `headroom-test-<scenario>-<account id>` for global
uniqueness, so a scan records that account ID inside the bucket name, where
redaction cannot reach it — it matches the account field of an ARN, and an S3
bucket ARN has none. Rewrite those names to placeholders after refreshing
`headroom_results/`. Terraform rebuilds them from `data.aws_caller_identity` at
apply time, so nothing reads the committed value.
