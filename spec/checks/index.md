# Checks

One document per registered check. Each is normative for that check and nothing
else; anything true of every check belongs in
[`../architecture/check-framework.md`](../architecture/check-framework.md),
[`../contracts/policy-model.md`](../contracts/policy-model.md), or
[`../invariants.md`](../invariants.md).

`tests/test_spec_corpus.py` fails when a registered check has no document here,
or a document here names no registered check.

## SCP checks

| Check | Pattern | Scope | Allowlist | Exemptions |
|---|---|---|---|---|
| [`deny_ec2_ami_owner`](scps/deny_ec2_ami_owner.md) | 5c | Regional | `ec2_allowed_ami_owners` | — |
| [`deny_ec2_imds_hop_limit`](scps/deny_ec2_imds_hop_limit.md) | 2 | Regional | — | — |
| [`deny_ec2_imds_v1`](scps/deny_ec2_imds_v1.md) | 4 | Regional | — | Instance tag |
| [`deny_ec2_public_ip`](scps/deny_ec2_public_ip.md) | 2 | Regional | — | — |
| [`deny_eks_create_cluster_without_tag`](scps/deny_eks_create_cluster_without_tag.md) | 3 | Regional | — | — |
| [`deny_iam_saml_provider_not_aws_sso`](scps/deny_iam_saml_provider_not_aws_sso.md) | 1 | Global | — | — |
| [`deny_iam_user_creation`](scps/deny_iam_user_creation.md) | 5b | Global | `iam_allowed_users` | — |
| [`deny_lambda_auth_type_none`](scps/deny_lambda_auth_type_none.md) | 2 | Regional | — | — |
| [`deny_rds_unencrypted`](scps/deny_rds_unencrypted.md) | 2 | Regional | — | — |

## RCP checks

The six third-party-access checks implement pattern 5a and generate the same
statement shape, differing only in `Action` and in which allowlist variable
feeds it. The shared statement is specified once in
[`../contracts/policy-model.md`](../contracts/policy-model.md).

`deny_service_confused_deputy` is not one of them. It implements pattern 6, the
composition, and shares only `Effect`, `Principal`, and `Resource` with the six:
it denies the union of their six actions rather than one service's, and its
`Condition` allowlists `aws:SourceAccount` behind `Null` and `Bool` gates rather
than allowlisting `aws:PrincipalAccount`. What it generates is specified in
[`rcps/deny_service_confused_deputy.md`](rcps/deny_service_confused_deputy.md).

| Check | Scope | Action denied | Non-account principals |
|---|---|---|---|
| [`deny_ecr_third_party_access`](rcps/deny_ecr_third_party_access.md) | Regional | `ecr:*` | Recorded as violations |
| [`deny_kms_third_party_access`](rcps/deny_kms_third_party_access.md) | Regional | `kms:*` | Recorded as violations |
| [`deny_s3_third_party_access`](rcps/deny_s3_third_party_access.md) | Global | `s3:*` | Recorded as violations |
| [`deny_secrets_manager_third_party_access`](rcps/deny_secrets_manager_third_party_access.md) | Regional | `secretsmanager:*` | Recorded as violations |
| [`deny_sqs_third_party_access`](rcps/deny_sqs_third_party_access.md) | Regional | `sqs:*` | Recorded as violations |
| [`deny_sts_third_party_assumerole`](rcps/deny_sts_third_party_assumerole.md) | Global | `sts:AssumeRole` | **Not a finding** — its RCP denies `sts:AssumeRole` alone, which a federated identity cannot call. A `CanonicalUser`, and a `Federated` principal granted the literal `sts:AssumeRole`, abort the run instead: **no results at all**, not a verdict |
| [`deny_service_confused_deputy`](rcps/deny_service_confused_deputy.md) | Both | All six of the above | **Not read** — it measures source guards, not principals |

The five resource-policy analyzers read the `Principal` element through one
function, `read_principal`, and reach one verdict from it. The sixth reads the
same facts and acts on two of the three, for the reason its column gives.
[`../contracts/policy-model.md`](../contracts/policy-model.md) owns the rule.

The seventh re-runs all six analyzers rather than reading what they recorded, so
each of them has two callers in a full estate scan: its own check, and
`deny_service_confused_deputy`. **The second call costs no AWS request.** Each
of the six is wrapped by `memoize_per_session`, so whichever caller runs first
pays for the reads — `describe_repositories`, `get_repository_policy`, and
`get_registry_policy` for ECR; `list_keys`, `describe_key`, `get_key_policy`,
and `list_grants` for KMS; `list_buckets`, `get_bucket_acl`, and
`get_bucket_policy` for S3; `list_secrets` and `get_resource_policy` for Secrets
Manager; `list_queues` and `get_queue_attributes` for SQS; and `list_roles` alone
for IAM, whose trust policy arrives inline on the role — and the second is served
from memory. Budget
a full RCP pass at one set of these calls per account, not two.

The memo is keyed on the account's `Session` object, never on an account ID or
name, which is what keeps one account's resource policies out of another
account's allowlist; [`../architecture/aws-execution.md`](../architecture/aws-execution.md#three-things-concurrency-changes-elsewhere)
owns the three memos and their lifetime. A second call for one session carrying
different organization arguments raises rather than serving the first call's
answer to a different question.
`test_the_shared_analyzers_read_an_account_once_for_both_callers` in
`tests/performance/test_call_counts.py` pins the count, and
`test_every_doubly_called_analyzer_is_memoized` in `tests/test_aws_helpers.py`
is the discovery-driven guard that fails when an analyzer loses its decorator.
`test_confused_deputy_reads_every_analyzer_producing_sources` in
`tests/test_checks_deny_service_confused_deputy.py` fails by name when an
analyzer producing `service_principal_sources` is not read by the check; both
guards walk the same discovery.

Registering the seventh check is still what triggers the second pass: its
Terraform variable gates the rendered statement, not the scan. A resumed run
issues fewer of these calls or none, because a check whose result file already
exists is skipped — and the total is unchanged either way, since the memo is
filled by whichever of the two callers actually runs.

## The per-check document contract

Every document carries this frontmatter, validated by
`tests/test_spec_corpus.py`:

| Field | Meaning |
|---|---|
| `id` | The registered check name. Must equal the filename stem. |
| `kind` | `scp` or `rcp`. Must match the directory and the registry. |
| `status` | `implemented`, `planned`, or `deprecated`. |
| `applies_to` | Repository paths this document is normative for. Each must exist. |
| `depends_on` | Global invariant IDs the check relies on. Each must be defined in [`../invariants.md`](../invariants.md). |
| `verification` | Test files that pin this check's behavior. Each must exist. |

And these sections, in this order:

1. **Objective**, with **Scope** and **Non-goals**
2. **Enforced statement** — the effect, action, resource, and conditions, plus
   the policy pattern
3. **Evidence** — the AWS APIs called and the attributes read
4. **Decision table** — the per-resource verdicts: compliant, violation,
   exemption, whatever the check does not record, and unknown. Not blocked:
   that is a per-account placement outcome, and it belongs in **Placement and
   generated policy**.
5. **Failure behavior** — what happens on `AccessDenied`, an unreadable region,
   a missing or unparseable policy
6. **Result contract** — the summary fields and entry shape this check writes
7. **Placement and generated policy** — the Terraform variables, and the
   allowlist round trip where there is one
8. **Accepted limitations** — evidence-based, never speculative
9. **Acceptance scenarios** — concrete inputs and their expected verdicts
10. **Referenced invariants**
11. **Implementation** — links to source and tests

A heading with nothing beneath it is a problem the validator reports,
whether it names one of these eleven, a **Known conflict** section, or
anything else a document happens to state.

A **Known conflict** section appears only where one exists, and says
`Status: unresolved`. The register below and the check documents are two views
of one set: every check the register's **Where** column names carries such a
section, and every check carrying one is named there. A conflict recorded in
only one of the two is a conflict half its readers never see.

## Unresolved conflicts

Places where the implementation, this corpus, and the evidence committed beside
them disagree. Each is **reported, not fixed**, because settling it is not a
prose change — it alters which policies are generated, or what a committed
artifact claims to be the output of — and
[`../README.md`](../README.md) requires reporting a conflict rather than guessing
which side is right.

**One is open.**

| # | Where | Conflict |
|---|---|---|
| 7 | [`deny_ecr_third_party_access`](rcps/deny_ecr_third_party_access.md) | Four committed result files still carry `repositories_third_parties_can_access`, `repositories_with_wildcards`, and `total_repositories_analyzed`, which the check renamed to `policies_third_parties_can_access`, `policies_with_wildcards`, and `total_policies_analyzed`. Rewriting them would make evidence claim to be the output of a code version that never wrote it, and regenerating them needs a live run of the test organization |

A resolved conflict leaves nothing behind here. What it was and how it was
settled is in git history, and the rule it produced is in the document that owns
that rule — so a row kept after the fact would be a second copy of a settled
rule, going stale on its own schedule.

A number is allocated once and never reused, because commit messages cite them
and git history cannot be edited. **The next conflict is 9.** Whoever opens it
advances that number here.

## Statements with no check

The SCP module emits one statement that no registered check gates:

| Sid | Statement | When |
|---|---|---|
| `DenyRootLeaveOrganization` | `Deny organizations:LeaveOrganization on *` | The module's `target_id` starts with `r-` |

It needs no check because it can never break an existing workload: no account
should be leaving the organization, and nothing an account does in the ordinary
course invokes it. It is documented in
[`../contracts/terraform.md`](../contracts/terraform.md) rather than here,
because it belongs to the module rather than to the check framework.

This is not a breach of INV-10. INV-10 binds a statement gated by a Terraform
*variable* to a check that measures exactly that statement; `DenyRootLeaveOrganization`
is gated by the shape of `target_id`, not by a variable, so no verdict is being
made on the wrong evidence. It would become a breach the moment this statement
gained a variable with no check behind it.

## Adding a check

Write the specification first — `tests/test_spec_corpus.py` fails until it
exists. Then
[`../../HOW_TO_ADD_A_CHECK.md`](../../HOW_TO_ADD_A_CHECK.md) for the
implementation walkthrough, and
[`../architecture/check-framework.md`](../architecture/check-framework.md) for
what the framework requires.
