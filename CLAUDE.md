# CLAUDE.md

Guidance for agents working in this repository. `AGENTS.md` points here; this file is the single source of truth for *how to work*. [`spec/`](spec/README.md) is the single source of truth for *what the software must do*.

## Truth hierarchy

The version-controlled specification corpus is the primary product. The implementation is an expression of that corpus.

- `spec/` is **normative**: it states intended behavior. [`spec/README.md`](spec/README.md) carries the full authority model and precedence chain; read it before your first change.
- Code and tests are **evidence of current behavior**, not of intent.
- Where the two disagree, **report the conflict**. Do not quietly change either side to match the other. If the intent is unambiguous, fix the implementation and say so; if it is not, record it in the unresolved table in [`spec/checks/index.md`](spec/checks/index.md) and leave behavior alone.
- Change the specification and the implementation in the same commit. A behavior change with no corresponding specification edit is incomplete.
- Git history supplies dates. No document carries a manual "last updated" field.

## The pipeline

Headroom scans an AWS Organization and generates Terraform SCPs and RCPs that will not break existing workloads. One pass, one direction:

Configuration → organization discovery → checks → result artifacts → placement → Terraform generation → reconciliation.

[`spec/architecture/overview.md`](spec/architecture/overview.md) owns the stages.

## Always

These are global invariants; [`spec/invariants.md`](spec/invariants.md) states each one in full and is the place to cite, argue with, or amend it.

- **INV-15** — use obviously fake AWS identifiers everywhere, including commit messages. An identifier from a bug report, error message, console screenshot, or API response is real; rewrite it before it enters the repo.
- **INV-14** — persisted results keep wire compatibility unless you are performing an explicit migration. A later run reads back both the JSON and the filenames.
- **INV-13** — every stage from collection to Terraform rendering reads the registry. A check declares its `TerraformSection` and, where its statement takes one, its `Allowlist` on `@register_check`; `parse_results.py`, `placement/`, and both generators name no check, and `test_generic_pipeline_modules_name_no_check` fails if one does. Check discovery in `headroom/checks/__init__.py` is the one sanctioned dynamic import; everywhere else, import at the top of the file.
- **INV-04** — organization membership, analyzable accounts, and hierarchy are distinct projections. Code that collapses them is wrong.
- **INV-01** — absence of evidence is not evidence of safety. A region that could not be read, a policy that could not be parsed, and an API that failed are not "no findings".

## Routes

Match the longest path prefix. Always load [`spec/README.md`](spec/README.md) and
[`spec/invariants.md`](spec/invariants.md), whatever you are touching; load the
rest only as this table directs. Specification paths are shown relative to
`spec/`.

| Touched path | Specifications | Also open |
|---|---|---|
| `headroom/checks/scps/<name>.py` | [`checks/scps/<name>.md`](spec/checks/scps/), [`architecture/check-framework.md`](spec/architecture/check-framework.md) | That specification's own `applies_to` and `verification`. A **new** check also needs [`HOW_TO_ADD_A_CHECK.md`](HOW_TO_ADD_A_CHECK.md) and declares `terraform_section` on `@register_check`; a new service adds a `TerraformSection` member in `headroom/enums.py`. `test_every_registered_scp_check_is_rendered` fails by name when a check does not reach the module, `test_every_registered_check_is_declared_by_its_module` when `test_environment/modules/scps/variables.tf` does not declare it, and `test_every_registered_check_is_read_by_a_statement` when no statement in its `locals.tf` reads it. |
| `headroom/checks/rcps/<name>.py` | [`checks/rcps/<name>.md`](spec/checks/rcps/), [`architecture/check-framework.md`](spec/architecture/check-framework.md), [`contracts/policy-model.md`](spec/contracts/policy-model.md) | As above, plus an `Allowlist` naming `unique_third_party_accounts` and the module variable; `test_every_registered_rcp_check_is_rendered` fails by name, `test_every_registered_check_is_declared_by_its_module` when `test_environment/modules/rcps/variables.tf` does not declare either, and `test_every_registered_check_is_read_by_a_statement` when no statement in its `locals.tf` reads either. |
| `headroom/checks/base.py`, `headroom/checks/registry.py` | [`architecture/check-framework.md`](spec/architecture/check-framework.md), [`contracts/results.md`](spec/contracts/results.md) | `headroom/write_results.py` - `BaseCheck.execute` is its one call site. `tests/test_checks_registry.py`. `headroom/terraform/parameters.py` renders from the definitions. |
| `headroom/aws/policy_documents.py` | [`contracts/policy-model.md`](spec/contracts/policy-model.md), every `checks/rcps/*.md` | Every adapter that reads a statement: `headroom/aws/ecr.py`, `kms.py`, `s3.py`, `secretsmanager.py`, `sqs.py`, `iam/roles.py`. A change to how a statement is read is a change to all six. `read_principal` is the one rule all six read a `Principal` element by, and `tests/test_aws_policy_documents.py` pins it; six copies of that walk once disagreed four ways. |
| `headroom/aws/<service>.py` | the `checks/*` documents naming that service, [`contracts/policy-model.md`](spec/contracts/policy-model.md) | `headroom/aws/policy_documents.py`, if statement interpretation moves. |
| `headroom/aws/organization.py`, `headroom/aws/organization_snapshot.py` | [`architecture/aws-execution.md`](spec/architecture/aws-execution.md), [`contracts/placement.md`](spec/contracts/placement.md) | Keep INV-04's three projections distinct. `discover_organization` is the run's one read of Organizations; every later stage consumes the frozen `OrganizationSnapshot`. `tests/test_aws_organization_snapshot.py`, `tests/test_placement_hierarchy.py`, `tests/test_nested_ou_hierarchy.py`. |
| `headroom/analysis.py`, `headroom/log_context.py` | [`architecture/aws-execution.md`](spec/architecture/aws-execution.md) for the worker pool and the failure policy | One worker per account, one session per worker. Each memo — `get_all_regions` and `memoize_per_session` in `headroom/aws/helpers.py`, `get_instances` in `headroom/aws/ec2.py` — is a `WeakKeyDictionary` keyed on that session, so a memo entry reached by two accounts is a correctness bug. `log_context.py` stamps the account on the thread; `tests/conftest.py` restores the thread-local between tests. `TestRunChecksPool` in `tests/test_analysis.py`, `tests/performance/test_call_counts.py`. |
| `headroom/aws/sessions.py`, `headroom/aws/helpers.py` | [`architecture/aws-execution.md`](spec/architecture/aws-execution.md) | `find_tag_value_as_iam_matches` is the one rule both tag checks read their tag by, so a change to it changes [`checks/scps/deny_ec2_imds_v1.md`](spec/checks/scps/deny_ec2_imds_v1.md) and [`checks/scps/deny_eks_create_cluster_without_tag.md`](spec/checks/scps/deny_eks_create_cluster_without_tag.md) together. |
| `headroom/write_results.py`, `headroom/parse_results.py` | [`contracts/results.md`](spec/contracts/results.md), [`contracts/placement.md`](spec/contracts/placement.md) | Both readers: `parse_results.py` for SCPs, `headroom/terraform/generate_rcps.py` for RCPs. A filename change can silently skip accounts without any reader failing, and a re-scan is caught only from the second file it leaves. `tests/test_write_results.py`, `tests/test_parse_results.py`, `TestRunChecks` in `tests/test_analysis_extended.py`. |
| `headroom/placement/` | [`contracts/placement.md`](spec/contracts/placement.md) | - |
| `headroom/terraform/` | [`contracts/terraform.md`](spec/contracts/terraform.md), [`contracts/placement.md`](spec/contracts/placement.md) | `plan.py` renders and validates the whole run without touching disk; `apply.py` is the only place Headroom writes, links, or deletes. `tests/test_terraform_plan.py`, `tests/test_terraform_apply.py`. `parameters.py` is the one renderer both generators call; `tests/test_terraform_parameters.py`. |
| `headroom/config.py`, `headroom/usage.py`, `sample_config.yaml` | [`contracts/configuration.md`](spec/contracts/configuration.md) | `README.md` and [`documentation/SETUP.md`](documentation/SETUP.md). `tests/test_config.py`, `tests/test_main.py`. |
| `headroom/main.py` | [`architecture/overview.md`](spec/architecture/overview.md) for the stage order, [`architecture/aws-execution.md`](spec/architecture/aws-execution.md) for the top-level `try`, [`contracts/terraform.md`](spec/contracts/terraform.md) for the compile-then-apply boundary | Both workflows parse, place, and print but write nothing; `main()` calls `compile_terraform_plan` and then `apply_terraform_plan`. |
| `headroom/constants.py`, `headroom/enums.py`, `headroom/types.py`, `headroom/utils.py`, `headroom/output.py` | Whichever contract owns the value you are changing | The consumer. These modules hold no behavior of their own; a constant is normative wherever it is consumed. |
| `test_environment/modules/` | [`contracts/terraform.md`](spec/contracts/terraform.md), [`contracts/policy-model.md`](spec/contracts/policy-model.md), the affected `checks/*` documents | - |
| `tests/` | [`verification/strategy.md`](spec/verification/strategy.md) | - |
| `spec/checks/` | [`checks/index.md`](spec/checks/index.md) | `tests/test_spec_corpus.py` for what is mechanically enforced. |
| Prose in any `.md`, with no behavior change | The owner named in [`spec/README.md`](spec/README.md) | No implementation file is implicated. `tests/test_documentation_links.py` fails on a relative link whose target is missing, and `tests/test_spec_corpus.py` on a malformed or missing check specification; run those two in place of `tox`. |

Three things no row can key on:

- **A change to how something fails also touches
  [`spec/architecture/aws-execution.md`](spec/architecture/aws-execution.md).** It
  owns the general failure policy, so a new tolerated exception, a widened
  `except`, or a moved `try` changes it whatever file you edited.
- **Correcting a claim in one specification means checking whether another states
  the same thing.** A documentation-only fix matches no path row at all.
  `aws-execution.md` has twice been the document left stale by a correction made
  elsewhere — once for tag tolerance, once for the top-level `try`.
- **A test file named in a check specification's `verification:` list routes to
  that specification.** `tests/` is the longest prefix any row can offer and it
  points only at [`verification/strategy.md`](spec/verification/strategy.md), but a
  check test encodes that specification's **Decision table** and **Acceptance
  scenarios**, and a service test encodes its **Evidence** and **Failure
  behavior**. Editing the evidence with the statement of intent unread is the
  failure the truth hierarchy exists to prevent.
  `grep -l '<filename>' spec/checks/*/*.md` names the owners, and there is often
  more than one — `tests/test_aws_policy_documents.py` answers to seven
  specifications and `tests/test_aws_ec2.py` to four. Renaming or deleting such a
  file is already caught, since `tests/test_spec_corpus.py` fails on a
  `verification:` path that does not exist; changing what it asserts is caught by
  nothing.

## Conventions

[`CONVENTIONS.md`](CONVENTIONS.md) is authoritative for code conventions, and is
imported below so that it loads with this file. It carries the fail-fast rules,
the single-source-of-defaults rule for CLI and config values, and the import
rules including the check-discovery exception above.

@CONVENTIONS.md

## Completion

- Read the implementation and the existing tests for every boundary you touch before editing.
- Write the failing test first and watch it fail for the reason you expect, then write only enough code to pass it. One test, one implementation, repeat — do not write every test up front. Start a bug fix with the test that reproduces it.
- An assertion that computes its expected value the way the code computes it passes by construction and can never disagree with the code. Take expected values from an independent source: a known-good literal, a worked example, the documented shape of the AWS policy.
- Tests are flat under `tests/`, one file per module.
- Run the smallest relevant test files while working, then `tox` before calling the work done.
- If verification cannot run, report the exact unavailable dependency or environment constraint instead of a pass.
- Update the specification document that owns what you changed, in the same change. `spec/README.md` names the owner. Do this once, when the code has settled, rather than rewriting prose after every edit.
