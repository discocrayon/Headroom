# CLAUDE.md

Guidance for agents working in this repository. `AGENTS.md` points here; this file is the single source of truth.

## Truth hierarchy

Code and tests define current behavior. `Headroom-Specification.md` is the specification: it expresses intent, and agents keep it current. The flow runs from code to specification, never back — do not regenerate or replace implementation from it, and do update the section describing behavior you changed, in the same change. Where the two disagree, resolve the discrepancy explicitly and say which side you changed.

## The pipeline

Headroom scans an AWS Organization and generates Terraform SCPs and RCPs that will not break existing workloads. One pass, one direction:

Configuration → organization discovery → checks → result artifacts → placement → Terraform generation → reconciliation.

## Always

- Use obviously fake AWS identifiers in code, tests, documentation, and examples: real prefix, real length, a repeated digit for the body (`111111111111`, `i-11111111111111111`, `ami-11111111111111111`). An identifier that arrives from a bug report, error message, console screenshot, or API response is real; rewrite it before it enters the repo, commit messages included.
- Preserve wire compatibility of persisted results unless you are performing an explicit migration. A later run reads back both the result JSON and the result filenames, and `results_exist` tolerates the account-name and the account-name-plus-ID form so an existing results directory still resumes.
- Check discovery under `headroom/checks/` intentionally uses dynamic imports: `headroom/checks/__init__.py` imports every module in `scps/` and `rcps/` so each `@register_check` decorator runs and a new check needs no edit elsewhere. That is the exception; everywhere else, import at the top of the file.
- Organization membership, analyzable accounts, and hierarchy are distinct projections, and code that collapses them is wrong. `get_all_organization_account_ids` is deliberately unfiltered, because a closed account is still an organization member and still matches organization-based RCP conditions. `get_subaccount_information` drops the management account, `skip_account_ids`, and every non-ACTIVE account. `analyze_organization_structure` builds the OU tree that placement walks.

## Routes

Read the branch that matches your change and skip the rest. `Headroom-Specification.md` is over 6,000 lines: open it to answer a specific question about intent, or to update the section covering what you changed, never as background reading.

- **Adding or changing a check, or registry discovery** → `HOW_TO_ADD_A_CHECK.md`, `headroom/checks/registry.py`, and `tests/test_checks_registry.py`. Every stage from collection to Terraform is driven by the registry rather than by check name, with one exception: a new RCP check must also be named in `RCP_TERRAFORM_VARIABLES`, which `test_table_covers_every_registered_rcp_check` in `tests/test_generate_rcps.py` enforces.
- **Principal, action, wildcard, or statement interpretation** → `headroom/aws/policy_documents.py` plus every service adapter that reads policy documents: `headroom/aws/ecr.py`, `kms.py`, `s3.py`, `secretsmanager.py`, `sqs.py`, and `iam/roles.py`. A change to how a statement is read is a change to all of them.
- **Generated paths, symlinks, ownership markers, or reconciliation** → "Generation Is Reconciliation, Not Appending" in `documentation/ARCHITECTURE.md`, then `headroom/terraform/reconcile.py`, `ensure_org_info_symlink` in `headroom/main.py`, and `tests/test_terraform_reconcile.py`. Generation is render-before-mutate: the whole plan is built before any file is written or deleted, ownership is the marker on a file's first line, and a run that parses zero result files aborts rather than emptying the directories.
- **Result JSON schemas, filenames, resume behavior, or cache detection** → the writer `headroom/write_results.py`, its one call site `BaseCheck.execute` in `headroom/checks/base.py`, and both readers, `headroom/parse_results.py` for SCPs and `headroom/terraform/generate_rcps.py` for RCPs. The readers only glob `*.json` per check directory and take account identity from the JSON `summary`; resume is a separate path, through `all_check_results_exist` in `headroom/analysis.py` into `results_exist`. So a filename change can silently re-scan or silently skip accounts without any reader failing. Tests: `tests/test_write_results.py`, `tests/test_parse_results.py`, and `TestRunChecks` in `tests/test_analysis_extended.py`.
- **The worker pool, the cooperative abort, or a per-session memo** → "Concurrency model" in `documentation/ARCHITECTURE.md`, then `run_checks` in `headroom/analysis.py`, `get_all_regions` / `memoize_per_session` in `headroom/aws/helpers.py`, `get_instances` in `headroom/aws/ec2.py` -- the third memo, and the only one not in `helpers.py` -- and `headroom/log_context.py`, with `TestRunChecksPool` in `tests/test_analysis.py` and `tests/performance/test_call_counts.py`. One worker per account and one session per worker is what makes the three memos safe: each is a `WeakKeyDictionary` keyed on the session object, so a memo reached by two accounts is a correctness bug, not a slow path. `log_context.py` rides that same property: a worker stamps its account on the thread before its first check and clears it on the way out, so a pool path that returns without doing either leaves every later record labeled with another account, and `tests/conftest.py` restores that thread-local between tests. `design-docs/` holds the design and plan this grew from; both are fully implemented and their checkboxes were never ticked, so read them for why a decision was made and never as work outstanding.
- **Account enumeration or hierarchy behavior** → `headroom/analysis.py` and `headroom/aws/organization.py`, keeping the three projections above distinct, with `tests/test_placement_hierarchy.py` and `tests/test_nested_ou_hierarchy.py`.
- **Public CLI options or configuration** → `headroom/usage.py`, `headroom/config.py`, and `sample_config.yaml`, then update `README.md` and `documentation/SETUP.md`, with `tests/test_config.py` and `tests/test_main.py`.
- **Documentation prose with no behavior change** → edit the file; no implementation file is implicated. `tests/test_documentation_links.py` is the only test that reads Markdown and it fails only on a relative link whose target is missing, so run it in place of `tox` when you add, move, or retarget a link.

## Conventions

`.cursorrules` is authoritative for code conventions. It carries the fail-fast rules, the single-source-of-defaults rule for CLI and config values, and the import rules including the check-discovery exception above.

## Completion

- Read the implementation and the existing tests for every boundary you touch before editing.
- Write the failing test first and watch it fail for the reason you expect, then write only enough code to pass it. One test, one implementation, repeat — do not write every test up front. Start a bug fix with the test that reproduces it.
- An assertion that computes its expected value the way the code computes it passes by construction and can never disagree with the code. Take expected values from an independent source: a known-good literal, a worked example, the documented shape of the AWS policy.
- Tests are flat under `tests/`, one file per module. The single exception is `tests/performance/`, which holds call-count contracts rather than behavior tests.
- Run the smallest relevant test files while working, then `tox` before calling the work done.
- If verification cannot run, report the exact unavailable dependency or environment constraint instead of a pass.
- Update documentation when public behavior, configuration, output formats, invariants, or the routing above changed, including the section of `Headroom-Specification.md` that covers it, and otherwise leave it alone. Do this once, when the code has settled, rather than rewriting prose after every edit.
