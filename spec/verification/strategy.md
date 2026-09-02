# Verification strategy

Owns what counts as proof that the implementation matches this corpus. Tests and
schemas are executable parts of the specification: a rule stated here and pinned
by a named test is enforced, and a rule stated here with no test is an intention.

## The gate

`tox` is the gate. It runs the whole thing on Python 3.12 and 3.13, and every
step must pass:

| Step | Requirement |
|---|---|
| `pytest tests/` | Every test passes |
| Coverage of `headroom/` | **100%**. `.coveragerc` omits `*/__main__.py` and `.tox/*`, which are not source |
| Coverage of `tests/` | **100%** — the test suite must exercise its own helpers |
| `mypy headroom/ tests/` | Clean, under a strict configuration |
| `pre-commit run --all-files` | End-of-file, trailing whitespace, autoflake, flake8, autopep8 |

`.coveragerc` also excludes any line marked `pragma: no cover`. **No line in
`headroom/` or `tests/` carries one today**, so the 100% figure currently means
every statement. It is an escape hatch, not a budget: a new one needs a reason
in review, because that figure is only worth what the exclusions leave in.

Nothing runs those five steps for you. The repository has no `.github/`
directory and no workflow, and whether `pre-commit`'s git hook is installed is a
per-clone fact — it is not installed in this clone. `pre-commit run --all-files`
is a `tox` step either way. Every gate this document names runs when a human
types `tox`.

The `pytest` configuration lives in `pytest.ini` under a `[pytest]` section.
`[tool:pytest]` is a valid section name only inside `setup.cfg`; a `pytest.ini`
that used it instead parsed without error while every `addopts`, `testpaths`,
and `markers` entry it declared went silently inert. `--strict-config` and
`--strict-markers` are part of the gate: the former fails collection on an
unknown ini key, the latter on an unregistered marker.
`test_pytest_reads_the_ini_settings` pins that these settings are the running
configuration, not merely text in a file pytest never applied.

100% coverage on both trees is a floor, not the objective. It says every line ran;
it says nothing about whether the assertion was worth making. The rules below are
what make a covered line meaningful.

While working, run the smallest relevant test files. Run `tox` before calling the
work done. If it cannot run, report the exact unavailable dependency or
environment constraint — never a pass.

## Test-first

Write the failing test first and watch it fail for the reason you expect, then
write only enough code to pass it. One test, one implementation, repeat. Start a
bug fix with the test that reproduces it.

A test written after the code passes immediately, which proves nothing: it was
shaped by the implementation it is meant to judge.

## Assertions must be independently derived

An assertion that computes its expected value the way the code computes it passes
by construction and can never disagree with the code.

Take expected values from an independent source: a known-good literal, a worked
example, or the documented shape of the AWS policy or API response. Where a
per-check specification states a decision table or an acceptance scenario, that
is such a source — the specification is written from intent, and the test asserts
against it.

Fixtures must be shaped like **real** AWS responses. An impossible one hid a
released bug for a version;
[`../invariants.md`](../invariants.md#inv-08--record-the-value-the-condition-key-will-hold)
states the case that settled it.

## Layout

Tests are flat under `tests/`, one file per module, with one subdirectory,
named below. The only shared fixture is `tests/conftest.py`, which restores the
two pieces of process-wide state a handful of tests mutate: the
`threading.local` account `headroom/log_context.py` keeps, and the root
logger's handlers, filters, formatters, and level. It restores unconditionally
— a restore that runs only when a change was detected is a restore that is only
sometimes exercised.

| File | Covers |
|---|---|
| `tests/test_<module>.py` | `headroom/<module>.py` |
| `tests/test_aws_<service>.py` | `headroom/aws/<service>.py` |
| `tests/test_checks_<check_name>.py` | one check |
| `tests/test_<helper>.py` | `tests/<helper>.py` — the suite's own helpers, which is what 100% coverage of `tests/` is for |
| `tests/performance/test_call_counts.py` | the three per-session memos and the one-time organization read, by call count |

Four of the five helper modules have a test file by that rule: `conftest.py`,
`data_standards.py`, `documentation_links.py`, and `spec_corpus.py`.
`constants.py` is shared fixture data with no logic of its own, covered by the
files that import it. Two test files cover neither a `headroom/` module nor a
helper, because what they check is a repository convention rather than code:
`tests/test_pytest_configuration.py`, that pytest reads the settings `pytest.ini`
declares, and `tests/test_committed_terraform_examples.py`, that the committed
Terraform under `test_environment/` still plans and that each module declares
every variable the registry will make the generator pass.

Four cases depart from that, each deliberate:

- `tests/test_nested_ou_hierarchy.py` — generates org info and policies from one
  hierarchy and asserts every `local.` a policy reads is one the org info
  declares (INV-12). Cross-module by construction: the bug only appears when two
  modules are generated from one input.
- `tests/test_main_integration.py` — the pipeline end to end against fakes.
- `tests/test_analysis_extended.py` — a second file over `headroom/analysis.py`,
  holding the account-enumeration and resume paths. It is a size split rather
  than a boundary, and the two would be better merged than imitated.
- `tests/test_aws_iam.py` — one file over three source files, `headroom/aws/iam/
  roles.py`, `users.py`, and `saml_providers.py`, with a class apiece. They are
  one IAM surface rather than three subsystems, and the trust-policy grammar the
  first depends on is the bulk of the file.

That subdirectory is `tests/performance/`, and it holds a different kind of
test: call-count contracts, not behavior. They assert counts rather than wall
clock, so they cannot flake. Three classes, covering two different things:

| Class | Pins |
|---|---|
| `TestCallCounts` | The three per-session memos — the region list, the EC2 sweep, and the six shared analyzers |
| `TestNoCheckRepeatsAnother` | No `(service, region, operation)` triple is issued twice in one account's run |
| `TestOrganizationsIsReadOnce` | INV-17 — the one-time organization read that replaced four independent ones. Not a per-account memo, and the reason this directory is not named for them |

All three of `TestCallCounts`'s tests hand-enumerate what they drive — `range(11)`
in the first, a literal `SHARED_ANALYZERS` list in the third — so a check
registered tomorrow is outside all of them. `TestNoCheckRepeatsAnother` is the
registry-driven one that covers it, which is why the two classes are not
redundant.

## Named guard tests

These pin invariants that no ordinary unit test would catch. Renaming one without
replacing it removes an invariant's only enforcement.

| Test | Pins |
|---|---|
| `test_only_the_sessions_module_constructs_a_session` | INV-16 — one construction site for sessions |
| `test_only_the_aws_package_constructs_a_client` | The boundary [`../architecture/overview.md`](../architecture/overview.md) states — nothing outside `aws/` builds a boto3 client, the orchestrator included |
| `test_only_enabled_regions_are_requested` | INV-16 — `describe_regions` takes no arguments |
| `test_every_state_aws_defines_is_classified` | INV-03 — a new AWS lifecycle state fails the pin when a human runs `tox` |
| `test_every_registered_rcp_check_is_rendered` | INV-13 — every registered RCP check reaches the module with `<check> = true` and its allowlist variable; reading the value, not just the parameter's presence, means a check hardwired to `false` cannot pass as rendered |
| `test_every_registered_scp_check_is_rendered` | INV-13 — the SCP counterpart of the row above: every registered SCP check reaches the module with `<check> = true` |
| `test_generic_pipeline_modules_name_no_check` | INV-13 — no stage from collection through rendering branches on a check name. Reads the orchestrator, check discovery, and every stage module from collection to rendering as source, reporting any registered name, or any `DENY_`-prefixed constant, outside a `#` comment, so the historical note `parse_results.py` carries stays legal and a comparison hidden in a docstring does not |
| `test_render_order_is_independent_of_registration_order` | INV-13 — a reversed registry yields the same definition order, which is what both generators render from |
| `test_every_committed_module_call_passes_every_required_variable` | The committed worked examples still plan — a module variable with no default is passed by every generated call under `test_environment/` |
| `test_every_registered_check_is_declared_by_its_module` | INV-13 — the other direction: every registered check name and allowlist variable is a variable its module's `variables.tf` declares, so the argument the generator passes is one `terraform plan` accepts |
| `tests/test_spec_corpus.py` | Every registered check has exactly one specification |
| `test_the_conflict_register_and_the_check_documents_agree` | The conflict register and the per-check documents name the same checks |
| `test_every_named_guard_resolves_to_a_real_test` | This table itself — every guard named below or above resolves to a test that exists. The table named `test_only_the_aws_package_constructs_a_client` for as long as no such test did |
| `test_the_documented_count_matches_what_the_live_test_directory_holds` | INV-15 — the standing exception's stated size matches the directory |
| `test_no_identifier_from_the_exception_appears_outside_it` | INV-15 — a real identifier stays inside `test_environment/` |
| `test_no_identifier_of_a_non_account_kind_reads_as_real_anywhere` | INV-15 — an identifier of any kind its table names but the account reads as fabricated wherever it appears, `test_environment/` included |
| `test_every_kind_inv_15_names_has_a_matcher` | INV-15 — a kind the invariant's own table names is scanned. It reads the table; the assertion it replaced compared the constant against a hardcoded copy of itself |
| `test_a_summary_without_the_key_raises` | INV-01 — a missing violation count aborts rather than clearing the account |
| `test_a_page_without_the_accounts_key_raises` | INV-01 — a `ListAccounts` page with no `Accounts` key aborts rather than undersizing organization membership |
| `test_a_written_result_parses` | A check's own output survives the reader that consumes it. It round-trips one check, `deny_iam_user_creation`, through `parse_scp_result_files`. No RCP check is round-tripped through `parse_rcp_result_files`, and six of the seven override `_build_results_data` with a shape their reader never sees under test |
| `test_only_policy_documents_reads_a_statement_principal` | One reader for the `Principal` element — six copies once disagreed four ways |
| `test_every_principal_element_read_reaches_read_principal` | One reader for the `Principal` element, per read — the name guard above passes a seventh copy that reads the element off a local called `statement` |
| `test_only_policy_documents_normalizes_a_statement_action` | One reader for the `Action` element — five copies then disagreed four ways |
| `test_pytest_reads_the_ini_settings` | The gate's own strictness settings are applied, not merely declared |
| `test_a_directory_default_is_written_in_one_place` | [`../contracts/configuration.md`](../contracts/configuration.md)'s single source of defaults — a directory path is written in `config.py` and nowhere else under `headroom/`, the `--help` string included |
| `test_every_cited_invariant_is_defined_anywhere_in_the_corpus` | A citation anywhere in the corpus, a per-check document's own prose included, names an invariant that exists |
| `test_a_document_may_not_state_the_same_section_twice` | One topic, one place — the rule `spec/README.md` sets |
| `test_a_required_section_with_no_content_is_a_problem` | A section with nothing under its heading is a problem — the required eleven, a `Known conflict`, or any other heading a document states |

## What the corpus test enforces

`tests/test_spec_corpus.py` reads the registry and this directory tree, with no
network and no AWS calls. It fails when:

- a registered check has no specification, or more than one;
- a specification names a check that is not registered;
- a specification's frontmatter is missing a required field, or its `id` or
  `kind` disagrees with the registry;
- two specifications share an `id`;
- a specification's `depends_on` cites an invariant ID that
  `invariants.md` does not define;
- any document's text anywhere in the corpus — not only a per-check
  specification's `depends_on` field — cites an invariant ID that
  `invariants.md` does not define;
- a relative link inside `spec/` points at a file that does not exist;
- a check is named in the unresolved-conflict register with no **Known
  conflict** section in its own document, or carries one that the register does
  not name;
- a document states the same section heading twice;
- a section has nothing under its heading, in any document in the corpus and
  not only in a per-check specification — the rule reached sixteen of the
  twenty-nine until INV-01's body proved deletable with its heading kept.

Adding a check therefore fails the suite until its specification exists. That is
the intended order: the specification is written first.

## What the identifier test enforces

`tests/test_data_standards.py` reads the repository as text. It exists because
INV-15 states the size of its own standing exception in prose and nothing
compared that sentence to `test_environment/`, so the prose drifted;
[`../invariants.md`](../invariants.md#inv-15--aws-identifiers-in-the-repository-are-obviously-fake)
owns that episode and every rule this test reads back. The test fails when:

- the count INV-15 spells disagrees with the identifiers `test_environment/`
  holds, whether one was added or the prose was left behind;
- an identifier from the exception appears outside `test_environment/`;
- an identifier of any kind INV-15's table names but the account reads as real
  anywhere at all, `test_environment/` included;
- a kind INV-15 names has no matcher, which is how six of the seven came to be
  unscanned while the invariant claimed to cover them all.

The account kind is the one the scan cannot recognize on sight, for the reason
INV-15 gives, so this test catches its arrival indirectly: adding one to
`test_environment/` moves the count, and adding one anywhere else is caught
only once it also appears in the sandbox. Every other kind carries a shape a
plain number does not, which the invariant's kinds table names, so each is
reported where it stands and the sandbox buys it no cover. Review is still the
first line, and INV-15 still binds where the test is silent.

The test's own fixtures are the awkward case, and the way they are written is
deliberate. Proving a matcher matches needs a body that reads as real —
`0abcdef1234567890` for an AMI, `example12345` for an organization — and a file
that writes such a body directly behind its `ami-` prefix is reported by the
very scan the fixture exists to exercise. This paragraph was reported that way
itself, on its first draft. So the body is a named constant and the prefix is
joined to it at runtime: `f"ami-{AWS_DOCUMENTATION_AMI_BODY}"`. The scanner
reads the repository as text and never sees a complete identifier; the test
does. Inline the literal and the suite fails on the file that wrote it —
correct, and a puzzle to anyone who has not read this paragraph. INV-15's
standing exception is not involved: no complete identifier is committed, so
there is nothing for an exception to cover.

## Live verification

`test_environment/` holds Terraform for a complete sample organization —
accounts, roles, deliberately non-compliant resources — used to confirm that a
generated policy actually denies what it claims to. It costs real money and is
not part of `tox`.

Topology, execution, cost, and cleanup:
[`../../test_environment/README.md`](../../test_environment/README.md).

A live result is evidence about AWS, not about Headroom. Where the two disagree —
a policy AWS enforces differently than a check predicted — the finding belongs in
the affected check's specification, measured with a `--dry-run` probe and cited.
