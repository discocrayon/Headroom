# Contributing

Headroom is specified before it is implemented. [`spec/`](spec/README.md) is
normative, code and tests are evidence of current behavior, and where the two
disagree the conflict is reported rather than patched over.
[`CLAUDE.md`](CLAUDE.md) carries the truth hierarchy, the routing from a touched
file to the documents that govern it, and what counts as done;
[`CONVENTIONS.md`](CONVENTIONS.md) carries the code conventions. Read both
before your first change.

## Running the suite

```bash
tox                              # everything: coverage, mypy, pre-commit
pytest tests/test_analysis.py    # one file while iterating
mypy headroom/ tests/            # type checking alone
```

`tox` runs the tests under Python 3.12 and 3.13 with coverage, then `mypy`,
then the pre-commit hooks. It is the gate: a change is done when `tox` passes.

`tox` also needs `terraform` on the PATH. `tests/test_terraform_module_plans.py`
plans both Terraform modules under `test_environment/modules/` through
`terraform test`, with no AWS credentials, and the first run downloads the AWS
provider into each module's git-ignored `.terraform/` directory.

## The quality bar

- **100% line coverage**, for `headroom/` and for `tests/` alike. A test helper
  nothing calls fails the build.
- **Typed throughout.** mypy rejects an untyped or partially typed function,
  and [`CONVENTIONS.md`](CONVENTIONS.md) rules out `Any`.
- **Test first.** Write the failing test, watch it fail for the reason you
  expect, then write only enough code to pass it. Take expected values from an
  independent source - a known-good literal, a worked example, the documented
  shape of the AWS policy - never from the code under test.
- **Fake identifiers only.** Every AWS account ID, instance ID, AMI ID, ARN, KMS
  key ID, and Organizations ID in code, tests, docs, and commit messages is an
  obvious placeholder: real prefix, real length, one repeated digit.
  `tests/test_data_standards.py` enforces this as INV-15.
- **One test file per module**, flat under `tests/`.

## Adding a check

1. Write the check's specification under [`spec/checks/`](spec/checks/index.md)
   first. `tests/test_spec_corpus.py` fails until it exists.
2. Follow [`HOW_TO_ADD_A_CHECK.md`](HOW_TO_ADD_A_CHECK.md). It names every file
   a check touches and the test that fails when one is missed.
3. Add the check's row to the table in [`README.md`](README.md#checks) and
   update the two counts in the prose around it. `tests/test_readme.py` fails
   until both are done.

Good first contributions are checks that follow the pattern of an existing one.

## Before you open a pull request

- `tox` passes.
- The specification document that owns what you changed is updated in the same
  change. [`spec/README.md`](spec/README.md#document-ownership) names the owner.
- No real AWS identifier appears anywhere in the diff or the commit message.
