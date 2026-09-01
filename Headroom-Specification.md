# Headroom specification

**This file has moved. The specification is now [`spec/`](spec/README.md).**

It was one 4,334-line document holding requirements, architecture,
implementation excerpts, generated examples, runbooks, and roadmap at once. Its
check inventory covered 7 of the 15 checks that were registered when it was
retired — the registry has grown since — and the same behavior was
stated in as many as five places, so a change landed in one of them and left the
rest quietly wrong. The IMDS exemption behavior alone was described four
different ways within this file.

This page exists so that existing links and bookmarks land somewhere useful. It
is not normative and carries no behavior of its own.

## Where things went

| Looking for | Read |
|---|---|
| What Headroom is for, and the safety promise | [`spec/product.md`](spec/product.md) |
| The rules no subsystem may break | [`spec/invariants.md`](spec/invariants.md) |
| The pipeline and module responsibilities | [`spec/architecture/overview.md`](spec/architecture/overview.md) |
| Role chain, sessions, regions, account projections, concurrency | [`spec/architecture/aws-execution.md`](spec/architecture/aws-execution.md) |
| The registry and `BaseCheck` | [`spec/architecture/check-framework.md`](spec/architecture/check-framework.md) |
| Config fields, CLI options, defaults | [`spec/contracts/configuration.md`](spec/contracts/configuration.md) |
| Result JSON, filenames, redaction, resume | [`spec/contracts/results.md`](spec/contracts/results.md) |
| SCP/RCP semantics, policy patterns, statement grammar | [`spec/contracts/policy-model.md`](spec/contracts/policy-model.md) |
| Where a policy attaches, and allowlist unions | [`spec/contracts/placement.md`](spec/contracts/placement.md) |
| Generated files, ownership marker, reconciliation | [`spec/contracts/terraform.md`](spec/contracts/terraform.md) |
| What one check decides | [`spec/checks/index.md`](spec/checks/index.md) |
| Test layers and gates | [`spec/verification/strategy.md`](spec/verification/strategy.md) |

Material that was never normative moved out of the corpus entirely:

| Looking for | Read |
|---|---|
| IAM role setup, credentials, troubleshooting | [`documentation/SETUP.md`](documentation/SETUP.md) |
| Example CLI and Terraform output | [`documentation/EXAMPLES.md`](documentation/EXAMPLES.md) |
| Live-test topology, execution, cost, cleanup | [`test_environment/README.md`](test_environment/README.md) |
| Future work | [`ROADMAP.md`](ROADMAP.md) |
| Adding a check | [`HOW_TO_ADD_A_CHECK.md`](HOW_TO_ADD_A_CHECK.md) |

## Reading the corpus

[`spec/README.md`](spec/README.md) is the manifest. It carries the authority
model, which document owns which topic, and the precedence order between them.
Routing from the path you are touching to the specifications that govern it is
in [`CLAUDE.md`](CLAUDE.md#routes).

The full contents of this file remain in git history.
