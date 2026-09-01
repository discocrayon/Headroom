# Architecture: the check framework

Owns how a check is discovered, what a check must implement, and what the
framework does around it. What each individual check *decides* lives in
[`../checks/index.md`](../checks/index.md); how to author one lives in
[`../../HOW_TO_ADD_A_CHECK.md`](../../HOW_TO_ADD_A_CHECK.md).

Implementation: `headroom/checks/registry.py`, `headroom/checks/base.py`,
`headroom/checks/__init__.py`. Tests: `tests/test_checks_registry.py`, plus one
`tests/test_checks_<name>.py` per check.

## Discovery

A check registers itself:

```python
@register_check("scps", "deny_ec2_public_ip")
class DenyEc2PublicIpCheck(BaseCheck[DenyEc2PublicIp]):
```

The decorator records the class under its name, stamps `CHECK_NAME` and
`CHECK_TYPE` onto it, and registers the name-to-type mapping that the result
writer resolves directories through.

`headroom/checks/__init__.py` imports every module under `scps/` and `rcps/` so
each decorator runs. **This is the repository's one sanctioned dynamic import.**
Everywhere else, imports are at the top of the file. It exists so that
registering a check is the whole of wiring it into discovery: collection, result
writing, and placement iterate the registry rather than a hardcoded list.

Not every later stage does. Parsing and Terraform generation still branch on a
hardcoded check name, and INV-13 records the three departures and how each
fails. So a new check does take edits outside its own module: the framework's
own minimum is the list under "Adding a check" below, and a check carrying an
allowlist also takes edits to `headroom/types.py`, `headroom/parse_results.py`,
and `headroom/terraform/generate_scps.py`, which
[`../../HOW_TO_ADD_A_CHECK.md`](../../HOW_TO_ADD_A_CHECK.md) enumerates.

`check_type` is `scps` or `rcps`. It is the directory the results go in and the
policy type generated from them; nothing infers it from the check's name.

## What a check implements

`BaseCheck` is a template method. A concrete check implements exactly three
methods and inherits everything else.

| Method | Returns | Responsibility |
|---|---|---|
| `analyze(session)` | `List[T]` | Every AWS call. One entry per resource examined. |
| `categorize_result(result)` | `(CheckCategory, dict)` | The verdict for one resource, and the entry to record |
| `build_summary_fields(check_result)` | `dict` | The check-specific part of the summary |

`T` is the check's own per-resource type. The framework does not inspect it.

The split is the point: `analyze` may call AWS and may not decide;
`categorize_result` decides and may not call AWS. A check that reaches for AWS
during categorization has put a network failure inside a verdict.

## The three categories

| Category | Meaning | Blocks deployment |
|---|---|---|
| `VIOLATION` | The policy statement would deny this resource | **Yes** |
| `EXEMPTION` | The statement's condition would spare this resource | No |
| `COMPLIANT` | The statement would allow this resource | No |

A category the framework does not recognize is silently dropped from all three
buckets, so a check must return one of the three.

`EXEMPTION` may only be claimed where the scan can see the dimension the
exemption turns on, or something that reliably stands in for it (INV-09). Only
`deny_ec2_imds_v1` currently produces exemptions, and it substitutes an instance
tag for the launch request's tag; its document states what that costs.

## What `execute` does

The template method, in order:

1. `analyze(session)` — one list of raw results.
2. `categorize_result` for each, sorted into violations, exemptions, compliant.
3. A summary of `account_name`, `account_id`, `check`, plus
   `build_summary_fields`.
4. `write_check_results(...)` — the single call site for the result writer.
   Schema: [`../contracts/results.md`](../contracts/results.md).
5. A completion line naming the three counts.

A check does not choose its filename, its directory, or its redaction. Those are
the framework's, so they stay uniform across every check.

## What the framework does not do

- **No retry, no error suppression.** An exception from `analyze` propagates and
  aborts the run (INV-02). A check that means to tolerate a specific per-region
  or per-resource failure handles it itself, records the outcome in its result,
  and says so in its document.
- **No resume logic.** Whether to run at all is decided before instantiation, by
  `results_exist`.
- **No ordering guarantee** between checks or between accounts.

## Construction

Every check is constructed with the same seven keyword arguments:

`check_name`, `account_name`, `account_id`, `results_dir`, `org_account_ids`,
`org_id`, `exclude_account_ids`.

`org_id` is this organization's ID. Every source guard scoped to an
organization — `aws:SourceOrgID` and `aws:SourceOrgPaths` — is classified
against it: a guard naming this organization needs no allowlist entry, and one
naming any other organization names accounts no allowlist can carry.

`BaseCheck.__init__` accepts and ignores `**kwargs`, so a check that needs
neither extra does not have to declare it. The two extras are `org_account_ids`
and `org_id`, and both are meaningful only to RCP checks: all seven declare
them, and none of the nine SCP checks does. A check needing something genuinely
new must have it passed by `run_checks_for_type`, which constructs every check
identically.

## Adding a check: the framework's requirements

Full walkthrough in
[`../../HOW_TO_ADD_A_CHECK.md`](../../HOW_TO_ADD_A_CHECK.md). The framework
itself requires only:

1. A module under `headroom/checks/scps/` or `headroom/checks/rcps/`, so
   discovery imports it.
2. `@register_check` with a type and a name.
3. The three abstract methods.
4. A specification under [`../checks/`](../checks/index.md) — enforced by
   `tests/test_spec_corpus.py`.
5. For an RCP check, an entry in `RCP_TERRAFORM_VARIABLES` — enforced by
   `test_table_covers_every_registered_rcp_check`.

Steps 4 and 5 are the two in this list the registry cannot wire up on its own.
They are the framework's minimum, not the whole cost of adding a check —
Discovery above names the rest.
