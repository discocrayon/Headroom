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
@register_check(
    "scps",
    "deny_ec2_ami_owner",
    terraform_section=TerraformSection.EC2,
    allowlist=Allowlist(
        summary_key="unique_ami_owners",
        terraform_variable="ec2_allowed_ami_owners",
        empty_allowlist_comment="deny_ec2_ami_owner stays off here: ...",
    ),
)
class DenyEc2AmiOwnerCheck(BaseCheck[DenyEc2AmiOwner]):
```

The decorator records a frozen `CheckDefinition` under the check's name — the
class, the name and type, the `TerraformSection` its parameters render under,
and the `Allowlist` its statement is scoped by, if any — and stamps `CHECK_NAME`
and `CHECK_TYPE` onto the class. The check passes `CHECK_TYPE` to the result
writer, which looks nothing up. It validates first: a
duplicate name, a class already registered under another name, an unknown type,
an RCP check with no allowlist, an empty allowlist key or variable, a blank
`empty_allowlist_comment` (empty or only whitespace), or a name or allowlist
variable another definition already claims fails at import time and inserts
nothing. So does a `CheckType` member passed as the type: it is a `str` and
compares equal to its value, but it formats as `CheckType.SCPS`, and the result
writer builds a check's directory by formatting the type, so the check would
write under `results/CheckType.SCPS/` while the parser reads `results/scps/`.

`headroom/checks/__init__.py` imports every module under `scps/` and `rcps/` so
each decorator runs. **This is the repository's one sanctioned dynamic import.**
Everywhere else, imports are at the top of the file. It exists so that
registering a check is the whole of wiring it into the pipeline: collection,
parsing, and both Terraform generators read the registry rather than a
hardcoded list, result writing is handed the check's `CHECK_TYPE`, and
placement consumes what parsing read from it without a lookup of its own
(INV-13). The one thing a check's module
cannot declare is a new `TerraformSection`; `headroom/enums.py` declares those,
in render order.

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
2. `@register_check` with a type, a name, a `terraform_section`, and — where
   the statement is scoped by an allowlist — an `Allowlist` naming the summary
   key it writes and the module variable it fills. A check whose empty
   allowlist must leave the statement off states why as
   `empty_allowlist_comment` (INV-06); one whose values are ARNs sets
   `restores_account_ids`. That sentence is not module-local: it renders in
   the module the placement names and in every module below it, over a
   smaller account set and at a target of a different kind, so it must read
   true of any subset of the accounts it was written about.
   [`../contracts/terraform.md`](../contracts/terraform.md) owns why.
3. The three abstract methods.
4. A specification under [`../checks/`](../checks/index.md) — enforced by
   `tests/test_spec_corpus.py`.

Step 4 is the one in this list the registry cannot wire up on its own. The
list is the framework's minimum, not the whole cost of adding a check: the
Terraform module still needs its variable and its statement, and the
walkthrough linked above enumerates the rest.
