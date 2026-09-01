# Contract: Terraform generation

Owns what a run writes to the SCP and RCP directories, what it deletes, and the
interface between the generated files and the policy modules.

Implementation: `headroom/terraform/` — `generate_scps.py`, `generate_rcps.py`,
`generate_org_info.py`, `models.py`, `utils.py`, `reconcile.py`. Modules:
`test_environment/modules/scps/`, `test_environment/modules/rcps/`. Tests:
`tests/test_generate_scps.py`, `tests/test_generate_rcps.py`,
`tests/test_generate_org_info.py`, `tests/test_terraform_reconcile.py`,
`tests/test_terraform_utils.py`, `tests/test_terraform_models.py`,
`tests/test_nested_ou_hierarchy.py`, `tests/test_committed_terraform_examples.py`.

Illustrative rendered output:
[`../../documentation/EXAMPLES.md`](../../documentation/EXAMPLES.md).

## The output directories

| Directory | Holds |
|---|---|
| `scps_dir` | `grab_org_info.tf`, plus one `.tf` per SCP target |
| `rcps_dir` | A symlink to `grab_org_info.tf`, plus one `.tf` per RCP target |

Both are **reconciled projections of the current run** (INV-11). They hold what
this run rendered and nothing else Headroom previously wrote.

Appending was the original behavior, and it meant a policy that moved from an OU
down to individual accounts kept its OU-wide attachment — still denying the
account whose new violation caused the move. Reconciling instead means a run
deletes, and three rules make deleting safe: the whole plan is built before
anything is written or removed ([Render before mutate](#render-before-mutate)),
ownership comes from a marker inside the file rather than from its name
([Ownership marker](#ownership-marker)), and a run that read nothing aborts
rather than emptying the directory (INV-01), because deleting everything is also
how a broken run would present.

## File names

| Target | SCP file | RCP file | Module name | `target_id` |
|---|---|---|---|---|
| Root | `root_scps.tf` | `root_rcps.tf` | `scps_root` / `rcps_root` | `local.root_ou_id` |
| OU | `<ou_base_name>_ou_scps.tf` | `<ou_base_name>_ou_rcps.tf` | `scps_<base>_ou` / `rcps_<base>_ou` | `local.<base>_ou_id` |
| Account | `<account_name>_scps.tf` | `<account_name>_rcps.tf` | `scps_<name>` / `rcps_<name>` | `local.<name>_account_id` |

`<account_name>` and `<ou_base_name>` are Terraform-safe identifiers:
lowercased, non-alphanumerics collapsed to single underscores, trimmed, and
prefixed `ou_` if they would otherwise start with a non-letter.

An OU's identifier is built from its **path down from the root**, so two OUs
sharing a name under different parents stay apart (INV-12). Two OUs
canonicalizing to the same identifier, or one claiming the reserved name `root`,
aborts the run rather than overwriting a file. An OU whose name reduces to
nothing usable aborts too.

An account's identifier is built from its name and gated the same way, in
`make_account_base_names` (INV-12). Two accounts claiming one identifier aborts,
as does a name that reduces to nothing usable. Two details differ from the OU
gate:

- It runs over **every account in the organization**, not the analyzed subset.
  `grab_org_info.tf` declares a local for every account the hierarchy holds, so
  a collision between an analyzed account and one excluded by `skip_account_ids`
  is still a duplicate local in the generated Terraform.
- Its error names the **account names**, where the OU error names OU IDs.
  `exclude_account_ids` exists so an operator never has to see account IDs, and
  the generated Terraform looks accounts up by name anyway.

The three shapes above share one filename namespace, not three. An account
named `root` claims the root's file; an account whose safe name ends `_ou`
claims an OU's; two accounts whose names normalize alike claim each other's.
The OU gate and the account gate each keep their own namespace clean and neither
can see the other, nor the fixed root filenames. So every target's render goes
through `claim_plan_path`, which compares the thing that actually collides — the
destination path — against every path already claimed earlier in the same run.
The plan is keyed on that path, so an unguarded second write would replace the
first with nothing raised, and render-before-mutate would then write a plan
already missing a file. A target whose filename is already claimed aborts the
run instead of overwriting the earlier target's file and reporting success
(INV-01); the error names that target and the filename so an operator can act on
it.

Detection, not a naming convention, closes this. Renaming one shape to dodge
one collision class leaves the others open, and two account names can still
normalize alike under any convention chosen, so no set of committed filename
changes closes every class. Checking the rendered filename itself against the
plan already built, regardless of which kind of target produced it, catches
all three classes — root/account, OU/account, and account/account — without
changing a single committed filename.

## Ownership marker

The first line of every `.tf` file Headroom writes:

```
# Code generated by Headroom. DO NOT EDIT.
```

This line, and nothing else, makes a file Headroom's to delete.

A marker inside the file, rather than a filename pattern or a manifest kept
beside the directory, because both alternatives get the deletion wrong.
A pattern wide enough to match the `<account_name>_scps.tf` above also matches
the hand-written `custom_scps.tf` an operator put next to it, so it over-claims.
A manifest is separate state that can drift from the directory it describes: it
orphans whatever it loses track of and over-deletes whatever it names wrongly. A
marker travels with the file, so the file and the claim on it cannot disagree.

- Matched as a **whole first line**, never as a substring. `scps/README.md`
  quotes the marker inside an indented code block while explaining it, so a
  substring scan deletes the document that describes the convention.
- A **symlink is never claimed**, checked before the file is even read.
  `rcps/grab_org_info.tf` points at the real file in `scps/`, so reading through
  the link finds the marker and would delete a link Headroom maintains.
- A file that cannot be read is not claimed. A file we cannot read is a file we
  cannot prove is ours.
- The scan does **not** recurse. `.terraform/` and any module directory below
  the output directory belong to Terraform.

## Render before mutate

Generation builds the whole plan — a mapping of destination path to rendered
content — before touching disk. A failure during rendering has written nothing
and leaves the previous output whole.

Writing is then two steps:

1. Write each planned file, **skipping any whose content is already identical**.
   These directories are committed; rewriting identical bytes turns every run
   into apparent churn.
2. Delete every marked file in either directory that the plan does not name.

Reconciliation runs once, after **both** the SCP and RCP workflows have
succeeded, over both directories against the combined plan. A raise in either
workflow skips it entirely.

An empty recommendation list is a plan for an empty directory, not a no-op. That
is what removes the attachment for a policy that no longer has a placement — and
it is why a run that parsed zero results aborts first (INV-01).

## `grab_org_info.tf`

Written outside both policy workflows, before either runs, into `scps_dir`. It
carries the ownership marker, so reconciliation must count it as expected or it
would be deleted on every run.

`generate_terraform_org_info` takes `snapshot.hierarchy`, the
`OrganizationHierarchy` that `discover_organization` built with its one call to
`build_organization_hierarchy` — the same object `handle_scp_workflow` and
`handle_rcp_workflow` receive. A second, independent walk here once fed only
this file while the policy generators referenced names built from the first;
two walks of a live organization can disagree, and the Terraform then fails at
plan time on a reference to a local this file never declared (INV-12). One walk
means the locals declared below and the references the generators emit are
always built from the same data.

It declares:

| Local | Value |
|---|---|
| `root_ou_id` | The organization root ID, with a validation error if there is not exactly one root |
| `<ou_base_name>_ou_id` | Each OU's ID, resolved by name within its parent's children |
| `<account_name>_account_id` | Each account's ID, resolved by name within its parent OU's child accounts |

Both sides of this contract build the OU local's name with the same function,
`ou_id_local_name()` (INV-12). A nested OU resolves through its own parent's data
source at whatever depth; an account resolves through its own parent OU, and an
account parented directly to the root resolves against the organization's full
account list. Each local is preceded by a validation local that errors at plan
time when the name does not resolve to exactly one target.

One shared function rather than two that agree, because the two stopped agreeing
once: `generate_org_info` declared `local.<ou_base_name>_ou_id` for top-level
OUs only while the policy generators emitted references for OUs at any depth,
and the Terraform failed at plan time on an undeclared local. Each module's own
tests passed throughout — one asserted the reference, the other asserted the
declaration, and neither could see the mismatch between them.
`tests/test_nested_ou_hierarchy.py` generates both from one hierarchy. That is
the naming route to the plan-time failure INV-12 prevents; the second-walk route
at the top of this section reaches the same failure from the other side.

`rcps_dir` gets a **relative symlink** to it rather than a copy, recreated on
every run.

## Module interface

Both generated module calls take a `target_id` validated to be a 12-digit
account ID, an `ou-` prefixed OU ID, or an `r-` prefixed root ID.

### SCP module

One boolean per check, named exactly for the check. Two allowlist variables,
each rendered **only when its check is enabled**:

| Allowlist variable | Fed by |
|---|---|
| `ec2_allowed_ami_owners` | `deny_ec2_ami_owner` |
| `iam_allowed_users` | `deny_iam_user_creation` |

`iam_allowed_users` entries have their account ID rewritten to
`${local.<account_name>_account_id}` so the ARN resolves through the same
generated locals as everything else.

`deny_ec2_ami_owner` is forced **off**, with a rendered comment saying why, when
the covered accounts observed no AMI owner at all (INV-06).
[`../invariants.md`](../invariants.md#inv-06--an-empty-allowlist-is-never-rendered-as-an-empty-list)
owns what an empty allowlist would do were it rendered.

The module assembles one policy from the enabled statements and attaches it. If
no statement is enabled, no policy resource is created. A root target
additionally gets an unconditional `organizations:LeaveOrganization` deny, which
no check gates: it is a guardrail the module adds because it can never break an
existing workload.

### RCP module

One boolean and one allowlist variable per check, named by
`RCP_TERRAFORM_VARIABLES` in `generate_rcps.py`. A registered RCP check absent
from that table is parsed and then silently dropped at render time, so
`test_table_covers_every_registered_rcp_check` holds it in sync with the registry
(INV-13).

Every check appears in every rendered module call: enabled with its allowlist, or
explicitly `false`. Variable names are listed in
[`policy-model.md`](policy-model.md) alongside the statements they gate.

Unlike the SCP module, the RCP module creates and attaches its policy
unconditionally.

### Policy size

Both modules validate the rendered policy against the 5,120-character
Organizations limit **at plan time** rather than at apply time. What each
measures is the length of
`jsonencode(jsondecode(data.aws_iam_policy_document.<name>.json))` — the
provider's rendering of the statement list, round-tripped to strip insignificant
whitespace — and not the length of the module's own statement list, which the
provider normalizes before rendering. The figures below count the former.

AWS permits at most 5 directly attached policies of each type per target, or 4
where `FullAWSAccess` is still attached. Headroom emits one policy of each type
per target and does not manage that budget.

**The RCP budget is exhaustible.** `modules/rcps/rcps.tf` creates exactly one
`aws_organizations_policy`, so all seven statements share one document. With
seven statements includable simultaneously the scaffolding alone costs roughly
2,240 of the 5,120 characters, and each additional twelve-digit account ID costs
about 14 more, leaving room for a couple of hundred allowlist entries across all
seven lists combined. `DenyServiceConfusedDeputy` is 339 of that scaffolding on
its own, measured with an empty allowlist, because it carries six services'
actions and three condition blocks. A large enough organization will hit the
plan-time `error()`, now slightly sooner.

**Both figures are carried forward, not re-measured.** They come from `8bdeb4d`,
the commit that added the seventh statement, and no `terraform plan` has been
run against the module since to confirm either. The 339 in particular is
asserted there as measured, and a later reader encoding `local.rcp_1_policy`
directly reached 317 for that statement and 1,772 for the whole document without
being able to close the gap — the length that counts is the provider's
rendering, which needs credentials for
`data.aws_organizations_organization.current` to read. The 14 does check out
from the repository alone: a quoted twelve-digit account ID is 14 characters, 15
with the comma joining it to the next.

**Splitting across a second policy is deliberately not implemented.** A loud
failure at plan time is the correct outcome: the alternative is silently
truncating an allowlist and denying access the organization depends on, which
is the safety promise inverted. Changes to `modules/rcps/` are in any case a
non-goal for the generator, which writes module *calls* and never module
bodies.

### Rollback

Every check's statement, in either module, is gated by its own `deny_<check>`
boolean. Setting that variable to `false` for a target removes exactly the
statement it gates and leaves every other statement in the module in place.
This is the rollback for any generated policy, not a mechanism specific to one
check.

A manual `false` does not survive the next run: generation rewrites the file
([Render before mutate](#render-before-mutate)). The edit is overwritten
exactly when the run still recommends `true` — the case it was made for — and
holds only where the run would have rendered `false` anyway.

## Committed worked examples

`test_environment/scps/` and `test_environment/rcps/` are committed as worked
examples of what a run produces, not as fixtures a test builds fresh, and
nothing compared them to the module they call — so they can drift silently.
They once did, by different amounts for different variables:
`deny_ec2_public_ip` (`7470b5b`, 2025-11-11) and `deny_lambda_auth_type_none`
(`1a56210`, 2025-11-18) sat unpassed in the three committed SCP module calls
for months. `deny_ec2_imds_hop_limit` (`60a2992`, 2026-08-19) was newer: the
files' last substantive rewrite before this pin (`56cda9f` and `6b74d76`,
both 2026-08-25) came six days after that variable already existed, and
still omitted it. However long the gap ran, a module call missing a variable
with no default is a call `terraform plan` refuses, so the worked example
this repository ships could not be planned at all, and nothing noticed.

`test_every_committed_module_call_passes_every_required_variable` closes that
gap. It reads each module's `variables.tf` for the variables it declares with
no default, reads every generated module call under `test_environment/scps/`
and `test_environment/rcps/` for the variables it assigns, and fails by name
when a call omits one. A variable added to a module without being added to
every committed call that uses it fails the suite.
