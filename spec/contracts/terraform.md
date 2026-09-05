# Contract: Terraform generation

Owns what a run writes to the SCP and RCP directories, what it deletes, and the
interface between the generated files and the policy modules.

Implementation: `headroom/terraform/` — `generate_scps.py`, `generate_rcps.py`,
`generate_org_info.py`, `parameters.py`, `disabled_reasons.py`, `plan.py`,
`apply.py`, `models.py`, `utils.py`. The three `generate_*` modules render and
write nothing, `parameters.py` is the one parameter renderer two of them share
and `disabled_reasons.py` the one derivation of why a check is off, `plan.py`
merges and validates what they rendered, and `apply.py` is the only one that
touches the filesystem. Modules: `test_environment/modules/scps/`,
`test_environment/modules/rcps/`. Tests: `tests/test_generate_scps.py`,
`tests/test_generate_rcps.py`, `tests/test_generate_org_info.py`,
`tests/test_terraform_parameters.py`, `tests/test_terraform_disabled_reasons.py`,
`tests/test_terraform_plan.py`, `tests/test_terraform_apply.py`,
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
- An **unrelated symlink is never claimed**, checked before the file is even
  read. Reading through a link finds whatever the target holds, and a marker
  found that way says nothing about the link.
  `rcps/grab_org_info.tf` is the one exception, because it is Headroom's own:
  the reserved link this run plans. Apply creates it when it is absent, leaves
  it exactly as it is when it already resolves to the right file, and replaces
  it when it points somewhere else. A marked regular file at that path — the
  shape an older layout left on disk — is migrated into the link; an unmarked
  file or a directory there aborts the run, like any other ownership conflict.
- A file that cannot be read is not claimed. A file we cannot read is a file we
  cannot prove is ours.
- The scan does **not** recurse. `.terraform/` and any module directory below
  the output directory belong to Terraform.

## Render before mutate

The boundary is the whole run, not one directory. `compile_terraform_plan`
renders the organization data sources, every SCP file, every RCP file, and the
reserved `rcps/grab_org_info.tf` symlink into one `TerraformPlan`, validates it,
and touches the filesystem nowhere. `apply_terraform_plan` is the only code in
Headroom that writes, links, or deletes. Both policy workflows parse, place, and
print but write nothing, so a failure in either — or in rendering, or in
validation — leaves the previous output whole and deployable.

The compiler merges the three renderers' output through `claim_plan_path` rather
than by assignment. Each renderer keeps its own namespace collision-free and
none can see the others, so an ordinary dictionary update would silently drop
one component's file and hand validation a plan already missing it
([File names](#file-names)).

Applying is preflight, then mutation. Apply revalidates the plan it was handed
rather than trusting it: the compiler is the only thing that builds one, but
nothing in the type stops a caller from assembling a `TerraformPlan` by hand and
passing it straight to the one function that mutates the disk. A complete
read-only pass then proves Headroom owns every destination before the first
`mkdir`, and reports every conflict it found at once rather than the first — an
operator who fixes one ownership conflict per run learns of the next one only by
running again.

The mutation order is directories, then the changed files, then the link, then
the stale deletions. Deleting last is what makes a stale file's removal
conditional on the desired writes having succeeded. A file whose content already
matches is never opened for write and a correct link is never recreated, so two
identical applications leave file mtimes and symlink `lstat` metadata untouched:
these directories are committed, and rewriting identical bytes turns every run
into apparent churn.

A planned write is a fully written sibling temp file renamed over the
destination, never a truncation in place. Opening the destination itself
truncates it before any content arrives, so a write that dies in between leaves
a 0-byte file carrying no marker — which the next run's ownership check then
refuses as a file Headroom does not own, wedging every later run until a human
deletes the leftover. Renaming also splits any inode the destination shares, so
a hardlinked stale file that the identity guard deliberately retains keeps its
own content instead of silently acquiring the planned file's. The temp file is a
sibling, so the rename stays within one filesystem, and is deliberately not
named `*.tf`, so an orphan left by a failed write is invisible to Terraform and
to the stale-file scan alike.

This is not a transaction and must not be described as one. Parsing, rendering,
validation, and preflight failures mutate nothing; an OS failure partway through
the mutation phase can still leave a partial apply.

An empty recommendation list is a plan for an empty directory, not a no-op. That
is what removes the attachment for a policy that no longer has a placement — and
it is why a run that parsed zero results aborts first (INV-01).

## Two names for one output directory

`scps_dir` and `rcps_dir` pointing at one directory would generate every RCP
file over the SCP file of the same name and reduce `grab_org_info.tf` to a
symlink to itself. Three checks sit at three distances from the mistake, because
no one of them can see what the next one sees.

`HeadroomConfig` rejects the two settings being written identically, which
catches a plain typo at the point it is made rather than on the far side of a
scan of every account in the organization. It rejects a `..` component in either
setting for the same reason the compiler can afford to be lexical: Headroom
folds `..` away without reading anything and the operating system does not, so
the two disagree about where a file goes the moment a component of the path is a
symlink.

Compilation compares the two paths lexically, which is what keeps it free of
filesystem access and what makes the same plan validate identically on every
machine. It therefore catches only two spellings of one path — not a symlink,
and not a case variant on a case-insensitive filesystem, both of which reach one
inode under two names.

`apply_terraform_plan` compares them by device and inode instead, twice: in
preflight, where the alias joins the one aggregated ownership report, and again
immediately after the directories are created, which is the only point at which
an alias that `mkdir` itself produced first becomes observable. Both abort
naming both configured paths, and neither has written, linked, or deleted
anything.

## `grab_org_info.tf`

Rendered alongside everything else and written by apply into `scps_dir`. It
carries the ownership marker, so the plan must name it or the stale-file pass
would delete it on every run.

`render_terraform_org_info` takes `snapshot.hierarchy`, the
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

`rcps_dir` gets a **relative symlink** to it rather than a copy. The plan
carries the file the link must point at, not the text the link must hold. The
text is a relative path, and a relative path is relative to where the link
really lives: computing it lexically from the configured `rcps_dir` is wrong as
soon as that spelling is a symlink to somewhere else, because the link is
created inside the directory the spelling points at and resolves from there.
Apply computes it with `os.path.realpath` on both sides, which reads the
filesystem and is therefore apply's to do rather than the compiler's. Nothing
downstream would have caught the lexical version: the next run reads the same
wrong text back, finds it equal to the same wrong expectation, and leaves a
dangling link in place while reporting a converged run.

## Escaping

Every value Headroom places between double quotes in HCL passes through
`hcl_escape` in `headroom/terraform/models.py`, once, at the line that emits
the quotes. It applies the escapes HCL's quoted-template grammar defines — a
backslash, a double quote, a newline, a carriage return, a tab — and doubles
the first character of `${` and `%{` so neither opens an interpolation or a
directive. Other control characters are not escaped: AWS constrains the names
this renders to the ASCII range, and none is typed in practice.

OU and account names are the values that carry arbitrary text. AWS
Organizations validates both with `[\s\S]*`, to 128 and 50 characters. Each
reaches `grab_org_info.tf` in three places — the `ou.name ==` comparison in a
`for` expression, the `error(...)` message beside it, and the comment above —
and once reached all three verbatim. A quote or a backslash in a name then
failed `terraform plan` after apply had written the file, since `validate_plan`
checks paths, links, and the marker rather than syntax; a `${` was
interpolated; and a line break ended the comment early, leaving the rest of the
name as a bare top-level line, though the same break also broke the quoted
occurrences, so the file did not parse. `tests/test_generate_org_info.py`
renders names holding each of those characters and pins the escaped output.

A comment has no escape syntax, so its one hazard is the line break.
`comment_text` in `headroom/terraform/models.py` replaces every line break with
the two-character sequence `\n`. `TerraformComment.render` passes its text
through it, and so does the header line of every module block, which names the
account or OU the module covers; the organization renderer emits its
name-bearing comments through `TerraformComment`. No rendered comment spans
lines. `tests/test_terraform_models.py` pins both renderers.

A parameter value is data and is escaped in full. One producer composes
template text instead: an allowlist whose definition sets
`restores_account_ids` has the account ID in each ARN replaced by a reference
to that account's local, so the module hardcodes no account ID.
`_replace_account_id_in_arn` in `headroom/terraform/parameters.py` does the
rewrite and escapes the other segments itself, along with any value it leaves
unrewritten, and the renderer emits the allowlist with `template=True`, which
is the only opt-out from the rule. `tests/test_terraform_parameters.py` pins
the escaped output around a live reference. `target_id` on a module block is
the one other reference, and it is emitted unquoted, never as a string value.

## Module interface

Both generated module calls take a `target_id` validated to be a 12-digit
account ID, an `ou-` prefixed OU ID, or an `r-` prefixed root ID.

### SCP module

One boolean per check, named exactly for the check. An allowlist variable for
each check whose definition declares one, rendered **only when its check is
enabled**; today two:

| Allowlist variable | Fed by |
|---|---|
| `ec2_allowed_ami_owners` | `deny_ec2_ami_owner` |
| `iam_allowed_users` | `deny_iam_user_creation` |

Both names come from the check's `Allowlist` in its own module; nothing in
`generate_scps.py` names either.

`iam_allowed_users` entries have their account ID rewritten to
`${local.<account_name>_account_id}` so the ARN resolves through the same
generated locals as everything else. The rewrite belongs to the
`restores_account_ids` flag, not to IAM: it reads the ARN's account field
whatever service the ARN names, so a future KMS or SQS allowlist declaring the
flag renders locals rather than the accounts' real IDs. An ARN naming an account
outside the hierarchy, or one with no account field, is emitted literally.

A check whose `Allowlist` declares an `empty_allowlist_comment` — both of these
do — is forced **off**, with that comment rendered, when the covered accounts
observed no value at all (INV-06).
[`../invariants.md`](../invariants.md#inv-06--an-empty-allowlist-is-never-rendered-as-an-empty-list)
owns what an empty allowlist would do were it rendered. The renderer logs the
same comment at warning level as `Module <module name>: <comment>`, so the run's
log names the module and the reason together.

The module assembles one policy from the enabled statements and attaches it. If
no statement is enabled, no policy resource is created. A root target
additionally gets an unconditional `organizations:LeaveOrganization` deny, which
no check gates: it is a guardrail the module adds because it can never break an
existing workload.

### RCP module

One boolean and one allowlist variable per check. The boolean is the check
name; the allowlist variable is the `terraform_variable` the check's
`Allowlist` declares in its own module. Both generators render from
`get_check_definitions`, so a registered check cannot be dropped at render;
`test_every_registered_rcp_check_is_rendered` pins it (INV-13).

Every check appears in every rendered module call: enabled with its allowlist, or
explicitly `false`. Variable names are listed in
[`policy-model.md`](policy-model.md) alongside the statements they gate.

Unlike the SCP module, the RCP module creates and attaches its policy
unconditionally.

### Parameter order

Both module calls render their parameters in one order: sections in the
declaration order of `TerraformSection` in `headroom/enums.py`, each headed by
its comment and separated from the next by a blank line, and checks by name
within a section. Import order and registration order play no part, so two
runs over one registry render identically. `headroom/terraform/parameters.py`
is the one renderer both generators call. It aborts the run on a
recommendation naming a check no definition of that module's policy type
describes, and on a recommendation for an allowlist check that carries no list
at all — an observed-empty allowlist is `[]`, and `None` there is lost data
(INV-01).

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

## Why a check renders false

Every registered check renders in every generated module call (INV-13), so most
booleans in most files are `false` for reasons that have nothing to do with
that file's target. Three unrelated facts once rendered identically: a
guardrail already in force further up the tree, one held off by a violation
somewhere below, and one no account was ever scanned for. INV-01 makes the
third the one a reader must never take for the other two.

Every `false` that has no recommendation behind it therefore carries a comment
above it saying which. `headroom/terraform/disabled_reasons.py` derives them,
and it names no check: a check name reaches it only as data, from `check_names`
and from the keys of the maps it is handed (INV-13). `placed_targets` reduces
a run's recommendations to the target IDs each check attaches at, once per run
rather than once per target — a `none` recommendation attaches nowhere and
contributes nothing. `split_placements` beside it drops the `none`
recommendation the same way, before asking what any allowlist renders — a
`none` recommendation carries no allowlist, since placement unioned one over no
accounts, and reading that as lost data would abort generation for the whole
organization over one check no account is safe for. It then calls
`placed_targets` twice, over the recommendations that render `true` and over
the ones an empty allowlist turned off ([The empty-allowlist
boundary](#the-empty-allowlist-boundary)), because a placement that renders
`false` enforces nothing and must not be reported as enforcing anything. Each
generator calls the split once, telling it which field carries the allowlist,
since that is the one thing the two recommendation types disagree on. The split
is per recommendation rather than per check name: one check can be placed at
two targets with only one of the two allowlists empty.
`disabled_reasons` then answers for one target, from those two maps, the
coverage map ([`placement.md`](placement.md#check-coverage)), and the
hierarchy. A check with a recommendation naming this target is absent from what
it returns, and that absence is what the renderer keys on: the map is keyed on
*no recommendation names this target*, not on *renders false*.

A root file's target is the organization root's own ID rather than `None`, so
ancestry is one set-membership question at every level instead of three cases
to enumerate, and no separate level argument can fall out of step with it. The
three ID namespaces do not overlap, so the hierarchy alone says whether an ID
is the root, an OU, or an account, and an ID the hierarchy does not hold aborts
the run the way every other read of the hierarchy in generation does. Nothing
here is caught and turned into a missing comment: a silently absent reason
would read as a shape the grammar does not define.

### The four shapes

For a target `T` and a check `C` that no recommendation places at `T`, exactly
one shape applies. `T`'s own accounts are the frame for every count and every name:
the root file counts the whole organization, an OU file counts that OU's
subtree, an account file counts itself.

| # | Condition | Rendered text |
|---|---|---|
| 1 | A recommendation for `C` names a strict **ancestor** of `T` | `Enforced at the organization root`, or `Enforced at OU high_value_assets` |
| 2 | A recommendation for `C` names a strict **descendant** of `T` | `Enforced below at OU acme_acquisition, OU high_value_assets; blocked elsewhere by 1 of 4 analyzed accounts (shared-foo-bar)` |
| 3 | Neither, and `C` analyzed at least one account under `T` | `Blocked by 2 of 4 analyzed accounts (acme-co, shared-foo-bar)` |
| 4 | `C` analyzed no account under `T` | `No results for this check - not evidence of safety` |

A target is named `the organization root`, `OU <path>`, or `account <name>`.
The OU path is the same root-down label the file header carries, built by
`ou_path_names`, so a nested OU reads `OU Production / Data` and two OUs
sharing a name stay apart (INV-12).

Shape 1 names one ancestor. The traversal places a check at most once on any
root-to-leaf chain — a safe root ends the walk, and a safe OU marks its whole
subtree covered — so no target has two placed ancestors.

Shape 2's descendants are any targets below `T`, which for a root or an OU file
may be OUs, accounts, or both: `Enforced below at OU high_value_assets, account
acme-co`. An account is a leaf, so **shape 2 never appears in an account file**;
an account's `false` is shape 1, 3, or 4.

The blocked clause collapses grammatically, the way placement's own `reasoning`
collapses its analyzed-of-reached counts:

| Situation | Clause |
|---|---|
| Some of the analyzed accounts | `blocked by 2 of 4 analyzed accounts (acme-co, shared-foo-bar)` |
| All of them, and more than one | `blocked by all 4 analyzed accounts (acme-co, fort-knox, security-tooling, shared-foo-bar)` |
| One analyzed account, `T` an OU or the root | `blocked by the only analyzed account (acme-co)` |
| `T` an account | `blocked by this account's violations` — the count is always one of one and the account is `T`, which the filename already names |

Shape 3 capitalizes the clause and stands alone. Shape 2 appends it after `; `
in lower case and leads it with `blocked elsewhere by`, because the targets it
has just named are where the check is in force.

### Exactly one shape applies

The traversal in `HierarchyPlacementAnalyzer.determine_placement`
([`placement.md`](placement.md#the-traversal)) is what makes the four
exhaustive and mutually exclusive, and that is why the grammar is four fixed
shapes rather than a free combination of clauses.

1. **Shape 1 excludes 2 and 3.** An ancestor placement required every analyzed
   account in that ancestor's subtree — a superset of `T`'s — to be safe. No
   violation under `T`, and no placement below `T`, can coexist with it.
2. **Shape 2 always carries its second clause.** `T` was passed over only
   because an analyzed account under it was unsafe, so a descendant placement
   implies a violation under `T`. The clause is never omitted.
3. **Shape 3 can never report none blocked.** If every analyzed account under
   `T` were safe and `T` had results, `is_safe_for_ou(T)` holds, `T` takes the
   placement, and `C` renders `true`. So at least one account is unsafe
   whenever at least one was analyzed.
4. **Shape 4 is exactly "no analyzed account under `T`".** It covers a check
   that produced no results at all — four of the nine SCP checks in the
   committed examples, since SCP parsing tolerates a missing check directory
   where RCP parsing aborts ([`placement.md`](placement.md#rcp-placement)) —
   and an OU whose every account was skipped or non-ACTIVE. One INV-01
   statement serves both.

### Formatting

| Rule | Why |
|---|---|
| Names sort lexicographically, on the rendered phrase rather than the ID | Two runs over one result set render identical bytes, the determinism [Parameter order](#parameter-order) already keeps |
| At most five names, then `and N more` | A committed file must not scale with the size of the organization. The cap applies independently to shape 2's target list, to the off-below list shapes 2 and 3 can carry, and to the blocked-account list |
| Wrapped at 72 characters **of comment text** | `TerraformComment.render` prepends `  # `, so a wrapped line occupies 76 columns |
| A name never splits across lines | Hyphens are not break points, and a name's own spaces are non-breaking while wrapping, so `security-tooling-production` and `Prod US` each stay whole. A name longer than the width overflows its line rather than breaking, because a corrupted identifier is worse than a long comment |
| Each wrapped line is its own `TerraformComment` | `comment_text` folds a real line break into the two-character sequence `\n` ([Escaping](#escaping)), so a comment that spans lines has to arrive as separate lines |

### The empty-allowlist boundary

A check forced off by an empty allowlist (INV-06) is none of the four shapes.
It **has** a recommendation naming `T`: placement cleared the target, and
generation turned the statement off because the covered accounts observed no
value at all. `disabled_reasons` returns nothing for it, and the comment
rendered is the check's own `empty_allowlist_comment`, the sentence the check
wrote rather than one the grammar composed, wrapped to the same width as every
comment beside it. `renders_enabled` in `parameters.py` is the one place that
decides the flip; `_render_definition` and `split_placements` read it.
`deny_ec2_ami_owner` in `test_environment/scps/root_scps.tf` is the committed
example.

Per file, the two mechanisms can never both fire, because the reasons map is
keyed on the absence of a recommendation and not on the boolean's value. Across
files they meet, and that is what the flipped map exists for. A flipped
placement at `T` enforces nothing at all, so every target under `T` renders the
**same `empty_allowlist_comment`** rather than shape 1: `Enforced at the
organization root` above a root file that itself renders `false` is the INV-01
failure these comments exist to remove, stated more confidently than the bare
`false` it replaced. The committed examples carried exactly that until this
was fixed, on `deny_ec2_ami_owner` in both OU files.

Repeating the sentence below `T` is sound because emptiness is monotone
downward. The allowlist at `T` is the union of what the accounts under `T`
observed, and the union over any subset of them is a subset of that: empty at
`T` means empty at every descendant. A descendant of a **live** placement still
gets shape 1, which is why shape 1 is asked before the flipped map — the two
can be siblings under one root.

Monotonicity carries the sentence only as far as the accounts something looked
at. `empty_allowlist_comment` is a claim about what the covered accounts held —
no resolvable AMI owner, no third-party principal — and a descendant whose own
accounts produced no result contributed nothing to the union it generalises
from. Repeating it there would report absence of evidence as evidence of safety,
so **shape 4 outranks the flipped map**: a target with no results of its own
says so, whatever a flipped ancestor found. Shape 1 keeps its place above both,
because it names where the policy attaches rather than what was observed, and
that stays true of a target whatever was scanned under it. The resulting
precedence is shape 1, shape 4, the flipped map, then shapes 2 and 3.

This widens what a check author signs up for. A sentence written for the module
the check was placed in now renders in every module below it, over a smaller
account set and at a target of a different kind, so it must read true for any
subset of the accounts it was written about. `empty_allowlist_comment` in
[`../architecture/check-framework.md`](../architecture/check-framework.md) owns
that requirement.

Above a flipped placement the correction runs the other way. A target whose only
descendant placement was flipped off stops getting shape 2, because `Enforced
below at OU sandbox` would name a target that enforces nothing; it falls to
shape 3, which is the true statement, since a violation somewhere under it is
why the placement went below it at all. Shape 3 still names the flipped
targets, the way shape 2 does: `Blocked by 1 of 3 analyzed accounts (fort-knox);
off below at OU sandbox`. A shape 3 count with safe accounts in it arises only
this way — a safe account under an unplaced target sits under some placement
below it, and were that placement live the target would be shape 2 — so leaving
the flipped targets unnamed would leave the reader to guess where the safe
accounts went, and to guess wrong.

A target with **both** kinds of placement below it keeps shape 2 and names them
both: `Enforced below at OU acme_acquisition; off below at OU shared_services;
blocked elsewhere by 1 of 3 analyzed accounts (fort-knox)`. Naming only the live
half leaves the reader to subtract — three analyzed, one blocking, one covered
below, so the third must be covered too — and the third is protected nowhere,
because a flipped placement enforces nothing. That is the same false belief
shape 1 above a flipped root would create outright, reached by omission instead,
which is why the count alone is not enough even though every number in it is
right.

The blocked clause always has an account to name, in shape 2 as much as in
shape 3. A target takes no placement of its own only when some analyzed account
under it is unsafe, and that premise is what both shapes rest on: it is equally
why a shape-2 target holds a placement below rather than at itself. So the
clause can never come back with an empty list of accounts, and
`_blocked_clause` **raises** rather than rendering one. Only a coverage map
disagreeing with the placements it was built beside can reach that, and the
sentence it would otherwise compose — `blocked by the only analyzed account ()`
— names nobody while blaming them.

### Where the derivation lives

`parameters.py` derives no reasons. `reasons` is a
`Mapping[str, List[str]]` from check name to already-wrapped comment lines, and
the renderer emits one `TerraformComment` per line above the check's boolean —
a list rather than a string, because a comment that spans lines cannot be one
`TerraformComment`. It is the one renderer both generators call, and handing it
the target, the recommendation list, and the hierarchy relationships would make
it a placement reader as well as a renderer. Each generator calls
`disabled_reasons` itself, once per target, and passes the result down.

The one sentence `parameters.py` does render itself is the check's own
`empty_allowlist_comment`, which belongs to the boolean it is flipping and
reaches no other target's file from there. Wrapping it is presentation, not
derivation, and `wrap_comment` in `models.py` is the shared primitive both
modules call — it lives beside `TerraformComment` because that is what it
produces lines for, and because a renderer reaching into another module's
private helper for it would be the coupling this section exists to prevent.

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

`test_every_registered_check_is_declared_by_its_module` closes the same gap from
the registry's side. Every registered check name is passed as its module's
boolean, and every allowlist's `terraform_variable` alongside it when the check
is enabled, so each must be a variable the module declares; a check registered
without its `variable` block passed every test and failed at the operator's
`terraform plan` with an unsupported argument. The guard reads each module's
`variables.tf` for every declaration, with or without a default, and fails by
name when a definition names something the module does not declare.

`test_every_registered_check_is_read_by_a_statement` takes the step after. It
reads the module's `locals.tf`, comments removed, for `include = var.<check
name>` and for `var.<allowlist variable>`, and fails by name on a declared
variable no statement reads: an argument `terraform plan` accepts and the
policy ignores, so the check would report its policy in place while the module
attached nothing for it. Neither guard reads the statement itself. Whether it
names the right actions, resource type, or condition key is the check
specification's `verification` list to catch.

None of the three guards asks whether a committed call is the output of a run,
and only one half of the examples currently is. `test_environment/scps/` was
regenerated from the committed results and carries the comments
[Why a check renders false](#why-a-check-renders-false) describes.
`test_environment/rcps/` was not: its bare `false` booleans are output from
before those comments existed, not a counterexample to the grammar. It cannot
be regenerated as the SCP half was, because four registered RCP checks have no
results directory and `parse_rcp_result_files` raises on a missing one, so no
run against this fixture reaches rendering at all. Its calls also disagree with
what placement would produce from the results that are committed:
`deny_s3_third_party_access` blocks only in fort-knox, which makes it safe at OU
`acme_acquisition` and at the account `security-tooling`, and both files render
it `false`. `deny_ecr_third_party_access` is not one of those — it is clean in
all four results, so it places at the root, and `false` below its target is
exactly what a root placement renders; what is missing there is a committed
`root_rcps.tf`. [`../checks/index.md`](../checks/index.md#unresolved-conflicts)
carries the two as conflicts 9 and 10.
