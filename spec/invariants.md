# Global invariants

These apply to every subsystem and every check. A subsystem contract or a
per-check specification may narrow one; none may silently override one. A
deliberate exception is recorded either here, at the invariant, or at the
lower-precedence document that narrows it — which cites the invariant by ID, so
the narrowing stays reachable from the rule it bends.

Narrowing takes two shapes, and both are live. A subsystem contract tolerates a
failure the invariant says aborts:
[`architecture/aws-execution.md`](architecture/aws-execution.md#failure-policy)
records two tolerances under INV-02. A per-check specification narrows an
invariant for one resource of its own:
[`checks/scps/deny_lambda_auth_type_none.md`](checks/scps/deny_lambda_auth_type_none.md)
tolerates a `ResourceNotFoundException` under INV-01, because a function deleted
mid-scan cannot violate anything. Those two pointers are examples rather than a
roster; an uncounted roster kept here is what would go stale, the way the
sentence claiming an exception lived nowhere but at its invariant went stale.

Each invariant carries a stable ID. Per-check specifications cite these IDs in
their **Referenced invariants** section and in `depends_on`, and
`tests/test_spec_corpus.py` checks that every cited ID exists.

Every invariant here protects the safety promise in
[`product.md`](product.md): a generated policy is one the accounts it reaches
already satisfy.

---

## INV-01 — Absence of evidence is not evidence of safety

A missing observation must never be read as a clean observation. Where the two
are indistinguishable in an artifact, the run aborts with an error naming what
was missing.

This is the invariant most of the others exist to serve, because the failure it
prevents is silent: a policy that looks safe precisely because nothing was
looked at.

Concretely, each of these aborts rather than continuing:

- A generation run that parsed zero SCP result files, or whose RCP parse found
  neither a cleared account nor a blocked one.
- A registered RCP check with no results directory.
- A result for a check that feeds an allowlist whose summary omits the key its
  definition names — `unique_ami_owners` for `deny_ec2_ami_owner`, `users` for
  `deny_iam_user_creation` — or holds anything but a list under it. An absent
  key reads identically to an account that observed nothing, and `null` was
  dropped by the placement union as though the check declared no allowlist.
- A results directory, or a placement recommendation, naming a check the
  registry does not know — under `scps/` and `rcps/` alike. Results nobody
  reads are indistinguishable from results that were read.
- A `skip_account_ids` entry matching no account in the organization.
- An account whose lifecycle state cannot be classified (see INV-03).

## INV-02 — A run fails whole, never partially

An error while analyzing any account aborts the entire run. Errors are never
logged and stepped over.

A partial run is more dangerous than no run: an account skipped for a transient
error is indistinguishable in the results from an account with zero violations,
so swallowing the error can green-light a policy that breaks it. Accounts that
genuinely cannot be analyzed are excluded up front, by lifecycle state or by
configuration, where the exclusion is visible.

**Aborting is cooperative, because Python cannot kill a running thread.** The
accounts still in flight stop at their next checkpoint rather than immediately,
and a check already inside `execute()` finishes and writes its result file.
That file is complete and valid, so the invariant holds where it matters: no
partial artifact is handed to the next stage, and the results on disk stay
truthful about the accounts they name.

**Whole failure is a claim about the artifact, not about the report.** One
exception reaches `main`, and reporting only that one would tell an operator
about a single account out of however many failed. The other failures, and the
count of accounts cancelled before they ran, are reported alongside it;
[`architecture/aws-execution.md`](architecture/aws-execution.md#what-an-aborted-run-tells-the-operator)
owns the three parts and why each covers accounts the others cannot see.

## INV-03 — Only ACTIVE accounts are analyzed, and an unknown state aborts

`CLOSED`, `SUSPENDED`, `PENDING_ACTIVATION`, and `PENDING_CLOSURE` accounts are
not analyzed. The first three reject role assumption; the fourth is leaving the
organization and must not hold back an organization-wide policy.

State is read from `State`, falling back to `Status`. An account reporting
neither, or reporting a state Headroom does not know, aborts the run — neither
guess is safe, and the two causes have different remedies.
`test_every_state_aws_defines_is_classified` in
`tests/test_aws_organization_snapshot.py` is meant to surface a newly added AWS
state when the SDK is upgraded.

## INV-04 — Organization membership, analyzable accounts, and hierarchy are three distinct projections

Code that collapses any two of them is wrong.

All three are captured once, by `discover_organization`, and carried together
on the frozen `OrganizationSnapshot` that every later stage reads.

| Projection | Field | Built by | Contains |
|---|---|---|---|
| Organization membership | `member_account_ids` | `list_organization_accounts` | Every account the API reports, **unfiltered** — a closed account is still a member and still matches organization-based RCP conditions |
| Analyzable accounts | `analyzable_accounts` | `_select_analyzable_accounts` | ACTIVE accounts, minus the management account, minus `skip_account_ids` |
| Hierarchy | `hierarchy` | `build_organization_hierarchy` | The OU tree that placement walks |

Carrying them on one frozen object is how the invariant is enforced rather than
merely stated: a stage cannot reassign a field to a projection it computed
itself, and the first two are immutable the whole way down. `hierarchy` is the
exception, and [`architecture/aws-execution.md`](architecture/aws-execution.md)
says why.

## INV-05 — The subtree is the unit of OU reasoning

A policy attached to an OU governs every account in that OU **and in every OU
beneath it**. Every question asked about an OU — is it safe to attach here, what
must its allowlist hold, which accounts does this recommendation affect — is
asked of the whole subtree.

Placement therefore stops at the highest safe OU rather than attaching again
beneath it. [`contracts/placement.md`](contracts/placement.md#the-traversal)
owns the walk that reaches it.

Judging an OU by the accounts parented directly to it once declared a parent
safe while a violating account two levels down was never examined, and unioned
an allowlist that omitted that account's resources. Nothing errored, because the
report never mentioned the accounts it had skipped. Pinned by
`tests/test_nested_ou_hierarchy.py`.

## INV-06 — An empty allowlist is never rendered as an empty list

An allowlist with no values is never written into a policy document as `[]`.
This invariant governs the two shapes where an empty list would be actively
wrong, and for both of them a check whose covered accounts observed no allowlist
values leaves its policy **off**, with a rendered comment saying why:

| Shape | What an empty list would do |
|---|---|
| A condition allowlist, `StringNotEquals`-style | Denies every call rather than none. `deny_ec2_ami_owner`. |
| A resource allowlist, `NotResource` | Not a valid document at all. The IAM policy grammar admits one or more values in a resource array, so Organizations rejects the whole policy at apply time — every other statement in that module with it. `deny_iam_user_creation`. |

The second shape is the wider blast radius of the two, because the rejected
document is the module's whole policy rather than the one statement that was
malformed.

**Two RCP allowlist clauses are a third shape, and this invariant does not
disable either.** The `aws:PrincipalAccount` clause on the six third-party-access
checks, and `deny_service_confused_deputy`'s `aws:SourceAccount` clause, are each
omitted from the rendered condition rather than written as `[]` when their
allowlist is empty; the statement still renders and still denies every
out-of-organization principal or source.
[`contracts/policy-model.md`](contracts/policy-model.md#the-rcp-allowlist-statement)
states what the `aws:PrincipalAccount` omission changes and why;
[`checks/rcps/deny_service_confused_deputy.md`](checks/rcps/deny_service_confused_deputy.md)
does the same for `aws:SourceAccount`. Leaving either off for an empty allowlist
would be wrong: it would disable the six checks on exactly the accounts that
granted no third party anything, and `deny_service_confused_deputy` on exactly
the accounts that pinned no third-party source.

This is distinct from INV-01: observing nothing is a legitimate fact about those
accounts, whereas failing to record an observation is a broken artifact and
aborts.

## INV-07 — An allowlist round trip is complete or the check does not ship

A check that feeds an allowlist must carry its values the whole way:
`summary_key` → `SCPCheckResult.allowlist_values` → the placement union →
`terraform_variable`. The first and last links are declared once, on the
`Allowlist` the check registers with, and the two between are generic, so a
check declares the chain rather than building it.

Break the chain anywhere and the check still reports 100% compliance while its
allowlist arrives empty, and what that costs splits by shape. Where INV-06's
guard applies, nothing deploys and the gap is silent. Where INV-06 deliberately
declines to disable the statement — the RCP allowlist clauses it names there —
the statement renders with its clause omitted and denies every
out-of-organization principal or source, the third parties the round trip failed
to carry included. That is the destructive case, and it is why this is an
invariant rather than a convention: a broken chain does not withhold a
protection there, it deploys a denial of exactly the access the scan was meant
to preserve. `deny_ec2_ami_owner` shipped with the first and last links only.
That was before INV-06's guard existed, so the empty allowlist would have
rendered as `[]` and denied everything.

## INV-08 — Record the value the condition key will hold

Collect what the IAM condition key evaluates to at authorization time, not the
field of the same name in the describe call.

The founding case is `ec2:Owner`, which does not always hold the `OwnerId` an
AMI's describe call returns: collecting that field alone produced an allowlist
that denied the exact AMI the scan had just cleared.
[`checks/scps/deny_ec2_ami_owner.md`](checks/scps/deny_ec2_ami_owner.md#the-value-recorded-is-the-value-the-condition-key-holds)
states what the key does evaluate to, and measures it. Fixtures for a
condition-key check must be shaped like real API responses; an impossible one
(`OwnerId: "amazon"`) hid this for a release.

## INV-09 — Scan the dimension the policy enforces

A check must read the same dimension its policy statement conditions on, or
declare in its specification what it reads instead and what the substitution
costs.

Three checks substitute, of which two are tag checks reading a tag off an
existing resource in place of the `aws:RequestTag/` key the statement
conditions on, and the third is not. Each declares the substitution and its
cost in its own document:

- [`deny_ec2_imds_v1`](checks/scps/deny_ec2_imds_v1.md) — the SCP conditions on
  `aws:RequestTag/ExemptFromIMDSv2` on the `RunInstances` request, and the scan
  reads the tag off the resulting instance.
- [`deny_eks_create_cluster_without_tag`](checks/scps/deny_eks_create_cluster_without_tag.md)
  — the SCP conditions on `aws:RequestTag/PavedRoad` on the `CreateCluster`
  request, and the scan reads the tag off the existing cluster. Its document
  states this as the weaker of the two substitutions and says why.
- [`deny_ec2_public_ip`](checks/scps/deny_ec2_public_ip.md) — the SCP conditions
  on `ec2:AssociatePublicIpAddress` on the `RunInstances` request, and the scan
  reads `PublicIpAddress` off the running instance. Not a tag substitution: an
  address attached after launch reads the same as one the request assigned, and
  a subnet default can assign one the request never specified, which the scan
  cannot see before the launch happens. Its document states both.

Reading a narrower **population** than the statement will govern is not a
substitution under this invariant. A scan that reads the running fleet for a
statement conditioning on the same key at launch time is measuring the right
dimension and seeing fewer of them; that gap belongs in the check's **Accepted
limitations**, not here. INV-09 is about measuring a *different key* from the
one the statement evaluates.

## INV-10 — One verdict gates one statement

A Terraform variable that includes or omits a policy statement is backed by a
check that measures exactly that statement.

One variable gating two statements means one verdict is being made on two
different kinds of evidence, and the weaker evidence silently authorizes the
stronger statement.

## INV-11 — Generation is reconciliation, not appending

A run's output is the complete desired state of its Terraform directory: a
target that drops out of the recommendations loses its file.

Three rules make deleting safe — render before mutate, ownership as a marker on
the file's first line, and an abort on a run that read nothing (INV-01). Each is
stated with its argument in
[`contracts/terraform.md`](contracts/terraform.md), which owns them.

## INV-12 — One name, one rule, both generators

Every OU is named for its path down from the root, and the side that declares
the name and the side that references it build it with one shared function
rather than with two implementations that agree today. Colliding or reserved
names abort rather than overwrite.

**Accounts are named by the same rule and gated the same way.** Everything
generated for an account — its policy file, its module name, the ID local its
policies target — is built from one identifier, so two accounts reducing to one
identifier aborts rather than letting the second take the first's place. The
account gate runs over every account in the hierarchy rather than the analyzed
subset, because a local is declared for every account the hierarchy holds: a
collision between an analyzed account and a skipped one is still a duplicate
local in the generated Terraform.

**A third gate spans the namespaces the first two cannot see.** The OU gate and
the account gate each keep their own namespace clean, and neither sees the
other or the fixed root filenames. An account named `Root` reduces to `root`
and claims the root policy file; an account named `Sandbox OU` reduces to
`sandbox_ou` and claims the file belonging to an OU named `Sandbox`. The plan is
keyed on the destination path, so an unguarded second write would replace the
first silently and the run would write a plan already missing a file. Claiming
the path is what compares the thing that actually collides.

[`contracts/terraform.md`](contracts/terraform.md) owns the functions, the
locals they name, and the plan-time failure a second implementation produces.

## INV-13 — Every stage is registry-driven

Between check collection and Terraform generation, no stage may branch on a
hardcoded check name. A check registers itself with `@register_check`, which
records a frozen `CheckDefinition` — class, name, type, the `TerraformSection`
its parameters render under, and the `Allowlist` its statement is scoped by,
if any — and every stage reads that definition rather than naming the check.

What each stage reads:

| Stage | Reads from the definition |
|---|---|
| Collection, result writing, resume | Class, name, type; result writing resolves the check's directory through the name-to-type mirror `register_check` fills in `headroom/constants.py` |
| SCP parsing | `allowlist.summary_key`, and whether to restore redacted account IDs. An unregistered check name aborts: the one the file's `summary.check` declares, or the directory's when the file declares none |
| RCP parsing | `allowlist.summary_key`, through the same reader SCP parsing uses. A registered check with no results directory aborts, and so does a directory under `rcps/` naming no registered check |
| SCP placement | Nothing. It unions whatever `allowlist_values` the results carry |
| Both generators | `get_check_definitions(check_type)`: every definition of that type in render order, with its section, its boolean, and its allowlist variable. A recommendation naming an unregistered check aborts |

One rule reads a declared allowlist for both policy types:
`parse_results._read_declared_allowlist` takes the key the definition names,
aborts when it is absent, and restores the owning account ID when the
definition says so. A change to that abort or that restoration is a change to
SCP and RCP parsing together.

Render order is `(TerraformSection rank, check name)`, so neither import order
nor registration order can move a parameter. `TerraformSection` in
`headroom/enums.py` is the one remaining central declaration: it names
services, not checks, and its declaration order is the render order. A new
check in an existing service touches only its own module; a new service adds
one member there.

A definition is validated as it registers, before it is inserted: a duplicate
name, a class already registered under another name, an unknown type or a
`CheckType` member in place of its string value, an RCP check with no allowlist,
an allowlist with an empty summary key, Terraform variable, or empty-allowlist
comment, or a name or allowlist variable colliding with another definition's
fails at import time. [`architecture/check-framework.md`](architecture/check-framework.md#discovery)
states each rule.

Six named guards enforce this. `test_generic_pipeline_modules_name_no_check`
fails when the orchestrator, check discovery, or any collection, result-writing,
parsing, placement, or rendering module names a registered check or a
`DENY_`-prefixed constant outside a `#` comment.
`test_every_registered_scp_check_is_rendered` and
`test_every_registered_rcp_check_is_rendered` fail by name when a registered
check does not reach its module.
`test_every_registered_check_is_declared_by_its_module` fails by name when the
module's `variables.tf` does not declare a check name or allowlist variable the
generator will pass — the step after reaching the module, which `terraform plan`
would otherwise refuse at the operator's desk.
`test_every_registered_check_is_read_by_a_statement` fails by name when no
statement in the module's `locals.tf` is gated by a check's boolean or reads its
allowlist variable — the step after declaration, which `terraform plan` accepts
and the policy silently ignores.
`test_render_order_is_independent_of_registration_order` reverses the registry
and pins the order both generators render from.

This was not always so. Parsing once branched on two check names in three
places, RCPs rendered from a hand-maintained table, and SCPs from straight-line
code naming all nine checks. Five RCP checks were once collected against every
account on every run and rendered as disabled, which is indistinguishable in
the output from a check that found nothing, and a tenth SCP check would have
been collected, written, parsed, and placed, then dropped at render with no
test failing.

## INV-14 — Persisted results keep wire compatibility

A later run reads back both the result JSON and the result filenames. Changing
either without an explicit migration can silently skip accounts without
any reader failing, or re-scan them, which
[`contracts/results.md`](contracts/results.md#one-file-per-account) catches at
read time from the second file the re-scan leaves, but only after the scan has
been paid for.

`results_exist` therefore tolerates both the account-name and the
account-name-plus-ID filename forms, so an existing results directory still
resumes after `exclude_account_ids` changes.

**Two deliberate breaks.** SCP parsing once defaulted a missing `summary.violations`
to zero and now raises. A results directory written before every check emitted the
key no longer parses, and the error names the check to re-run. The invariant is
about not changing a format silently; this changes one loudly, on purpose, because
the tolerance it replaces was reading an unanswered safety question as a pass
(INV-01).

The second is the same shape. SCP parsing once read a missing `summary.users`
on a `deny_iam_user_creation` result as no users and left the policy off. It
now raises, like every other allowlist key: the check has written `users`
since it shipped, so no file it wrote is affected, and one rule — an absent
allowlist key aborts — replaces two.

## INV-15 — AWS identifiers in the repository are obviously fake

Every AWS identifier committed to this repository — in code, tests,
documentation, examples, and commit messages — uses a real prefix, a real
length, and a body of one repeated digit: `111111111111`,
`i-11111111111111111`, `ami-11111111111111111`. Where no repeated digit will
do, the body is one repeated letter instead. The IAM unique ID is that case,
and today the only one: AWS encodes it in a Base32
alphabet that omits `0`, `1`, `8`, and `9`, so `AROA11111111111111111` is not
a value AWS could have issued, and a body of repeated `2`, `3`, `4`, or `5`
decodes to a plausible twelve-digit account rather than to nothing. Repeated
`6` and `7` resolve to nothing too, but only by overrunning the twelve-digit
range. Most letters are no safer: a body of any letter from `Q` to `Z` sits
above the encoding's offset and decodes to a plausible account, exactly as
repeated `2` through `5` do, and only `A` through `P` fall below it. One
letter form is the rule so that no fixture body has to be run through the
decoder to learn what it does. The form is
`AROAAAAAAAAAAAAAAAAAA` for a role and `AIDAAAAAAAAAAAAAAAAAA` for a user,
whose bodies sit below the encoding's offset and resolve to no account.

**An identifier that has to decode is fake by the account it names.** A
fixture about a grantee whose account can be read cannot use a body that
reads back as nothing, so that identifier is built by inverting
`headroom/aws/iam_unique_ids.py` until it resolves to a placeholder account:
`AROA6RVFFB77QAAAAAAAA` decodes to `999999999999`. Its body is opaque, and
what makes it obviously fake is the account it hands back rather than the
shape it is written in.
[`../HOW_TO_ADD_A_CHECK.md`](../HOW_TO_ADD_A_CHECK.md) states both forms as a
practitioner's checklist, under `test_data_standards`.

The table below is the one place the scanned kinds are named. Each row is a
kind `tests/data_standards.py` carries a matcher for, and the shape that
matcher reads it by. The rule above is wider than the table: a kind can be
covered by the invariant and have no row, and one is.

| Kind | Recognized by |
|---|---|
| `account` | Twelve digits |
| `ami` | The `ami-` prefix |
| `instance` | The `i-` prefix |
| `kms_key` | The hyphen groups of a UUID |
| `organization` | The `o-` prefix |
| `organizational_unit` | The `ou-` prefix |
| `root` | The `r-` prefix |

An ARN is not a row of its own: the account field it carries is the account
row's work, and the resource part is a name rather than an identifier AWS
issued.

`tests/test_data_standards.py` reads this table, so a kind added here without a
matcher fails the suite.

**The IAM unique ID and the access key ID are covered by the rule and have no
row, so nothing scans for either.** A real `AROA`, `AIDA`, `AKIA`, or `ASIA`
value pasted from a console or an API response enters the repository with every
gate green, and the placeholders above are held by review alone. The rows are
absent as a consequence rather than an oversight: adding one forces a matcher,
and a matcher would report the published vectors the second standing exception
below sanctions. Nobody has written one that exempts those vectors and nothing
else, so these kinds stay unguarded, and a value of either is caught only by
the reader.

An identifier arriving from a bug report, error message, console screenshot, or
API response is real. Rewrite it before it enters the repository.

**Two standing exceptions.** Each is scoped — one to a directory, one to a
single test — and each is granted for what it buys. A third would need the
same argument made here, in the same place.

`test_environment/` commits one real twelve-digit account ID: the
operating-system publisher that owns the public Ubuntu images, named as the
owner filter in
[`../test_environment/test_deny_ec2_ami_owner/data.tf`](../test_environment/test_deny_ec2_ami_owner/data.tf).
It is load-bearing. That data source resolves a live AMI by owner, so a
fabricated owner matches no image and the lookup fails at `terraform plan`: the
scenario would launch nothing, and `deny_ec2_ami_owner` — the check it exists to
exercise — would have nothing to find. The identifier is one its publisher
documents for customers to name in exactly this filter, never the operator's
own, which is what makes the trade acceptable and does not make it compliant.
The exception is the directory's and not the identifier's: the same value in
code, tests, or documentation is a leak rather than an instance of it.
[`../test_environment/README.md`](../test_environment/README.md) describes where
it appears.

`tests/test_aws_iam_unique_ids.py` commits nine real values, all of them in
`test_the_published_vectors_decode`: three `ASIA` access key IDs with the three
accounts they decode to, one `AROA` unique ID with the account it decodes to,
and a second `AROA` that decodes to nothing. They buy the decoder its only
independent oracle. Every other expected value in that file is obtained by
inverting the decoder under test, and an assertion derived that way agrees with
the code by construction
([`verification/strategy.md`](verification/strategy.md#assertions-must-be-independently-derived)),
so the suite would pass with the offset, the doubling, or the displaced low bit
all wrong. Fabricating a tenth value would only re-derive the arithmetic again.

The two halves are not interchangeable, which is why the exception is this
wide. The access key vectors are what the research documenting the encoding
publishes, so they are what attests the arithmetic; all three decode to an even
account, so none of them reaches the displaced low bit. The `AROA` pair carries
the claim the access key vectors cannot: that a principal unique ID is encoded
the same way as an access key ID, which no AWS documentation states, and the
one whose account is odd is also what pins the displacement. Dropping either
half leaves a load-bearing claim resting on this repository's own say-so. The
exception covers those nine values in that one file: none of them may appear
elsewhere, and a tenth is a new exception rather than an extension of this one.

**The operator's own identifiers are not covered, and two reached the repository
anyway.** `headroom_results/` recorded S3 bucket names ending in the account ID
of the account holding the bucket, because the scenarios name buckets that way
for global uniqueness. Redaction did not catch them and will not: it matches the
account field of an ARN, and `arn:aws:s3:::name` has no account field, per
[`contracts/results.md`](contracts/results.md#redaction). They were rewritten to
placeholders, which cost nothing — Terraform builds those names at apply time
from `data.aws_caller_identity`, so nothing reads the recorded value. A live run
regenerates the files and reintroduces them, so it is a manual step after every
refresh until the scenarios stop naming buckets after the account.

The count above is not maintained by hand. `tests/test_data_standards.py` reads
it back and fails when it disagrees with what the directory holds, which is how
it came to say thirteen while sixteen were committed; the same test fails when
an identifier from the `test_environment/` exception appears outside that
directory. Nothing mechanical reads the second exception at all: the account
gate reports only identifiers that also appear under `test_environment/`, and
the `AROA` kind has no matcher.

The scan behind that test carries one matcher per row of the table. A body
reads as fabricated when each of its hyphen-separated parts uses few enough
distinct characters to be deliberate, counts plainly up or down, or is a word
naming the fixture it belongs to. `r-root` and `ou-fake-payments` are
legible for that last reason, and are accepted by that named rule rather than by
leaving their kind unmatched.

The `test_environment/` exception is granted for account IDs and for nothing
else, so every other kind the table names is held to that standard everywhere,
`test_environment/` included — an AMI ID or an OU ID gains nothing by sitting in
that directory. Only the account kind keeps the narrower, exception-scoped rule,
and not because the sandbox earns it: a twelve-digit number a test fabricates
carries no evidence of being real, so a repository-wide rule on that kind would
fail on the fixtures written to exercise the scan itself.

## INV-16 — Credentials are minted regionally, and only enabled regions are scanned

Every boto3 session is built by `headroom/aws/sessions.py` with
`sts_regional_endpoints = regional`, at every hop of the assume-role chain.
Credentials minted at the global STS endpoint are invalid in opt-in regions, and
Headroom scans every enabled region, so opt-in regions are the normal case.
`test_only_the_sessions_module_constructs_a_session` pins the single
construction site.

Region discovery calls `describe_regions` with no arguments, which returns only
the regions the account has enabled. `AllRegions=True` would add regions the
account cannot use and turn each into a doomed API call.
`test_only_enabled_regions_are_requested` pins it.

## INV-17 — One read of the organization, one view of it

A run reads AWS Organizations exactly once, in `discover_organization`, and
every later stage consumes the `OrganizationSnapshot` it returns. The scan, SCP
generation, RCP generation, and the org-info writer never call Organizations
again.

Two reads of a live organization can disagree, and every way they disagree is a
silent wrong answer rather than a failure. An account created between the scan
and generation is absent from the results and present in the hierarchy, so an
OU-level policy is recommended over an account nothing has checked. An account
closed between them is the reverse. A rename moves the Terraform identifier a
policy targets away from the one the org info declares, which is the plan-time
failure INV-12 exists to prevent, reached by a different route.

This is what INV-04 counts three of, and the two are enforced by the same
object: INV-04 says the three projections are distinct and must not be collapsed
into one another, INV-17 says all three come from one read and no stage may take
its own. The snapshot is frozen so neither can be undone by accident; INV-04
states what that freezing does and does not reach.
