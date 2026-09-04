# Contract: results

Owns the persisted result artifact: where a file goes, what it holds, how it is
read back, and how a run resumes from one.

Implementation: writer `headroom/write_results.py`, its single call site
`BaseCheck.execute` in `headroom/checks/base.py`, readers
`headroom/parse_results.py` (SCPs) and `headroom/terraform/generate_rcps.py`
(RCPs). Tests: `tests/test_write_results.py`, `tests/test_parse_results.py`,
`TestRunChecks` in `tests/test_analysis_extended.py`.

**This artifact is a wire format** (INV-14). Both the JSON and the filenames are
read back by a later run. A change to either can silently skip accounts without
any reader raising, because the readers glob `*.json` and take account identity
from the file's own `summary`; a change that re-scans them instead is caught by
[One file per account](#one-file-per-account), and only from the second file
the re-scan leaves.

## Layout

```
{results_dir}/{check_type}/{check_name}/{account_identifier}.json
```

- `check_type` is `scps` or `rcps`, passed to the writer as the check's
  registered `CHECK_TYPE`, never inferred from the check name's spelling. The
  writer looks nothing up. It once read a name-to-type map in `constants` that
  the `register_check` decorator filled as a side effect, so a process that
  imported the writer without `headroom.checks` found the map empty and
  resolved no path for any check; the CLI imports the checks first and never
  met it. `test_the_writer_resolves_a_path_without_the_registry_imported`
  pins the fresh-interpreter case.
- `account_identifier` is `{account_name}_{account_id}`, or `{account_name}`
  alone when `exclude_account_ids` is set.

## Filename compatibility

Existence is tested against **both** filename forms — with and without the
account ID — regardless of the current `exclude_account_ids` setting. Toggling
that option must not orphan an existing results directory into a full re-scan.

## Account names must survive becoming a filename

The account name is interpolated into the filename, so a name that is not a
usable filename is a run that cannot write results. Both guards run at
discovery, in `headroom/aws/organization_snapshot.py`, before any account is
scanned — the failure belongs before the expensive part, not after it.

**A name that cannot become a filename aborts the run.** Four rejections, each
reported with the account it belongs to, because they are unrelated and an
operator reading one message about several accounts needs to know which account
hit which:

| Rejected | Why |
|---|---|
| Empty | Not a filename reason: the name is the account's identity in the result file, and an empty one is unresolvable at read time |
| Holds a null byte | No filesystem accepts it |
| Over 237 bytes UTF-8 | Both Linux and macOS cap a path component at 255 bytes, and the longest suffix spends eighteen: `_`, a twelve-digit account ID, and `.json` |
| Reads as a path rather than a filename | The resolver hands the interpolated name to `Path`, which reads a separator as structure rather than as text |

A leading dot is deliberately allowed. `pathlib.Path.glob` matches a dotfile,
unlike a shell, and the reader takes account identity from inside the file, so
`.Prod.json` is read back correctly.

**With `exclude_account_ids` set, two accounts sharing a name abort the run.**
That setting drops the account ID, which is the only guaranteed-unique component
of the filename, so both accounts resolve to one path — and with a worker per
account, that is two threads interleaving `json.dump` output into one file:
either corrupt JSON, or a valid file holding two accounts' results spliced
together, which then feeds policy generation. Organizations enforces uniqueness
on account email, not on account name, so this is reachable rather than
theoretical. The message names the colliding spellings and how many accounts
carry each, never the account IDs — printing those would defeat the setting that
created the collision.

Names are compared the way a filesystem compares them, by **Unicode canonical
caseless matching**: `NFD(casefold(NFD(x)))`, Unicode D145. Both axes matter and
they must be folded together rather than in sequence.

- Case alone is not enough. APFS resolves `café` composed (one U+00E9) and
  decomposed (`e` + U+0301) to the same file, exactly as it does `Prod` and
  `prod`.
- Normalizing and then folding is not enough either, because the fold can undo
  the normalization just performed. `ſ` (U+017F, long s) followed by U+0301 has
  no precomposed form, so NFC returns it unchanged; casefold then maps U+017F to
  `s`, producing `s` + U+0301 — the decomposition of `ś`, not `ś` itself. The two
  names key differently while APFS stores them in one inode, verified by reading
  the same `st_ino` back for both spellings. The trailing NFD is what closes
  that.

On a filesystem that folds neither axis the comparison is stricter than it needs
to be, and two accounts that could coexist are rejected. That is the deliberate
direction to err: the cost is a rename, and the cost of the other direction is
two accounts' results in one file.

## Document shape

There are two shapes, and they do not divide by check type: one of the seven
RCP checks writes the first. `summary` is the only key common to both, and it is
the only key any reader parses; the rest is evidence for a human.

### The base shape

All nine SCP checks take `BaseCheck._build_results_data` unchanged, and so does
one RCP check:

| Key | Holds |
|---|---|
| `summary` | Account identity, check name, counts, and check-specific fields |
| `violations` | One entry per resource the policy statement would deny |
| `exemptions` | One entry per resource the statement's condition would spare |
| `compliant_instances` | One entry per resource the statement would allow |

`compliant_instances` is named for the first check written and is now generic.
Renaming it is a wire-format migration.

### The two-list shape

Six of the seven RCP checks override `_build_results_data` and name their keys
for what they scanned — the resource in five of them, and the policy in ECR's,
whose analyzer reads the registry policy as well as each repository's. The
seventh, `deny_service_confused_deputy`, scans six resource types rather than
one, so it has nothing single to name keys for: it overrides nothing and writes
the base shape above.

| Check | Keys besides `summary` |
|---|---|
| `deny_ecr_third_party_access` | `policies_third_parties_can_access`, `policies_with_wildcards` |
| `deny_kms_third_party_access` | `keys_third_parties_can_access`, `keys_with_wildcards` |
| `deny_s3_third_party_access` | `buckets_third_parties_can_access`, `buckets_with_wildcards` |
| `deny_secrets_manager_third_party_access` | `secrets_third_parties_can_access`, `secrets_with_wildcards` |
| `deny_sqs_third_party_access` | `queues_third_parties_can_access`, `queues_with_wildcards` |
| `deny_sts_third_party_assumerole` | `roles_third_parties_can_access`, `roles_with_wildcards` |
| `deny_service_confused_deputy` | `violations`, `exemptions`, `compliant_instances` |

`*_third_parties_can_access` is `violations + compliant`, so a wildcard finding
appears in both lists. `*_with_wildcards` is `violations` alone. Renaming either
key, in any of the six, is a wire-format migration (INV-14).

A reader that expects a `*_third_parties_can_access` pair in every RCP file gets
the seventh wrong; one that switches on `summary.check` does not. Beyond the
common keys below, its `summary` adds `unique_third_party_accounts` and
`third_party_account_count`, and the entry shape inside its three lists is
specified in
[`../checks/rcps/deny_service_confused_deputy.md`](../checks/rcps/deny_service_confused_deputy.md).

### Summary keys every check writes

| Key | Type | Notes |
|---|---|---|
| `account_name` | string | As resolved by `use_account_name_from_tags` |
| `account_id` | string | **Absent** when `exclude_account_ids` is set |
| `check` | string | The registered check name |
| `scanned_at` | string | When the check finished for this account, in the scanning machine's local zone |
| `violations` | integer | The count, written even when it is always zero |

`violations` is the count every placement decision turns on, and it is written by
all sixteen registered checks — nine SCP and seven RCP. A check whose every
entry is compliant writes zero rather than omitting the key: a reader cannot
tell an absent key from a genuine zero, and the two mean opposite things.

`scanned_at` is written for a person opening the file, and nothing reads it.
That is what fixes its shape: `SCAN_TIMESTAMP_FORMAT` in
`headroom/constants.py` renders the operator's wall clock — `09-04-2026 4:15 PM
PDT` — rather than an ISO instant, because the question it answers is "when was
this scanned" and not "which of these two files is newer". The zone is
whichever one the machine that ran the scan is set to, so the same run written
from a UTC container reads `09-04-2026 11:15 PM UTC`; a scan says where it ran
rather than claiming one team's zone. The abbreviation is the real one for the
date, so a September scan reads `PDT` and a January scan `PST`.

The value is the moment the check **finished** for that account — `execute`
builds the summary once `analyze` has returned. It is per file rather than per
run: resume means one directory holds files from several runs, and a single
run-start stamp copied onto every file would misdate the ones it reused.

Every check writes it, in both document shapes. `BaseCheck.execute` builds
`summary` before it calls `_build_results_data`, so the six RCP checks that
override that method carry the key without naming it.

Everything else in `summary` comes from the check's `build_summary_fields` and is
specified in that check's document under [`../checks/`](../checks/index.md).

### Summary keys a reader requires

A reader raises rather than defaulting when one of these is missing, because the
missing key and a legitimately empty value mean opposite things (INV-01).

| Key | Required by | Missing means |
|---|---|---|
| `check` | RCP parsing | The file cannot be confirmed to belong to its directory |
| `violations` | SCP and RCP parsing | Whether the account is safe is unknown, and defaulting answers it in the safest direction. `results_exist` skips an account whose result file already exists, so re-running without deleting the file repeats the same failure; both readers' errors name the file and prescribe exactly that. `ResultFilePathResolver.exists()` accepts either filename format, so the remedy also names the directory holding the other form — deleting only the file the reader tripped on leaves the skip in place when both are present |
| `unique_third_party_accounts` | RCP parsing, as the `summary_key` every RCP definition declares | The allowlist would render empty, which denies every third party (INV-06) |
| The `summary_key` an SCP check's `Allowlist` declares — `unique_ami_owners` for `deny_ec2_ami_owner`, `users` for `deny_iam_user_creation` | SCP parsing | Indistinguishable from an account that observed nothing, which would leave the policy off rather than flag a stale result |

A key that is present but holds anything other than a list aborts the same way,
naming the file and the key: `null` is neither an observation nor an absent key,
and carrying it forward crashed on the account-ID restore or was dropped by the
placement union as though the check declared no allowlist.

RCP parsing additionally rejects a file whose `summary.check` disagrees with the
directory it was found in: a result filed under the wrong check would be
attributed to the wrong policy.

Both readers reject a check the registry does not hold, and resolve the name
before requiring any key of the file: a stale directory is stale throughout, and
reporting its first absent key would send the operator to re-run a check that no
longer exists. SCP parsing rejects a file whose `summary.check` — or whose
directory, when the file declares none — is not a registered SCP check, naming
the file and saying to delete it, and the directory with it when the directory
holds only that check's results. RCP parsing rejects a directory under `rcps/`
naming no registered RCP check, naming the directory and saying to delete it.
Both say to register a check under that name instead if the check is not gone.
Neither error is the registry's own `Unknown check`, which names no file and no
remedy, and which `main` would label a configuration error — which a stale
results directory is not.

SCP parsing defaulted `violations` to zero until
`deny_iam_saml_provider_not_aws_sso` shipped without the key and had every
account it rejected cleared for a root-level deny. The remaining SCP summary
fields — `exemptions`, `compliant`, `compliance_percentage`, `total_instances` —
are still defaulted, deliberately: no placement decision reads them, so a missing
one costs accuracy in a report rather than safety in a policy.

## Redaction

When `exclude_account_ids` is set, before the file is written:

1. Every 12-digit account ID inside an ARN, anywhere in the document, is
   replaced with `REDACTED`. The match is on the ARN's account field
   specifically — `arn:<partition>:<service>:<region>:<account>:` — so an
   account-shaped number elsewhere in a string survives, and so does one in a
   string that is not an ARN.
2. `summary.account_id` is removed.

**Every partition, not only `aws`.** GovCloud, China, and the isolated regions
append hyphenated qualifiers to the partition — `aws-us-gov`, `aws-cn`,
`aws-iso-b` — and an operator there sets `exclude_account_ids` for the same
reason a commercial one does. The pattern once matched the literal `arn:aws:`,
so those partitions kept their account IDs in a file written specifically to be
committed. Nothing in `test_environment/` exercises a non-commercial partition,
which is why it survived; `test_redact_every_aws_partition` pins it now.

Redaction being partition-agnostic does not make Headroom runnable outside the
commercial partition — the role ARNs it assumes are still hardcoded, per
[`../architecture/aws-execution.md`](../architecture/aws-execution.md). This
closes the leak ahead of that rather than after it.

Redaction is not reversible in general. SCP parsing restores the account ID into
the values of an allowlist whose definition sets `restores_account_ids` — today
`deny_iam_user_creation`'s user ARNs — once the account has been identified,
because the allowlist those ARNs feed must name real accounts. The restore
matches the same account field the redaction did — `restore_account_id_in_arns`
in `headroom/write_results.py` is built from the same pattern — so a user or
role whose name carries the literal `REDACTED` keeps its name. It once replaced
the token wherever it appeared in the string.

## Identifying the account a file describes

Readers take account identity from the file, never from the filename:

1. Use `summary.account_id` when present. An ID the hierarchy does not hold is
   an error, not an account.
2. Otherwise resolve `summary.account_name` against the organization hierarchy.
3. A file with neither is an error.

Either way the account a file resolves to is in the hierarchy. An account that
left the organization after its scan leaves its file behind, and the ID is
still well-formed, so only the hierarchy can say it is gone. Read as written
the SCP reader would count it as analyzed under a root placement that cannot
reach it — `3 of 2 accounts reached by root were analyzed` — and the RCP
reader would carry its third parties into an allowlist that no longer protects
it. The error names the file and the account and says to delete the file;
re-running would not regenerate it, since the account is no longer scanned.
`skip_account_ids` and non-ACTIVE accounts are in the hierarchy
([`../architecture/aws-execution.md`](../architecture/aws-execution.md#analyzable-accounts--_select_analyzable_accounts)),
so a file from an earlier run that scanned one of them still resolves.

Name resolution is exact-match first. A name matching nothing exactly falls back
to comparing names with case and separators ignored, because result files are
written under the configured name — a slug such as `management-account` where
Organizations reports `Management Account`. The fallback resolves only when
exactly **one** account matches; zero or several is an error rather than a guess.
A name consisting only of separators canonicalizes to the empty string and is
left unresolved, so it cannot match every other such name.

Organizations enforces uniqueness on account email, not on account name, so
several accounts genuinely can share a name. That is an error at read time, not
something to resolve arbitrarily.

### One file per account

A check directory holds at most one result file per account. Both readers
group the files they parse by check and then by the account each resolves
to — by the rule above, never by filename — and abort once, after every
directory is read, when two files resolve to one account. The error names
every check, account, and file at once and prescribes deleting every listed
file before re-running, so one sweep clears a rename that left a pair under
every check. The RCP reader raises this before it reports a registered check
with no directory: that abort's remedy is a re-run, which would write fresh
files beside the stale ones and push this abort to the next run, while
deleting the listed files and re-running fills the missing directory too
([`placement.md`](placement.md#rcp-placement) owns that abort).

The case this exists for is an account rename. `results_exist` looks the
account up under its current name, misses the file written under the old
one, scans again, and writes a second file beside the first. Under the
default both carry the same `summary.account_id` and both match the readers'
glob; with `exclude_account_ids` set the old name resolves to no account and
the read already fails by the rule above, so this rule closes the default
case. Without it the SCP reader would deploy from whichever copy was clean
while the RCP reader would build the allowlist from whichever sorted last.
Agreeing duplicates abort too: the directory still misdescribes what was
scanned, and the operator learns it now rather than on the run where the
copies finally differ.

## Resume

A check is skipped when its result file already exists for that account. There
is no freshness check and no expiry: **delete the file to re-run the check.**
Existence is tested by filename, so a renamed account is scanned again under its
new name; [One file per account](#one-file-per-account) catches the pair at read
time.

`summary.scanned_at` does not change this. It records when a result was
produced, and resume still turns on existence alone: a result from a year ago
is skipped exactly as one from this morning is. Reading the timestamp as a
freshness signal would make it load-bearing, and it is not.

Resume is evaluated at two granularities, and both must agree with the writer's
naming or a run silently re-scans or silently skips:

| Function | Question |
|---|---|
| `results_exist` | Does this one check have a result for this account? |
| `all_check_results_exist` | Do *all* registered checks of this type have one? |

`run_checks` skips an account entirely when both `scps` and `rcps` are complete;
otherwise it assumes the account role and runs only the checks whose files are
missing.

**An aborted run is resumable at that same granularity.** A failure stops the
scan (INV-02), and the files already written stay: each is complete and valid,
because a check already inside `execute()` finishes rather than being killed
mid-write. The re-run reads them and scans only what is left, which is why the
abort reports how many accounts were never analyzed —
[`../architecture/aws-execution.md`](../architecture/aws-execution.md#what-an-aborted-run-tells-the-operator)
owns that report. Nothing marks a file as coming from an aborted run, and
nothing needs to: a result file means that check ran to completion for that
account.

## Ordering and stability

Result files are written with `indent=2` and a trailing newline so they can be
committed and diffed. Two runs against unchanged infrastructure should produce
files that differ in `summary.scanned_at` and nowhere else; a check that emits
unordered collections makes its own output churn and should sort them.

`scanned_at` is the one field expected to differ between runs, and it differs in
every file of every run. That is the cost of recording when a scan happened, and
it is paid deliberately: a one-line diff per file still reads as "nothing
changed", while suppressing the timestamp in the artifact that gets committed
would mean the committed files are the ones that cannot say how old they are.
The worked examples under `test_environment/headroom_results/` pick the key up
on the next real scan; hand-writing a value into them would state a scan time
that never happened.
