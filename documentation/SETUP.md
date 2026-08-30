# Detailed Setup Guide

## IAM Role Requirements

The tool requires two types of IAM roles to be deployed across your AWS Organization:

### 1. Headroom Role (All Accounts)

Deploy a `Headroom` role in **every account** you want to analyze. This role needs permissions to:
- Describe EC2 instances (all regions)
- List IAM users and roles
- Read IAM policies
- Describe EKS clusters (all regions)
- Describe RDS instances (all regions)
- Read S3 bucket policies
- Read ECR repository policies

**Example Terraform**: See [`test_environment/headroom_roles.tf`](https://github.com/discocrayon/Headroom/blob/main/test_environment/headroom_roles.tf)

### 2. OrgAndAccountInfoReader Role (Management Account)

Deploy an `OrgAndAccountInfoReader` role in your [AWS Organizations management account](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_getting-started_concepts.html#organization-structure). This role needs permissions to:
- List AWS Organizations accounts
- Describe organizational units
- Read account tags
- Describe the organization, for its ID

The organization ID classifies `aws:SourceOrgID` and `aws:SourceOrgPaths` guards on service principals: a guard naming your organization needs no allowlist entry, and one naming another organization withholds the confused deputy statement from that account. Without `organizations:DescribeOrganization` the run aborts rather than guessing.

**Example Terraform**: See [`test_environment/org_and_account_info_reader.tf`](https://github.com/discocrayon/Headroom/blob/main/test_environment/org_and_account_info_reader.tf)

### Trust Configuration

**All roles must trust the Security Analysis Account** where Headroom runs from.

In the `test_environment/`, this is represented by `aws_organizations_account.security_tooling.id` ([see code](https://github.com/search?q=repo%3Adiscocrayon%2Fheadroom%20aws_organizations_account.security_tooling.id&type=code)).

### SCP Exemption Requirement

**The `Headroom` role must be exempt from any SCP that restricts access by region**, such as a region allowlist built on `aws:RequestedRegion`.

Headroom analyzes every region that is *enabled* for the account. Region enablement is independent of SCPs, so a region an SCP denies is still returned by `ec2:DescribeRegions` and still scanned. If a region-allowlist SCP applies to the `Headroom` role, its API calls in the denied regions fail with `AccessDenied`.

Headroom treats those failures as fatal rather than as an absence of findings, because it cannot distinguish "this region has nothing" from "this region could not be read", and the second silently understates what a generated policy must allow. A read it could not complete therefore aborts the run instead of contributing an empty result. With the exemption in place, an `AccessDenied` unambiguously means a missing permission.

Exempt the role with a condition on the SCP's deny statement:

```json
{
  "Effect": "Deny",
  "NotAction": ["iam:*", "organizations:*", "sts:*"],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "aws:RequestedRegion": ["us-east-1", "us-west-2"]
    },
    "ArnNotLike": {
      "aws:PrincipalArn": "arn:aws:iam::*:role/Headroom"
    }
  }
}
```

## Execution Options

### Option 1: From the Security Analysis Account (Recommended)

This is the standard execution pattern.

**Setup:**
1. Deploy `Headroom` role in all accounts (trusting Security Analysis Account)
2. Deploy `OrgAndAccountInfoReader` role in management account (trusting Security Analysis Account)
3. Run Headroom from the Security Analysis Account

**Configuration:**
```yaml
management_account_id: '222222222222'
# Do NOT set security_analysis_account_id
```

**Execution flow:**
- Headroom assumes `OrgAndAccountInfoReader` in management account
- Headroom assumes `Headroom` role in each member account

### Option 2: From the Management Account

If you need to run Headroom directly from your management account.

**Setup:**
1. Deploy `Headroom` role in all accounts (trusting Security Analysis Account)
2. Deploy `OrgAndAccountInfoReader` role in management account (trusting Security Analysis Account)
3. Ensure `OrganizationAccountAccessRole` exists in Security Analysis Account (standard AWS Organizations role)
4. Run Headroom from the Management Account

**Configuration:**
```yaml
management_account_id: '222222222222'
security_analysis_account_id: '111111111111'  # Required for this option
```

**Execution flow:**
- Headroom assumes `OrganizationAccountAccessRole` in Security Analysis Account
- Then assumes `OrgAndAccountInfoReader` in management account
- Then assumes `Headroom` role in each member account

## Configuration Parameters

### Required
- `management_account_id`: Your AWS Organizations management account ID

### Optional
- `security_analysis_account_id`: Only required if running from management account (Option 2)
- `exclude_account_ids`: When `true`, excludes account IDs from result files and filenames (default: `false`). This redacts identifiers; it does not skip any account. See [Resolving Result Files Back to Accounts](#resolving-result-files-back-to-accounts).
- `skip_account_ids`: Account IDs to leave out of analysis entirely (default: `[]`). See [Skipping Accounts](#skipping-accounts).
- `use_account_name_from_tags`: When `true`, uses tag-based account names instead of AWS Organizations names (default: `false`)
- `account_tag_layout`: Tag keys for extracting account metadata (all optional)
- `max_account_workers`: how many accounts to analyze at once. Defaults to 16, and must be
  between 1 and 32. See [Tuning `max_account_workers`](#tuning-max_account_workers).

Every key is one of the above. Headroom refuses to start on a key it does not recognize,
rather than ignoring it: a dropped key is indistinguishable from a misspelled one, and the
setting most likely to be misspelled is one whose loss changes how the run behaves without
changing whether it succeeds. `max_account_worker: 1` used to configure sixteen workers and
say nothing. The same applies to the keys inside `account_tag_layout`.

### Skipping Accounts

```yaml
skip_account_ids:
  - '333333333333'
  - '444444444444'
```

A skipped account is never scanned, so it writes no result files. Policy
placement only ever sees accounts that have results, which has a consequence
worth being explicit about:

**Skipped accounts do not restrain org-wide policy.** They are absent from the
compliance picture rather than flagged as unknown, so Headroom recommends the
same root-level or OU-level placement it would if the account did not exist.
A generated policy can therefore deny actions a skipped account relies on. Skip
an account only when you accept that outcome for it.

Two things skipping does **not** do:

1. **It does not remove the account from your organization's membership set.**
   That set distinguishes in-org principals from third parties. Dropping a
   skipped account from it would reclassify it as a third party and add it to
   the generated RCP allowlist, widening the policy instead of narrowing it.
2. **It does not delete result files written by earlier runs.** Results already
   on disk keep feeding policy generation. To stop an account from influencing
   generated policy after you skip it, delete its files under
   `{results_dir}/{scps,rcps}/*/`.

Every entry must match an account ID that AWS Organizations reports. An entry
matching nothing aborts the run rather than silently analyzing an account you
believe is excluded. Quote the IDs: unquoted YAML parses them as integers and
the config is rejected.

Because the skip list is consulted before lifecycle-state classification, it
also serves as an escape hatch for an account whose state Headroom cannot
classify and which would otherwise abort the run.

### Account Tag Layout

All tags are optional. The tool works even without these tags on your accounts:

```yaml
account_tag_layout:
  environment: 'Environment'  # Falls back to "unknown" if missing
  name: 'Name'                # Falls back to AWS account name or ID if missing
  owner: 'Owner'              # Falls back to "unknown" if missing
```

**Tag behavior:**
- `environment`: Extracted if present, falls back to "unknown" if missing
- `name`: Only used when `use_account_name_from_tags: true`, falls back to account ID if missing
- `owner`: Extracted if present, falls back to "unknown" if missing

### Resolving Result Files Back to Accounts

With `exclude_account_ids: true`, result files carry no account ID, so the
account name alone identifies an account -- both when a file is written and
when it is read back. Two requirements follow, and Headroom enforces each of
them at the point it can. A third rule applies whatever this setting is: an
account name has to be usable as a filename at all, which Headroom checks for
every run -- see
["cannot be used as result filenames"](#cannot-be-used-as-result-filenames).

**Names must be unique.** Before any account is scanned, Headroom aborts if two
accounts it is about to analyze share a name, naming the colliding spellings
but never the account IDs -- printing those would defeat the setting that
created the collision. Two such accounts would write to one file, and because
accounts are analyzed concurrently that file would hold interleaved output from
both. Names are compared the way a case-insensitive filesystem compares them,
so `Prod` and `prod` collide, as do the composed and decomposed spellings of
`café`. The comparison does not vary by platform, so a pair that would not
actually have collided on Linux still aborts; renaming one account is the fix.

**Names must resolve back.** The name in the file comes from the `name` tag;
the name in the organization hierarchy always comes from AWS Organizations.
Headroom matches exactly first, then retries ignoring case and separators, so a
`Name` tag of `management-account` still resolves to an account Organizations
calls `Management Account`, logging a warning that the two differ.

Resolution fails loudly when the answer is not unique or not present:
- The name matches two or more accounts (Organizations enforces uniqueness on
  account email, not on account name). The startup check above does not rule
  this out. It runs only under `exclude_account_ids`, which is off by default,
  and it folds case and Unicode normal form where this lookup also folds
  separators -- so `Prod-US` and `Prod US` are two names to that check and one
  name here. A name reaching this branch is therefore either shared with an
  account the check never saw (the management account, a skipped account, or
  one that is not ACTIVE) or shared with one it saw and read as distinct.
  Rename one account, or set `exclude_account_ids: false` so result files
  carry account IDs.
- The name matches nothing — most often a `name` tag that is missing (the name
  then falls back to the account ID, which matches no account name), a tag that
  is not merely a re-spelling of the account name, or a stale result file left
  behind after an account was renamed.

### Tuning `max_account_workers`

Each worker holds its own boto3 session carrying its own parsed AWS service models, which
measures at roughly 43 MB. That is what bounds this setting, not CPU: analysis is
overwhelmingly network-bound, so the interpreter is idle most of the run.

| Workers | Resident memory | 300 accounts |
| --- | --- | --- |
| 1 | baseline | ~3.8 hours (measured) |
| 8 | ~0.4 GB | ~30 minutes (projected) |
| 16 (default) | ~0.8 GB | ~16 minutes (projected) |
| 32 (maximum) | ~1.5 GB | ~9 minutes (projected) |

Only the serial row is measured. It was taken with the region-list and EC2-instance caches
in place; before those, a serial run took roughly 4.9 hours. A third cache, covering the
resource policies two checks each read, landed afterwards and removes about 68 region
probes per account, so the serial row is if anything now pessimistic.

The other three rows are projected from it rather than measured, and the projection is not
a straight division. Roughly 2.2 minutes of a 300-account run is GIL-bound Python that no
number of workers removes -- client construction and JSON parsing, measured at about 0.45
seconds per account -- so the model is `2.2 + 225.8 / workers`. Dividing the whole 228
minutes instead puts the 32-worker row at 7 minutes, about 30% optimistic, and that is the
row an operator raising the cap is relying on. Real numbers will be worse again: workers
contend for the lock around client construction on the shared session, and AWS throttles
per account rather than per worker.

Set it to `1` to analyze accounts one at a time. That runs the same code path as any other
value rather than a separate serial branch, so it is a safe way to get readable logs and a
simple stack trace while debugging.

A failure in any account aborts the whole run. Queued accounts never start, and accounts
already in flight stop after their current check. Nothing is lost: each check writes its own
result file as it completes, and a re-run skips the results already on disk.

### Reading the Logs

Every line carries the account its thread is working on, in brackets after the logger name:

```
DEBUG:headroom.aws.sqs:[payments_111111111111] Analyzing SQS queues in eu-west-1
```

Accounts are analyzed concurrently, so lines from different accounts interleave and most of
them name only a region or a resource. The bracket is what makes a line attributable. Work
that does not belong to any one account -- startup, configuration, Terraform generation --
is stamped `-`.

One line sizes the whole run, printed once the resume filter has run:

```
INFO:headroom.analysis:[-] Analyzing 116 account(s) with 16 worker(s)
```

Both counts are what the pool is given, not what is configured. Accounts whose results are
already on disk are filtered out before this line, so on a resumed run the count is smaller
than the organization; and because threads are spawned on demand, a run with less work than
`max_account_workers` reports the smaller number.

The default level is INFO, which reports one line per account as it starts, finishes, or
stops. Per-region progress is DEBUG, so a run at the default level says nothing between
starting an account and finishing it. Raise the level when an account looks stuck:

```python
import logging
logging.getLogger("headroom").setLevel(logging.DEBUG)
```

When a run aborts, the last lines account for what did not happen. Every account that
failed is named, not only the one whose error propagated, and a final line gives the number
of accounts that were cancelled before they started:

```
ERROR:headroom.analysis:[-] Checks failed for account payments_111111111111: ClientError(...)
ERROR:headroom.analysis:[-] Aborting: 184 account(s) were never analyzed. Results on disk cover the rest, and a re-run resumes from them.
```

## Test Environment

The [`test_environment/`](https://github.com/discocrayon/Headroom/tree/main/test_environment) folder contains complete Terraform code to set up:
- A sample AWS Organization structure
- All required IAM roles
- Example SCPs and RCPs
- Test resources for validation

You can apply this Terraform from your management account to reproduce a working environment and test Headroom.

## Troubleshooting

### "Access Denied" errors
- Verify trust relationships on IAM roles
- Check that the principal account ID matches where you're running Headroom
- Ensure IAM policies include all required permissions
- If the error names a specific region, check that the `Headroom` role is exempt from any region-allowlist SCP (see [SCP Exemption Requirement](#scp-exemption-requirement)). Headroom scans every *enabled* region, so an SCP that denies a region it can still see aborts the run.

### "AuthFailure" in one region only

`AWS was not able to validate the provided access credentials`, raised from a
single region while every other region succeeds, means the credentials were
minted at the global STS endpoint. Those tokens are valid only in regions that
are enabled by default, so every opt-in region rejects them.

Headroom mints its own credentials regionally, so this points at a session it
did not build. Check for a boto3 `Session` constructed outside
`headroom/aws/sessions.py`, and confirm the region is genuinely enabled rather
than mid-enablement, which reports the same error:

```bash
aws account get-region-opt-status --region-name <region> --account-id <member-account-id>
```

### "Role not found" errors
- Confirm roles are deployed in the correct accounts
- Verify role names match: `Headroom` and `OrgAndAccountInfoReader`
- Check that you're using the correct account IDs in configuration

### Configuration validation errors
- Ensure `management_account_id` is always set
- Only set `security_analysis_account_id` if running from management account
- Validate YAML syntax in your config file
- `Extra inputs are not permitted` names a key Headroom does not recognize. Check it against
  [Configuration Parameters](#configuration-parameters); it is usually a typo.

### "cannot be used as result filenames"

An account name becomes part of its result filename, so a name containing `/` builds a path
into a subdirectory rather than a filename and the account's results end up somewhere policy
generation does not look. A name holding a null byte, or one long enough to overrun the
filesystem's 255-byte limit on a single path component, fails the write outright -- account
names come from a tag under `use_account_name_from_tags`, and a tag value runs to 256
characters where Organizations caps a name at 50. An empty name is refused as well, because
it cannot become a Terraform identifier later. Headroom checks all of this before the scan
starts and names the accounts, with the reason beside each one. Rename them, or set
`use_account_name_from_tags: true` and give them a `name` tag that is a plain filename.

A leading dot is fine: `pathlib.Path.glob` matches dotfiles, and the readers take account
identity from the JSON rather than the filename.
