---
id: deny_ec2_ami_owner
kind: scp
status: implemented
applies_to:
  - headroom/checks/scps/deny_ec2_ami_owner.py
  - headroom/aws/ec2.py
depends_on:
  - INV-01
  - INV-02
  - INV-06
  - INV-07
  - INV-08
  - INV-16
verification:
  - tests/test_checks_deny_ec2_ami_owner.py
  - tests/test_aws_ec2.py
  - tests/test_parse_results.py
  - tests/test_generate_scps.py
---

# deny_ec2_ami_owner

## Objective

Deny an EC2 launch from an AMI whose owner is not one the organization already
uses, so an image published by an unknown account cannot become a running
instance.

### Scope

Launches and launch-adjacent fleet APIs, restricted to the image resource.

### Non-goals

- Does not examine AMIs that exist but were never launched from.
- Does not read launch templates or Auto Scaling group configurations.
- Does not cover `ec2:ModifyFleet`, deliberately. It *does* support `ec2:Owner` —
  raising a fleet's target capacity launches from its launch template's AMI — so
  this is a scope decision, not an authorization limit.
- Does not cover `ec2:RunScheduledInstances`, `ec2:ModifySpotFleetRequest`, or
  `ec2:CreateLaunchTemplateVersion`, for the opposite reason: they list no image
  resource, so a statement scoped to `image/*` never matches them. Naming them
  would read as coverage while denying nothing.
- Does not judge an AMI's contents, only who published it.

## Enforced statement

```
Effect:    Deny
Action:    ec2:CreateFleet, ec2:RequestSpotFleet,
           ec2:RequestSpotInstances, ec2:RunInstances
Resource:  arn:aws:ec2:*::image/*
Condition: StringNotEquals
             ec2:Owner = <ec2_allowed_ami_owners>
```

Pattern 5c, condition value allowlist. The four actions are the launch paths AWS
authorizes against the image resource.

## Evidence

Per enabled region: `ec2:DescribeInstances`, then `ec2:DescribeImages` for each
distinct AMI, called with `IncludeDisabled=True` and `IncludeDeprecated=True` so a
hidden image is asked for up front.

**The instance sweep is issued once per account, not once per check.**
`get_instances` memoizes each region's projected instances on the session, so
the first of the four EC2 checks to reach a region pays for
`ec2:DescribeInstances` and the other three read the memo. Four identical
sweeps per region was 51 of the 68 calls a 17-region account made.
`tests/performance/test_call_counts.py` pins the count. The memo also owns the
terminated filter, so no check sees a terminated instance at all — collecting
once is what let the identical opening test in all four be stated once.

The AMI resolutions are cached separately and more narrowly: one dictionary per
region, held for the length of this check's pass over that region, covering the
AMIs that did not resolve as well as the ones that did, so a dead AMI shared by
many instances costs one lookup. It is not shared with the other three checks —
they do not resolve AMIs — and it does not outlive the account.

| Read | Used for |
|---|---|
| `State.Name` on the instance | Terminated instances are skipped |
| `ImageId` on the instance | Which AMI to resolve |
| `ImageOwnerAlias` on the image | The allowlist value, where present |
| `OwnerId` on the image | The allowlist value otherwise |
| `State` on the image | A `disabled` image is logged, and still resolves |

### The value recorded is the value the condition key holds

`ec2:Owner` evaluates to the AMI's `ImageOwnerAlias` where it has one, and to its
numeric `OwnerId` otherwise. The allowlist therefore records the alias where
there is one — `amazon`, `aws-marketplace` — and the numeric ID where there is
not.

This is INV-08's founding case;
[`../../invariants.md`](../../invariants.md#inv-08--record-the-value-the-condition-key-will-hold)
owns what collecting the wrong half of that pair cost and what it settled about
fixtures.

Only `amazon` and `aws-marketplace` are recognized aliases. Any other alias
aborts the run rather than entering an allowlist as a value `ec2:Owner` may never
hold.

### Measured

`RunInstances --dry-run` against the statement this repository generates:

| AMI | Allowlist | Result |
|---|---|---|
| Amazon Linux 2023 (`ImageOwnerAlias: amazon`) | numeric `OwnerId` | DENY |
| Amazon Linux 2023 | `["amazon"]` | ALLOW |
| Amazon Linux 2023 | numeric `OwnerId` and `"amazon"` | ALLOW |
| Rocky Linux (no `ImageOwnerAlias`) | numeric `OwnerId` | ALLOW |
| Rocky Linux | `["amazon"]` | DENY |

Rows 1 and 4 are the whole rule: for an aliased AMI the numeric owner does not
satisfy `ec2:Owner`, and for an unaliased one it is the only thing that does.
Recording the wrong half of the pair denies a launch the scan had just cleared.

`aws-marketplace` is inferred from the `amazon` rows rather than measured. Every
reachable Marketplace AMI required a subscription, and EC2 returns
`OptInRequired` before it evaluates the statement, so a dry run there cannot
tell an allow from a deny.

## Decision table

| State | Condition | Category |
|---|---|---|
| Compliant | The AMI resolved to an owner | `COMPLIANT` |
| Violation | The AMI did not resolve | `VIOLATION` |
| Exemption | — | Never produced |
| Unknown | The AMI did not resolve, with a recorded reason | Recorded as a violation, with `owner_unknown_reason` |
| Skipped | `State.Name == "terminated"` | Not recorded |
| Skipped | An instance with no `ImageId` | Logged and dropped, not counted |

Two unknown reasons are distinguished, because they mean different things:

| Reason | Meaning |
|---|---|
| `not_visible` | `DescribeImages` did not surface the AMI even when asked for disabled and deprecated images — an Allowed AMIs setting filters it, or it was shared and then unshared |
| `deregistered` | The AMI ID no longer resolves at all, which is what deregistration leaves behind on a long-lived instance |

An unresolvable AMI is a violation because its owner cannot enter the allowlist,
so a policy attached here would deny that instance's relaunch.

## Failure behavior

| Situation | Behavior |
|---|---|
| `ClientError` on `DescribeInstances` in any region | `RuntimeError`, aborting the run |
| `InvalidAMIID.NotFound` / `InvalidAMIID.Unavailable` on `DescribeImages` | Recorded as `deregistered` |
| Any other `ClientError` on `DescribeImages`, `AccessDenied` included | Re-raised, aborting the run |
| An image returned with no `OwnerId` | `RuntimeError` |
| An unrecognized owner alias | `RuntimeError` |

## Result contract

Base document shape. Summary fields beyond the common three:

| Key | Meaning |
|---|---|
| `total_instances`, `violations`, `compliant`, `compliance_percentage` | Counts |
| `unique_ami_owners` | Sorted allowlist values observed — alias where present, else numeric ID |
| `unknown_ami_owners` | `{reason: count}` |

Entry shape: `instance_id`, `region`, `ami_id`, `ami_owner`, `ami_owner_alias`,
`ami_name`, `owner_unknown_reason`.

`ami_owner` holds the numeric owner; the alias is in `ami_owner_alias`.
`unique_ami_owners` is the field that feeds the allowlist, and it holds whichever
of the two `ec2:Owner` would carry.

**`unique_ami_owners` is required on read** (INV-01). A result file lacking it
predates AMI owner collection, and parsing raises and names the check to re-run
rather than reading the file at all.
[`../../invariants.md`](../../invariants.md#inv-01--absence-of-evidence-is-not-evidence-of-safety)
owns why a missing key here cannot be read as a genuine zero.

## Placement and generated policy

Standard SCP placement at zero violations, plus the allowlist round trip
(INV-07): `summary.unique_ami_owners` → `SCPCheckResult.ami_owners` → the sorted
union across the accounts a placement covers →
`SCPPlacementRecommendations.ec2_allowed_ami_owners` → the
`ec2_allowed_ami_owners` Terraform variable.

Terraform variables: `deny_ec2_ami_owner` (boolean) and
`ec2_allowed_ami_owners` (list, rendered only when the boolean is true).

**An empty allowlist is never rendered** (INV-06). Where the covered accounts
observed no resolvable AMI owner at all, this check's statement is left off
rather than rendered with an empty `ec2_allowed_ami_owners`.
[`../../invariants.md`](../../invariants.md#inv-06--an-empty-allowlist-is-never-rendered-as-an-empty-list)
owns what an empty list would do and what generation emits in its place.
Observing no owner is a fact about accounts that ran no instances, so the rest
of the organization still generates.

## Accepted limitations

1. **An alias is broader than the AMI observed.** Allowlisting `amazon` because
   one Amazon Linux AMI was seen permits every Amazon-published AMI.
2. Instances with no `ImageId` are dropped entirely and are not counted in
   `total_instances`.
3. AMIs referenced by launch templates but never launched from do not enter the
   allowlist, so the first launch after attachment can be denied.
4. **A terminated instance is not read**, so an AMI every launch of which has
   since been terminated does not enter the allowlist either, and relaunching
   from it after attachment would be denied. The skip is uniform across the
   four EC2 analyzers and costs the other three nothing — they report on a
   fleet that is out of scope by design, since nothing already launched can be
   denied by a statement AWS evaluates against `RunInstances`. This is the one
   check whose reading feeds an allowlist, so here the skip narrows what the
   generated policy permits. No source records a decision to accept that; it is
   limitation 3 reached by a different route.
5. `AccessDenied` on `DescribeImages` aborts rather than recording an unknown.

## Acceptance scenarios

1. An instance from an AMI with `ImageOwnerAlias: "amazon"` → compliant, and
   `unique_ami_owners` holds `amazon`, not the numeric ID.
2. An instance from an AMI owned by `111111111111` with no alias → compliant,
   and `unique_ami_owners` holds `111111111111`.
3. An instance whose AMI `DescribeImages` will not return → violation with
   `owner_unknown_reason: "not_visible"`.
4. An instance whose AMI returns `InvalidAMIID.NotFound` → violation with
   `owner_unknown_reason: "deregistered"`.
5. An account whose every instance resolves, but to no owner at all → the policy
   is left off with a comment, and generation continues for other targets.
6. A result file with no `unique_ami_owners` key → generation aborts naming the
   check and the account.
7. An account whose only instance launched from a given AMI is terminated →
   that instance is not recorded, the AMI's owner is absent from
   `unique_ami_owners`, and a relaunch from it would be denied. This is
   limitation 4.

## Referenced invariants

INV-01, INV-02, INV-06, INV-07, INV-08, INV-16.

## Implementation

- `headroom/checks/scps/deny_ec2_ami_owner.py`
- `headroom/aws/ec2.py` — `get_ec2_ami_owner_analysis`
- `headroom/enums.py` — `AmiOwnerUnknownReason`
- `headroom/parse_results.py` — `_extract_ami_owners`
- `headroom/terraform/generate_scps.py` — `_build_ec2_terraform_parameters`
- Tests: `tests/test_checks_deny_ec2_ami_owner.py`, `tests/test_aws_ec2.py`,
  `tests/test_parse_results.py`, `tests/test_generate_scps.py`
