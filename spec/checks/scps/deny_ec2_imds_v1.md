---
id: deny_ec2_imds_v1
kind: scp
status: implemented
applies_to:
  - headroom/checks/scps/deny_ec2_imds_v1.py
  - headroom/aws/ec2.py
  - headroom/aws/helpers.py
depends_on:
  - INV-02
  - INV-09
  - INV-16
verification:
  - tests/test_checks_deny_ec2_imds_v1.py
  - tests/test_aws_ec2.py
---

# deny_ec2_imds_v1

## Objective

Require IMDSv2 on **newly launched** EC2 instances, by denying a
`RunInstances` call that would leave the instance answering IMDSv1.

### Scope

Launches only. The statement conditions on the `RunInstances` request, so nothing
this check reads can be denied by it: the fleet already running keeps answering
IMDSv1 until it is replaced. That is deliberate — a statement that could break
running workloads is not what Headroom generates.

### Non-goals

- Does not cover `ec2:ModifyInstanceMetadataOptions`, so an instance can still be
  moved back to `optional` after launch.
- Does not read the IMDS endpoint state. `HttpEndpoint: disabled` is not a
  defense: it can be re-enabled with `ModifyInstanceMetadataOptions`, which this
  statement does not cover, and the instance then answers IMDSv1.
- Does not read instance profiles or role tags. No IAM client is constructed, and
  `test_no_iam_client_is_ever_created` pins that.

## Enforced statement

```
Effect:    Deny
Action:    ec2:RunInstances
Resource:  arn:aws:ec2:*:*:instance/*
Condition: StringNotEquals
             ec2:MetadataHttpTokens             = "required"
             aws:RequestTag/ExemptFromIMDSv2    = "true"
```

Pattern 4, exception tag ([`../../contracts/policy-model.md`](../../contracts/policy-model.md)).
Both keys sit in one `StringNotEquals` block and are therefore ANDed: the launch
is denied only when it neither requires IMDSv2 nor carries the exemption tag.

`StringNotEquals`, not the `IfExists` form: a request that omits the key is
denied.

## Evidence

`ec2:DescribeInstances`, per enabled region.

**The instance sweep is issued once per account, not once per check.**
`get_instances` memoizes each region's projected instances on the session, so
the first of the four EC2 checks to reach a region pays for
`ec2:DescribeInstances` and the other three read the memo. Four identical
sweeps per region was 51 of the 68 calls a 17-region account made.
`tests/performance/test_call_counts.py` pins the count. The memo also owns the
terminated filter, so no check sees a terminated instance at all — collecting
once is what let the identical opening test in all four be stated once.

| Read | Used for |
|---|---|
| `State.Name` | Terminated instances are skipped |
| `MetadataOptions.HttpTokens` | The verdict. Absent means `optional`. |
| `Tags` | The exemption, read off the instance |
| `InstanceId` | Identity |

### The exemption is read from a proxy

The statement conditions on `aws:RequestTag/ExemptFromIMDSv2`, a tag on the
**launch request**. A scan cannot see a request that already happened, so this
check reads the tag off the **instance** instead.

The proxy holds because the same `TagSpecifications` entry that exempts the
launch is what puts the tag on the instance it creates. This is one of the
substitutions INV-09 sanctions, and
[`../../invariants.md`](../../invariants.md) is where they are listed; the costs
of this one are stated under [accepted limitations](#accepted-limitations).

The two halves of the tag are matched differently, and the scan follows both:

- **Key: case-insensitive.** IAM matches condition key names, including the tag
  key after the slash, without regard to case, so `exemptfromimdsv2` exempts too.
- **Value: case-sensitive.** The condition uses `StringNotEquals`, so an instance
  tagged `True` is **not** exempt to enforcement and must not be reported exempt.
  Measured with `RunInstances --dry-run`: `true` allows the launch, `True` does
  not.

## Decision table

| State | Condition | Category |
|---|---|---|
| Compliant | `HttpTokens == "required"` | `COMPLIANT` |
| Exemption | `HttpTokens == "optional"` **and** the instance carries `ExemptFromIMDSv2` (any case) with the exact value `true` | `EXEMPTION` |
| Violation | `HttpTokens == "optional"` and no such tag | `VIOLATION` |
| Skipped | `State.Name == "terminated"` | Not recorded |
| Unknown | — | Not produced; every failure aborts |

Exemptions count toward compliance in the summary: `compliant_count` is
`len(compliant) + len(exemptions)`.

## Failure behavior

| Situation | Behavior |
|---|---|
| `ClientError` in any region | `RuntimeError`, aborting the run (INV-02) |
| Unreadable region | Not distinguished from any other `ClientError`; the run aborts |
| Instance carries `ExemptFromIMDSv2` twice in differing cases | `RuntimeError` from the shared tag reader — which of the two values IAM would compare is not guessable |
| Tag absent | Not exempt |

## Result contract

Base document shape ([`../../contracts/results.md`](../../contracts/results.md)).

Summary fields beyond the common three:

| Key | Meaning |
|---|---|
| `total_instances` | Violations + exemptions + compliant |
| `violations`, `exemptions`, `compliant` | Counts |
| `compliance_percentage` | `(compliant + exemptions) / total * 100` |

Entry shape in all three arrays: `region`, `instance_id`, `imdsv1_allowed`,
`exemption_tag_present`.

## Placement and generated policy

Standard SCP placement: an account is safe at zero violations, so an account
whose IMDSv1 instances are all tagged is safe
([`../../contracts/placement.md`](../../contracts/placement.md)).

Terraform variable `deny_ec2_imds_v1`, a boolean. No allowlist.

## Accepted limitations

1. **The running fleet is out of reach.** By design; see Scope.
2. **The proxy can be wrong in both directions.** A tag applied with
   `CreateTags` *after* launch reports the instance exempt, while a relaunch
   under the same IaC would be denied. An instance whose IaC does not declare the
   tag but was tagged by hand reads the same way.
3. **`ModifyInstanceMetadataOptions` is uncovered**, so compliance is a
   launch-time property only.
4. **The endpoint state is ignored on purpose.** An instance with
   `HttpEndpoint: disabled` and `HttpTokens: optional` is a violation.

## Acceptance scenarios

1. An instance with `HttpTokens: required` and no tags → compliant; the account
   stays eligible.
2. An instance with `HttpTokens: optional` tagged `ExemptFromIMDSv2=true` →
   exemption; the account stays eligible.
3. The same instance tagged `ExemptFromIMDSv2=True` → violation; the account is
   ineligible.
4. The same instance tagged `exemptfromimdsv2=true` → exemption; the key matches
   without regard to case.
5. An instance with `HttpTokens: optional`, `HttpEndpoint: disabled`, no tag →
   violation.
6. An instance carrying both `ExemptFromIMDSv2=true` and
   `exemptfromimdsv2=false` → the run aborts.
7. One untagged IMDSv1 instance anywhere in an OU's subtree → no OU-level
   placement for that subtree (INV-05).

## Referenced invariants

INV-02, INV-09, INV-16.

## Implementation

- `headroom/checks/scps/deny_ec2_imds_v1.py`
- `headroom/aws/ec2.py` — `get_ec2_imds_v1_analysis`
- `headroom/aws/helpers.py` — `find_tag_value_as_iam_matches`, shared with
  [`deny_eks_create_cluster_without_tag`](deny_eks_create_cluster_without_tag.md)
- `headroom/constants.py` — `IMDS_EXEMPTION_TAG_KEY`, `IMDS_EXEMPTION_TAG_VALUE`
- `test_environment/modules/scps/locals.tf`
- Tests: `tests/test_checks_deny_ec2_imds_v1.py`, `tests/test_aws_ec2.py`
