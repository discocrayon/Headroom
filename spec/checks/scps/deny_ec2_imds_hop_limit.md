---
id: deny_ec2_imds_hop_limit
kind: scp
status: implemented
applies_to:
  - headroom/checks/scps/deny_ec2_imds_hop_limit.py
  - headroom/aws/ec2.py
depends_on:
  - INV-02
  - INV-10
  - INV-13
  - INV-16
verification:
  - tests/test_checks_deny_ec2_imds_hop_limit.py
  - tests/test_aws_ec2.py
---

# deny_ec2_imds_hop_limit

## Objective

Deny an EC2 launch whose IMDS response is allowed to travel more than one
network hop, which is what lets a container or a compromised process on the
instance reach credentials the host was issued.

### Scope

Launches only, like every EC2 check here. The condition reads the
`RunInstances` request.

### Non-goals

- Does not cover `ec2:ModifyInstanceMetadataOptions`, so a hop limit raised after
  launch is invisible and unenforced.
- Does not read launch templates or Auto Scaling group configurations — the
  same gap [`deny_ec2_ami_owner`](deny_ec2_ami_owner.md) states, where it also
  records what the gap costs.
- **Has no exemption mechanism of any kind.** There is no tag, no allowlist, and
  no `EXEMPTION` branch in the categorizer. Any statement elsewhere that this
  check exempts on a tag is wrong.

## Enforced statement

```
Effect:    Deny
Action:    ec2:RunInstances
Resource:  arn:aws:ec2:*:*:instance/*
Condition: NumericGreaterThan
             ec2:MetadataHttpPutResponseHopLimit = "1"
```

Pattern 2, conditional deny.

There is deliberately **no** `ec2:MetadataHttpEndpoint` clause. This check and
[`deny_ec2_imds_v1`](deny_ec2_imds_v1.md) are two statements gated by two
variables, each measured by the evidence that actually decides it (INV-10). They
were once one variable over two statements, and the weaker evidence authorized
the stronger statement.

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
| `MetadataOptions.HttpPutResponseHopLimit` | The verdict. Absent means `1`. |
| `MetadataOptions.HttpEndpoint` | Recorded only. Absent means `enabled`. |
| `InstanceId` | Identity |

**The endpoint state does not enter the decision.** An instance with IMDS
disabled and a hop limit of 3 is still a violation: the endpoint can be
re-enabled with an API this statement does not cover, and the hop limit is then
live.

## Decision table

| State | Condition | Category |
|---|---|---|
| Violation | `hop_limit > 1` | `VIOLATION` |
| Compliant | `hop_limit <= 1` | `COMPLIANT` |
| Exemption | — | Never produced |
| Skipped | `State.Name == "terminated"` | Not recorded |
| Unknown | — | Not produced; every failure aborts |

## Failure behavior

| Situation | Behavior |
|---|---|
| `ClientError` in any region | `RuntimeError`, aborting the run (INV-02) |
| Unreadable region | Not distinguished; the run aborts |
| `MetadataOptions` absent or partial | Defaults applied: hop limit `1`, endpoint `enabled` |

## Result contract

Base document shape. Summary fields beyond the common three: `total_instances`,
`violations`, `compliant`, `compliance_percentage`.

There is **no `exemptions` key**, because this check produces none.

Entry shape: `instance_id`, `region`, `hop_limit`, `imds_enabled`.

## Placement and generated policy

Standard SCP placement at zero violations. Terraform variable
`deny_ec2_imds_hop_limit`, a boolean. No allowlist.

**Expect this check to stay unplaced.** Violations are the norm on a modern
fleet rather than an edge case, for two compounding reasons:

1. An AMI carrying `imds-support=v2.0` — current Amazon Linux 2023 among them —
   supplies a hop limit above 1 to a launch that names no `MetadataOptions` at
   all. A dry run against a live account confirms `MaxImdsHopLimit` denies that
   default launch. A default AL2023 instance is a violation before anyone
   configures anything.
2. A container adds a network hop, so workloads on ECS, EKS, or plain Docker
   generally need a hop limit of at least 2 to reach IMDS.

Placement enables an SCP only where every covered account reports zero
violations, so in practice this stays unplaced until a fleet explicitly pins hop
limit 1 everywhere. Whether 1 is the right threshold for a fleet on modern AMIs
is the operator's decision; this check does not assume it, it only reports what
enforcing it would cost.

## Accepted limitations

1. Launch-time only; the running fleet keeps whatever hop limit it has.
2. `ModifyInstanceMetadataOptions` is uncovered.
3. A hop limit above 1 is sometimes genuinely needed — a container on the host
   reaching IMDS through the bridge. There is no exemption path, so such an
   account simply blocks the policy until the workload changes.

## Acceptance scenarios

1. An instance with `HttpPutResponseHopLimit: 1` → compliant.
2. An instance with no `MetadataOptions` at all → compliant, by the default of 1.
3. An instance with `HttpPutResponseHopLimit: 2` → violation.
4. An instance with `HttpPutResponseHopLimit: 3` and `HttpEndpoint: disabled` →
   violation; the endpoint state does not excuse it.
5. A terminated instance with hop limit 5 → not recorded, and the account stays
   eligible.

## Referenced invariants

INV-02, INV-10, INV-13, INV-16.

## Implementation

- `headroom/checks/scps/deny_ec2_imds_hop_limit.py`
- `headroom/aws/ec2.py` — `get_ec2_imds_hop_limit_analysis`
- `test_environment/modules/scps/locals.tf`
- Tests: `tests/test_checks_deny_ec2_imds_hop_limit.py`, `tests/test_aws_ec2.py`
