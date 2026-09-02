---
id: deny_ec2_public_ip
kind: scp
status: implemented
applies_to:
  - headroom/checks/scps/deny_ec2_public_ip.py
  - headroom/aws/ec2.py
depends_on:
  - INV-02
  - INV-13
  - INV-16
verification:
  - tests/test_checks_deny_ec2_public_ip.py
  - tests/test_aws_ec2.py
---

# deny_ec2_public_ip

## Objective

Deny an EC2 launch that would assign the instance a public IP address, so
instances reach the internet through a NAT gateway and are reachable only
through a load balancer.

### Scope

Launches only, and only the public IP the launch itself assigns.

### Non-goals

- Does not cover Elastic IP association after launch (`ec2:AssociateAddress`).
- Does not read subnet `MapPublicIpOnLaunch` defaults, so it cannot predict a
  launch that would receive a public IP from the subnet rather than the request.
- Does not evaluate route tables, security groups, or actual reachability. A
  public IP is the proxy for exposure, not exposure itself.

## Enforced statement

```
Effect:    Deny
Action:    ec2:RunInstances
Resource:  arn:aws:ec2:*:*:network-interface/*
Condition: Bool
             ec2:AssociatePublicIpAddress = "true"
```

Pattern 2, conditional deny.

**The Resource is the network interface, not the instance.** `RunInstances`
is authorized once per resource the launch touches, and the
[service reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html)
binds `ec2:AssociatePublicIpAddress` to the `network-interface` resource type
alone; it is not on `instance` and not an action-level key. On the instance
ARN the key is therefore absent, a `Bool` condition on an absent key is false,
and a statement scoped to `instance/*` never matches. The statement was scoped
that way once and could not fire, while the check reported the SCP in place.
`test_every_registered_check_is_read_by_a_statement` proves a statement is
gated by `var.deny_ec2_public_ip`, not what it denies, so the statement's shape
is pinned only here and in the module's own comment; `terraform validate`
accepts either scope.

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
| `PublicIpAddress` | The verdict, read from the instance's top level |
| `InstanceId` | Identity |
| `OwnerId`, on the **reservation** rather than the instance | The account field of the synthesized ARN. A reservation returned without one aborts the run: it is the account in every instance ARN this check reports, and the response carries nothing else to take it from |

## Decision table

| State | Condition | Category |
|---|---|---|
| Violation | `PublicIpAddress` is present | `VIOLATION` |
| Compliant | `PublicIpAddress` is absent | `COMPLIANT` |
| Exemption | — | Never produced |
| Skipped | `State.Name == "terminated"` | Not recorded |
| Unknown | — | Not produced; every failure aborts |

## Failure behavior

| Situation | Behavior |
|---|---|
| `ClientError` in any region | `RuntimeError`, aborting the run (INV-02) |
| Unreadable region | Not distinguished; the run aborts |
| `OwnerId` absent | The synthesized ARN carries an empty account field rather than raising |

## Result contract

Base document shape. Summary fields beyond the common three: `total_instances`,
`violations`, `compliant`, `compliance_percentage`.

Entry shape: `instance_id`, `region`, `public_ip_address`, `has_public_ip`,
`instance_arn`.

## Placement and generated policy

Standard SCP placement at zero violations. Terraform variable
`deny_ec2_public_ip`, a boolean. No allowlist.

## Accepted limitations

1. **Only the instance's top-level `PublicIpAddress` is read.** A public address
   on a secondary network interface, or an Elastic IP that does not surface
   there, is not detected. An account can therefore pass this check while
   holding publicly addressed instances.
2. The synthesized `instance_arn` hardcodes the `aws` partition, so a GovCloud or
   China instance is reported under the wrong partition. Nothing downstream reads
   the field.
3. Subnet-assigned public IPs are invisible before launch, so an account can pass
   the check and still have launches denied after the policy is attached, if the
   subnet default would assign one.

## Acceptance scenarios

1. An instance with no `PublicIpAddress` → compliant.
2. An instance with `PublicIpAddress: "111.111.111.111"` → violation.
3. A terminated instance with a public IP → not recorded.
4. An instance whose only public address is on a secondary ENI → reported
   compliant. This is limitation 1, not a defect to fix silently.

## Referenced invariants

INV-02, INV-13, INV-16.

## Implementation

- `headroom/checks/scps/deny_ec2_public_ip.py`
- `headroom/aws/ec2.py` — `get_ec2_public_ip_analysis`
- `test_environment/modules/scps/locals.tf`
- Tests: `tests/test_checks_deny_ec2_public_ip.py`, `tests/test_aws_ec2.py`
