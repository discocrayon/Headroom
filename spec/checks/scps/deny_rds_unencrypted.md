---
id: deny_rds_unencrypted
kind: scp
status: implemented
applies_to:
  - headroom/checks/scps/deny_rds_unencrypted.py
  - headroom/aws/rds.py
depends_on:
  - INV-02
  - INV-13
  - INV-16
verification:
  - tests/test_checks_deny_rds_unencrypted.py
  - tests/test_aws_rds.py
---

# deny_rds_unencrypted

## Objective

Deny creation of an RDS instance or cluster without encryption at rest.
Encryption cannot be enabled in place after creation, so the creation call is the
only place to enforce it.

### Scope

Creation, plus the one restore path that supports the condition key.

### Non-goals

- Does not cover `rds:RestoreDBInstanceFromDBSnapshot`,
  `rds:RestoreDBClusterFromSnapshot`, or
  `rds:RestoreDBInstanceToPointInTime`, none of which are scanned or denied.
- Does not read snapshots, read replicas, or Global Clusters.
- Does not check which KMS key encrypts the database, only that one does.

## Enforced statement

```
Effect:    Deny
Action:    rds:CreateDBInstance, rds:CreateDBCluster,
           rds:RestoreDBClusterFromS3, rds:CreateBlueGreenDeployment
Resource:  *
Condition: Bool
             rds:StorageEncrypted = "false"
```

Pattern 2, conditional deny. Three of the four —
`rds:CreateDBCluster`, `rds:RestoreDBClusterFromS3`, and
`rds:CreateBlueGreenDeployment` — are documented in the AWS Service
Authorization Reference as supporting `rds:StorageEncrypted`.

`rds:CreateDBInstance` is **not**, and is included anyway. The reasoning was
that an unsupported condition key leaves `Bool` evaluating false, so the `Deny`
would simply not apply and nothing would break — the attempt was free. It was
then measured by hand against a live account: the statement does block an
unencrypted `CreateDBInstance`, so the key is supported and undocumented. The
Reference is evidence of what AWS has written down, not of what IAM does.

## Evidence

Per enabled region: `rds:DescribeDBInstances` and `rds:DescribeDBClusters`, both
paginated.

| Read | Used for |
|---|---|
| `DBInstanceIdentifier` / `DBClusterIdentifier`, and the ARN | Identity |
| `StorageEncrypted` | The verdict. Absent means `False`. |
| `Engine` | Recorded. Absent means `"unknown"`. |

An absent `StorageEncrypted` is read as **unencrypted**, which is the
conservative direction: it over-reports violations and so under-deploys the
policy.

## Decision table

| State | Condition | Category |
|---|---|---|
| Violation | `StorageEncrypted` is falsy or absent | `VIOLATION` |
| Compliant | `StorageEncrypted` is true | `COMPLIANT` |
| Exemption | — | Never produced |
| Unknown | — | Not produced; every failure aborts |

## Failure behavior

`headroom/aws/rds.py` has **no exception handling.** `AccessDenied`, an RDS
endpoint unavailable in an enabled region, or any other `ClientError` propagates
and aborts the run (INV-02).

## Result contract

Base document shape. Summary fields beyond the common three: `total_databases`
(**not** `total_instances`), `violations`, `compliant`,
`compliance_percentage`.

Entry shape: `db_identifier`, `db_type` (`"instance"` or `"cluster"`), `region`,
`engine`, `encrypted`, `db_arn`.

## Placement and generated policy

Standard SCP placement at zero violations. Terraform variable
`deny_rds_unencrypted`, a boolean. No allowlist.

## Accepted limitations

1. **An Aurora cluster and each of its member instances are both enumerated**, so
   one logical database is counted more than once in `total_databases` and can
   produce several findings. The compliance percentage is therefore weighted
   toward clusters with many members. The deployability verdict is unaffected,
   since it turns on the violation count being zero.
2. Restore paths other than `RestoreDBClusterFromS3` are neither scanned nor
   denied, so an unencrypted database can still be restored into the account.
3. No error handling of any kind, so a region where RDS is unavailable aborts the
   run rather than being skipped.

## Acceptance scenarios

1. An instance with `StorageEncrypted: true` → compliant.
2. An instance with `StorageEncrypted: false` → violation.
3. An instance with no `StorageEncrypted` key → violation, by the conservative
   default.
4. An encrypted Aurora cluster with two encrypted members → three compliant
   entries and `total_databases: 3`.
5. `AccessDenied` on `DescribeDBClusters` in one region → the run aborts.

## Referenced invariants

INV-02, INV-13, INV-16.

## Implementation

- `headroom/checks/scps/deny_rds_unencrypted.py`
- `headroom/aws/rds.py` — `get_rds_unencrypted_analysis`
- `test_environment/modules/scps/locals.tf`
- Tests: `tests/test_checks_deny_rds_unencrypted.py`, `tests/test_aws_rds.py`
