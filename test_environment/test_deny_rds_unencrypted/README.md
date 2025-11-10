# Test RDS Resources for deny_rds_unencrypted SCP

This directory contains test RDS instances and Aurora clusters for validating the `deny_rds_unencrypted` SCP check.

## Resources Created

### RDS Instances
- **encrypted-instance** (compliant) - PostgreSQL with encryption enabled
- **unencrypted-instance** (violation) - MySQL without encryption

### Aurora Clusters
- **encrypted-cluster** (compliant) - Aurora MySQL with encryption enabled
- **unencrypted-cluster** (violation) - Aurora PostgreSQL without encryption

## Purpose

These resources test:
1. Detection of unencrypted RDS instances
2. Detection of unencrypted Aurora clusters
3. Proper categorization of encrypted vs unencrypted databases
4. Multi-engine support (MySQL, PostgreSQL, Aurora)

## Cost Considerations

**⚠️ WARNING:** These resources incur AWS charges.

- RDS instances: ~$0.017/hour each (db.t3.micro)
- Aurora clusters: ~$0.082/hour each (db.t3.medium)

**Estimated cost: ~$2-3 per day if left running**

## Usage

### Create Test Resources

```bash
cd test_environment/test_deny_rds_unencrypted
terraform init
terraform plan
terraform apply
```

### Run Headroom Analysis

```bash
cd ../..
python -m headroom.main --config my_config.yaml
```

### Clean Up (IMPORTANT)

```bash
cd test_environment/test_deny_rds_unencrypted
terraform destroy
```

## Expected Results

When running Headroom with these resources:

- **Violations:** 2 (unencrypted-instance, unencrypted-cluster)
- **Compliant:** 2 (encrypted-instance, encrypted-cluster)
- **Compliance Percentage:** 50%

## Resource Distribution

- **acme-co:** encrypted-instance (COMPLIANT), unencrypted-cluster (VIOLATION)
- **shared-foo-bar:** unencrypted-instance (VIOLATION)
- **fort-knox:** encrypted-cluster (COMPLIANT)

## Notes

- All resources use minimal instance sizes to reduce costs
- Deletion protection is disabled for easy cleanup
- Skip final snapshot is enabled for faster destruction
- Resources are spread across 3 test accounts for realistic testing
