# Sequence Diagrams

## Main CLI Flow
```mermaid
sequenceDiagram
  participant User
  participant CLI as headroom.__main__ / headroom.main
  participant Usage as headroom.usage
  participant Analysis as headroom.analysis
  participant ParseSCP as headroom.parse_results
  participant ParseRCP as headroom.terraform.generate_rcps
  participant Org as headroom.aws.organization
  participant Snapshot as headroom.aws.organization_snapshot
  participant TFSCP as headroom.terraform.generate_scps
  participant TFRCP as headroom.terraform.generate_rcps
  participant TFOrg as headroom.terraform.generate_org_info

  User->>CLI: run `python -m headroom --config sample_config.yaml`
  CLI->>Usage: parse_cli_args()
  CLI->>Usage: load_yaml_config(path)
  CLI->>Usage: merge_configs(yaml, cli)

  Note over CLI: Organization discovery, once per run
  CLI->>Snapshot: discover_organization(config, org_client)
  Snapshot->>Org: list_organization_accounts(), find_organization_root(), build_organization_hierarchy()
  Org-->>Snapshot: membership and OrganizationHierarchy
  Snapshot-->>CLI: OrganizationSnapshot

  CLI->>Analysis: perform_analysis(config, security_session, snapshot)
  Analysis-->>CLI: None (writes JSON results)

  CLI->>TFOrg: generate_terraform_org_info(snapshot.hierarchy, path)
  Note right of TFOrg: The hierarchy is passed in, not walked here
  TFOrg-->>CLI: scps/grab_org_info.tf written
  CLI->>CLI: ensure_org_info_symlink(rcps_dir, scps_dir)

  Note over CLI: SCP Workflow
  CLI->>ParseSCP: analyze_scp_compliance(config, org_hierarchy)
  ParseSCP->>ParseSCP: parse_scp_result_files()
  ParseSCP->>ParseSCP: determine_scp_placement()
  ParseSCP-->>CLI: List[SCPPlacementRecommendations]
  CLI->>TFSCP: generate_scp_terraform(recommendations, hierarchy)
  TFSCP-->>CLI: SCP Terraform files written

  Note over CLI: RCP Workflow
  CLI->>ParseRCP: parse_rcp_result_files(results_dir, hierarchy)
  ParseRCP-->>CLI: List[RCPCheckParseResult]
  CLI->>ParseRCP: determine_rcp_placement(parse_results, hierarchy)
  ParseRCP-->>CLI: List[RCPPlacementRecommendations]
  CLI->>TFRCP: generate_rcp_terraform(recommendations, hierarchy)
  TFRCP-->>CLI: RCP Terraform files written

  Note over CLI: Both workflows succeeded, so the plan is complete
  CLI->>CLI: reconcile_generated_terraform(dirs, expected)
  CLI-->>User: Done
```

## Security Analysis: Enumerate Accounts and Run Checks

```mermaid
sequenceDiagram
  participant Main as headroom.main
  participant Analysis as headroom.analysis
  participant Org as headroom.aws.organization
  participant STS as boto3 STS
  participant Orgs as boto3 Organizations
  participant Registry as headroom.checks.registry
  participant BaseCheck as headroom.checks.base.BaseCheck
  participant SCPCheck as SCP Check (e.g., deny_ec2_imds_v1)
  participant RCPCheck as RCP Check (e.g., deny_sts_third_party_assumerole)
  participant WriteResults as headroom.write_results
  participant FS as filesystem

  Main->>STS: assume OrgAndAccountInfoReader role
  STS-->>Main: temp credentials
  Main->>Orgs: discover_organization(): describe_organization, list_accounts,<br/>list_roots, the OU traversal, then list_tags_for_resource per analyzable account
  Orgs-->>Main: OrganizationSnapshot
  Main->>Analysis: perform_analysis(config, security_session, snapshot)
  loop for each snapshot.analyzable_accounts entry (concurrently, max_account_workers at a time)
    Analysis->>Analysis: all_check_results_exist("scps", account_info, config)
    Analysis->>Analysis: all_check_results_exist("rcps", account_info, config)
    opt if any results don't exist
      Analysis->>STS: assume Headroom role in account
      STS-->>Analysis: temp credentials

      Note over Analysis,RCPCheck: Run SCP Checks
      Analysis->>Registry: get_all_check_classes("scps")
      Registry-->>Analysis: [SCPCheck1, SCPCheck2, ...]
      loop for each SCP check class
        Analysis->>SCPCheck: check = CheckClass(...)
        Analysis->>SCPCheck: check.execute(session)
        SCPCheck->>SCPCheck: analyze(session) -> raw results
        SCPCheck->>SCPCheck: categorize_result() -> violations/exemptions/compliant
        SCPCheck->>SCPCheck: build_summary_fields() -> summary
        SCPCheck->>WriteResults: write_check_results(...)
        WriteResults->>FS: write JSON to results_dir/scps/check_name/
      end

      Note over Analysis,RCPCheck: Run RCP Checks
      Analysis->>Registry: get_all_check_classes("rcps")
      Registry-->>Analysis: [RCPCheck1, RCPCheck2, ...]
      loop for each RCP check class
        Analysis->>RCPCheck: check = CheckClass(...)
        Analysis->>RCPCheck: check.execute(session)
        RCPCheck->>RCPCheck: analyze(session) -> raw results
        RCPCheck->>RCPCheck: categorize_result() -> violations/exemptions/compliant
        RCPCheck->>RCPCheck: build_summary_fields() -> summary
        RCPCheck->>WriteResults: write_check_results(...)
        WriteResults->>FS: write JSON to results_dir/rcps/check_name/
      end
    end
  end
```

## SCP Results Parsing and Placement

```mermaid
sequenceDiagram
  participant Results as headroom.parse_results
  participant FS as filesystem
  participant Hierarchy as HierarchyPlacementAnalyzer

  Note over Results: Parse SCP results from disk
  Results->>FS: scan results_dir/scps/**/*.json
  FS-->>Results: raw JSON files
  Results->>Results: parse_scp_result_files(results_dir, org_hierarchy)
  Results-->>Results: List[SCPCheckResult]

  Note over Results: Determine placement using hierarchy
  Results->>Results: determine_scp_placement(results, org_hierarchy)
  Results->>Hierarchy: determine_placement(results, is_safe_for_root, is_safe_for_ou, get_account_id)
  Hierarchy->>Hierarchy: Check if safe for root (all violations = 0)
  Hierarchy->>Hierarchy: Group results by OU
  Hierarchy->>Hierarchy: Check if safe for each OU
  Hierarchy-->>Results: List[PlacementCandidate]
  Results-->>Results: Convert to SCPPlacementRecommendations
  Results-->>Caller: List[SCPPlacementRecommendations]
```

## RCP Results Parsing and Placement

```mermaid
sequenceDiagram
  participant GenRCP as headroom.terraform.generate_rcps
  participant FS as filesystem
  participant Hierarchy as HierarchyPlacementAnalyzer

  Note over GenRCP: Parse RCP results from disk
  GenRCP->>FS: scan results_dir/rcps/{check_name}/*.json for each registered check
  FS-->>GenRCP: raw JSON files
  GenRCP->>GenRCP: parse_rcp_result_files(results_dir, org_hierarchy)
  GenRCP->>GenRCP: _parse_single_rcp_result_file()
  GenRCP-->>GenRCP: List[RCPCheckParseResult] (one per registered check)

  Note over GenRCP: Determine placement using hierarchy, once per check
  GenRCP->>GenRCP: determine_rcp_placement(parse_results, org_hierarchy)
  loop for each registered RCP check
    GenRCP->>GenRCP: _determine_check_rcp_placement(parse_result, org_hierarchy)
    GenRCP->>Hierarchy: determine_placement(accounts, is_safe_for_root, is_safe_for_ou, get_account_id)
    Hierarchy->>Hierarchy: Check if safe for root (no account blocks this check)
    Hierarchy->>Hierarchy: Skip OUs holding an account blocked for this check
    Hierarchy->>Hierarchy: Check if safe for each OU
    Hierarchy-->>GenRCP: List[PlacementCandidate]
    GenRCP->>GenRCP: Convert to RCPPlacementRecommendations
  end
  GenRCP-->>Caller: List[RCPPlacementRecommendations]
```
