## Execution Flow

**Note:** This diagram shows Headroom running from the security analysis account (recommended). The `security_analysis_account_id` configuration is optional and only needed if running from the management account.

```mermaid
sequenceDiagram
    participant Tool as Headroom CLI<br/>(Security Analysis Account)
    participant Mgmt as OrgAndAccountInfoReader<br/>(Management Account)
    participant Prod1 as Headroom Role<br/>(Production Account 1)
    participant ProdN as Headroom Role<br/>(Other Accounts...)

    Note over Tool: Step 1: Get Organization Info
    Tool->>Mgmt: AssumeRole(OrgAndAccountInfoReader)
    Mgmt-->>Tool: Session Credentials
    Tool->>Mgmt: list_accounts()
    Mgmt-->>Tool: Account List with Tags & OU Structure
    Tool->>Mgmt: describe_organizational_units()
    Mgmt-->>Tool: OU Hierarchy

    Note over Tool: Step 2: Run Checks on Each Account
    Tool->>Prod1: AssumeRole(Headroom)
    Prod1-->>Tool: Session Credentials

    Note over Tool,Prod1: Run SCP Checks (via registry)
    Tool->>Prod1: describe_instances() [all regions]
    Prod1-->>Tool: EC2 Instance Details
    Tool->>Tool: Check IMDSv2 Compliance
    Tool->>Tool: Write SCP Results to JSON

    Note over Tool,Prod1: Run RCP Checks (via registry)
    Tool->>Prod1: list_roles(), get_role()
    Prod1-->>Tool: IAM Role Details & Trust Policies
    Tool->>Tool: Check Third-Party AssumeRole
    Tool->>Tool: Write RCP Results to JSON

    Tool->>ProdN: AssumeRole(Headroom)
    ProdN-->>Tool: Session Credentials
    Tool->>ProdN: Run All Registered Checks
    ProdN-->>Tool: Check Results
    Tool->>Tool: Write Results to JSON

    Note over Tool: Step 3: Parse Results & Generate Terraform
    Tool->>Mgmt: AssumeRole(OrgAndAccountInfoReader)
    Mgmt-->>Tool: Session Credentials
    Tool->>Mgmt: Get Organization Hierarchy
    Mgmt-->>Tool: Full OU Structure

    Tool->>Tool: Parse SCP Results
    Tool->>Tool: Determine SCP Placement (root/OU/account)
    Tool->>Tool: Generate SCP Terraform Files

    Tool->>Tool: Parse RCP Results
    Tool->>Tool: Determine RCP Placement (root/OU/account)
    Tool->>Tool: Generate RCP Terraform Files

    Tool->>Tool: Generate Org Info Data Sources
```
