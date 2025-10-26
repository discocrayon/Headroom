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

    Note over Tool: Step 2: Analyze Each Account
    Tool->>Prod1: AssumeRole(Headroom)
    Prod1-->>Tool: Session Credentials
    Tool->>Prod1: describe_instances() [all regions]
    Prod1-->>Tool: EC2 Instance Details
    Tool->>Prod1: Check IMDSv2 Compliance
    Prod1-->>Tool: Compliance Results

    Tool->>ProdN: AssumeRole(Headroom)
    ProdN-->>Tool: Session Credentials
    Tool->>ProdN: describe_instances() [all regions]
    ProdN-->>Tool: EC2 Instance Details
    Tool->>ProdN: Check IMDSv2 Compliance
    ProdN-->>Tool: Compliance Results

    Note over Tool: Step 3: Generate Outputs
    Tool->>Tool: Write JSON Results
    Tool->>Tool: Generate Terraform SCPs
    Tool->>Tool: Generate Org Data Sources
```
