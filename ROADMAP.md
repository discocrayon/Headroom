## Future Features / Roadmap

Tooling functionality:
- Instead of Headroom determining it, provide an OU, org-id or account ID and have it auto-generate the SCP and RCP Terraform
- Metrics-based decision making around which SCPs should be deployed next
- Metrics based on violations present in AWS accounts
- SCP/RCP scoring metrics: calculated by `SCPs/RCPs in use`/`Service in use` at account and OU and org levels
- Auto-add a given SCP/RCP at the most widely applicable level possible (e.g. root if all accounts can have it enabled) once analysis is performed
- Add **past state checking** via [Sigma Rules](https://github.com/SigmaHQ/sigma) inside the repository, and add support for checking past CloudTrail logs in ElasticSearch, Splunk, SumoLogic, [etc.](https://sigmahq.io/docs/digging-deeper/backends.html#available)
- Add **observability queries** via [Sigma Rules](https://github.com/SigmaHQ/sigma) inside the repository, and add support for generating Terraform for alerting off of  SCP-caused denials of CloudTrail logs in ElasticSearch, Splunk, SumoLogic, [etc.](https://sigmahq.io/docs/digging-deeper/backends.html#available)

Auto-Verification of SCPs/RCPs:
- SCP/RCP testing via MCP and possible integration with GitHub Actions

SCP Limitation Improvement:
- (Questionable utility until this project has more SCPs) Add functionality to replace `FullAWSAccess` SCP with service allowlist, allowing an extra custom SCP per account (4 vs. 5).

Intra-account improvements:
- Integrate with AWS SSO, and, given names of resources, comes up with an AWS SSO role that can only access those resources, and creates SCPs

Auto Egress Filtering:
- Automatically add Chaser Systems and/or Route 53 DNS Firewall in audit mode, then analyze those results to place all used domains on allowlist, and enable enforcement mode

Auto Terraform IAM least privilege policy editor:
- Based on CloudTrail data, restrict IAM policies, auto-generated code changes to do so
- Based on TGW flow logs, auto-edit NACL Terraform, to prevent 'peered' (via TGW) VPCs from talking to each other
- Based on VPC flow logs, auto-edit Security Group Terraform, to the stricter CIDR range

Auto Terraform module generation:
- Based on SCPs, create a module per service, to serve as a 'resource wrapper' that will be compatible with

Auto Terraform linting:
- Analyze IaC repositories for overlap with SCP/RCP violations, create GitHub PRs to fix them, possibly wrapping [checkov](https://github.com/bridgecrewio/checkov) or [SemGrep](https://github.com/semgrep/semgrep) and leveraging [SARIF files](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)

Apply to Kubernetes security:
- Create metrics based on [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) (Baseline)
- Auto-edit Kubernetes Yaml to apply secure-defaults
- Auto-generate Kubernetes Yaml of [Validating Admission Policies](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/#getting-started-with-validating-admission-policy), to generate, e.g. an allowlist of validating admission and mutating admission webhooks.
