# LLM Optimization Recommendations for HOW_TO_ADD_A_CHECK.md

## Executive Summary

This document provides concrete recommendations for optimizing HOW_TO_ADD_A_CHECK.md for AI coding assistants like Cursor and Claude. The goal is to make the guide more "parseable" and actionable for LLMs while maintaining human readability.

---

## 1. Add Structured Metadata Header

**Current:** Guide starts with title and basic version info
**Recommendation:** Add machine-readable metadata block

```yaml
---
document_type: implementation_guide
target_audience: [human_developer, ai_assistant]
llm_instructions: |
  This guide walks through adding a new compliance check to Headroom.
  Use this guide to generate complete, production-ready implementations.
  Always follow the checklist and code quality standards.
context_dependencies:
  - headroom/checks/base.py (BaseCheck pattern)
  - headroom/checks/registry.py (check registration)
  - documentation/POLICY_TAXONOMY.md (policy patterns)
estimated_tokens: 15000
last_updated: 2025-11-09
version: 1.0
---
```

**Why:** LLMs can quickly understand document purpose and dependencies

---

## 2. Add "Quick Reference Card" Section

**Current:** Information spread throughout document
**Recommendation:** Add concise reference card at top (after TOC)

```markdown
## 🤖 LLM Quick Reference

### File Creation Pattern
- Check: `headroom/checks/{scps|rcps}/{check_name}.py`
- AWS Logic: `headroom/aws/{service}.py`
- Tests: `tests/test_checks_{check_name}.py`, `tests/test_aws_{service}.py`
- Terraform: `test_environment/test_{check_name}.tf`

### Must-Implement Methods
1. `analyze(session) -> List[T]` - Fetch AWS data
2. `categorize_result(result: T) -> tuple[str, JsonDict]` - Categorize as violation/compliant/exemption
3. `build_summary_fields(result) -> JsonDict` - Calculate summary stats

### Critical Standards
- ✅ Type hints on ALL functions (no `Any` except `**kwargs`)
- ✅ All imports at top (never inside functions)
- ✅ Specific exceptions (never `except Exception`)
- ✅ 100% test coverage
- ✅ Use `JsonDict` not `Dict[str, Any]`

### Validation Commands
```bash
mypy headroom/ tests/          # Type checking
pytest tests/ --cov=headroom   # Tests + coverage
tox                            # All quality checks
```
```

**Why:** LLMs can quickly extract key patterns without reading entire document

---

## 3. Explicit File Templates Section

**Current:** Code snippets embedded in narrative
**Recommendation:** Dedicate section with complete file templates

```markdown
## File Templates

### Template: Check Class (SCP Pattern 2)

**File:** `headroom/checks/scps/{check_name}.py`

```python
"""Check for {DESCRIPTION}."""

from typing import List

import boto3

from ...aws.{service} import {DataModel}, get_{check_name}_analysis
from ...constants import {CHECK_CONSTANT}
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("scps", {CHECK_CONSTANT})
class {CheckClassName}(BaseCheck[{DataModel}]):
    """
    Check for {DESCRIPTION}.

    This check identifies:
    - {VIOLATION_DESCRIPTION}
    - {COMPLIANT_DESCRIPTION}
    """

    def analyze(self, session: boto3.Session) -> List[{DataModel}]:
        """Analyze {RESOURCE_TYPE} for {CHECK_PURPOSE}."""
        return get_{check_name}_analysis(session)

    def categorize_result(
        self,
        result: {DataModel}
    ) -> tuple[str, JsonDict]:
        """Categorize a single result."""
        result_dict = {
            # Map dataclass fields to dict
        }

        if {VIOLATION_CONDITION}:
            return ("violation", result_dict)
        return ("compliant", result_dict)

    def build_summary_fields(
        self,
        check_result: CategorizedCheckResult
    ) -> JsonDict:
        """Build check-specific summary fields."""
        total = len(check_result.violations) + len(check_result.compliant)
        compliant_count = len(check_result.compliant)
        compliance_pct = (compliant_count / total * 100) if total else 100

        return {
            "total_{resources}": total,
            "violations": len(check_result.violations),
            "compliant": compliant_count,
            "compliance_percentage": compliance_pct,
        }
```

**Substitution Keys:**
- `{check_name}` - Snake case check name (e.g., `deny_rds_unencrypted`)
- `{CheckClassName}` - PascalCase class name (e.g., `DenyRdsUnencryptedCheck`)
- `{service}` - AWS service name (e.g., `rds`)
- `{DataModel}` - Dataclass name (e.g., `DenyRdsUnencrypted`)
- `{CHECK_CONSTANT}` - Constant name (e.g., `DENY_RDS_UNENCRYPTED`)
- `{DESCRIPTION}` - Human-readable description
- `{VIOLATION_CONDITION}` - Boolean condition for violations
- `{resources}` - Plural resource name (e.g., `databases`)
```

**Why:** LLMs can copy template and perform simple substitutions

---

## 4. Decision Tree in Structured Format

**Current:** Text-based decision tree
**Recommendation:** Add JSON/YAML representation

```markdown
### Step 0.1: Determine Check Type (Machine Readable)

```json
{
  "decision_tree": {
    "question": "What are you analyzing?",
    "options": [
      {
        "answer": "AWS Resources (EC2, RDS, S3, etc.)",
        "result": {
          "check_type": "SCP",
          "focus": "What resources exist that violate policy?",
          "examples": ["Unencrypted RDS databases", "EC2 with IMDSv1", "Public S3 buckets"],
          "output_type": "Allowlists for Pattern 5, exemption tracking for Pattern 4",
          "implementation_path": "headroom/checks/scps/"
        }
      },
      {
        "answer": "IAM Trust Policies / Access Control",
        "result": {
          "check_type": "RCP",
          "focus": "Who can access what?",
          "examples": ["Third-party role assumptions", "Cross-account S3 access"],
          "output_type": "Allowlists of approved external accounts",
          "implementation_path": "headroom/checks/rcps/"
        }
      }
    ]
  }
}
```
```

**Why:** LLMs can parse structured data more reliably than prose

---

## 5. Add Explicit "LLM Implementation Instructions"

**Recommendation:** Add sections specifically for LLM execution

```markdown
## 🤖 LLM Implementation Instructions

### Execution Mode: Step-by-Step Implementation

When implementing a new check, follow this execution order:

**Phase 1: Gather Requirements (LLM should ask user)**
```yaml
required_inputs:
  - check_name: "Snake case name (e.g., deny_rds_unencrypted)"
  - check_type: "SCP or RCP"
  - aws_service: "Service to analyze (e.g., rds, ec2, s3)"
  - pattern: "Policy pattern number (1-6)"
  - description: "What policy violation are we detecting?"
  - api_calls: "List of AWS API calls needed"
```

**Phase 2: File Creation Sequence (execute in order)**
1. Create constant in `headroom/constants.py`
2. Create AWS analysis in `headroom/aws/{service}.py`
3. Create check class in `headroom/checks/{scps|rcps}/{check_name}.py`
4. Create tests in `tests/test_aws_{service}.py` and `tests/test_checks_{check_name}.py`
5. Update Terraform module in `test_environment/modules/{scps|rcps}/variables.tf`
6. Update Terraform module in `test_environment/modules/{scps|rcps}/locals.tf`
7. Update Terraform generator in `headroom/terraform/generate_{scps|rcps}.py`

**Phase 3: Validation (run after each file)**
```bash
# After creating Python files
mypy headroom/aws/{service}.py
mypy headroom/checks/{scps|rcps}/{check_name}.py

# After creating tests
pytest tests/test_aws_{service}.py -v
pytest tests/test_checks_{check_name}.py -v

# After all changes
tox
```

**Phase 4: Quality Pass (before completion)**
- Run full checklist in "Complete Checklist" section
- Check for DRY violations (search for duplicate patterns)
- Verify indentation minimization (look for nested if/for blocks)
- Confirm 100% test coverage
```

**Why:** Provides clear execution flow for LLMs to follow

---

## 6. Annotate Code Examples with Tags

**Current:** Code examples without context markers
**Recommendation:** Add semantic tags to examples

```markdown
<!-- LLM: COPY_TEMPLATE - This is a complete working example -->
```python
# FILE: headroom/aws/rds.py
# PURPOSE: Data model and analysis for RDS encryption check
# DEPENDENCIES: boto3, logging, dataclasses
# PATTERN: Multi-region AWS resource analysis

from dataclasses import dataclass
from typing import List
import boto3
import logging

logger = logging.getLogger(__name__)


@dataclass
class DenyRdsUnencrypted:
    """Data model for RDS encryption analysis."""
    # ... (complete implementation)
```
<!-- END_TEMPLATE -->
```

**Why:** LLMs can identify which code blocks to copy vs. adapt

---

## 7. Add "Common Patterns" Reference

**Recommendation:** Extract reusable patterns into dedicated section

```markdown
## Common Implementation Patterns

### Pattern: Multi-Region Resource Analysis

**Use When:** Analyzing AWS resources that exist in specific regions (EC2, RDS, S3, etc.)

```python
# PATTERN: Multi-region analysis with pagination
from .helpers import get_all_regions

def analyze_{resource}_in_all_regions(session: boto3.Session) -> List[Result]:
    """Analyze {resource} across all regions."""
    all_results = []
    regions = get_all_regions(session)
    
    for region in regions:
        logger.info(f"Analyzing {resource} in {region}")
        regional_results = _analyze_{resource}_in_region(session, region)
        all_results.extend(regional_results)
    
    return all_results

def _analyze_{resource}_in_region(
    session: boto3.Session,
    region: str
) -> List[Result]:
    """Analyze {resource} in specific region."""
    client = session.client("{service}", region_name=region)
    results = []
    
    try:
        paginator = client.get_paginator("{operation}")
    except ClientError as e:
        logger.warning(f"Failed to get paginator in {region}: {e}")
        return []
    
    for page in paginator.paginate():
        items = page.get("{ItemsKey}", [])
        for item in items:
            result = _analyze_single_item(item, region)
            results.append(result)
    
    return results
```

**Substitutions:**
- `{resource}` → Resource name (plural, e.g., "databases", "instances")
- `{service}` → AWS service name (e.g., "rds", "ec2")
- `{operation}` → Paginator operation (e.g., "describe_db_instances")
- `{ItemsKey}` → Response key for items (e.g., "DBInstances")

### Pattern: Categorization with Exemptions (Pattern 4)

**Use When:** Check supports exemption tags

```python
def categorize_result(self, result: DataModel) -> tuple[str, JsonDict]:
    """Categorize with exemption support."""
    result_dict = {
        # ... map fields ...
    }
    
    # Check exemption first
    if result.exemption_tag_present:
        return ("exemption", result_dict)
    
    # Then check violation
    if {violation_condition}:
        return ("violation", result_dict)
    
    # Default to compliant
    return ("compliant", result_dict)
```
```

**Why:** LLMs can identify and apply the correct pattern for the situation

---

## 8. Add File Dependency Graph

**Recommendation:** Show dependencies visually and in machine-readable format

```markdown
## File Dependency Graph

```mermaid
graph TD
    A[constants.py] --> B[aws/{service}.py]
    B --> C[checks/{type}/{check}.py]
    A --> C
    C --> D[tests/test_checks_{check}.py]
    B --> E[tests/test_aws_{service}.py]
    
    F[modules/{type}/variables.tf] --> G[modules/{type}/locals.tf]
    G --> H[terraform/generate_{type}.py]
    C --> H
```

**JSON Representation:**
```json
{
  "file_dependencies": {
    "headroom/checks/scps/deny_rds_unencrypted.py": {
      "depends_on": [
        "headroom/constants.py",
        "headroom/aws/rds.py",
        "headroom/checks/base.py",
        "headroom/checks/registry.py",
        "headroom/types.py"
      ],
      "creates": [
        "test_environment/headroom_results/scps/deny_rds_unencrypted/*.json"
      ],
      "tested_by": [
        "tests/test_checks_deny_rds_unencrypted.py"
      ]
    }
  }
}
```
```

**Why:** LLMs can understand which files to read before implementing

---

## 9. Add Validation Checklist in Machine-Readable Format

**Current:** Narrative checklist
**Recommendation:** Add structured validation rules

```markdown
## Validation Rules (Machine Readable)

```yaml
validation_rules:
  type_checking:
    command: "mypy headroom/ tests/"
    must_pass: true
    error_tolerance: 0
    
  unit_tests:
    command: "pytest tests/test_checks_{check_name}.py tests/test_aws_{service}.py -v"
    must_pass: true
    min_coverage: 100
    
  code_quality:
    command: "tox"
    must_pass: true
    checks:
      - flake8
      - mypy
      - pytest
      
  code_standards:
    - rule: "No `Any` type except in `**kwargs`"
      validation: "grep -r 'Any' headroom/checks/{type}/{check}.py | grep -v kwargs"
      expected_matches: 0
      
    - rule: "All imports at top of file"
      validation: "Check no import statements inside functions"
      
    - rule: "Specific exception handling"
      validation: "grep -E 'except (Exception:|:)' headroom/"
      expected_matches: 0
      
  file_creation:
    required_files:
      - "headroom/checks/{type}/{check_name}.py"
      - "headroom/aws/{service}.py"
      - "tests/test_checks_{check_name}.py"
      - "tests/test_aws_{service}.py"
    
  file_modifications:
    required_changes:
      - file: "headroom/constants.py"
        pattern: "^{CHECK_CONSTANT} = "
        
      - file: "test_environment/modules/{type}/variables.tf"
        pattern: 'variable "{check_name}"'
        
      - file: "headroom/terraform/generate_{type}.py"
        pattern: '{check_name} ='
```
```

**Why:** LLMs can programmatically validate implementation

---

## 10. Separate "Tutorial Mode" from "Reference Mode"

**Recommendation:** Structure document with two entry points

```markdown
# How to Add a New Check to Headroom

**Choose your mode:**

1. **📖 Tutorial Mode (First-time implementers, LLMs with full context)**
   - Start at [Phase 0: Planning & Design](#phase-0-planning--design)
   - Follow all phases sequentially
   - Read explanations and examples
   
2. **⚡ Reference Mode (Experienced implementers, LLMs with check requirements)**
   - Jump to [LLM Quick Reference](#-llm-quick-reference)
   - Use [File Templates](#file-templates)
   - Follow [Validation Rules](#validation-rules-machine-readable)

---

## ⚡ Reference Mode

### Prerequisites (Already have)
- [ ] Check name (e.g., `deny_rds_unencrypted`)
- [ ] Check type (SCP or RCP)
- [ ] AWS service (e.g., `rds`)
- [ ] Policy pattern (1-6)
- [ ] AWS API calls needed
- [ ] Exemption mechanism (if any)

### Implementation Steps (Quick)
1. Copy template from [File Templates](#file-templates)
2. Perform substitutions
3. Run validation commands
4. Check quality standards
5. Done

---

## 📖 Tutorial Mode

(Existing detailed content starts here...)
```

**Why:** LLMs can skip to relevant section based on context needs

---

## 11. Add "Anti-Patterns" Section with Linter Rules

**Recommendation:** Document what NOT to do in structured format

```markdown
## Anti-Patterns (What NOT to Do)

### AP-001: Using `Any` Type

**Bad:**
```python
def categorize_result(self, result: T) -> tuple[str, Dict[str, Any]]:
```

**Good:**
```python
from ...types import JsonDict
def categorize_result(self, result: T) -> tuple[str, JsonDict]:
```

**Detection:**
```bash
grep -n 'Dict\[str, Any\]' headroom/checks/ | grep -v kwargs
```

**Exception:** Only acceptable in `**kwargs: Any` when matching base class

---

### AP-002: Imports Inside Functions

**Bad:**
```python
def analyze_databases(session):
    from .helpers import get_regions  # WRONG
    regions = get_regions(session)
```

**Good:**
```python
from .helpers import get_regions

def analyze_databases(session):
    regions = get_regions(session)
```

**Detection:**
```bash
grep -A 5 '^def ' headroom/ | grep 'from\|import'
```

(Continue for all anti-patterns...)
```

**Why:** LLMs can check their generated code against anti-patterns

---

## 12. Add "Context Blocks" for LLM State Management

**Recommendation:** Add explicit context needed for each phase

```markdown
## Phase 1: Python Implementation

**LLM Context Required:**
```yaml
files_to_read_first:
  - headroom/checks/base.py  # Understand BaseCheck interface
  - headroom/checks/scps/deny_ec2_imds_v1.py  # Reference implementation
  - headroom/types.py  # Type aliases available
  - headroom/constants.py  # Existing constants

requirements_from_user:
  - check_name: "Must be snake_case"
  - aws_service: "Which AWS service"
  - resource_type: "What resources to analyze"
  - violation_criteria: "How to identify violations"

outputs_this_phase:
  - Constant in constants.py
  - Data model class
  - Analysis function
  - Check class with 3 required methods
```

### Step 1.1: Add Check Name Constant

**Current Context:**
- File: `headroom/constants.py`
- Action: Add new constant
- Naming: `{ACTION}_{SERVICE}_{DESCRIPTOR}`

**Implementation:**
(existing content...)
```

**Why:** Helps LLMs manage context window and know what to load

---

## Implementation Priority

**High Priority (Implement First):**
1. Add LLM Quick Reference section
2. Add File Templates section  
3. Add Validation Rules in YAML
4. Add LLM Implementation Instructions

**Medium Priority:**
5. Add structured decision trees
6. Add Common Patterns reference
7. Annotate code examples with tags

**Lower Priority:**
8. Add file dependency graph
9. Separate Tutorial/Reference modes
10. Add anti-patterns with detection
11. Add context blocks
12. Add metadata header

---

## Testing Recommendations

After implementing changes, test with LLMs:

1. **Prompt Test 1:** "Implement a new check for S3 bucket public access"
   - LLM should ask for requirements
   - Follow template-based approach
   - Generate complete, working code

2. **Prompt Test 2:** "Add deny_lambda_unencrypted check"
   - LLM should reference templates
   - Apply correct patterns
   - Run validation commands

3. **Prompt Test 3:** "What files do I need to modify to add an RCP check?"
   - LLM should extract from Quick Reference
   - List files in dependency order

---

## Example: Optimized Section

Here's how Section 1.3 would look with optimizations:

```markdown
### Step 1.3: Create Check Class

<!-- LLM_CONTEXT
requires: [Step 1.1 complete, Step 1.2 complete]
outputs: headroom/checks/{type}/{check_name}.py
validation: mypy + pytest
-->

**File:** `headroom/checks/scps/{check_name}.py`

**Template Variables:**
```yaml
check_name: "deny_rds_unencrypted"  # Snake case
CheckClass: "DenyRdsUnencryptedCheck"  # PascalCase
DataModel: "DenyRdsUnencrypted"  # From Step 1.2
service: "rds"  # AWS service name
CHECK_CONSTANT: "DENY_RDS_UNENCRYPTED"  # From Step 1.1
```

**Implementation:**

<!-- LLM: COPY_TEMPLATE -->
```python
# TEMPLATE: SCP Check Class (Pattern 2 - Conditional Deny)
# FILE: headroom/checks/scps/{check_name}.py

"""Check for {DESCRIPTION}."""

from typing import List
import boto3

from ...aws.{service} import {DataModel}, get_{check_name}_analysis
from ...constants import {CHECK_CONSTANT}
from ...types import JsonDict
from ..base import BaseCheck, CategorizedCheckResult
from ..registry import register_check


@register_check("scps", {CHECK_CONSTANT})
class {CheckClass}(BaseCheck[{DataModel}]):
    """Check for {DESCRIPTION}."""

    def analyze(self, session: boto3.Session) -> List[{DataModel}]:
        """Analyze {RESOURCE_TYPE} for {PURPOSE}."""
        return get_{check_name}_analysis(session)

    def categorize_result(
        self,
        result: {DataModel}
    ) -> tuple[str, JsonDict]:
        """Categorize single result."""
        result_dict = {
            # Map all dataclass fields from {DataModel}
        }

        if {VIOLATION_CONDITION}:
            return ("violation", result_dict)
        return ("compliant", result_dict)

    def build_summary_fields(
        self,
        check_result: CategorizedCheckResult
    ) -> JsonDict:
        """Build summary statistics."""
        total = len(check_result.violations) + len(check_result.compliant)
        compliant_count = len(check_result.compliant)
        compliance_pct = (compliant_count / total * 100) if total else 100

        return {
            "total_{resources}": total,
            "violations": len(check_result.violations),
            "compliant": compliant_count,
            "compliance_percentage": compliance_pct,
        }
```
<!-- END_TEMPLATE -->

**Validation:**
```bash
# Type check
mypy headroom/checks/scps/{check_name}.py

# Verify registration
python -c "from headroom.checks.registry import get_check_names; \
           assert '{check_name}' in get_check_names()"
```

**Next Step:** [Step 1.4: Verify Check Registration](#step-14-verify-check-registration)
```

---

## Summary

These optimizations make the guide:
1. **More structured** - Machine-readable formats (YAML/JSON)
2. **More actionable** - Complete templates with clear substitutions
3. **More verifiable** - Explicit validation commands
4. **More navigable** - Quick reference + tutorial modes
5. **More contextual** - Clear dependencies and prerequisites
6. **More pattern-based** - Reusable implementation patterns

**Estimated Implementation Time:** 8-12 hours

**Expected Benefit:** 
- 50% faster LLM implementation time
- Higher quality initial code generation
- Fewer back-and-forth clarifications
- More consistent implementations

