## 2025-10-26, 12:10 PM - Fixed terminology: "root account" to "management account"

### Changes Made

Updated documentation to consistently use "management account ID" instead of "root account ID".

#### Files Updated

1. **README.md** (line 186)
   - Changed: "AWS Organizations root account ID"
   - To: "AWS Organizations management account ID"

2. **Headroom-Specification.md** (line 39)
   - Changed: "AWS Organizations root account"
   - To: "AWS Organizations management account"

#### Rationale

AWS Organizations uses "management account" as the official terminology for the account that manages the organization. Using "root account" can be confusing as it might be confused with the root user of an account. Consistent terminology improves clarity.

**Note**: The test file `test_parse_results.py` uses "root accounts" in a different context (referring to accounts at the root of the organizational unit hierarchy), so those references were left unchanged.

