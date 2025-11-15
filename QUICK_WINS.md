# Quick Wins - Implement These First

These refactorings provide the **highest value with the lowest risk**. Each can be completed in under 2 hours.

---

## 1. Create Enums Module (30 minutes)

**Impact:** Prevents bugs, improves IDE support, makes code self-documenting

**Steps:**
1. Create `headroom/enums.py` with CheckType, PlacementLevel, CheckCategory
2. Find/replace string literals throughout codebase
3. Add imports
4. Run tests

**Find these strings and replace:**
- `"scps"` → `CheckType.SCPS`
- `"rcps"` → `CheckType.RCPS`
- `"root"` → `PlacementLevel.ROOT`
- `"ou"` → `PlacementLevel.OU`
- `"account"` → `PlacementLevel.ACCOUNT`
- `"violation"` → `CheckCategory.VIOLATION`
- `"exemption"` → `CheckCategory.EXEMPTION`
- `"compliant"` → `CheckCategory.COMPLIANT`

---

## 2. Extract Account Identifier Utility (20 minutes)

**Impact:** DRY principle, centralized formatting logic

**Steps:**
1. Create `headroom/utils.py`
2. Add `format_account_identifier()` function
3. Find/replace all instances of `f"{.*}_{.*account_id}"`
4. Run tests

**Search pattern:**
```python
# Find:
f"{account_.*name}_{account.*id}"
f"{self.account_name}_{self.account_id}"

# Replace with:
format_account_identifier(account_name, account_id)
format_account_identifier(self.account_name, self.account_id)
```

---

## 4. Improve Error Messages (30 minutes)

**Impact:** Better debugging, clearer error context

**Steps:**
1. In `main.py`, split generic exception handler:
   ```python
   except ValueError as e:
       OutputHandler.error("Configuration Error", e)
       logger.error(f"Invalid configuration: {e}", exc_info=True)
       exit(1)
   except RuntimeError as e:
       OutputHandler.error("Runtime Error", e)
       logger.error(f"Runtime error: {e}", exc_info=True)
       exit(1)
   except ClientError as e:
       error_code = e.response['Error']['Code']
       OutputHandler.error(f"AWS API Error ({error_code})", e)
       exit(1)
   ```

2. In `analysis.py`, improve `_fetch_account_tags()` error handling
3. Run tests

---

## 5. Extract Small Helper Functions (1 hour)

**Impact:** Improved readability, reduced complexity

**Functions to extract first (easiest):**

### In `parse_results.py`:
```python
def _group_results_by_check_name(
    results_data: List[SCPCheckResult]
) -> Dict[str, List[SCPCheckResult]]:
    """Group check results by check name."""
    check_groups: Dict[str, List[SCPCheckResult]] = {}
    for result in results_data:
        if result.check_name not in check_groups:
            check_groups[result.check_name] = []
        check_groups[result.check_name].append(result)
    return check_groups

def _get_safe_results(
    check_results: List[SCPCheckResult]
) -> List[SCPCheckResult]:
    """Filter results to only those with zero violations."""
    return [r for r in check_results if r.violations == ZERO_VIOLATIONS]
```

### In `analysis.py`:
```python
def _get_account_identifier(account_info: AccountInfo) -> str:
    """Get display identifier for an account."""
    return format_account_identifier(account_info.name, account_info.account_id)

def _all_checks_complete(
    account_info: AccountInfo,
    config: HeadroomConfig
) -> bool:
    """Check if all checks are complete for an account."""
    return (
        all_check_results_exist("scps", account_info, config) and
        all_check_results_exist("rcps", account_info, config)
    )
```

---

## Testing After Each Change

After each quick win, run:

```bash
# 1. Run all tests
tox

# 2. Check types
mypy headroom/

# 3. Quick integration test
python -m headroom --config my_config.yaml

# 4. Verify no new linting errors
# (automatic in tox)
```

---

## Expected Timeline

- **Monday AM:** Quick wins 1-3 (Enums, Utils, Constants)
- **Monday PM:** Quick wins 4-5 (Error handling, Extract helpers)
- **Tuesday:** Review and test
- **Wednesday:** Merge to main

---

## Rollback Plan

Before starting:
```bash
git checkout -b refactor/quick-wins
```

If issues arise:
```bash
git checkout main
```

Commit after each quick win so you can cherry-pick if needed.

---

## Success Criteria

✅ All existing tests pass
✅ No new mypy errors
✅ No new linting errors
✅ Code is more readable
✅ No functionality changes

---

## Next Steps After Quick Wins

Once quick wins are complete and merged:
1. Phase 2: ResultFilePathResolver (medium complexity)
2. Phase 3: Break up large functions (requires more testing)
3. Phase 4: Terraform testability improvements

See `REFACTORING_PLAN.md` for full roadmap.
