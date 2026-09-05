"""
Build the coverage maps the two builders build.

`scp_check_coverage` and `rcp_check_coverage` both name every registered
check of their policy type, present with empty sets for one that produced no
result, so absence from the map means a caller assembled it wrong rather
than a check that scanned nothing. `disabled_reasons` indexes the map on
that promise. A test handing it a bare dict of the checks it cares about is
handing it a map production never produces, which is why this exists rather
than a literal at each call site.
"""

from typing import Dict

from headroom.checks.registry import get_check_names
from headroom.types import CheckCoverage

NOTHING_JUDGED = CheckCoverage(analyzed_accounts=frozenset(), unsafe_accounts=frozenset())


def coverage_for(check_type: str, **judged: CheckCoverage) -> Dict[str, CheckCoverage]:
    """
    Name every registered check of one policy type, overriding the named ones.

    Args:
        check_type: "scps" or "rcps"
        judged: Coverage for the checks a test cares about, by check name

    Returns:
        Every registered check of that type, carrying the coverage the caller
        gave it or empty sets where the caller named none
    """
    coverage = {check_name: NOTHING_JUDGED for check_name in get_check_names(check_type)}
    coverage.update(judged)
    return coverage
