from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


# Centralized defaults for directories
DEFAULT_RESULTS_DIR = "test_environment/headroom_results"
DEFAULT_SCPS_DIR = "test_environment/scps"
DEFAULT_RCPS_DIR = "test_environment/rcps"

# Accounts analyzed concurrently. Memory sets this, not the GIL: each worker
# holds its own botocore session carrying its own parsed service models, which
# measures at roughly 43 MB. Sixteen workers stay under a gigabyte.
DEFAULT_ACCOUNT_WORKERS = 16

# Upper bound on max_account_workers. At 32 workers resident memory passes
# 1.5 GB; wanting more is a signal to revisit the design rather than raise this.
# sessions.py also sizes the STS client's connection pool to this value, as a
# ceiling that currently binds nothing -- see the comment there.
MAX_ACCOUNT_WORKERS = 32


class AccountTagLayout(BaseModel):
    # These are the only tags Headroom reads. A fourth key here is an intent
    # it cannot honour, so it aborts rather than dropping it silently.
    model_config = ConfigDict(extra="forbid")

    environment: str
    name: str
    owner: str


class HeadroomConfig(BaseModel):
    # An unknown key aborts rather than being ignored. pydantic's default is
    # to drop it, which turned a misspelled `max_account_workers` into a
    # silent fall back to the default -- the run still works, just not the
    # way the operator asked. Nothing here is optional enough to be worth
    # guessing at, so a key Headroom does not recognize is an error.
    model_config = ConfigDict(extra="forbid")

    management_account_id: Optional[str] = None
    security_analysis_account_id: Optional[str] = None
    # Exclude account IDs from result files and filenames
    exclude_account_ids: bool = False
    # Account IDs to leave out of analysis entirely.
    #
    # A skipped account is never scanned, so it writes no result files and is
    # invisible to policy placement, which only sees accounts that have results.
    # Org-wide policies are therefore generated as if the account did not exist
    # and may deny actions it relies on.
    #
    # Skipping does not remove the account from the organization membership set
    # used to tell in-org principals from third parties; see
    # get_all_organization_account_ids.
    skip_account_ids: List[str] = []
    use_account_name_from_tags: bool
    account_tag_layout: AccountTagLayout
    # Base directory where check result JSONs are written/read
    results_dir: str = DEFAULT_RESULTS_DIR
    # Base directory where Terraform SCP files are generated
    scps_dir: str = DEFAULT_SCPS_DIR
    # Base directory where Terraform RCP files are generated
    rcps_dir: str = DEFAULT_RCPS_DIR
    # Accounts analyzed concurrently. 1 runs them serially, on the same code
    # path, which is the escape hatch for debugging. See SETUP.md for the
    # memory cost per worker.
    max_account_workers: int = Field(
        default=DEFAULT_ACCOUNT_WORKERS,
        ge=1,
        le=MAX_ACCOUNT_WORKERS,
    )
