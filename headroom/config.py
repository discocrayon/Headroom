import os
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator


# Centralized defaults for directories
DEFAULT_RESULTS_DIR = "test_environment/headroom_results"
DEFAULT_SCPS_DIR = "test_environment/scps"
DEFAULT_RCPS_DIR = "test_environment/rcps"

# Accounts analyzed concurrently. Memory sets this, not the GIL: each worker
# holds its own botocore session carrying its own parsed service models, which
# measures at roughly 43 MB. Sixteen workers stay under a gigabyte.
DEFAULT_ACCOUNT_WORKERS = 16

# Upper bound on max_account_workers. Each worker costs roughly 43 MB of
# sessions and parsed service models on top of a ~130 MB base, so 32 puts
# resident memory just over 1.5 GB; wanting more is a signal to revisit the
# design rather than raise this. SETUP.md tabulates the three settings.
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
    # used to tell in-org principals from third parties; see the snapshot's
    # member_account_ids.
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

    @model_validator(mode="after")
    def _check_output_directories(self) -> "HeadroomConfig":
        """
        Reject the two output-directory settings Terraform generation cannot
        honour, at the point they are set rather than after a full scan.

        A `..` component makes the configured path and the written path two
        different places as soon as any component of the path is a symlink.
        Generation folds `..` away lexically, on purpose -- it reads nothing,
        so the same configuration compiles to the same plan everywhere -- but
        the OS resolves the same spelling by walking each component in turn.
        Rather than teach the compiler to read the filesystem, forbid the one
        spelling on which the two disagree.

        One directory for both policy types is the other. Generation rejects
        it too, and has to: only it can see two different spellings that
        reach one directory. What a plain typo does not deserve is to be
        found out on the far side of a scan of every account.

        Returns:
            This configuration, unchanged

        Raises:
            ValueError: If either directory traverses a parent, or both name
                one directory
        """
        for field_name in ("scps_dir", "rcps_dir"):
            value = getattr(self, field_name)
            if os.pardir in Path(value).parts:
                raise ValueError(
                    f"{field_name} ({value!r}) must not contain {os.pardir!r}. "
                    "Headroom folds it away lexically and the operating system "
                    "does not, so the two disagree about where the file goes "
                    "the moment a component of the path is a symlink. Spell the "
                    "directory out."
                )

        if self.scps_dir == self.rcps_dir:
            raise ValueError(
                f"scps_dir and rcps_dir are the same directory: {self.scps_dir!r}. "
                "Every RCP file would be generated over an SCP file of the same "
                "name. Set them to different directories."
            )

        return self
