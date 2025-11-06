from typing import Optional
from pydantic import BaseModel


# Centralized defaults for directories
DEFAULT_RESULTS_DIR = "test_environment/headroom_results"
DEFAULT_SCPS_DIR = "test_environment/scps"
DEFAULT_RCPS_DIR = "test_environment/rcps"


class AccountTagLayout(BaseModel):
    environment: str
    name: str
    owner: str


class HeadroomConfig(BaseModel):
    management_account_id: Optional[str] = None
    security_analysis_account_id: Optional[str] = None
    # Exclude account IDs from result files and filenames
    exclude_account_ids: bool = False
    use_account_name_from_tags: bool
    account_tag_layout: AccountTagLayout
    # Base directory where check result JSONs are written/read
    results_dir: str = DEFAULT_RESULTS_DIR
    # Base directory where Terraform SCP files are generated
    scps_dir: str = DEFAULT_SCPS_DIR
    # Base directory where Terraform RCP files are generated
    rcps_dir: str = DEFAULT_RCPS_DIR
