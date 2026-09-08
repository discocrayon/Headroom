"""
Pin the two ways the explicit-Any gate can be switched off quietly.

`mypy.ini` turns on `disallow_any_explicit`, so `tox` fails on an explicit
`Any` in `headroom/` or `tests/`. A `type: ignore[explicit-any]` silences it
one line at a time, and editing the flag silences it everywhere. CONVENTIONS.md
forbids both; this file makes either fail by name.
"""

import configparser
from pathlib import Path
from typing import List

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
_MARKER = "type: ignore[explicit-any]"

# mypy synthesizes `__dataclass_fields__: dict[str, Any]` on every pydantic
# model, because BaseModel's metaclass is a dataclass_transform, and reports
# that Any at the class line as though the file wrote it. headroom/config.py
# carries the reason beside each line.
_SANCTIONED_IGNORES = [
    "headroom/config.py: class AccountTagLayout(BaseModel):  # type: ignore[explicit-any]",
    "headroom/config.py: class HeadroomConfig(BaseModel):  # type: ignore[explicit-any]",
]


def _explicit_any_ignores() -> List[str]:
    """
    Every line under headroom/ and tests/ that silences explicit-any.

    This file names the marker in its own strings and is skipped; nothing
    else may spell it except a comment mypy reads.
    """
    found = []
    for tree in ("headroom", "tests"):
        for path in sorted((REPOSITORY_ROOT / tree).rglob("*.py")):
            if path == Path(__file__).resolve():
                continue
            for line in path.read_text().splitlines():
                if _MARKER in line:
                    found.append(f"{path.relative_to(REPOSITORY_ROOT)}: {line.strip()}")
    return found


def test_disallow_any_explicit_stays_on() -> None:
    """Turning the flag off would readmit every Any the sweep removed."""
    config = configparser.ConfigParser()
    config.read(REPOSITORY_ROOT / "mypy.ini")

    assert config.getboolean("mypy", "disallow_any_explicit"), (
        "mypy.ini no longer sets disallow_any_explicit = True. CONVENTIONS.md "
        "forbids Any and this flag is what enforces it; "
        "spec/verification/strategy.md owns the gate."
    )


def test_only_the_two_pydantic_models_silence_explicit_any() -> None:
    """A new ignore needs a reason in review, not a quiet comment."""
    assert _explicit_any_ignores() == _SANCTIONED_IGNORES
