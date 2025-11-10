"""
Compliance checks for Headroom security analysis.

Automatically discovers and imports all check modules to ensure they register
themselves via the @register_check decorator.
"""

import importlib
import pkgutil
from pathlib import Path


def _discover_and_register_checks() -> None:
    """
    Automatically discover and import all check modules.

    Walks through scps/ and rcps/ directories and imports all Python files.
    This triggers the @register_check decorator, which registers checks in
    the registry.

    This eliminates the need for manual imports when adding new checks.
    """
    checks_dir = Path(__file__).parent

    for check_type in ["scps", "rcps"]:
        check_type_dir = checks_dir / check_type

        for module_info in pkgutil.iter_modules([str(check_type_dir)]):
            module_name = f"headroom.checks.{check_type}.{module_info.name}"
            importlib.import_module(module_name)


_discover_and_register_checks()

# Check classes are accessed via registry, not direct imports
__all__ = []
