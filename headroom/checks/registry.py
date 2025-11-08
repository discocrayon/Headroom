"""
Check registry for auto-discovery of compliance checks.

This module provides a decorator-based registry pattern that allows checks
to self-register. This eliminates the need for hardcoded check lists and
makes adding new checks require zero changes to other files.
"""

from typing import Dict, List, Optional, Type

from .base import BaseCheck
from ..constants import register_check_type as _register_check_type

_CHECK_REGISTRY: Dict[str, Type[BaseCheck]] = {}


def register_check(check_type: str, check_name: str):
    """
    Decorator to register a check class.

    Args:
        check_type: Type of check (scps, rcps)
        check_name: Name of the check (deny_imds_v1_ec2, third_party_assumerole)

    Usage:
        @register_check("scps", "deny_imds_v1_ec2")
        class DenyImdsV1Ec2Check(BaseCheck):
            ...
    """
    def decorator(cls: Type[BaseCheck]) -> Type[BaseCheck]:
        _CHECK_REGISTRY[check_name] = cls
        cls.CHECK_NAME = check_name
        cls.CHECK_TYPE = check_type
        # Also register with constants module for write_results
        _register_check_type(check_name, check_type)
        return cls
    return decorator


def get_check_class(check_name: str) -> Type[BaseCheck]:
    """
    Get check class by name.

    Args:
        check_name: Name of the check

    Returns:
        Check class

    Raises:
        ValueError: If check name is not registered
    """
    if check_name not in _CHECK_REGISTRY:
        raise ValueError(f"Unknown check: {check_name}")
    return _CHECK_REGISTRY[check_name]


def get_all_check_classes(check_type: Optional[str] = None) -> List[Type[BaseCheck]]:
    """
    Get all registered check classes, optionally filtered by type.

    Args:
        check_type: Filter by check type (scps, rcps), or None for all

    Returns:
        List of check classes
    """
    if check_type:
        return [cls for cls in _CHECK_REGISTRY.values() if cls.CHECK_TYPE == check_type]
    return list(_CHECK_REGISTRY.values())


def get_check_names(check_type: Optional[str] = None) -> List[str]:
    """
    Get all check names, optionally filtered by type.

    Args:
        check_type: Filter by check type (scps, rcps), or None for all

    Returns:
        List of check names
    """
    checks = get_all_check_classes(check_type)
    return [cls.CHECK_NAME for cls in checks]


def get_check_type_map() -> Dict[str, str]:
    """
    Get mapping of check names to check types.

    This replaces the hardcoded CHECK_TYPE_MAP in constants.py.

    Returns:
        Dictionary mapping check names to check types (scps, rcps)
    """
    return {cls.CHECK_NAME: cls.CHECK_TYPE for cls in _CHECK_REGISTRY.values()}

