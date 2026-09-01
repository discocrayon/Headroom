"""Tests that pytest reads the settings pytest.ini declares."""

import pytest


def test_pytest_reads_the_ini_settings(pytestconfig: pytest.Config) -> None:
    """
    The settings in pytest.ini must reach the running pytest.

    A pytest.ini whose section is [tool:pytest] parses without error and is
    then ignored in full: that spelling is valid only inside setup.cfg. Every
    addopt, testpaths, and marker declaration goes silently inert, so the
    strictness the gate is supposed to enforce is not enforced at all and
    nothing in the suite notices. Assert the applied configuration rather
    than the file's text, because it is the applied configuration that was
    missing.
    """
    assert pytestconfig.getini("testpaths") == ["tests"]
    assert pytestconfig.getoption("strict_markers") is True
    assert pytestconfig.getoption("strict_config") is True
