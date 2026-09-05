"""
Organizations the generator tests share.

Both generators render the same organization shapes and asserted the same
fixtures, written out twice. A fixture lives here once, so a change to what
the organization looks like reaches both generators' tests together.
"""

from headroom.types import AccountOrgPlacement, OrganizationHierarchy, OrganizationalUnit


def make_org_empty() -> OrganizationHierarchy:
    """
    Build an organization holding no OU and no account.

    Returns:
        A hierarchy with a root and nothing under it
    """
    return OrganizationHierarchy(root_id="r-1111", organizational_units={}, accounts={})


def make_nested_org() -> OrganizationHierarchy:
    """
    Build a two-level organization: one OU holding one account.

    Root r-1111
      production (ou-1111-11111111) .... acme-co (111111111111)

    Returns:
        A hierarchy with one OU attached to the root and one account
        attached to that OU
    """
    return OrganizationHierarchy(
        root_id="r-1111",
        organizational_units={
            "ou-1111-11111111": OrganizationalUnit(
                ou_id="ou-1111-11111111",
                name="production",
                parent_ou_id=None,
                child_ous=[],
                accounts=["111111111111"],
            ),
        },
        accounts={
            "111111111111": AccountOrgPlacement(
                account_id="111111111111",
                account_name="acme-co",
                parent_ou_id="ou-1111-11111111",
                ou_path=["production"],
            ),
        },
    )
