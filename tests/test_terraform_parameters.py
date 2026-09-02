"""
Tests for the shared check-parameter renderer.

Every test drives `render_check_parameters` with synthetic definitions, so
nothing here depends on which checks happen to be registered.
"""

import logging
from typing import Dict, List, Optional

import pytest

from headroom.checks.registry import Allowlist, CheckDefinition
from headroom.checks.scps.deny_ec2_public_ip import DenyEc2PublicIpCheck
from headroom.enums import TerraformSection
from headroom.terraform.models import TerraformComment, TerraformParameter
from headroom.terraform.parameters import render_check_parameters
from headroom.types import AccountOrgPlacement, OrganizationHierarchy


def make_definition(
    check_name: str,
    terraform_section: TerraformSection,
    allowlist: Optional[Allowlist] = None,
) -> CheckDefinition:
    """
    Build a definition for a check that does not exist.

    The renderer never reads `check_class`, so every synthetic definition
    reuses one real class.

    Args:
        check_name: Name the definition renders its boolean under
        terraform_section: Section the definition renders in
        allowlist: The allowlist its statement is scoped by, if any

    Returns:
        A definition the renderer can consume
    """
    return CheckDefinition(
        check_class=DenyEc2PublicIpCheck,
        check_name=check_name,
        check_type="scps",
        terraform_section=terraform_section,
        allowlist=allowlist,
    )


def make_hierarchy() -> OrganizationHierarchy:
    """
    Build an organization holding one account, attached to the root.

    Returns:
        A hierarchy whose only account is 111111111111, named "acme-co"
    """
    return OrganizationHierarchy(
        root_id="r-1111",
        organizational_units={},
        accounts={
            "111111111111": AccountOrgPlacement(
                account_id="111111111111",
                account_name="acme-co",
                parent_ou_id=None,
                ou_path=["r-1111"],
            ),
        },
    )


def test_one_section_with_nothing_enabled_renders_a_comment_then_false() -> None:
    """A definition absent from the allowlist map renders disabled."""
    definitions = [
        make_definition("deny_ec2_alpha", TerraformSection.EC2),
        make_definition("deny_ec2_beta", TerraformSection.EC2),
    ]
    allowlists: Dict[str, Optional[List[str]]] = {}

    elements = render_check_parameters(
        definitions,
        allowlists,
        "scps_test",
        make_hierarchy(),
    )

    assert elements == [
        TerraformComment("EC2"),
        TerraformParameter("deny_ec2_alpha", False),
        TerraformParameter("deny_ec2_beta", False),
    ]


def test_two_sections_are_separated_by_a_blank_line() -> None:
    """A blank comment goes between sections, and never before the first."""
    definitions = [
        make_definition("deny_ec2_alpha", TerraformSection.EC2),
        make_definition("deny_eks_alpha", TerraformSection.EKS),
    ]
    allowlists: Dict[str, Optional[List[str]]] = {}

    elements = render_check_parameters(
        definitions,
        allowlists,
        "scps_test",
        make_hierarchy(),
    )

    assert elements == [
        TerraformComment("EC2"),
        TerraformParameter("deny_ec2_alpha", False),
        TerraformComment(""),
        TerraformComment("EKS"),
        TerraformParameter("deny_eks_alpha", False),
    ]


def test_check_with_no_allowlist_renders_only_its_boolean() -> None:
    """
    A definition declaring no allowlist contributes one element, enabled.

    Rendered beside a check that does declare one, so "nothing else" is a
    contrast rather than a statement about a renderer that emits no lists at
    all.
    """
    definitions = [
        make_definition("deny_ec2_alpha", TerraformSection.EC2),
        make_definition(
            "deny_ec2_beta",
            TerraformSection.EC2,
            Allowlist("unique_things", "ec2_allowed_things"),
        ),
    ]
    allowlists: Dict[str, Optional[List[str]]] = {
        "deny_ec2_alpha": None,
        "deny_ec2_beta": ["thing"],
    }

    elements = render_check_parameters(
        definitions,
        allowlists,
        "scps_test",
        make_hierarchy(),
    )

    assert elements == [
        TerraformComment("EC2"),
        TerraformParameter("deny_ec2_alpha", True),
        TerraformParameter("deny_ec2_beta", True),
        TerraformParameter("ec2_allowed_things", ["thing"]),
    ]


def test_enabled_allowlist_renders_its_values_in_the_order_given() -> None:
    """The renderer passes allowlist values through without re-sorting them."""
    definitions = [
        make_definition(
            "deny_ec2_alpha",
            TerraformSection.EC2,
            Allowlist("unique_things", "ec2_allowed_things"),
        ),
    ]
    allowlists: Dict[str, Optional[List[str]]] = {"deny_ec2_alpha": ["b", "a"]}

    elements = render_check_parameters(
        definitions,
        allowlists,
        "scps_test",
        make_hierarchy(),
    )

    assert elements == [
        TerraformComment("EC2"),
        TerraformParameter("deny_ec2_alpha", True),
        TerraformParameter("ec2_allowed_things", ["b", "a"]),
    ]


def test_disabled_check_with_an_allowlist_renders_only_its_boolean() -> None:
    """A check absent from the map renders false and no allowlist variable."""
    definitions = [
        make_definition(
            "deny_ec2_alpha",
            TerraformSection.EC2,
            Allowlist("unique_things", "ec2_allowed_things"),
        ),
    ]
    allowlists: Dict[str, Optional[List[str]]] = {}

    elements = render_check_parameters(
        definitions,
        allowlists,
        "scps_test",
        make_hierarchy(),
    )

    assert elements == [
        TerraformComment("EC2"),
        TerraformParameter("deny_ec2_alpha", False),
    ]


def test_empty_allowlist_with_a_comment_leaves_the_check_off(
    caplog: pytest.LogCaptureFixture
) -> None:
    """
    An enabled check whose allowlist came back empty renders off.

    The comment goes above the boolean, so a reader of the generated module
    sees the reason before the `false`.
    """
    definitions = [
        make_definition(
            "deny_ec2_alpha",
            TerraformSection.EC2,
            Allowlist(
                "unique_things",
                "ec2_allowed_things",
                empty_allowlist_comment="deny_ec2_alpha stays off here: reason",
            ),
        ),
    ]
    allowlists: Dict[str, Optional[List[str]]] = {"deny_ec2_alpha": []}

    with caplog.at_level(logging.WARNING):
        elements = render_check_parameters(
            definitions,
            allowlists,
            "scps_test",
            make_hierarchy(),
        )

    assert elements == [
        TerraformComment("EC2"),
        TerraformComment("deny_ec2_alpha stays off here: reason"),
        TerraformParameter("deny_ec2_alpha", False),
    ]
    warnings = [record for record in caplog.records if record.levelname == "WARNING"]
    assert len(warnings) == 1
    assert warnings[0].message == "Module scps_test: deny_ec2_alpha stays off here: reason"


def test_none_value_for_a_check_that_declares_an_allowlist_aborts() -> None:
    """
    A declaring check whose recommendation carries None is lost data.

    Parsing gives every such check a list, empty when nothing was observed,
    or aborts. None can only mean the values went missing on the way here,
    and rendering it as empty would quietly turn the statement off.
    """
    definitions = [
        make_definition(
            "deny_ec2_alpha",
            TerraformSection.EC2,
            Allowlist("unique_things", "ec2_allowed_things"),
        ),
    ]
    allowlists: Dict[str, Optional[List[str]]] = {"deny_ec2_alpha": None}

    with pytest.raises(
        RuntimeError,
        match="scps_test: deny_ec2_alpha declares an allowlist but its recommendation carries None",
    ) as raised:
        render_check_parameters(
            definitions,
            allowlists,
            "scps_test",
            make_hierarchy(),
        )

    assert str(raised.value).endswith(
        "instead of a list - an observed-empty allowlist is []."
    )


def test_empty_allowlist_without_a_comment_renders_the_empty_list(
    caplog: pytest.LogCaptureFixture
) -> None:
    """
    Without an empty-allowlist comment, an empty list is rendered as one.

    The allowlist declares no comment when the empty list is a safe thing to
    generate, so there is nothing to warn about either.
    """
    definitions = [
        make_definition(
            "deny_ec2_alpha",
            TerraformSection.EC2,
            Allowlist("unique_things", "ec2_allowed_things"),
        ),
    ]
    allowlists: Dict[str, Optional[List[str]]] = {"deny_ec2_alpha": []}

    with caplog.at_level(logging.WARNING):
        elements = render_check_parameters(
            definitions,
            allowlists,
            "scps_test",
            make_hierarchy(),
        )

    assert elements == [
        TerraformComment("EC2"),
        TerraformParameter("deny_ec2_alpha", True),
        TerraformParameter("ec2_allowed_things", []),
    ]
    assert caplog.records == []


def test_restores_account_ids_rewrites_arns_for_accounts_in_the_hierarchy() -> None:
    """
    An IAM ARN owned by a known account points at that account's local.

    An ARN from an account outside the hierarchy and a value that is not an
    ARN at all both pass through untouched.
    """
    definitions = [
        make_definition(
            "deny_ec2_alpha",
            TerraformSection.EC2,
            Allowlist("unique_things", "ec2_allowed_things", restores_account_ids=True),
        ),
    ]
    allowlists: Dict[str, Optional[List[str]]] = {
        "deny_ec2_alpha": [
            "arn:aws:iam::111111111111:user/x",
            "arn:aws:iam::999999999999:user/y",
            "amazon",
        ],
    }

    elements = render_check_parameters(
        definitions,
        allowlists,
        "scps_test",
        make_hierarchy(),
    )

    assert elements == [
        TerraformComment("EC2"),
        TerraformParameter("deny_ec2_alpha", True),
        TerraformParameter("ec2_allowed_things", [
            "arn:aws:iam::${local.acme_co_account_id}:user/x",
            "arn:aws:iam::999999999999:user/y",
            "amazon",
        ], template=True),
    ]


def test_restores_account_ids_rewrites_the_account_field_of_any_service_arn() -> None:
    """
    The rewrite reads the ARN's account field, not the service before it.

    restores_account_ids promises the account field is rewritten for every
    account in the hierarchy. The rewrite once did so for IAM ARNs only, so
    a KMS or SQS allowlist declaring the flag would have committed the
    account's real ID into Terraform. An S3 bucket ARN has no account field
    and passes through.
    """
    definitions = [
        make_definition(
            "deny_ec2_alpha",
            TerraformSection.EC2,
            Allowlist("unique_things", "ec2_allowed_things", restores_account_ids=True),
        ),
    ]
    allowlists: Dict[str, Optional[List[str]]] = {
        "deny_ec2_alpha": [
            "arn:aws:kms:us-east-1:111111111111:key/11111111-1111-1111-1111-111111111111",
            "arn:aws:s3:::acme-co-bucket",
        ],
    }

    elements = render_check_parameters(
        definitions,
        allowlists,
        "scps_test",
        make_hierarchy(),
    )

    assert elements == [
        TerraformComment("EC2"),
        TerraformParameter("deny_ec2_alpha", True),
        TerraformParameter("ec2_allowed_things", [
            "arn:aws:kms:us-east-1:${local.acme_co_account_id}:key/11111111-1111-1111-1111-111111111111",
            "arn:aws:s3:::acme-co-bucket",
        ], template=True),
    ]


def test_restores_account_ids_escapes_every_segment_but_the_reference() -> None:
    """
    A restored allowlist is template text, so the renderer escapes nothing
    and the rewrite escapes everything but the reference it inserts.

    An IAM path admits any printable ASCII character, `${` and `"` included,
    so the escape is live. A value the rewrite leaves alone - an ARN naming
    an account outside the hierarchy, or a value that is not an ARN - is
    escaped the same way, since it renders under the same flag.
    """
    definitions = [
        make_definition(
            "deny_ec2_alpha",
            TerraformSection.EC2,
            Allowlist("unique_things", "ec2_allowed_things", restores_account_ids=True),
        ),
    ]
    allowlists: Dict[str, Optional[List[str]]] = {
        "deny_ec2_alpha": [
            'arn:aws:iam::111111111111:user/${team}/"deploy"',
            'arn:aws:iam::999999999999:user/${team}',
            'amazon"',
        ],
    }

    elements = render_check_parameters(
        definitions,
        allowlists,
        "scps_test",
        make_hierarchy(),
    )

    assert elements[-1].render() == (
        "  ec2_allowed_things = [\n"
        '    "arn:aws:iam::${local.acme_co_account_id}:user/$${team}/\\"deploy\\"",\n'
        '    "arn:aws:iam::999999999999:user/$${team}",\n'
        '    "amazon\\"",\n'
        "  ]"
    )


def test_allowlist_that_does_not_restore_account_ids_renders_arns_literally() -> None:
    """Only an allowlist declaring restores_account_ids gets rewritten."""
    definitions = [
        make_definition(
            "deny_ec2_alpha",
            TerraformSection.EC2,
            Allowlist("unique_things", "ec2_allowed_things"),
        ),
    ]
    allowlists: Dict[str, Optional[List[str]]] = {
        "deny_ec2_alpha": ["arn:aws:iam::111111111111:user/x"],
    }

    elements = render_check_parameters(
        definitions,
        allowlists,
        "scps_test",
        make_hierarchy(),
    )

    assert elements == [
        TerraformComment("EC2"),
        TerraformParameter("deny_ec2_alpha", True),
        TerraformParameter("ec2_allowed_things", ["arn:aws:iam::111111111111:user/x"]),
    ]


def test_recommendation_for_an_unregistered_check_aborts() -> None:
    """
    A recommendation no definition describes would render nothing at all.

    Silently dropping it would generate a module missing the statement the
    placement asked for, so the run stops instead.
    """
    definitions = [make_definition("deny_ec2_alpha", TerraformSection.EC2)]
    allowlists: Dict[str, Optional[List[str]]] = {"deny_ec2_unknown": None}

    with pytest.raises(
        RuntimeError,
        match=(
            "Module scps_test was given a recommendation for deny_ec2_unknown, "
            "which no registered check describes"
        ),
    ):
        render_check_parameters(
            definitions,
            allowlists,
            "scps_test",
            make_hierarchy(),
        )


def test_disabled_check_with_an_empty_allowlist_comment_stays_silent(
    caplog: pytest.LogCaptureFixture
) -> None:
    """
    A check nothing enabled renders off without the comment or the warning.

    The comment explains why an otherwise deployable check was held back.
    A check placement never asked for was not held back by anything.
    """
    definitions = [
        make_definition(
            "deny_ec2_alpha",
            TerraformSection.EC2,
            Allowlist(
                "unique_things",
                "ec2_allowed_things",
                empty_allowlist_comment="deny_ec2_alpha stays off here: reason",
            ),
        ),
    ]
    allowlists: Dict[str, Optional[List[str]]] = {}

    with caplog.at_level(logging.WARNING):
        elements = render_check_parameters(
            definitions,
            allowlists,
            "scps_test",
            make_hierarchy(),
        )

    assert elements == [
        TerraformComment("EC2"),
        TerraformParameter("deny_ec2_alpha", False),
    ]
    assert caplog.records == []
