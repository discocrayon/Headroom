"""Tests for headroom.checks.registry module."""

import io
import re
import tokenize
from pathlib import Path
from typing import Callable, List, Optional

import pytest
import headroom.checks.registry
from headroom.checks.registry import (
    _CHECK_REGISTRY,
    Allowlist,
    get_check_class,
    get_all_check_classes,
    get_allowlist,
    get_check_definition,
    get_check_definitions,
    get_check_names,
    get_check_type_map,
    register_check,
)
from headroom.checks.scps.deny_ec2_ami_owner import DenyEc2AmiOwnerCheck
from headroom.checks.scps.deny_ec2_public_ip import DenyEc2PublicIpCheck
from headroom.enums import CheckType, TerraformSection

# The order the committed test_environment modules write their parameters in,
# read off test_environment/scps/acme_acquisition_ou_scps.tf and
# test_environment/rcps/acme_acquisition_ou_rcps.tf rather than computed.
RENDERED_SCP_ORDER = [
    "deny_ec2_ami_owner",
    "deny_ec2_imds_hop_limit",
    "deny_ec2_imds_v1",
    "deny_ec2_public_ip",
    "deny_eks_create_cluster_without_tag",
    "deny_iam_saml_provider_not_aws_sso",
    "deny_iam_user_creation",
    "deny_lambda_auth_type_none",
    "deny_rds_unencrypted",
]
RENDERED_RCP_ORDER = [
    "deny_ecr_third_party_access",
    "deny_kms_third_party_access",
    "deny_s3_third_party_access",
    "deny_secrets_manager_third_party_access",
    "deny_sqs_third_party_access",
    "deny_sts_third_party_assumerole",
    "deny_service_confused_deputy",
]


@pytest.fixture
def isolated_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Give one test its own copy of the registry a registration writes to.

    A registration the registry must refuse still runs the decorator. If a
    validation regressed, the throwaway check would land in the real registry
    for the rest of the session and every test after this one.
    """
    monkeypatch.setattr(
        headroom.checks.registry,
        "_CHECK_REGISTRY",
        dict(headroom.checks.registry._CHECK_REGISTRY),
    )


class TestGetCheckClass:
    """Test get_check_class function."""

    def test_get_check_class_deny_ec2_imds_v1(self) -> None:
        """Test retrieving DenyEc2ImdsV1Check class."""
        check_class = get_check_class("deny_ec2_imds_v1")
        assert check_class is not None
        assert check_class.CHECK_NAME == "deny_ec2_imds_v1"
        assert check_class.CHECK_TYPE == "scps"

    def test_get_check_class_deny_sts_third_party_assumerole(self) -> None:
        """Test retrieving ThirdPartyAssumeRoleCheck class."""
        check_class = get_check_class("deny_sts_third_party_assumerole")
        assert check_class is not None
        assert check_class.CHECK_NAME == "deny_sts_third_party_assumerole"
        assert check_class.CHECK_TYPE == "rcps"

    def test_get_check_class_unknown_raises_value_error(self) -> None:
        """Test that unknown check name raises ValueError."""
        with pytest.raises(ValueError, match="Unknown check: nonexistent_check"):
            get_check_class("nonexistent_check")


class TestGetAllCheckClasses:
    """Test get_all_check_classes function."""

    def test_get_all_check_classes_no_filter(self) -> None:
        """Test getting all check classes without filter."""
        all_checks = get_all_check_classes()
        assert len(all_checks) == 16
        check_names = {cls.CHECK_NAME for cls in all_checks}
        assert "deny_ec2_imds_v1" in check_names
        assert "deny_ec2_imds_hop_limit" in check_names
        assert "deny_ec2_ami_owner" in check_names
        assert "deny_ec2_public_ip" in check_names
        assert "deny_eks_create_cluster_without_tag" in check_names
        assert "deny_iam_user_creation" in check_names
        assert "deny_lambda_auth_type_none" in check_names
        assert "deny_rds_unencrypted" in check_names
        assert "deny_iam_saml_provider_not_aws_sso" in check_names
        assert "deny_ecr_third_party_access" in check_names
        assert "deny_sts_third_party_assumerole" in check_names
        assert "deny_s3_third_party_access" in check_names
        assert "deny_secrets_manager_third_party_access" in check_names
        assert "deny_sqs_third_party_access" in check_names

    def test_get_all_check_classes_filter_by_scps(self) -> None:
        """Test getting check classes filtered by scps."""
        scp_checks = get_all_check_classes("scps")
        assert len(scp_checks) == 9
        check_names = {cls.CHECK_NAME for cls in scp_checks}
        assert "deny_ec2_imds_v1" in check_names
        assert "deny_ec2_imds_hop_limit" in check_names
        assert "deny_ec2_ami_owner" in check_names
        assert "deny_ec2_public_ip" in check_names
        assert "deny_eks_create_cluster_without_tag" in check_names
        assert "deny_iam_user_creation" in check_names
        assert "deny_lambda_auth_type_none" in check_names
        assert "deny_rds_unencrypted" in check_names
        assert "deny_iam_saml_provider_not_aws_sso" in check_names
        for check in scp_checks:
            assert check.CHECK_TYPE == "scps"

    def test_get_all_check_classes_filter_by_rcps(self) -> None:
        """Test getting check classes filtered by rcps."""
        rcp_checks = get_all_check_classes("rcps")
        assert len(rcp_checks) == 7
        check_names = {cls.CHECK_NAME for cls in rcp_checks}
        assert "deny_sts_third_party_assumerole" in check_names
        assert "deny_s3_third_party_access" in check_names
        assert "deny_ecr_third_party_access" in check_names
        assert "deny_secrets_manager_third_party_access" in check_names
        assert "deny_sqs_third_party_access" in check_names
        for check in rcp_checks:
            assert check.CHECK_TYPE == "rcps"


class TestGetCheckTypeMap:
    """Test get_check_type_map function."""

    def test_get_check_type_map_returns_correct_mapping(self) -> None:
        """Test that get_check_type_map returns correct check name to type mapping."""
        type_map = get_check_type_map()
        assert isinstance(type_map, dict)
        assert type_map["deny_ec2_imds_v1"] == "scps"
        assert type_map["deny_ec2_ami_owner"] == "scps"
        assert type_map["deny_ec2_imds_hop_limit"] == "scps"
        assert type_map["deny_ec2_public_ip"] == "scps"
        assert type_map["deny_eks_create_cluster_without_tag"] == "scps"
        assert type_map["deny_iam_user_creation"] == "scps"
        assert type_map["deny_lambda_auth_type_none"] == "scps"
        assert type_map["deny_rds_unencrypted"] == "scps"
        assert type_map["deny_iam_saml_provider_not_aws_sso"] == "scps"
        assert type_map["deny_ecr_third_party_access"] == "rcps"
        assert type_map["deny_kms_third_party_access"] == "rcps"
        assert type_map["deny_sts_third_party_assumerole"] == "rcps"
        assert type_map["deny_s3_third_party_access"] == "rcps"
        assert type_map["deny_secrets_manager_third_party_access"] == "rcps"
        assert type_map["deny_sqs_third_party_access"] == "rcps"
        assert type_map["deny_service_confused_deputy"] == "rcps"
        assert len(type_map) == 16


def test_every_registry_key_matches_its_class_check_name() -> None:
    """
    The decorator's key and the class attribute must agree.

    @register_check keys the registry by its check_name argument and stamps
    that same name onto the class, and collection reads it back off the class
    to name the results file each check writes. One class registered under
    two names would be listed and looked up under the registry's, then write
    and skip its results under the class's.
    """
    mismatched = {
        key: definition.check_class.CHECK_NAME
        for key, definition in _CHECK_REGISTRY.items()
        if key != definition.check_class.CHECK_NAME
    }

    assert mismatched == {}


def test_every_listed_check_name_is_retrievable() -> None:
    """The two registry projections must round trip."""
    for check_name in get_check_names():
        assert get_check_class(check_name).CHECK_NAME == check_name


def test_get_check_definition_carries_the_whole_registration() -> None:
    """
    One record answers every question the pipeline asks about a check.

    Parsing and both Terraform generators once named deny_ec2_ami_owner in
    straight-line code and repeated its allowlist beside it. Carrying the
    class, the type, the section and the allowlist on one definition is what
    let them stop, so that registering a check is the whole of wiring it in
    (INV-13).
    """
    definition = get_check_definition("deny_ec2_ami_owner")

    assert definition.check_class is DenyEc2AmiOwnerCheck
    assert definition.check_type == "scps"
    assert definition.terraform_section is TerraformSection.EC2
    allowlist = definition.allowlist
    assert allowlist is not None
    assert allowlist.summary_key == "unique_ami_owners"
    assert allowlist.terraform_variable == "ec2_allowed_ami_owners"
    assert allowlist.restores_account_ids is False
    assert allowlist.empty_allowlist_comment is not None
    assert allowlist.empty_allowlist_comment.startswith("deny_ec2_ami_owner stays off here")


def test_get_check_definition_unknown_check_raises_value_error() -> None:
    """
    An unregistered name fails the way get_check_class already fails.

    A KeyError escaping here reads as a corrupt dictionary rather than a
    misspelled check, and every caller downstream of the registry catches
    neither.
    """
    with pytest.raises(ValueError, match="Unknown check: nonexistent_check"):
        get_check_definition("nonexistent_check")


def test_get_check_definitions_lists_one_type_in_render_order() -> None:
    """
    The order the definitions come back in is the order Terraform renders.

    This is the list both generators write their module parameters from, so
    its order is the order of the committed test_environment modules:
    grouped by TerraformSection declaration order, then by check name within
    a section.
    """
    scp_names = [definition.check_name for definition in get_check_definitions("scps")]
    rcp_names = [definition.check_name for definition in get_check_definitions("rcps")]

    assert scp_names == RENDERED_SCP_ORDER
    assert rcp_names == RENDERED_RCP_ORDER


@pytest.mark.parametrize("check_type", ["policies", ""], ids=["misspelled", "empty"])
def test_get_check_definitions_unknown_type_raises(check_type: str) -> None:
    """
    A type naming no results directory is an error, not an empty answer.

    The filter behind this accessor is shared with two callers that take an
    optional type, so it reads a falsy value as "no filter": an empty string
    would return all sixteen definitions and a misspelled type none of them.
    Both are silently wrong - a module rendering statements of both kinds, or
    a module rendering nothing at all (INV-01).
    """
    with pytest.raises(
        ValueError,
        match=f"Unknown check type: '{check_type}'; expected 'scps' or 'rcps'",
    ):
        get_check_definitions(check_type)


def test_render_order_is_independent_of_registration_order(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Reversing the order the checks registered in must move no parameter.

    Registration order is the order headroom/checks/__init__.py imports the
    check modules in - alphabetical by filename today, and guaranteed by
    nothing. If it reached the generated Terraform, renaming one check file
    would rewrite the parameter order of every committed module (INV-13).
    """
    monkeypatch.setattr(
        headroom.checks.registry,
        "_CHECK_REGISTRY",
        dict(reversed(list(_CHECK_REGISTRY.items()))),
    )

    scp_names = [definition.check_name for definition in get_check_definitions("scps")]
    rcp_names = [definition.check_name for definition in get_check_definitions("rcps")]

    assert scp_names == RENDERED_SCP_ORDER
    assert rcp_names == RENDERED_RCP_ORDER


def test_get_allowlist_returns_the_declared_allowlist() -> None:
    """
    The allowlist is the check's, not the caller's to remember.

    Parsing reads the summary key to collect the values and rendering reads
    the Terraform variable to write them. Both once named the pair beside the
    check; this is the one record they read it from now (INV-13).
    """
    allowlist = get_allowlist("deny_iam_user_creation")

    assert allowlist.summary_key == "users"
    assert allowlist.terraform_variable == "iam_allowed_users"
    assert allowlist.restores_account_ids is True


def test_get_allowlist_check_without_an_allowlist_raises_value_error() -> None:
    """
    A check with no allowlist is a caller error, not an empty allowlist.

    deny_rds_unencrypted denies unconditionally: it has no allowlist to
    return, and returning an empty one would render an allowlist parameter
    the module never declared.
    """
    with pytest.raises(ValueError, match="Check 'deny_rds_unencrypted' declares no allowlist"):
        get_allowlist("deny_rds_unencrypted")


def test_get_allowlist_unknown_check_raises_value_error() -> None:
    """An unregistered name fails as an unknown check, not as a missing allowlist."""
    with pytest.raises(ValueError, match="Unknown check: nonexistent_check"):
        get_allowlist("nonexistent_check")


def test_registering_a_name_twice_raises_and_keeps_the_first_class(
    isolated_registry: None,
) -> None:
    """
    Two classes under one name would silently replace each other.

    The registry is a dict, so the second registration wins and the first
    check stops running - collected under a name that now analyzes something
    else. Copying a check file as the starting point for a new one and
    forgetting to change the name is how that happens.
    """

    class SecondPublicIpCheck(DenyEc2PublicIpCheck):
        """A check reusing a name the registry already holds."""

    with pytest.raises(ValueError, match="Check 'deny_ec2_public_ip' is already registered"):
        register_check(
            "scps",
            "deny_ec2_public_ip",
            terraform_section=TerraformSection.EC2,
        )(SecondPublicIpCheck)

    assert get_check_class("deny_ec2_public_ip") is DenyEc2PublicIpCheck


def test_registering_a_name_claimed_as_an_allowlist_variable_raises(
    isolated_registry: None,
) -> None:
    """
    A check name and an allowlist variable share one namespace.

    Both render as parameters of the same module, so a check named
    iam_allowed_users collides with deny_iam_user_creation's allowlist just
    as squarely as a second allowlist would: the boolean that enables the new
    statement and the ARN list that scopes the old one are written to one
    variable, and Terraform reads whichever came last.
    """

    class ShadowingCheck(DenyEc2PublicIpCheck):
        """A check named for a variable another check's allowlist writes."""

    with pytest.raises(
        ValueError,
        match="Check 'iam_allowed_users' is already claimed as the allowlist variable of 'deny_iam_user_creation'",
    ):
        register_check(
            "scps",
            "iam_allowed_users",
            terraform_section=TerraformSection.IAM,
        )(ShadowingCheck)

    assert "iam_allowed_users" not in get_check_names()


def test_registering_an_unknown_check_type_raises_and_registers_nothing(
    isolated_registry: None,
) -> None:
    """
    `scps` and `rcps` are directory names on disk, not free text.

    check_type picks the results directory the check writes into and the
    generator that renders it. A third value produces a check that collects
    happily, writes where nothing reads, and reaches no Terraform module.
    """

    class MistypedCheck(DenyEc2PublicIpCheck):
        """A check registered under a type no directory is named for."""

    with pytest.raises(
        ValueError,
        match="Check 'deny_ec2_mistyped' has unknown type 'policies'; expected 'scps' or 'rcps'",
    ):
        register_check(
            "policies",
            "deny_ec2_mistyped",
            terraform_section=TerraformSection.EC2,
        )(MistypedCheck)

    assert "deny_ec2_mistyped" not in get_check_names()
    assert "deny_ec2_mistyped" not in get_check_type_map()


def test_registering_a_check_type_enum_member_raises_and_registers_nothing(
    isolated_registry: None,
) -> None:
    """
    check_type is the plain string `scps` or `rcps`, not the CheckType member.

    A CheckType member is a str, so it passes a membership test against the
    two strings and every registry lookup that compares by equality, and
    mypy accepts it where a str is expected. It does not format as one: the
    result writer builds a check's directory by formatting the type it reads
    from the constants mirror, and a member there renders as `CheckType.SCPS`,
    so the check would write results/CheckType.SCPS/ while the parser reads
    results/scps/.
    """

    class EnumTypedCheck(DenyEc2PublicIpCheck):
        """A check registered under the enum member rather than its value."""

    with pytest.raises(
        ValueError,
        match=re.escape(
            "Check 'deny_ec2_enum_typed' has check_type <CheckType.SCPS: 'scps'>, "
            "which is not a plain string; pass 'scps' or 'rcps'"
        ),
    ):
        register_check(
            CheckType.SCPS,
            "deny_ec2_enum_typed",
            terraform_section=TerraformSection.EC2,
        )(EnumTypedCheck)

    assert "deny_ec2_enum_typed" not in get_check_names()
    assert "deny_ec2_enum_typed" not in get_check_type_map()


def test_registering_an_rcp_without_an_allowlist_raises(isolated_registry: None) -> None:
    """
    An RCP is placed by the allowlist it declares.

    RCP placement unions the third-party accounts each covered account
    observed and writes them into the module variable. Without an allowlist
    there is nothing to union and nothing to write, so the statement would be
    attached with no scope at all.
    """

    class UnscopedRcpCheck(DenyEc2PublicIpCheck):
        """An RCP check declaring no allowlist."""

    with pytest.raises(
        ValueError,
        match="RCP check 'deny_sqs_third_party_grants' declares no allowlist; RCP placement",
    ):
        register_check(
            "rcps",
            "deny_sqs_third_party_grants",
            terraform_section=TerraformSection.SQS,
        )(UnscopedRcpCheck)

    assert "deny_sqs_third_party_grants" not in get_check_names()


@pytest.mark.parametrize(
    "allowlist",
    [
        Allowlist(summary_key="", terraform_variable="unclaimed_allowlist"),
        Allowlist(summary_key="unclaimed_values", terraform_variable=""),
    ],
    ids=["no summary key", "no terraform variable"],
)
def test_registering_an_allowlist_missing_a_field_raises(
    isolated_registry: None,
    allowlist: Allowlist,
) -> None:
    """
    Both halves of an allowlist are read, so both must be there.

    Parsing looks the summary key up in every result file and aborts when it
    is absent, and rendering writes the unioned values into the Terraform
    variable. An empty string names a key no result carries and a variable no
    module declares, and neither failure surfaces until a run is under way.
    """

    class HalfDeclaredCheck(DenyEc2PublicIpCheck):
        """A check whose allowlist names only one of the two."""

    with pytest.raises(
        ValueError,
        match="Check 'deny_ec2_half_declared' allowlist needs a summary_key and a terraform_variable",
    ):
        register_check(
            "scps",
            "deny_ec2_half_declared",
            terraform_section=TerraformSection.EC2,
            allowlist=allowlist,
        )(HalfDeclaredCheck)

    assert "deny_ec2_half_declared" not in get_check_names()


@pytest.mark.parametrize(
    "terraform_variable,claimed_by",
    [
        ("deny_rds_unencrypted", "deny_rds_unencrypted"),
        ("iam_allowed_users", "deny_iam_user_creation"),
    ],
)
def test_registering_a_claimed_terraform_variable_raises(
    isolated_registry: None,
    terraform_variable: str,
    claimed_by: str,
) -> None:
    """
    Two checks cannot write one Terraform variable.

    Every check name is itself a module variable - the boolean that enables
    its statement - so an allowlist may collide with a check name as readily
    as with another allowlist. Either way the two values are rendered into
    one parameter, and the module reads whichever came last with no error
    from Terraform at all.
    """

    class CollidingVariableCheck(DenyEc2PublicIpCheck):
        """A check claiming a Terraform variable another check owns."""

    with pytest.raises(
        ValueError,
        match=f"Check 'deny_ec2_colliding' allowlist variable '{terraform_variable}' is already claimed by '{claimed_by}'",
    ):
        register_check(
            "scps",
            "deny_ec2_colliding",
            terraform_section=TerraformSection.EC2,
            allowlist=Allowlist(
                summary_key="unique_collisions",
                terraform_variable=terraform_variable,
            ),
        )(CollidingVariableCheck)

    assert "deny_ec2_colliding" not in get_check_names()


def test_registering_an_allowlist_variable_matching_its_own_name_raises(
    isolated_registry: None,
) -> None:
    """
    A check cannot claim its own name for its allowlist either.

    The name is already the boolean that enables the statement, so an
    allowlist written to it renders a list of values where the module expects
    true or false. Comparing the new variable only against the checks already
    registered cannot see that collision, because the colliding claim is the
    registration's own.
    """

    class SelfCollidingCheck(DenyEc2PublicIpCheck):
        """A check whose allowlist variable is its own check name."""

    with pytest.raises(
        ValueError,
        match="Check 'ec2_self_collide' allowlist variable 'ec2_self_collide' is already claimed by 'ec2_self_collide'",
    ):
        register_check(
            "scps",
            "ec2_self_collide",
            terraform_section=TerraformSection.EC2,
            allowlist=Allowlist(
                summary_key="unique_collisions",
                terraform_variable="ec2_self_collide",
            ),
        )(SelfCollidingCheck)

    assert "ec2_self_collide" not in get_check_names()


def test_registering_one_class_under_two_names_raises(
    isolated_registry: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    A class holds one CHECK_NAME, so it registers once.

    The decorator stamps the name onto the class, and the framework reads
    the check's name back from that attribute. A class registered twice
    would be collected under both names and carry only the second, so the
    first name's results would land in the second's directory and the first
    directory would stay empty.
    """
    monkeypatch.setattr(DenyEc2PublicIpCheck, "CHECK_NAME", DenyEc2PublicIpCheck.CHECK_NAME)

    with pytest.raises(
        ValueError,
        match=re.escape(
            "Check 'deny_ec2_public_ip_again' registers DenyEc2PublicIpCheck, "
            "which is already registered as 'deny_ec2_public_ip'"
        ),
    ):
        register_check(
            "scps",
            "deny_ec2_public_ip_again",
            terraform_section=TerraformSection.EC2,
        )(DenyEc2PublicIpCheck)

    assert DenyEc2PublicIpCheck.CHECK_NAME == "deny_ec2_public_ip"
    assert "deny_ec2_public_ip_again" not in get_check_names()


def test_registering_an_empty_allowlist_comment_raises(isolated_registry: None) -> None:
    """
    An empty comment is neither of the two things the field can mean.

    None says an empty allowlist renders as [] and the module omits the
    clause; a comment says the empty allowlist turns the statement off and
    explains why. The empty string is falsy, so it rendered the first way
    while reading as though the author had asked for the second.
    """

    class EmptyCommentCheck(DenyEc2PublicIpCheck):
        """A check whose empty-allowlist comment says nothing."""

    with pytest.raises(
        ValueError,
        match=re.escape(
            "Check 'deny_ec2_empty_comment' allowlist empty_allowlist_comment is empty; "
            "pass None to render an empty allowlist as [], or a comment saying why the "
            "statement stays off"
        ),
    ):
        register_check(
            "scps",
            "deny_ec2_empty_comment",
            terraform_section=TerraformSection.EC2,
            allowlist=Allowlist("unique_widgets", "ec2_allowed_widgets", empty_allowlist_comment=""),
        )(EmptyCommentCheck)

    assert "deny_ec2_empty_comment" not in get_check_names()


@pytest.mark.parametrize("accessor", [get_check_names, get_all_check_classes], ids=["names", "classes"])
@pytest.mark.parametrize("check_type", ["scp", ""], ids=["misspelled", "empty"])
def test_the_filtering_accessors_reject_an_unknown_check_type(
    accessor: Callable[[Optional[str]], object],
    check_type: str,
) -> None:
    """
    A misspelled type returned nothing, and "" returned everything.

    get_check_definitions already refuses a type that is not scps or rcps.
    The other two accessors filtered on truthiness instead: a caller
    iterating the empty list a typo produced runs no checks and writes no
    results, which nothing downstream can tell from an organization with
    nothing to report (INV-01). None still means every check.
    """
    with pytest.raises(
        ValueError,
        match=f"Unknown check type: '{check_type}'; expected 'scps' or 'rcps'",
    ):
        accessor(check_type)


def test_every_rcp_allowlist_collects_third_party_accounts() -> None:
    """
    Every RCP is scoped by the same summary key, and must keep saying so.

    RCP placement reads `unique_third_party_accounts` out of each result file
    to union the allowlist. A check whose results carry the accounts under
    another key parses to an empty allowlist rather than to an error, and an
    empty allowlist is exactly what a fully compliant account looks like
    (INV-01).
    """
    summary_keys = {
        definition.check_name: get_allowlist(definition.check_name).summary_key
        for definition in get_check_definitions("rcps")
    }

    assert summary_keys == {
        "deny_ecr_third_party_access": "unique_third_party_accounts",
        "deny_kms_third_party_access": "unique_third_party_accounts",
        "deny_s3_third_party_access": "unique_third_party_accounts",
        "deny_secrets_manager_third_party_access": "unique_third_party_accounts",
        "deny_sqs_third_party_access": "unique_third_party_accounts",
        "deny_sts_third_party_assumerole": "unique_third_party_accounts",
        "deny_service_confused_deputy": "unique_third_party_accounts",
    }


def test_every_check_renders_under_its_service_section() -> None:
    """
    The section a check renders under is the service it governs.

    The section is what groups a module's parameters, so a check filed under
    the wrong service moves silently in the generated Terraform - and
    deny_service_confused_deputy, which governs every service the six
    resource checks do, has to stay outside the alphabetical run.
    """
    sections = {
        check_name: get_check_definition(check_name).terraform_section
        for check_name in get_check_names()
    }

    assert sections == {
        "deny_ec2_ami_owner": TerraformSection.EC2,
        "deny_ec2_imds_hop_limit": TerraformSection.EC2,
        "deny_ec2_imds_v1": TerraformSection.EC2,
        "deny_ec2_public_ip": TerraformSection.EC2,
        "deny_eks_create_cluster_without_tag": TerraformSection.EKS,
        "deny_iam_saml_provider_not_aws_sso": TerraformSection.IAM,
        "deny_iam_user_creation": TerraformSection.IAM,
        "deny_lambda_auth_type_none": TerraformSection.LAMBDA,
        "deny_rds_unencrypted": TerraformSection.RDS,
        "deny_ecr_third_party_access": TerraformSection.ECR,
        "deny_kms_third_party_access": TerraformSection.KMS,
        "deny_s3_third_party_access": TerraformSection.S3,
        "deny_secrets_manager_third_party_access": TerraformSection.SECRETS_MANAGER,
        "deny_sqs_third_party_access": TerraformSection.SQS,
        "deny_sts_third_party_assumerole": TerraformSection.STS,
        "deny_service_confused_deputy": TerraformSection.SERVICE_CONFUSED_DEPUTY,
    }


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


def python_modules_under(package_directory: str) -> List[str]:
    """
    Repository-relative paths of every `.py` file under `package_directory`,
    recursively, sorted.
    """
    return sorted(
        str(module.relative_to(REPOSITORY_ROOT))
        for module in (REPOSITORY_ROOT / package_directory).rglob("*.py")
    )


# Every module the run executes between check discovery and Terraform
# generation, none of which may know one check from another (INV-13).
# The orchestrator comes first, since it parses, places and prints in both
# workflows; then discovery; then the stage modules in pipeline order.
# The two packages are globbed recursively, so a module added anywhere
# under either is scanned without an edit here.
_GENERIC_PIPELINE_MODULES = (
    "headroom/main.py",
    "headroom/checks/__init__.py",
    "headroom/analysis.py",
    "headroom/checks/base.py",
    "headroom/write_results.py",
    "headroom/parse_results.py",
    *python_modules_under("headroom/placement"),
    *python_modules_under("headroom/terraform"),
)


def check_name_dispatch(source: str, check_names: List[str]) -> List[str]:
    """
    Every name in `check_names` that appears in `source` as a whole word
    outside a `#` comment, plus every word beginning `DENY_` (the constants
    mirror of those names) outside a comment. Sorted, deduplicated.

    Comments are dropped with `tokenize.generate_tokens` (skip
    `tokenize.COMMENT`, join the remaining token strings with spaces).
    Docstrings and string literals are scanned: a generic module may cite a
    check in a historical comment, but not describe or compare one, so a
    docstring example such as `'deny_ec2_imds_v1'` trips the guard and the
    remedy is to reword the prose.
    """
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    uncommented = " ".join(token.string for token in tokens if token.type != tokenize.COMMENT)
    hits = [name for name in check_names if re.search(rf"\b{re.escape(name)}\b", uncommented)]
    hits.extend(re.findall(r"\bDENY_\w+", uncommented))
    return sorted(set(hits))


def test_a_check_name_and_a_check_constant_are_both_dispatch() -> None:
    """
    The guard has to be able to fail, in both shapes INV-13 forbids.

    A generic stage can name one check two ways: comparing against the
    registered name, or importing the constant that holds it. Neither is
    registry-driven, so the scan reports both.
    """
    assert check_name_dispatch('if name == "deny_ec2_ami_owner":\n', ["deny_ec2_ami_owner"]) == ["deny_ec2_ami_owner"]
    assert check_name_dispatch("from ..constants import DENY_EC2_AMI_OWNER\n", ["deny_ec2_ami_owner"]) == ["DENY_EC2_AMI_OWNER"]


def test_a_name_that_only_starts_with_a_check_name_is_not_dispatch() -> None:
    """
    A longer identifier that begins with a check name is not a branch on it.

    `deny_ec2_ami_owner_count` is a variable, not a comparison, so a
    substring scan would report every generic module that happened to name
    one and the guard would be worked around rather than obeyed.
    """
    assert check_name_dispatch("x = deny_ec2_ami_owner_count\n", ["deny_ec2_ami_owner"]) == []


def test_a_comment_is_exempt_and_a_docstring_is_not() -> None:
    """
    A `#` comment may cite a check; anything the reader executes or renders
    may not.

    parse_results carries the INV-01 note naming the check that shipped
    without a violation count, which is history rather than dispatch. A
    docstring or a string literal is the shape a comparison hides in, so it
    is scanned like any other token.
    """
    assert check_name_dispatch("# deny_ec2_ami_owner shipped without the key\nx = 1\n", ["deny_ec2_ami_owner"]) == []
    assert check_name_dispatch('"""deny_ec2_ami_owner"""\n', ["deny_ec2_ami_owner"]) == ["deny_ec2_ami_owner"]


def test_generic_pipeline_modules_name_no_check() -> None:
    """
    No stage between collection and rendering may branch on a check name.

    A check registers itself and every later stage discovers it from the
    registry (INV-13). A name in straight-line code here is a check the
    pipeline knows by hand, and the failure it produces is silent: the next
    check registered is collected, written, parsed and placed, then dropped
    wherever the branch did not name it. Parsing had no guard of this shape
    for as long as it branched on two check names.

    The subset assertion pins both halves of the tuple. The five globbed
    paths keep a package that stopped matching from scanning nothing and
    staying green; the six hand-listed ones keep the tuple from being
    shortened without the pin objecting.
    """
    named = {
        path: check_name_dispatch((REPOSITORY_ROOT / path).read_text(), get_check_names())
        for path in _GENERIC_PIPELINE_MODULES
    }

    assert {
        "headroom/main.py",
        "headroom/checks/__init__.py",
        "headroom/analysis.py",
        "headroom/checks/base.py",
        "headroom/write_results.py",
        "headroom/parse_results.py",
        "headroom/placement/__init__.py",
        "headroom/placement/hierarchy.py",
        "headroom/terraform/generate_rcps.py",
        "headroom/terraform/generate_scps.py",
        "headroom/terraform/parameters.py",
    } <= set(named)
    assert named == {path: [] for path in _GENERIC_PIPELINE_MODULES}
