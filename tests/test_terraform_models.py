"""
Tests for Terraform data models.

Tests the TerraformParameter, TerraformComment, and TerraformModule dataclasses
used for structured Terraform generation.
"""

import pytest

from headroom.constants import GENERATED_MARKER
from headroom.terraform.models import (
    TerraformModule,
    TerraformParameter,
    TerraformComment,
    hcl_escape,
)


class TestHclEscape:
    """
    Every value placed inside an HCL quoted string is escaped by this one rule.

    Expected values are the escape sequences HCL's quoted-template grammar
    defines, written out by hand: backslash, double quote, newline, carriage
    return, tab, and the two template sequences that would otherwise be
    interpolated. A bare `$` or `%` is not a template sequence and is left
    alone.
    """

    @pytest.mark.parametrize("value, literal", [
        ("plain", "plain"),
        ('say "hi"', 'say \\"hi\\"'),
        ("back\\slash", "back\\\\slash"),
        ("a\nb", "a\\nb"),
        ("a\rb", "a\\rb"),
        ("a\tb", "a\\tb"),
        ('${upper("x")}', '$${upper(\\"x\\")}'),
        ("%{ if true }a%{ endif }", "%%{ if true }a%%{ endif }"),
        ("$5 and 100%", "$5 and 100%"),
    ], ids=[
        "plain", "quote", "backslash", "newline", "carriage-return", "tab",
        "interpolation", "directive", "bare-dollar-and-percent",
    ])
    def test_escapes_one_sequence(self, value: str, literal: str) -> None:
        assert hcl_escape(value) == literal

    def test_backslash_is_escaped_before_the_quote_it_precedes(self) -> None:
        """
        The backslash rule runs first, or the quote's own backslash doubles.

        Input: a backslash then a quote. Output: an escaped backslash then an
        escaped quote, four characters, not five.
        """
        assert hcl_escape('\\"') == '\\\\\\"'


class TestTerraformParameter:
    """Tests for TerraformParameter class."""

    def test_render_boolean_true(self) -> None:
        """Test rendering boolean true value."""
        param = TerraformParameter("enabled", True)
        assert param.render() == "  enabled = true"

    def test_render_boolean_false(self) -> None:
        """Test rendering boolean false value."""
        param = TerraformParameter("enabled", False)
        assert param.render() == "  enabled = false"

    def test_render_string(self) -> None:
        """Test rendering string value."""
        param = TerraformParameter("name", "test-name")
        assert param.render() == '  name = "test-name"'

    def test_render_empty_string(self) -> None:
        """Test rendering empty string value."""
        param = TerraformParameter("description", "")
        assert param.render() == '  description = ""'

    def test_render_empty_list(self) -> None:
        """Test rendering empty list."""
        param = TerraformParameter("items", [])
        assert param.render() == "  items = []"

    def test_render_single_item_list(self) -> None:
        """Test rendering list with single item."""
        param = TerraformParameter("accounts", ["111111111111"])
        expected = '  accounts = [\n    "111111111111",\n  ]'
        assert param.render() == expected

    def test_render_multi_item_list(self) -> None:
        """Test rendering list with multiple items."""
        param = TerraformParameter("accounts", ["111111111111", "222222222222", "333333333333"])
        expected = '  accounts = [\n    "111111111111",\n    "222222222222",\n    "333333333333",\n  ]'
        assert param.render() == expected

    def test_render_integer(self) -> None:
        """Test rendering integer value."""
        param = TerraformParameter("count", 42)
        assert param.render() == "  count = 42"

    def test_render_float(self) -> None:
        """Test rendering float value."""
        param = TerraformParameter("percentage", 99.5)
        assert param.render() == "  percentage = 99.5"

    def test_render_with_special_characters(self) -> None:
        """Test rendering string with special characters."""
        param = TerraformParameter("arn", "arn:aws:iam::111111111111:user/path/username")
        assert param.render() == '  arn = "arn:aws:iam::111111111111:user/path/username"'

    def test_render_with_an_interpolation_sequence_renders_it_as_text(self) -> None:
        """
        A parameter value is data by default, never an expression.

        `${` in a value would be interpolated by Terraform, so it is escaped to
        `$${`, which renders the literal text. A producer that means the
        interpolation opts out with `template`, as the next test shows.
        """
        param = TerraformParameter("account_id", "${local.account_id}")
        assert param.render() == '  account_id = "$${local.account_id}"'

    def test_render_template_text_keeps_its_interpolation(self) -> None:
        """
        Template text renders as composed, so its reference stays live.

        `iam_allowed_users` is the value that needs this: each user ARN carries
        a reference to the account's local in place of the account ID. The
        producer escaped the data segments itself, so nothing is escaped here.
        """
        param = TerraformParameter(
            "iam_allowed_users",
            ["arn:aws:iam::${local.prod_account_id}:user/deploy"],
            template=True,
        )
        assert param.render() == (
            '  iam_allowed_users = [\n'
            '    "arn:aws:iam::${local.prod_account_id}:user/deploy",\n'
            '  ]'
        )


class TestTerraformComment:
    """Tests for TerraformComment class."""

    def test_render_simple_comment(self) -> None:
        """Test rendering simple comment."""
        comment = TerraformComment("EC2")
        assert comment.render() == "  # EC2"

    def test_render_empty_comment(self) -> None:
        """Test rendering empty comment creates blank line."""
        comment = TerraformComment("")
        assert comment.render() == ""

    def test_render_multiword_comment(self) -> None:
        """Test rendering comment with multiple words."""
        comment = TerraformComment("Secrets Manager")
        assert comment.render() == "  # Secrets Manager"

    def test_render_comment_with_special_chars(self) -> None:
        """Test rendering comment with special characters."""
        comment = TerraformComment("IAM (Identity & Access Management)")
        assert comment.render() == "  # IAM (Identity & Access Management)"

    def test_a_line_break_in_a_comment_stays_on_the_comment_line(self) -> None:
        """
        A comment has no escape syntax, so a line break is the only hazard.

        Left in, the rest of the text lands as a bare top-level line of HCL.
        It is replaced with the two-character sequence so the comment stays
        one line and still shows where the break was.
        """
        assert TerraformComment("Prod\n  injected = 1 #").render() == (
            "  # Prod\\n  injected = 1 #"
        )
        assert TerraformComment("a\r\nb\rc").render() == "  # a\\nb\\nc"


class TestTerraformModule:
    """Tests for TerraformModule class."""

    def test_render_minimal_module(self) -> None:
        """Test rendering module with no parameters or comment."""
        module = TerraformModule(
            name="test_module",
            source="../modules/test",
            target_id="local.test_id",
            parameters=[]
        )
        expected = '''# Code generated by Headroom. DO NOT EDIT.

module "test_module" {
  source = "../modules/test"
  target_id = local.test_id

}
'''
        assert module.render() == expected

    def test_render_module_with_comment(self) -> None:
        """Test rendering module with comment."""
        module = TerraformModule(
            name="test_module",
            source="../modules/test",
            target_id="local.test_id",
            parameters=[],
            comment="Test Environment"
        )
        expected = '''# Code generated by Headroom. DO NOT EDIT.
# Auto-generated SCP Terraform configuration for Test Environment
# Generated by Headroom based on compliance analysis

module "test_module" {
  source = "../modules/test"
  target_id = local.test_id

}
'''
        assert module.render() == expected

    def test_a_line_break_in_the_module_comment_stays_in_the_header(self) -> None:
        """
        The header names an account or OU, and Organizations allows any
        character in both. A line break left in would end the comment and
        land the rest of the name as a bare top-level line of HCL.
        """
        module = TerraformModule(
            name="test_module",
            source="../modules/test",
            target_id="local.test_id",
            parameters=[],
            comment='prod\nresource "x" "y" {}',
        )

        lines = module.render().splitlines()

        assert lines[1] == '# Auto-generated SCP Terraform configuration for prod\\nresource "x" "y" {}'
        assert not [line for line in lines if line.startswith("resource")]

    def test_render_module_with_single_parameter(self) -> None:
        """Test rendering module with single parameter."""
        module = TerraformModule(
            name="test_module",
            source="../modules/test",
            target_id="local.test_id",
            parameters=[TerraformParameter("enabled", True)]
        )
        expected = '''# Code generated by Headroom. DO NOT EDIT.

module "test_module" {
  source = "../modules/test"
  target_id = local.test_id

  enabled = true
}
'''
        assert module.render() == expected

    def test_render_module_with_multiple_parameters(self) -> None:
        """Test rendering module with multiple parameters."""
        module = TerraformModule(
            name="test_module",
            source="../modules/test",
            target_id="local.test_id",
            parameters=[
                TerraformParameter("enabled", True),
                TerraformParameter("name", "test-name"),
                TerraformParameter("count", 5),
            ]
        )
        expected = '''# Code generated by Headroom. DO NOT EDIT.

module "test_module" {
  source = "../modules/test"
  target_id = local.test_id

  enabled = true
  name = "test-name"
  count = 5
}
'''
        assert module.render() == expected

    def test_render_module_with_list_parameter(self) -> None:
        """Test rendering module with list parameter."""
        module = TerraformModule(
            name="scps_root",
            source="../modules/scps",
            target_id="local.root_ou_id",
            parameters=[
                TerraformParameter("deny_ec2_ami_owner", True),
                TerraformParameter("ec2_allowed_ami_owners", ["111111111111", "222222222222"]),
            ],
            comment="Organization Root"
        )
        expected = '''# Code generated by Headroom. DO NOT EDIT.
# Auto-generated SCP Terraform configuration for Organization Root
# Generated by Headroom based on compliance analysis

module "scps_root" {
  source = "../modules/scps"
  target_id = local.root_ou_id

  deny_ec2_ami_owner = true
  ec2_allowed_ami_owners = [
    "111111111111",
    "222222222222",
  ]
}
'''
        assert module.render() == expected

    def test_render_module_with_comments(self) -> None:
        """Test rendering module with section comments and blank lines."""
        module = TerraformModule(
            name="test_module",
            source="../modules/test",
            target_id="local.test_id",
            parameters=[
                TerraformComment("EC2"),
                TerraformParameter("deny_ec2_ami_owner", True),
                TerraformComment(""),
                TerraformComment("IAM"),
                TerraformParameter("deny_iam_user_creation", False),
            ]
        )
        expected = '''# Code generated by Headroom. DO NOT EDIT.

module "test_module" {
  source = "../modules/test"
  target_id = local.test_id

  # EC2
  deny_ec2_ami_owner = true

  # IAM
  deny_iam_user_creation = false
}
'''
        assert module.render() == expected

    def test_render_module_with_empty_list(self) -> None:
        """Test rendering module with empty list parameter."""
        module = TerraformModule(
            name="test_module",
            source="../modules/test",
            target_id="local.test_id",
            parameters=[
                TerraformParameter("enabled", True),
                TerraformParameter("items", []),
            ]
        )
        expected = '''# Code generated by Headroom. DO NOT EDIT.

module "test_module" {
  source = "../modules/test"
  target_id = local.test_id

  enabled = true
  items = []
}
'''
        assert module.render() == expected

    def test_render_module_with_complex_parameters(self) -> None:
        """
        Test rendering module with all parameter types.

        This represents a realistic SCP module configuration.
        """
        module = TerraformModule(
            name="scps_security_tooling_ou",
            source="../modules/scps",
            target_id="local.security_tooling_ou_id",
            parameters=[
                TerraformParameter("deny_ec2_ami_owner", True),
                TerraformParameter("ec2_allowed_ami_owners", ["111111111111"]),
                TerraformParameter("deny_ec2_imds_v1", False),
                TerraformParameter("deny_eks_create_cluster_without_tag", True),
                TerraformParameter("deny_iam_user_creation", True),
                TerraformParameter("iam_allowed_users", []),
                TerraformParameter("deny_rds_unencrypted", True),
            ],
            comment="OU Security Tooling"
        )

        result = module.render()

        assert 'module "scps_security_tooling_ou" {' in result
        assert 'source = "../modules/scps"' in result
        assert "target_id = local.security_tooling_ou_id" in result
        assert "deny_ec2_ami_owner = true" in result
        assert '"111111111111"' in result
        assert "deny_ec2_imds_v1 = false" in result
        assert "deny_eks_create_cluster_without_tag = true" in result
        assert "deny_iam_user_creation = true" in result
        assert "iam_allowed_users = []" in result
        assert "deny_rds_unencrypted = true" in result
        assert "# Auto-generated SCP Terraform configuration for OU Security Tooling" in result

    def test_render_rcp_module(self) -> None:
        """
        Test rendering RCP module configuration.

        This represents a realistic RCP module configuration.
        """
        module = TerraformModule(
            name="rcps_root",
            source="../modules/rcps",
            target_id="local.root_ou_id",
            parameters=[
                TerraformParameter("deny_ecr_third_party_access", True),
                TerraformParameter("ecr_third_party_access_account_ids_allowlist", ["111111111111", "222222222222"]),
                TerraformParameter("deny_sts_third_party_assumerole", True),
                TerraformParameter("sts_third_party_assumerole_account_ids_allowlist", ["111111111111"]),
                TerraformParameter("deny_sqs_third_party_access", False),
                TerraformParameter("deny_s3_third_party_access", True),
                TerraformParameter("s3_third_party_access_account_ids_allowlist", ["111111111111"]),
            ],
            comment="Organization Root",
            policy_type="RCP"
        )

        result = module.render()

        assert 'module "rcps_root" {' in result
        assert 'source = "../modules/rcps"' in result
        assert "target_id = local.root_ou_id" in result
        assert "deny_ecr_third_party_access = true" in result
        assert "ecr_third_party_access_account_ids_allowlist" in result
        assert "deny_sts_third_party_assumerole = true" in result
        assert "deny_sqs_third_party_access = false" in result
        assert "deny_s3_third_party_access = true" in result
        assert "# Auto-generated RCP Terraform configuration for Organization Root" in result
        assert "# Generated by Headroom based on third-party account analysis" in result


class TestTerraformParameterEdgeCases:
    """Test edge cases for TerraformParameter."""

    def test_render_with_quotes_in_string(self) -> None:
        """A quote inside a value is escaped, so the literal still closes where it should."""
        param = TerraformParameter("description", 'test "value"')
        assert param.render() == '  description = "test \\"value\\""'

    def test_render_list_items_are_escaped(self) -> None:
        """Every item in a list is a quoted literal and gets the same rule."""
        param = TerraformParameter("names", ['a"b', "c\\d"])
        assert param.render() == '  names = [\n    "a\\"b",\n    "c\\\\d",\n  ]'

    def test_render_zero_value(self) -> None:
        """Test rendering zero integer value."""
        param = TerraformParameter("count", 0)
        assert param.render() == "  count = 0"

    def test_render_negative_number(self) -> None:
        """Test rendering negative number."""
        param = TerraformParameter("offset", -5)
        assert param.render() == "  offset = -5"

    def test_render_list_with_empty_strings(self) -> None:
        """Test rendering list containing empty strings."""
        param = TerraformParameter("values", ["", "test", ""])
        expected = '  values = [\n    "",\n    "test",\n    "",\n  ]'
        assert param.render() == expected


class TestTerraformModuleEdgeCases:
    """Test edge cases for TerraformModule."""

    def test_render_with_quoted_target_id(self) -> None:
        """Test module with quoted target_id reference."""
        module = TerraformModule(
            name="test_module",
            source="../modules/test",
            target_id='"test-account-id"',
            parameters=[]
        )
        result = module.render()
        assert 'target_id = "test-account-id"' in result

    def test_render_with_special_chars_in_name(self) -> None:
        """Test module with special characters in name."""
        module = TerraformModule(
            name="test_module_123",
            source="../modules/test",
            target_id="local.test_id",
            parameters=[]
        )
        result = module.render()
        assert 'module "test_module_123"' in result

    def test_render_empty_comment(self) -> None:
        """Test module with empty string comment (should be treated as no comment)."""
        module = TerraformModule(
            name="test_module",
            source="../modules/test",
            target_id="local.test_id",
            parameters=[],
            comment=""
        )
        result = module.render()
        assert "# Auto-generated" not in result

    def test_render_always_opens_with_the_generated_marker(self) -> None:
        """The marker is what reconciliation claims a file by, so it is unconditional."""
        with_comment = TerraformModule(
            name="test_module",
            source="../modules/test",
            target_id="local.test_id",
            parameters=[],
            comment="Organization Root"
        )
        without_comment = TerraformModule(
            name="test_module",
            source="../modules/test",
            target_id="local.test_id",
            parameters=[]
        )

        for module in (with_comment, without_comment):
            assert module.render().splitlines()[0] == GENERATED_MARKER
