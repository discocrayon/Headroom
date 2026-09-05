"""
Terraform data models for structured representation.

Separates Terraform structure from rendering logic for better testability.
"""

import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, TypeAlias

from ..constants import GENERATED_MARKER

TerraformScalarValue: TypeAlias = bool | int | float | str
TerraformListValue: TypeAlias = list[str]
TerraformValue: TypeAlias = TerraformScalarValue | TerraformListValue

# Everything one renderer means its output directory to hold, keyed by
# destination path. Rendered, not yet written, and not yet the whole run's
# plan -- the compiler merges the three renderers' output into that.
RenderedTerraformFiles: TypeAlias = Dict[Path, str]


def hcl_escape(value: str) -> str:
    """
    Escape a value for placement inside an HCL quoted string.

    HCL's quoted-template grammar gives a backslash, a double quote, a
    newline, a carriage return, and a tab an escape each, and reads `${` and
    `%{` as the start of an interpolation or a directive unless the first
    character is doubled. Every value Headroom renders between double quotes
    passes through here, once, at the line that emits the quotes. OU and
    account names are the values that carry arbitrary text: AWS Organizations
    validates both with `[\\s\\S]*`, and they once reached the file verbatim,
    where a quote or a backslash failed `terraform plan` after the file was
    written and a `${` was interpolated.

    The backslash rule runs first so the backslashes the other rules add are
    not themselves doubled. Other control characters are left as they are:
    the names this renders are constrained to the ASCII range, and none is
    typed in practice.

    Args:
        value: The text to place between double quotes

    Returns:
        The text with every HCL escape applied, without the quotes
    """
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace("${", "$${")
        .replace("%{", "%%{")
    )


def comment_text(value: str) -> str:
    """
    Keep text placed in an HCL comment on one line.

    A comment has no escape syntax, so a line break is its one hazard: left
    in, the rest of the text lands as a bare top-level line of HCL. Every
    line break becomes the two-character sequence `\\n`, so the comment
    stays on one line and still shows where the break was. Every comment
    Headroom renders from a name passes through here: the parameter-level
    `TerraformComment`, and the module header that names an account or OU.

    Args:
        value: The comment's text, without the `#`

    Returns:
        The text with every line break replaced
    """
    return value.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\\n")


@dataclass
class TerraformParameter:
    """
    Single parameter in a Terraform module.

    A string value, alone or in a list, is data: it is escaped in full by
    `hcl_escape` when rendered, so a quote, a backslash, a line break, or a
    `${` in it reaches Terraform as that text. A producer that composes
    template text - literal segments around an interpolation that must stay
    live - sets `template` and takes on escaping its own data segments. An
    allowlist whose definition sets `restores_account_ids` is the one such
    value: `_replace_account_id_in_arn` in `parameters.py` puts a reference
    to the account's local where the account ID was and escapes every other
    segment.

    Attributes:
        key: Parameter name
        value: Parameter value (bool, str, list, or other type)
        template: True when a string value is HCL template text the producer
            already escaped, whose interpolations must survive rendering
    """
    key: str
    value: TerraformValue
    template: bool = False

    def _literal(self, value: str) -> str:
        """
        Return a string value as an HCL quoted literal.

        Args:
            value: The string value

        Returns:
            The value between double quotes, escaped unless it is template text
        """
        body = value if self.template else hcl_escape(value)
        return f'"{body}"'

    def render(self) -> str:
        """
        Render parameter as HCL.

        Returns:
            HCL-formatted parameter string with proper indentation
        """
        if isinstance(self.value, bool):
            return f"  {self.key} = {str(self.value).lower()}"
        if isinstance(self.value, list):
            if not self.value:
                return f"  {self.key} = []"
            items = [f"    {self._literal(item)}," for item in self.value]
            return f"  {self.key} = [\n" + "\n".join(items) + "\n  ]"
        if isinstance(self.value, str):
            return f"  {self.key} = {self._literal(self.value)}"
        return f"  {self.key} = {self.value}"


# Counts the comment text alone. TerraformComment.render prepends "  # ", so
# a wrapped line occupies 76 columns in the rendered file.
COMMENT_WIDTH = 72

# `textwrap` breaks only on ASCII whitespace, so this is the one space it
# will not break on. `unbreakable` puts it into a name and `wrap_comment`
# takes it back out, so it never reaches a rendered file.
UNBREAKABLE_SPACE = "\u00a0"


def unbreakable(text: str) -> str:
    """
    Keep a name on one comment line, whatever it contains.

    An account named `Prod US` landing on the width would otherwise render
    as `Prod` on one line and `US` on the next, two strings neither of which
    is an account. With its space made non-breaking the name travels through
    `wrap_comment` as one word, and comes out with its space restored.

    Args:
        text: A name that must not be split

    Returns:
        The name with every space made non-breaking
    """
    return text.replace(" ", UNBREAKABLE_SPACE)


def wrap_comment(text: str) -> List[str]:
    """
    Split comment text into lines that fit beside the code they explain.

    A hyphen is not a break opportunity here, and neither is a space inside
    a name `unbreakable` protected. Account and OU names are hyphenated
    throughout and some carry spaces, and `security-tooling-` on one line
    with `production)` on the next is two strings, neither of which is a
    name a reader can grep the file for. A name longer than the width
    overflows its line for the same reason: a corrupted identifier is worse
    than a long comment.

    Args:
        text: The whole comment, on one line

    Returns:
        The lines, each within the comment width but for a single name that
        exceeds it on its own, with every protected space an ordinary one
    """
    lines = textwrap.wrap(
        text, width=COMMENT_WIDTH, break_long_words=False, break_on_hyphens=False
    )
    return [line.replace(UNBREAKABLE_SPACE, " ") for line in lines]


@dataclass
class TerraformComment:
    """
    Comment line in a Terraform module.

    Used for section headers and explanatory comments within module blocks.
    Empty text creates a blank line for spacing.

    A comment has no escape syntax, so a line break in its text is the one
    hazard; `comment_text` folds it, and the module header folds its own
    text the same way.

    Attributes:
        text: Comment text (without the # prefix). Empty string creates blank line.
    """
    text: str

    def render(self) -> str:
        """
        Render comment as HCL.

        Returns:
            HCL-formatted comment string with proper indentation, or empty string for blank lines
        """
        if not self.text:
            return ""
        return f"  # {comment_text(self.text)}"


TerraformElement: TypeAlias = TerraformParameter | TerraformComment


@dataclass
class TerraformModule:
    """
    Structured representation of Terraform module.

    Attributes:
        name: Module instance name
        source: Module source path
        target_id: Target resource identifier
        parameters: List of module parameters and comments
        comment: Optional comment describing the module
        policy_type: Type of policy (SCP or RCP) for comment generation
    """
    name: str
    source: str
    target_id: str
    parameters: list[TerraformElement]
    comment: str = ""
    policy_type: str = "SCP"

    def render(self) -> str:
        """
        Render module as Terraform HCL.

        Returns:
            Complete Terraform module block as string
        """
        # Unconditional, and first: reconciliation identifies its own output by
        # this exact line, so a file rendered without it can never be cleaned up.
        lines: list[str] = [GENERATED_MARKER]

        if self.comment:
            lines.append(
                f"# Auto-generated {self.policy_type} Terraform configuration for {comment_text(self.comment)}"
            )
            if self.policy_type == "RCP":
                lines.append("# Generated by Headroom based on third-party account analysis")
            else:
                lines.append("# Generated by Headroom based on compliance analysis")
        lines.append("")

        lines.extend([
            f'module "{hcl_escape(self.name)}" {{',
            f'  source = "{hcl_escape(self.source)}"',
            f'  target_id = {self.target_id}',
            ""
        ])

        for element in self.parameters:
            lines.append(element.render())

        lines.append("}")
        return "\n".join(lines) + "\n"
