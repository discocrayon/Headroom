"""
The account a modern IAM unique ID encodes.

A KMS grant can name its grantee by bare unique ID rather than by ARN,
which reads as naming no account at all. An identifier in the current
format carries its owning account in the eight characters after the
prefix, so the account can be read back here rather than by calling IAM
with credentials the analysis does not hold. The adjacent iam/ package
holds the modules that call the IAM API; this one calls nothing and is
arithmetic on a string, which is why it sits beside policy_documents.py
instead.

The guarantee runs one way only. A None result says the encoding does not
resolve the identifier, not that the identifier is legacy: a value
decoding past 999999999999 is neither legacy nor resolvable. An account
handed back is evidence that the identifier is in the current format
rather than proof of it, because the format is marked by that one bit and
a legacy identifier carrying it set would decode to a plausible, wrong
account - which would be allowlisted in a generated RCP while the real
grantee stayed denied. The one legacy identifier on record carries J
where the bit would be, rank 9, below the threshold. A single value is an
observation and not a property.

The encoding is reverse-engineered from published research rather than an
AWS-supported contract, and AWS could change it without notice. Such a
change would not fail; it would mis-attribute silently. That research
covers the AKIA and ASIA access key IDs. AROA and AIDA reusing the same
encoding is an inference from the one published AROA whose account is
also on record, and tests/test_aws_iam_unique_ids.py holds both it and
the access key vectors.
https://awsteele.com/blog/2020/09/26/aws-access-key-format.html
"""

import re
from typing import Literal, Optional

# The alphabet and the two patterns stay module-level, so the module reads
# as one piece, but out of __all__ to say they are not the entry point:
# decode_account_id does not re-validate, so a consumer that matched a
# pattern itself and skipped iam_unique_id_kind would decode a shape
# nothing had checked. __all__ governs only `import *`, which appears
# nowhere in this repository, so this records intent and enforces nothing.
__all__ = [
    "IAMUniqueIDKind",
    "decode_account_id",
    "iam_unique_id_kind",
]

# The alphabet AWS encodes identifiers in, which omits 0, 1, 8, and 9.
AWS_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

# The two prefixes IAM documents for principal unique IDs, each followed by
# exactly seventeen characters of the alphabet above. A lowercase copy, a
# wrong length, or a role-session suffix is not a match - but that is
# fullmatch's doing in iam_unique_id_kind, not the anchors': `$` also
# matches before a trailing newline, so `re.match` on these patterns would
# accept a body with one welded on.
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids
IAM_ROLE_UNIQUE_ID_PATTERN = re.compile(r"^AROA[A-Z2-7]{17}$")
IAM_USER_UNIQUE_ID_PATTERN = re.compile(r"^AIDA[A-Z2-7]{17}$")

# What UnresolvedKMSGrantFinding.principal_kind records. Both values are
# written verbatim into the results file as unresolved_grants[].principal_kind,
# which the check's specification enumerates, so they are part of the contract
# operators, greps, and downstream tooling read those files by. Headroom's own
# readers take only the summary block, so renaming one would fail no test -
# which is why the constraint is written down here.
IAMUniqueIDKind = Literal["iam_role_unique_id", "iam_user_unique_id"]

# Characters in the AROA and AIDA prefixes, and in the run after it that
# carries all but the lowest bit of the account.
_PREFIX_LENGTH = 4
_ACCOUNT_CHARACTERS = 8


def _base32_value(encoded: str) -> int:
    """
    Read a run of AWS Base32 characters, most significant first.

    Args:
        encoded: Characters, every one of them in AWS_BASE32_ALPHABET

    Returns:
        The number the run spells

    Raises:
        ValueError: If a character is outside the alphabet, which means the
            caller passed something it had not matched against the patterns
    """
    value = 0

    for character in encoded:
        value = value * len(AWS_BASE32_ALPHABET) + AWS_BASE32_ALPHABET.index(character)

    return value


# Where the account encoding begins, and equal to 2 ** 39: the top bit of
# the forty-bit field the eight characters spell. It is a one-bit format
# flag rather than a threshold, so the comparison below tests that flag and
# the subtraction clears it. An identifier with the bit clear predates the
# encoding and its characters are random.
#
# The rejection is the one rule in this module with no code behind it. The
# post's own implementation masks and shifts unconditionally and has no
# notion of an unsupported identifier; rejecting below the flag is our
# reading of its prose about the legacy format.
_ACCOUNT_ENCODING_OFFSET = _base32_value("QAAAAAAA")

# An account ID is twelve digits. Forty bits of account space reach
# 2 * (2 ** 39 - 1) + 1, which is 1099511627775, so a decoding can land far
# outside the accounts AWS can issue. Nothing below zero can be reached,
# because a value under the offset is turned away before the subtraction,
# and zero itself is turned away in decode_account_id.
_ACCOUNT_DIGITS = 12
_LARGEST_ACCOUNT_ID = 10 ** _ACCOUNT_DIGITS - 1

# The account's lowest bit is displaced out of the eight-character field
# and into the character after it, which carries it as its own highest.
# That displacement is why the field is doubled: the field holds the
# account's upper thirty-nine bits. A rank at or above Q's - halfway up the
# alphabet - sets the bit that was moved.
_LOW_BIT_RANK = AWS_BASE32_ALPHABET.index("Q")


def iam_unique_id_kind(principal: str) -> Optional[IAMUniqueIDKind]:
    """
    Classify an IAM unique ID, or return None for any other shape.

    Strict on purpose. A value that merely resembles one - lowercase, the
    wrong length, a digit the alphabet omits - is not an identifier AWS
    could have issued, and reading an account out of one would allowlist
    an account nothing names. A session suffix is turned away for a
    different reason: AROA followed by seventeen characters, a colon, and
    a session name is a shape AWS does issue - CloudTrail's principalId
    among other places - and its seventeen body characters carry the same
    encoding. Nothing documents ListGrants returning that form, so
    decoding it would rest on a guess about where it came from, and the
    caller aborts the run on everything this turns away.

    Args:
        principal: A principal string, such as a grant's GranteePrincipal

    Returns:
        "iam_role_unique_id" for an AROA prefix, "iam_user_unique_id" for
        AIDA, or None
    """
    if IAM_ROLE_UNIQUE_ID_PATTERN.fullmatch(principal):
        return "iam_role_unique_id"

    if IAM_USER_UNIQUE_ID_PATTERN.fullmatch(principal):
        return "iam_user_unique_id"

    return None


def decode_account_id(unique_id: str) -> Optional[str]:
    """
    Return the twelve-digit account a modern IAM unique ID encodes.

    None when the encoding does not support the identifier: the format bit
    is clear, putting the value below the offset, which is the legacy
    random format, or the decoding lands on zero or past 999999999999,
    neither of which any account holds. The converse does not hold. An account handed back is evidence that the
    identifier is in the current format rather than proof of it - only the
    one bit saying so was set - and the module docstring states what a
    wrong account would cost.

    The shape is not re-checked here, so the caller must have matched
    IAM_ROLE_UNIQUE_ID_PATTERN or IAM_USER_UNIQUE_ID_PATTERN first, which
    is what iam_unique_id_kind does. Two shorter strings behave
    differently. One under eight body characters cannot reach the offset,
    so it is reported as unsupported and cannot be told apart from a
    genuine legacy identifier. One of exactly eight at or above QAAAAAAA
    clears that test and then raises on the ninth character it does not
    have.

    Args:
        unique_id: A value iam_unique_id_kind has classified

    Returns:
        The account ID, zero-padded to twelve digits, or None

    Raises:
        ValueError: If a character is outside AWS_BASE32_ALPHABET
        IndexError: If there is no ninth character after the prefix
    """
    body = unique_id[_PREFIX_LENGTH:]
    encoded = _base32_value(body[:_ACCOUNT_CHARACTERS])

    if encoded < _ACCOUNT_ENCODING_OFFSET:
        return None

    account = 2 * (encoded - _ACCOUNT_ENCODING_OFFSET)

    if AWS_BASE32_ALPHABET.index(body[_ACCOUNT_CHARACTERS]) >= _LOW_BIT_RANK:
        account += 1

    # Zero is rejected for the reason the top of the range is: a decoding
    # no account can hold is no account. It is the one result inside the
    # twelve digits that qualifies, because AWS publishes no smallest issued
    # ID and a floor above zero would be a guess at where accounts start.
    if account == 0 or account > _LARGEST_ACCOUNT_ID:
        return None

    return f"{account:0{_ACCOUNT_DIGITS}d}"
