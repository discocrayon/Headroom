"""
Tests for headroom.aws.iam_unique_ids module.
"""

from headroom.aws.iam_unique_ids import decode_account_id, iam_unique_id_kind


class TestIAMUniqueIDKind:
    def test_the_prefix_names_the_kind(self) -> None:
        """AROA is a role's unique ID and AIDA is a user's."""
        assert iam_unique_id_kind("AROAAAAAAAAAAAAAAAAAA") == "iam_role_unique_id"
        assert iam_unique_id_kind("AIDAAAAAAAAAAAAAAAAAA") == "iam_user_unique_id"

    def test_a_value_that_only_resembles_a_unique_id_is_not_one(self) -> None:
        """
        The shape is anchored at both ends and exactly seventeen characters.

        A grantee that is not recognized here reaches the caller's error
        path, so recognizing a near-miss would resolve an account from a
        string AWS never issued. The anchoring is fullmatch's rather than
        the pattern's: `$` also matches before a trailing newline, so the
        pattern on its own would accept a body with one welded on.
        """
        assert iam_unique_id_kind("AROAAAAAAAAAAAAAAAAA") is None
        assert iam_unique_id_kind("AROAAAAAAAAAAAAAAAAAAA") is None
        assert iam_unique_id_kind("aroaaaaaaaaaaaaaaaaaa") is None
        assert iam_unique_id_kind("AROAAAAAAAAAAAAAAAAAA:example-session") is None
        # A valid body with a newline welded on. The pattern's own `$`
        # matches right before it, so this is the case that separates
        # fullmatch from match, and nothing else in the suite covers it.
        assert iam_unique_id_kind("AROAAAAAAAAAAAAAAAAAA\n") is None
        # AKIA names an access key, a credential rather than a principal,
        # and is the nearest-miss prefix that exists in the wild.
        assert iam_unique_id_kind("AKIAAAAAAAAAAAAAAAAAA") is None
        assert iam_unique_id_kind("AWS Internal") is None

    def test_a_digit_outside_the_alphabet_is_not_a_unique_id(self) -> None:
        """
        AWS encodes these in a Base32 alphabet that omits 0, 1, 8, and 9.

        So AROA11111111111111111 is not an identifier AWS could have issued,
        and reading one would hand the decoder a character it has no value
        for. Each of the four excluded digits stands alone in an otherwise
        valid body.
        """
        assert iam_unique_id_kind("AROA0AAAAAAAAAAAAAAAA") is None
        assert iam_unique_id_kind("AROAA1AAAAAAAAAAAAAAA") is None
        assert iam_unique_id_kind("AIDAAA8AAAAAAAAAAAAAA") is None
        assert iam_unique_id_kind("AIDAAAA9AAAAAAAAAAAAA") is None
        assert iam_unique_id_kind("AROA11111111111111111") is None


class TestDecodeAccountID:
    def test_a_modern_unique_id_carries_its_account(self) -> None:
        """The eight characters after the prefix encode the account."""
        # Derived by inverting the decoder. 111111111111 is odd, so the
        # ninth character has to set the displaced low bit, and Q is the
        # lowest rank that does. The eight before it spell half of what is
        # left, 55555555555, above the 2 ** 39 format bit - which is
        # RTXV5AHD in the alphabet.
        assert decode_account_id("AROARTXV5AHDQAAAAAAAA") == "111111111111"

    def test_the_prefix_does_not_change_the_account(self) -> None:
        """
        A user's unique ID encodes its account exactly as a role's does.

        Only the four-character prefix differs, and it sits outside the run
        that carries the account.
        """
        assert decode_account_id("AIDARTXV5AHDQAAAAAAAA") == "111111111111"

    def test_the_largest_account_decodes(self) -> None:
        """The top of the twelve-digit range is inside the encoding."""
        # Built the same way as the case above. 999999999999 is odd, so the
        # ninth character is Q again, and the eight before it spell
        # 499999999999 above the 2 ** 39 format bit, which is 6RVFFB77.
        assert decode_account_id("AROA6RVFFB77QAAAAAAAA") == "999999999999"

    def test_the_offset_itself_encodes_no_account(self) -> None:
        """
        The first value the format flag admits resolves to no account.

        Doubling zero leaves zero, so this identifier arrives at
        000000000000, which no account holds: rendered into the RCP's
        aws:PrincipalAccount condition it would match no principal, which
        is the same as saying the decoding named no grantee. The top of
        the range is already read that way, and the rejection is exactly
        as wide as the arithmetic warrants - zero and nothing above it,
        since a floor higher up would invent a minimum AWS does not
        publish.
        """
        assert decode_account_id("AROAQAAAAAAAAAAAAAAAA") is None

    def test_the_account_after_the_zero_one_keeps_its_leading_zeros(self) -> None:
        """
        One rank up the displaced low bit is an account, and it decodes.

        An account ID is twelve digits however small the number is, so the
        decoding is padded out rather than handed back as "1". This is the
        identifier nearest the rejection above, so it also pins that the
        rejection covers the zero account alone.
        """
        assert decode_account_id("AROAQAAAAAAAQAAAAAAAA") == "000000000001"

    def test_a_value_below_the_offset_encodes_no_account(self) -> None:
        """
        The legacy identifiers AWS issued before this encoding are random.

        They sit below the offset, and there is no account to read out of
        one, so the caller has to keep treating them as unresolved.
        """
        assert decode_account_id("AROAAAAAAAAAAAAAAAAAA") is None

    def test_a_value_above_the_largest_account_encodes_no_account(self) -> None:
        """
        The encoding spans more numbers than there are account IDs.

        77777777 is the top of the eight-character field, and with an A
        ninth character it decodes to 1099511627774. The general maximum is
        one higher, when the ninth character sets the low bit as well.
        Neither is an account any decoding should hand back.
        """
        assert decode_account_id("AROA77777777AAAAAAAAA") is None

    def test_the_thirteenth_character_sets_the_accounts_lowest_bit(self) -> None:
        """
        Two identifiers differing only there decode to consecutive accounts.

        The character at or above Q's rank is "2", which sorts below "A" in
        ASCII and above "Z" in this alphabet. Comparing the characters
        rather than their ranks reads it as the low half and loses the bit,
        which is a wrong account rather than a crash.
        """
        assert decode_account_id("AROARTXV5AHDPAAAAAAAA") == "111111111110"
        assert decode_account_id("AROARTXV5AHD2AAAAAAAA") == "111111111111"

    def test_the_published_vectors_decode(self) -> None:
        """
        An independent check on the whole algorithm, in both directions.

        Every other expected value in this file was produced by inverting
        this decoder, so all of them would agree with it even if the offset,
        the doubling, or the low bit were wrong. These came from outside it
        and are the only evidence here that the algorithm is the one AWS
        uses.

        The three access key IDs are what the encoding research itself
        publishes, and they pin the doubling and the place values. All
        three decode to an even account, so none of them reaches the
        displaced low bit. The two AROA values carry the rest of the claim,
        that a principal unique ID is encoded like an access key ID, which
        no AWS documentation states; the first is the only published vector
        here whose account is odd, so it is also what pins the displacement.
        """
        # Nine real values appear below and the user approved every one of
        # them: five identifiers and the four accounts they decode to. A
        # fabricated set would only re-derive this decoder's own arithmetic
        # and prove nothing. These are the whole of the sanctioned
        # exception; INV-15 covers every other identifier in this file.

        # The access key IDs and their accounts are published together in
        # https://awsteele.com/blog/2020/09/26/aws-access-key-format.html,
        # which is the research this module's arithmetic comes from.
        assert decode_account_id("ASIAY34FZKAOKMUTVV7A") == "609629065244"
        assert decode_account_id("ASIAY34FZKBNKMUTVV7A") == "609629065306"
        assert decode_account_id("ASIAY34FZKBOKMUTVV7A") == "609629065308"

        # https://awsteele.com/blog/2026/07/01/apps-can-now-impersonate-human-access-to-aws-via-iam-identity-center.html
        # prints this unique ID beside the role ARN naming its account. It
        # is the only place a published AROA and its account appear
        # together, which is why the AROA half of the claim rests on it.
        assert decode_account_id("AROA52RQV4237EYPOIPDF") == "950363612855"

        # https://awsteele.com/blog/2023/11/19/reversing-aws-iam-unique-ids.html
        # resolves this one to a real account by a means Headroom does not
        # use - a mutating bucket-policy round trip. Offline it reads as
        # None, so it is the worked example of the limitation: an account
        # exists and this module cannot reach it.
        assert decode_account_id("AROAJMD24IEMKTX6BABJI") is None
