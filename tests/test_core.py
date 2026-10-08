import unittest

from stringprep_saslprep import saslprep, SASLprepError


class TestSASLprepHappyPath(unittest.TestCase):
    def test_ascii_passes_through(self):
        self.assertEqual(saslprep("user"), "user")

    def test_empty_string_returns_empty(self):
        self.assertEqual(saslprep(""), "")

    def test_simple_space_preserved(self):
        self.assertEqual(saslprep("a b"), "a b")

    def test_non_breaking_space_mapped_to_ascii_space(self):
        self.assertEqual(saslprep("a\u00A0b"), "a b")

    def test_zero_width_joiner_removed(self):
        self.assertEqual(saslprep("ab\u200Ccd"), "abcd")

    def test_zero_width_non_joiner_removed(self):
        self.assertEqual(saslprep("ab\u200Dcd"), "abcd")

    def test_nfkc_normalization_folds_compatibility(self):
        # U+FF21 FULLWIDTH LATIN CAPITAL LETTER A normalizes to ASCII 'A'.
        self.assertEqual(saslprep("\uFF21\uFF22\uFF23"), "ABC")

    def test_case_is_not_folded(self):
        # SASLprep does not casefold; it only normalizes.
        self.assertEqual(saslprep("User"), "User")

    def test_combining_sequence_normalized(self):
        # U+0041 U+0300 has a precomposed NFKC form U+00C0.
        self.assertEqual(saslprep("A\u0300"), "\u00C0")


class TestSASLprepProhibited(unittest.TestCase):
    def test_ascii_control_rejected(self):
        with self.assertRaises(SASLprepError):
            saslprep("a\u0000b")

    def test_delete_control_rejected(self):
        with self.assertRaises(SASLprepError):
            saslprep("a\u007Fb")

    def test_private_use_rejected(self):
        with self.assertRaises(SASLprepError):
            saslprep("a\uE000b")

    def test_supplementary_private_use_rejected(self):
        with self.assertRaises(SASLprepError):
            saslprep("a\U000F0000b")

    def test_surrogate_rejected(self):
        with self.assertRaises(SASLprepError):
            saslprep("a\uD800b")

    def test_non_character_code_point_rejected(self):
        with self.assertRaises(SASLprepError):
            saslprep("a\uFFFEb")

    def test_non_character_plane_end_rejected(self):
        with self.assertRaises(SASLprepError):
            saslprep("a\uFFFFb")


class TestSASLprepBidi(unittest.TestCase):
    def test_pure_rtl_passes(self):
        # A string of only Hebrew letters is valid.
        self.assertEqual(saslprep("\u05D0\u05D1\u05D2"), "\u05D0\u05D1\u05D2")

    def test_mixed_bidi_without_rtl_at_ends_rejected(self):
        # Latin 'a' then Hebrew 'alef' then Latin 'b': mixed directions,
        # does not start and end with RandALCat.
        with self.assertRaises(SASLprepError):
            saslprep("a\u05D0b")

    def test_mixed_bidi_with_rtl_at_ends_passes(self):
        # Starts and ends with Hebrew, Latin in the middle: allowed.
        result = saslprep("\u05D0a\u05D1")
        self.assertEqual(result, "\u05D0a\u05D1")


class TestSASLprepTableA1(unittest.TestCase):
    def test_table_a1_code_point_rejected(self):
        # U+0220 is in Table A.1.
        with self.assertRaises(SASLprepError):
            saslprep("\u0220")


class TestSASLprepTypeChecking(unittest.TestCase):
    def test_non_string_input_raises_type_error(self):
        with self.assertRaises(TypeError):
            saslprep(b"user")

    def test_none_raises_type_error(self):
        with self.assertRaises(TypeError):
            saslprep(None)

    def test_integer_raises_type_error(self):
        with self.assertRaises(TypeError):
            saslprep(42)


class TestSASLprepErrorType(unittest.TestCase):
    def test_saslprep_error_is_value_error(self):
        self.assertTrue(issubclass(SASLprepError, ValueError))

    def test_saslprep_raises_saslprep_error_subclass(self):
        try:
            saslprep("\u0000")
        except SASLprepError:
            return
        except Exception as exc:  # noqa: BLE001 - intentional
            self.fail("expected SASLprepError, got {}".format(type(exc)))
        self.fail("expected SASLprepError, nothing raised")


if __name__ == "__main__":
    unittest.main()
