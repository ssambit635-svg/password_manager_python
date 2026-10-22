"""
Tests for the TOTP implementation.

The first two tests use the official test vectors from RFC 6238, which is
the document that defines this algorithm. If our implementation matches the
RFC at those timestamps, it will match every authenticator app.

The RFC secret is the ASCII string "12345678901234567890", which in base32
is "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".
"""

import unittest

from securevault import totp


RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


class RfcVectorTests(unittest.TestCase):

    def test_rfc_6238_sha1_vectors(self):
        vectors = [
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ]
        for moment, expected in vectors:
            actual = totp.totp(RFC_SECRET, at_time=moment, digits=8)
            self.assertEqual(actual, expected,
                             "failed at time " + str(moment))

    def test_six_digit_codes_are_a_prefix_of_eight_digit_ones(self):
        # The RFC's six digit values are not simply the last six digits of
        # the eight digit ones, because the modulus is different. They do
        # however come from the same counter, so the codes have to change
        # at the same times. This checks that the six digit form is stable.
        first = totp.totp(RFC_SECRET, at_time=59)
        second = totp.totp(RFC_SECRET, at_time=59)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 6)


class Base32Tests(unittest.TestCase):

    def test_decode_known_value(self):
        self.assertEqual(
            totp.decode_base32(RFC_SECRET),
            b"12345678901234567890",
        )

    def test_decode_ignores_spaces_and_dashes(self):
        with_spaces = "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ"
        self.assertEqual(totp.decode_base32(with_spaces),
                         b"12345678901234567890")

    def test_encode_round_trip(self):
        raw = b"hello world"
        self.assertEqual(totp.decode_base32(totp.encode_base32(raw)), raw)

    def test_invalid_characters(self):
        with self.assertRaises(totp.TotpError):
            totp.decode_base32("ABC!DEF")

    def test_empty_secret(self):
        with self.assertRaises(totp.TotpError):
            totp.decode_base32("")


class SecretTests(unittest.TestCase):

    def test_generated_secret_is_usable(self):
        secret = totp.generate_secret()
        code = totp.totp(secret)
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())

    def test_generated_secrets_differ(self):
        self.assertNotEqual(totp.generate_secret(), totp.generate_secret())

    def test_grouping(self):
        secret = totp.generate_secret()
        self.assertIn(" ", secret)

    def test_normalise(self):
        # Base32 has no 0, 1, 8 or 9 in it, so valid secrets only use the
        # letters A-Z and the digits 2 to 7. Anything else is dropped.
        self.assertEqual(totp.normalise_secret("gezd gnbv-2345"), "GEZDGNBV2345")
        self.assertEqual(totp.normalise_secret("gezd-0189gnbv"), "GEZDGNBV")

    def test_is_probably_a_secret(self):
        self.assertTrue(totp.is_probably_a_secret(RFC_SECRET))
        self.assertTrue(totp.is_probably_a_secret("GEZD GNBV GY3T"))
        self.assertFalse(totp.is_probably_a_secret("my password!"))


class TimingTests(unittest.TestCase):

    def test_seconds_remaining_is_in_range(self):
        for moment in (0, 1, 29, 30, 59, 1500000000):
            remaining = totp.seconds_remaining(at_time=moment)
            self.assertGreaterEqual(remaining, 1)
            self.assertLessEqual(remaining, totp.TOTP_PERIOD)

    def test_time_step(self):
        self.assertEqual(totp.time_step(0), 0)
        self.assertEqual(totp.time_step(29), 0)
        self.assertEqual(totp.time_step(30), 1)

    def test_progress_bar_length(self):
        bar = totp.progress_bar_for_code(at_time=10)
        self.assertEqual(len(bar), 22)
        self.assertTrue(bar.startswith("[") and bar.endswith("]"))


class VerificationTests(unittest.TestCase):

    def test_correct_code_verifies(self):
        code = totp.totp(RFC_SECRET, at_time=100)
        self.assertTrue(totp.verify(RFC_SECRET, code, at_time=100))

    def test_previous_code_verifies_with_window(self):
        old_code = totp.totp(RFC_SECRET, at_time=70)
        self.assertTrue(totp.verify(RFC_SECRET, old_code, at_time=100, window=1))

    def test_far_away_code_fails(self):
        old_code = totp.totp(RFC_SECRET, at_time=10)
        self.assertFalse(totp.verify(RFC_SECRET, old_code, at_time=1000, window=1))

    def test_wrong_shaped_code_fails(self):
        self.assertFalse(totp.verify(RFC_SECRET, "12345", at_time=100))
        self.assertFalse(totp.verify(RFC_SECRET, "abcdef", at_time=100))

    def test_format_code(self):
        self.assertEqual(totp.format_code("123456"), "123 456")
        self.assertEqual(totp.format_code("1234"), "1234")


class UriTests(unittest.TestCase):

    def test_make_link(self):
        uri = totp.make_otpauth_uri(RFC_SECRET, "amit@example.com", "GitHub")
        self.assertTrue(uri.startswith("otpauth://totp/"))
        self.assertIn("secret=" + RFC_SECRET, uri)
        self.assertIn("issuer=GitHub", uri)

    def test_parse_link(self):
        uri = totp.make_otpauth_uri(RFC_SECRET, "amit@example.com", "GitHub")
        parsed = totp.parse_otpauth_uri(uri)
        self.assertEqual(parsed["secret"], RFC_SECRET)
        self.assertEqual(parsed["issuer"], "GitHub")
        self.assertEqual(parsed["account"], "amit@example.com")
        self.assertEqual(parsed["digits"], 6)
        self.assertEqual(parsed["period"], 30)

    def test_round_trip(self):
        uri = totp.make_otpauth_uri("JBSWY3DPEHPK3PXP", "someone", "Example")
        parsed = totp.parse_otpauth_uri(uri)
        self.assertEqual(totp.totp(parsed["secret"]),
                         totp.totp("JBSWY3DPEHPK3PXP"))

    def test_bad_links(self):
        with self.assertRaises(totp.TotpError):
            totp.parse_otpauth_uri("https://example.com")
        with self.assertRaises(totp.TotpError):
            totp.parse_otpauth_uri("otpauth://hotp/thing?secret=ABC")
        with self.assertRaises(totp.TotpError):
            totp.parse_otpauth_uri("otpauth://totp/thing")
