"""
Tests for the crypto module.

These are the tests that matter most. If something in here breaks, the
vault is either unreadable or, worse, readable by somebody who should not
have it.
"""

import unittest

from tests.support import TempFolderTestCase

from securevault import crypto, constants


class SaltTests(unittest.TestCase):

    def test_salt_is_random_and_the_right_size(self):
        first = crypto.generate_salt()
        second = crypto.generate_salt()
        self.assertEqual(len(first), constants.SALT_BYTES)
        self.assertNotEqual(first, second)

    def test_salt_text_round_trip(self):
        salt = crypto.generate_salt()
        text = crypto.salt_to_text(salt)
        self.assertEqual(crypto.salt_from_text(text), salt)

    def test_broken_salt_text_raises(self):
        with self.assertRaises(crypto.CryptoError):
            crypto.salt_from_text("this is not base64 at all!!!")


class KeyDerivationTests(unittest.TestCase):

    def test_same_password_and_salt_give_same_key(self):
        salt = crypto.generate_salt()
        first = crypto.derive_key("hello there", salt, 20000)
        second = crypto.derive_key("hello there", salt, 20000)
        self.assertEqual(first, second)

    def test_different_salt_gives_different_key(self):
        salt_one = crypto.generate_salt()
        salt_two = crypto.generate_salt()
        first = crypto.derive_key("hello there", salt_one, 20000)
        second = crypto.derive_key("hello there", salt_two, 20000)
        self.assertNotEqual(first, second)

    def test_different_password_gives_different_key(self):
        salt = crypto.generate_salt()
        first = crypto.derive_key("hello there", salt, 20000)
        second = crypto.derive_key("hello there!", salt, 20000)
        self.assertNotEqual(first, second)

    def test_key_is_32_bytes(self):
        salt = crypto.generate_salt()
        key = crypto.derive_key("hello there", salt, 20000)
        self.assertEqual(len(key), 32)

    def test_short_salt_refused(self):
        with self.assertRaises(crypto.CryptoError):
            crypto.derive_key("hello", b"short")

    def test_tiny_iteration_count_refused(self):
        with self.assertRaises(crypto.CryptoError):
            crypto.derive_key("hello", crypto.generate_salt(), 10)


class EncryptionTests(unittest.TestCase):

    def setUp(self):
        self.key = crypto.derive_key("a test password", crypto.generate_salt(), 20000)

    def test_round_trip_text(self):
        token = crypto.encrypt_text("the secret is 42", self.key)
        self.assertNotIn("the secret is 42", token)
        self.assertEqual(crypto.decrypt_text(token, self.key), "the secret is 42")

    def test_round_trip_dictionary(self):
        data = {"site": "GitHub", "tags": ["work"], "count": 3}
        token = crypto.encrypt_dict(data, self.key)
        self.assertEqual(crypto.decrypt_dict(token, self.key), data)

    def test_wrong_key_fails(self):
        other_key = crypto.derive_key("another password", crypto.generate_salt(), 20000)
        token = crypto.encrypt_text("secret", self.key)
        with self.assertRaises(crypto.WrongPasswordError):
            crypto.decrypt_text(token, other_key)

    def test_tampered_token_fails(self):
        token = crypto.encrypt_text("secret", self.key)
        # Change one character in the middle of the token. Fernet
        # authenticates the content, so this has to fail.
        middle = len(token) // 2
        replacement = "A" if token[middle] != "A" else "B"
        broken = token[:middle] + replacement + token[middle + 1:]
        with self.assertRaises(crypto.CryptoError):
            crypto.decrypt_text(broken, self.key)

    def test_empty_string_round_trip(self):
        token = crypto.encrypt_text("", self.key)
        self.assertEqual(crypto.decrypt_text(token, self.key), "")


class VerifierTests(unittest.TestCase):

    def setUp(self):
        self.key = crypto.derive_key("a test password", crypto.generate_salt(), 20000)

    def test_verifier_matches_itself(self):
        verifier = crypto.make_verifier(self.key)
        self.assertTrue(crypto.verifier_matches(verifier, self.key))

    def test_verifier_rejects_other_key(self):
        verifier = crypto.make_verifier(self.key)
        other = crypto.derive_key("different", crypto.generate_salt(), 20000)
        self.assertFalse(crypto.verifier_matches(verifier, other))

    def test_purposes_are_separate(self):
        self.assertNotEqual(
            crypto.make_verifier(self.key, "vault"),
            crypto.make_verifier(self.key, "recovery"),
        )

    def test_empty_stored_verifier_is_false(self):
        self.assertFalse(crypto.verifier_matches("", self.key))
        self.assertFalse(crypto.verifier_matches(None, self.key))

    def test_fingerprint_is_eight_characters(self):
        fingerprint = crypto.fingerprint(self.key)
        self.assertEqual(len(fingerprint), 8)
        self.assertEqual(fingerprint, fingerprint.upper())


class RecoveryCodeTests(unittest.TestCase):

    def test_code_has_the_expected_shape(self):
        code = crypto.generate_recovery_code()
        parts = code.split("-")
        self.assertEqual(len(parts), crypto.RECOVERY_GROUPS)
        for part in parts:
            self.assertEqual(len(part), crypto.RECOVERY_GROUP_SIZE)

    def test_codes_are_different(self):
        self.assertNotEqual(
            crypto.generate_recovery_code(),
            crypto.generate_recovery_code(),
        )

    def test_normalise_removes_noise(self):
        self.assertEqual(
            crypto.normalise_recovery_code("abcd-efgh jkmn"),
            "ABCDEFGHJKMN",
        )

    def test_short_recovery_code_refused(self):
        with self.assertRaises(crypto.CryptoError):
            crypto.derive_recovery_key("ABCD", crypto.generate_salt())


class ShareCodeTests(unittest.TestCase):

    def setUp(self):
        self.entry = {
            "site": "GitHub",
            "url": "https://github.com",
            "username": "amit",
            "password": "a very secret password",
            "notes": "this should not be shared",
            "id": "abc123",
        }

    def test_round_trip(self):
        code = crypto.make_share_code(self.entry, "share passphrase")
        self.assertTrue(code.startswith(constants.SHARE_CODE_PREFIX))
        opened = crypto.open_share_code(code, "share passphrase")
        self.assertEqual(opened["site"], "GitHub")
        self.assertEqual(opened["password"], "a very secret password")

    def test_notes_are_not_shared(self):
        code = crypto.make_share_code(self.entry, "share passphrase")
        opened = crypto.open_share_code(code, "share passphrase")
        self.assertNotIn("notes", opened)
        self.assertNotIn("this should not be shared", code)

    def test_wrong_passphrase_fails(self):
        code = crypto.make_share_code(self.entry, "share passphrase")
        with self.assertRaises(crypto.ShareCodeError):
            crypto.open_share_code(code, "different passphrase")

    def test_garbage_fails(self):
        with self.assertRaises(crypto.ShareCodeError):
            crypto.open_share_code("not a share code", "whatever")

    def test_too_short_passphrase_refused(self):
        with self.assertRaises(crypto.CryptoError):
            crypto.make_share_code(self.entry, "abc")


class StorageCryptoIntegrationTests(TempFolderTestCase):
    """A couple of tests that need real files."""

    def test_vault_token_survives_a_round_trip(self):
        salt = crypto.generate_salt()
        key = crypto.derive_key("hello", salt, 20000)
        token = crypto.encrypt_dict({"entries": [{"site": "x"}]}, key)
        self.data_directory.write_vault_token(token)
        read_back = self.data_directory.read_vault_token()
        self.assertEqual(crypto.decrypt_dict(read_back, key), {"entries": [{"site": "x"}]})

    def test_vault_file_does_not_contain_the_site_name(self):
        salt = crypto.generate_salt()
        key = crypto.derive_key("hello", salt, 20000)
        token = crypto.encrypt_dict({"entries": [{"site": "VerySecretSite"}]}, key)
        self.data_directory.write_vault_token(token)

        with open(self.data_directory.vault_path, "rb") as handle:
            raw = handle.read()

        self.assertNotIn(b"VerySecretSite", raw)


if __name__ == "__main__":
    unittest.main()
