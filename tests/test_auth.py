"""Tests for login, lockout, recovery, duress and changing the password."""

import unittest

from tests.support import TempFolderTestCase

from securevault import auth, constants, vault as vault_module


class SetupTests(TempFolderTestCase):

    def test_setup_returns_key_meta_and_code(self):
        key, meta, recovery_code = auth.setup_new_vault(
            self.data_directory, "a good long master password"
        )
        self.assertEqual(len(key), 32)
        self.assertIn("kdf", meta)
        self.assertIn("verifier", meta)
        self.assertTrue(recovery_code)

    def test_meta_file_is_written(self):
        auth.setup_new_vault(self.data_directory, "a good long master password")
        self.assertTrue(self.data_directory.meta_exists())
        meta = self.data_directory.read_meta()
        self.assertEqual(meta["kdf"]["algorithm"], "pbkdf2-hmac-sha256")

    def test_weak_passwords_are_refused(self):
        for password in ["short", "password", "aaaaaaaaaaaaaaaa", ""]:
            with self.assertRaises(auth.AuthError):
                auth.setup_new_vault(self.data_directory, password)

    def test_master_password_is_not_stored(self):
        password = "a unique master password 123"
        auth.setup_new_vault(self.data_directory, password)

        with open(self.data_directory.meta_path, "r", encoding="utf-8") as handle:
            raw = handle.read()

        self.assertNotIn(password, raw)


class UnlockTests(TempFolderTestCase):

    def setUp(self):
        TempFolderTestCase.setUp(self)
        self.key, self.meta, self.recovery_code = auth.setup_new_vault(
            self.data_directory, "a good long master password"
        )
        vault_module.Vault.create(self.data_directory, self.key, self.meta)

    def test_correct_password(self):
        key, meta = auth.unlock(self.data_directory, "a good long master password")
        self.assertEqual(key, self.key)

    def test_wrong_password(self):
        with self.assertRaises(auth.AuthError):
            auth.unlock(self.data_directory, "the wrong password")

    def test_counter_goes_up_on_success(self):
        auth.unlock(self.data_directory, "a good long master password")
        meta = self.data_directory.read_meta()
        self.assertEqual(meta["counters"]["unlocks"], 1)

    def test_failures_are_counted(self):
        with self.assertRaises(auth.AuthError):
            auth.unlock(self.data_directory, "wrong one")
        meta = self.data_directory.read_meta()
        self.assertEqual(meta["attempts"]["count"], 1)
        self.assertEqual(meta["counters"]["wrong_passwords"], 1)

    def test_lockout_after_too_many_failures(self):
        for _ in range(constants.MAX_LOGIN_ATTEMPTS):
            with self.assertRaises(auth.AuthError):
                auth.unlock(self.data_directory, "wrong one")

        with self.assertRaises(auth.LockedOutError):
            auth.unlock(self.data_directory, "wrong one")

        meta = self.data_directory.read_meta()
        locked, remaining = auth.is_locked_out(meta)
        self.assertTrue(locked)
        self.assertGreater(remaining, 0)

    def test_success_clears_the_counter(self):
        with self.assertRaises(auth.AuthError):
            auth.unlock(self.data_directory, "wrong one")
        auth.unlock(self.data_directory, "a good long master password")
        meta = self.data_directory.read_meta()
        self.assertEqual(meta["attempts"]["count"], 0)

    def test_clear_lockout_helper(self):
        for _ in range(constants.MAX_LOGIN_ATTEMPTS + 1):
            try:
                auth.unlock(self.data_directory, "wrong one")
            except auth.AuthError:
                pass
        meta = self.data_directory.read_meta()
        auth.clear_lockout(self.data_directory, meta)
        locked, remaining = auth.is_locked_out(self.data_directory.read_meta())
        self.assertFalse(locked)

    def test_no_meta_means_an_error(self):
        empty = self.storage.DataDirectory(self.temp_folder + "-missing")
        with self.assertRaises(auth.AuthError):
            auth.unlock(empty, "anything")

    def test_verify_master_password_does_not_count(self):
        self.assertTrue(auth.verify_master_password(self.meta, "a good long master password"))
        self.assertFalse(auth.verify_master_password(self.meta, "nope"))
        meta = self.data_directory.read_meta()
        self.assertEqual(meta["attempts"]["count"], 0)


class ChangePasswordTests(TempFolderTestCase):

    def setUp(self):
        TempFolderTestCase.setUp(self)
        self.open_vault, self.meta, self.recovery_code = self.make_vault(
            master_password="a good long master password"
        )
        self.entry = self.open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")

    def test_change_and_reopen(self):
        new_code = auth.change_master_password(
            self.data_directory, self.open_vault, self.meta,
            "a good long master password", "an entirely new master password"
        )
        self.assertNotEqual(new_code, self.recovery_code)

        key, meta = auth.unlock(self.data_directory, "an entirely new master password")
        reloaded = vault_module.Vault.load(self.data_directory, key, meta)
        self.assertEqual(reloaded.count(), 1)

        with self.assertRaises(auth.AuthError):
            auth.unlock(self.data_directory, "a good long master password")

    def test_wrong_current_password(self):
        with self.assertRaises(auth.AuthError):
            auth.change_master_password(
                self.data_directory, self.open_vault, self.meta,
                "not the current password", "a new master password here"
            )

    def test_same_password_refused(self):
        with self.assertRaises(auth.AuthError):
            auth.change_master_password(
                self.data_directory, self.open_vault, self.meta,
                "a good long master password", "a good long master password"
            )

    def test_weak_new_password_refused(self):
        with self.assertRaises(auth.AuthError):
            auth.change_master_password(
                self.data_directory, self.open_vault, self.meta,
                "a good long master password", "password"
            )

    def test_attachments_survive_a_password_change(self):
        blob_id = self.open_vault.attach_file(self.entry["id"], "a.txt", b"important")

        auth.change_master_password(
            self.data_directory, self.open_vault, self.meta,
            "a good long master password", "another long master password"
        )

        key, meta = auth.unlock(self.data_directory, "another long master password")
        reloaded = vault_module.Vault.load(self.data_directory, key, meta)

        # The blob gets a new id during a re-key, because the ciphertext is
        # written again under the new key. The entry knows the new id.
        reloaded_entry = reloaded.get(self.entry["id"])
        new_blob_id = reloaded_entry["attachments"][0]["id"]
        self.assertNotEqual(new_blob_id, blob_id)
        self.assertEqual(reloaded.read_attachment(self.entry["id"], new_blob_id),
                         b"important")

    def test_new_recovery_code_works(self):
        new_code = auth.change_master_password(
            self.data_directory, self.open_vault, self.meta,
            "a good long master password", "another long master password"
        )
        ok, key = auth.verify_recovery_code(self.open_vault.meta, new_code)
        self.assertTrue(ok)
        self.assertEqual(len(key), 32)


class RecoveryTests(TempFolderTestCase):

    def setUp(self):
        TempFolderTestCase.setUp(self)
        self.open_vault, self.meta, self.recovery_code = self.make_vault()
        self.open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")

    def test_verify_good_code(self):
        ok, key = auth.verify_recovery_code(self.meta, self.recovery_code)
        self.assertTrue(ok)
        self.assertEqual(key, self.open_vault.key)

    def test_verify_code_ignores_dashes_and_case(self):
        messy = self.recovery_code.replace("-", "").lower()
        ok, key = auth.verify_recovery_code(self.meta, messy)
        self.assertTrue(ok)

    def test_wrong_code(self):
        ok, key = auth.verify_recovery_code(self.meta, "AAAA-BBBB-CCCC-DDDD-EEEE")
        self.assertFalse(ok)
        self.assertIsNone(key)

    def test_reset_with_recovery(self):
        reloaded, new_code = auth.reset_with_recovery(
            self.data_directory, self.meta, self.recovery_code,
            "a replacement master password"
        )
        self.assertEqual(reloaded.count(), 1)
        self.assertNotEqual(new_code, self.recovery_code)

        key, meta = auth.unlock(self.data_directory, "a replacement master password")
        self.assertEqual(vault_module.Vault.load(self.data_directory, key, meta).count(), 1)

    def test_old_code_stops_working_after_reset(self):
        _vault, new_code = auth.reset_with_recovery(
            self.data_directory, self.meta, self.recovery_code,
            "a replacement master password"
        )
        meta = self.data_directory.read_meta()
        ok, key = auth.verify_recovery_code(meta, self.recovery_code)
        self.assertFalse(ok)

    def test_reset_with_bad_code(self):
        with self.assertRaises(auth.AuthError):
            auth.reset_with_recovery(
                self.data_directory, self.meta, "AAAA-BBBB-CCCC-DDDD-EEEE",
                "a replacement master password"
            )

    def test_regenerate_code(self):
        new_code = auth.regenerate_recovery_code(
            self.data_directory, self.meta, self.open_vault.key
        )
        ok, key = auth.verify_recovery_code(self.data_directory.read_meta(), new_code)
        self.assertTrue(ok)


class DuressTests(TempFolderTestCase):

    def setUp(self):
        TempFolderTestCase.setUp(self)
        self.open_vault, self.meta, self.recovery_code = self.make_vault()

    def test_setup_and_check(self):
        decoy, key = auth.setup_duress(
            self.data_directory, self.meta, "the duress password"
        )
        self.assertTrue(auth.has_duress(self.meta))
        self.assertEqual(auth.check_duress_password(self.meta, "the duress password"), key)
        self.assertIsNone(auth.check_duress_password(self.meta, "something else"))

    def test_duress_password_opens_a_separate_vault(self):
        decoy, key = auth.setup_duress(
            self.data_directory, self.meta, "the duress password"
        )
        decoy.add_entry("Harmless", "someone", "an ordinary looking password")

        self.open_vault.add_entry("Real Bank", "amit", "kR7#mQ2!xL9$")

        opened = auth.open_decoy_vault(self.data_directory, key, self.meta)
        self.assertEqual(opened.count(), 1)
        self.assertEqual(opened.entries[0]["site"], "Harmless")

    def test_duress_cannot_equal_master(self):
        with self.assertRaises(auth.AuthError):
            auth.setup_duress(
                self.data_directory, self.meta, "a good long master password"
            )

    def test_remove_duress(self):
        auth.setup_duress(self.data_directory, self.meta, "the duress password")
        auth.remove_duress(self.data_directory, self.meta)
        self.assertFalse(auth.has_duress(self.meta))
        self.assertFalse(self.data_directory.decoy_exists())

    def test_duress_is_not_counted_as_a_login_attempt(self):
        auth.setup_duress(self.data_directory, self.meta, "the duress password")
        auth.check_duress_password(self.meta, "the duress password")
        meta = self.data_directory.read_meta()
        self.assertEqual(meta["attempts"]["count"], 0)


class PasswordRuleTests(unittest.TestCase):

    def test_validation_messages(self):
        self.assertTrue(auth.validate_new_master_password("short"))
        self.assertTrue(auth.validate_new_master_password("aaaaaaaaa"))
        self.assertTrue(auth.validate_new_master_password("password"))
        self.assertEqual(auth.validate_new_master_password("a good long password"), [])

    def test_describe_lockout(self):
        meta = {"attempts": {"count": 0, "locked_until": None}}
        text = auth.describe_lockout(meta)
        self.assertIn(str(constants.MAX_LOGIN_ATTEMPTS), text)

    def test_attempts_left(self):
        meta = {"attempts": {"count": constants.MAX_LOGIN_ATTEMPTS - 1}}
        self.assertEqual(auth.attempts_left(meta), 1)

    def test_score_helper(self):
        self.assertGreater(auth.master_password_score("a good long password"), 30)
