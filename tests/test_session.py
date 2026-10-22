"""
Tests for the session: settings, the auto lock clock, and locking.

The auto lock is the feature most likely to break quietly, because it is a
timer and timers are hard to test without waiting. The trick used here is to
move the session's last activity timestamp into the past by hand. No sleeping
required.
"""

from tests.support import TempFolderTestCase

from securevault import session as session_module, clipboard, constants


class SessionTests(TempFolderTestCase):

    def setUp(self):
        TempFolderTestCase.setUp(self)
        self.open_vault, self.meta, self.code = self.make_vault()
        self.entry = self.open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        self.session = session_module.Session(
            self.data_directory, self.open_vault, self.meta
        )

    def tearDown(self):
        self.session.finish()
        TempFolderTestCase.tearDown(self)

    # -- settings ------------------------------------------------------

    def test_default_auto_lock(self):
        self.assertEqual(self.session.auto_lock_seconds,
                         constants.DEFAULT_AUTO_LOCK_SECONDS)

    def test_setting_is_persisted(self):
        self.session.set_setting("auto_lock_seconds", 120)
        meta = self.data_directory.read_meta()
        self.assertEqual(meta["settings"]["auto_lock_seconds"], 120)

    def test_auto_lock_is_clamped(self):
        self.session.set_setting("auto_lock_seconds", 1)
        self.assertEqual(self.session.auto_lock_seconds,
                         constants.MIN_AUTO_LOCK_SECONDS)

        self.session.set_setting("auto_lock_seconds", 999999)
        self.assertEqual(self.session.auto_lock_seconds,
                         constants.MAX_AUTO_LOCK_SECONDS)

    def test_broken_setting_falls_back(self):
        self.session.set_setting("auto_lock_seconds", "not a number")
        self.assertEqual(self.session.auto_lock_seconds,
                         constants.DEFAULT_AUTO_LOCK_SECONDS)

    def test_clipboard_seconds_are_clamped(self):
        self.session.set_setting("clipboard_seconds", -5)
        self.assertEqual(self.session.clipboard_seconds, 0)
        self.session.set_setting("clipboard_seconds", 1000)
        self.assertEqual(self.session.clipboard_seconds, 300)

    # -- the clock -----------------------------------------------------

    def test_fresh_session_is_not_idle(self):
        self.assertFalse(self.session.should_auto_lock())
        self.assertGreater(self.session.seconds_until_lock(), 0)

    def test_idle_session_locks(self):
        self.session.set_setting("auto_lock_seconds", constants.MIN_AUTO_LOCK_SECONDS)
        self.session.last_activity -= (constants.MIN_AUTO_LOCK_SECONDS + 1)
        self.assertTrue(self.session.should_auto_lock())
        self.assertEqual(self.session.seconds_until_lock(), 0)

    def test_touch_resets_the_clock(self):
        self.session.set_setting("auto_lock_seconds", constants.MIN_AUTO_LOCK_SECONDS)
        self.session.last_activity -= (constants.MIN_AUTO_LOCK_SECONDS + 1)
        self.session.touch()
        self.assertFalse(self.session.should_auto_lock())
        self.assertLess(self.session.idle_seconds(), 2)

    # -- locking -------------------------------------------------------

    def test_lock_drops_the_key(self):
        self.assertIsNotNone(self.session.vault.key)
        self.session.lock()
        self.assertTrue(self.session.locked)
        self.assertIsNone(self.session.vault.key)

    def test_fingerprint(self):
        fingerprint = self.session.key_fingerprint()
        self.assertEqual(len(fingerprint), 8)

        self.session.lock()
        self.assertEqual(self.session.key_fingerprint(), "locked")

    # -- messages and stats --------------------------------------------

    def test_notes_are_delivered_once(self):
        self.session.note("first")
        self.session.note("second")
        self.assertEqual(self.session.take_messages(), ["first", "second"])
        self.assertEqual(self.session.take_messages(), [])

    def test_stats_line(self):
        line = self.session.stats_line()
        self.assertIn("1 entries", line)
        self.assertIn("0 in trash", line)

    # -- clipboard -----------------------------------------------------

    def test_copy_failure_is_reported_not_raised(self):
        if clipboard.is_available():
            self.skipTest("a clipboard tool exists on this machine")

        ok, message = self.session.copy_password(self.entry)
        self.assertFalse(ok)
        self.assertIn("clipboard", message.lower())

    def test_copying_marks_the_entry_used(self):
        if not clipboard.is_available():
            self.skipTest("no clipboard tool on this machine")

        ok, message = self.session.copy_password(self.entry)
        self.assertTrue(ok)
        self.assertEqual(self.entry["use_count"], 1)


class LoggingTests(TempFolderTestCase):

    def test_log_writes_to_meta(self):
        open_vault, meta, code = self.make_vault()
        session = session_module.Session(self.data_directory, open_vault, meta)
        session.log("something_happened", "a detail")

        reloaded = self.data_directory.read_meta()
        self.assertEqual(reloaded["audit_log"][-1]["event"], "something_happened")
        self.assertEqual(reloaded["audit_log"][-1]["detail"], "a detail")

    def test_decoy_sessions_do_not_touch_the_shared_audit_log(self):
        open_vault, meta, code = self.make_vault()
        before = len(meta.get("audit_log", []))

        decoy = session_module.Session(
            self.data_directory, open_vault, meta, is_decoy=True
        )
        decoy.log("decoy_activity", "should not be written")

        reloaded = self.data_directory.read_meta()
        self.assertEqual(len(reloaded.get("audit_log", [])), before)

    def test_log_survives_a_broken_meta(self):
        open_vault, meta, code = self.make_vault()
        session = session_module.Session(self.data_directory, open_vault, meta)
        session.meta = {"audit_log": "not a list"}
        # Should not raise. Logging must never break what it is logging.
        session.log("event", "detail")
