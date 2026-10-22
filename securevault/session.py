"""
session.py

One open session. This is what exists between typing the master password and
closing the program.

It holds three things:

  * the open vault, and therefore the key
  * the settings, which live in meta.json
  * the clock used for the auto lock

The auto lock is the least glamorous feature in this whole project and the
most likely to save you. The scenario is simple: you unlock the vault, get
distracted, walk away, and somebody else sits at your computer. The vault
was open. After the timeout a session refuses to do anything else, and the
menu sends you back to the login screen.

Every action the user takes calls touch(). The main menu checks
should_auto_lock() before drawing itself. That is all there is to it. There
is no thread, no signal handler, and no cleverness, because cleverness in a
timer is how you end up with a program that locks in the middle of saving.
"""

import time

from . import utils, crypto, clipboard, constants


class Session:
    """An unlocked vault, plus everything around it."""

    def __init__(self, data_directory, open_vault_object, meta, is_decoy=False):
        self.data_directory = data_directory
        self.vault = open_vault_object
        self.meta = meta
        self.is_decoy = bool(is_decoy)
        self.started_at = utils.now_iso()
        self.last_activity = time.monotonic()
        self.locked = False
        self.messages = []  # small notes shown once at the top of the menu

    # -- settings -------------------------------------------------------

    def setting(self, name, default=None):
        """Read a setting from meta.json with a fallback."""
        settings = self.meta.get("settings") or {}
        if name in settings:
            return settings[name]
        return default

    def set_setting(self, name, value, save=True):
        """Change a setting and write it to disk."""
        if "settings" not in self.meta or not isinstance(self.meta["settings"], dict):
            self.meta["settings"] = {}
        self.meta["settings"][name] = value
        if save:
            self.data_directory.write_meta(self.meta)
        return value

    @property
    def auto_lock_seconds(self):
        value = self.setting("auto_lock_seconds", constants.DEFAULT_AUTO_LOCK_SECONDS)
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = constants.DEFAULT_AUTO_LOCK_SECONDS
        if value < constants.MIN_AUTO_LOCK_SECONDS:
            value = constants.MIN_AUTO_LOCK_SECONDS
        if value > constants.MAX_AUTO_LOCK_SECONDS:
            value = constants.MAX_AUTO_LOCK_SECONDS
        return value

    @property
    def clipboard_seconds(self):
        value = self.setting("clipboard_seconds", constants.DEFAULT_CLIPBOARD_SECONDS)
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = constants.DEFAULT_CLIPBOARD_SECONDS
        return max(0, min(300, value))

    # -- auto lock ------------------------------------------------------

    def touch(self):
        """Record that the user just did something."""
        self.last_activity = time.monotonic()

    def idle_seconds(self):
        return int(time.monotonic() - self.last_activity)

    def seconds_until_lock(self):
        return max(0, self.auto_lock_seconds - self.idle_seconds())

    def should_auto_lock(self):
        """
        True when the idle time has passed the limit.

        The check happens at the top of the menu loop, never in the middle of
        an operation, so a slow password change cannot be interrupted by the
        lock and leave a half written file.
        """
        return self.seconds_until_lock() <= 0

    def lock(self):
        """
        Close the vault.

        The key is replaced with None rather than left lying around. Python
        cannot truly erase a string from memory, and a determined attacker
        with a debugger can find it, but dropping the reference is the best
        a script can do and it is much better than nothing.
        """
        self.locked = True
        self.vault.key = None
        self.meta = {}
        clipboard.cancel_pending_wipe()
        return True

    # -- convenience ----------------------------------------------------

    def log(self, event, detail=""):
        """
        Add an entry to the audit log and save meta.json.

        Nothing is logged while the decoy vault is open. The audit log lives
        in meta.json, which both vaults share, and writing decoy activity into
        it would mean a person who was handed the decoy could read the real
        vault's history. Not logging at all is the simplest way to keep the
        two separate.
        """
        if self.is_decoy:
            return

        try:
            self.data_directory.log_and_save(self.meta, event, detail)
        except Exception:
            # Logging must never break the thing it is logging about.
            pass

    def note(self, message):
        """Leave a short message to show at the top of the next menu."""
        self.messages.append(str(message))

    def take_messages(self):
        """Return and clear the pending messages."""
        messages = self.messages
        self.messages = []
        return messages

    def copy_password(self, entry):
        """
        Copy an entry's password to the clipboard and mark it as used.

        Returns (ok, message). The caller prints the message, because the
        caller is the one that knows whether the screen is in a weird state.
        """
        try:
            clipboard.copy_text(entry["password"], self.clipboard_seconds)
        except clipboard.ClipboardError as problem:
            return False, str(problem)

        self.vault.mark_used(entry["id"])
        self.log("password_copied", entry["site"])
        return True, clipboard.copy_hint(self.clipboard_seconds)

    def copy_text(self, text, what="text"):
        """Copy something that is not a password (a username, a url)."""
        try:
            clipboard.copy_text(text, self.clipboard_seconds)
        except clipboard.ClipboardError as problem:
            return False, str(problem)
        return True, what + " copied. Cleared in " + str(self.clipboard_seconds) + " seconds."

    def key_fingerprint(self):
        """The short fingerprint of the open vault's key."""
        if self.vault.key is None:
            return "locked"
        return crypto.fingerprint(self.vault.key)

    def stats_line(self):
        """A short description of the session, used in the status bar."""
        return (str(self.vault.count()) + " entries, "
                + str(self.vault.trash_count()) + " in trash")

    def finish(self):
        """Called when the program exits."""
        clipboard.cancel_pending_wipe()
        self.locked = True
        if self.vault is not None:
            self.vault.key = None
