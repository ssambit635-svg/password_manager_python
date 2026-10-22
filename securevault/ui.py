"""
ui.py

Every screen in the program.

This file is big, and it is big on purpose. The original project had the
menus and the logic mixed together in one 500 line file, which meant you
could not change a menu without risking the encryption. Here, the logic is
in the other modules and this file only does two things: ask questions and
print answers. When it needs to do something real, it calls a function from
another module and shows the result.

The general shape of every screen is the same:

    * show a header
    * show some information
    * offer a numbered list of actions
    * do one action
    * come back

It is not exciting, and that is the point. A terminal program should feel
predictable.
"""

import os
import time
import select
import datetime

from . import constants, utils, crypto, auth, storage, strength, generator
from . import totp, vault as vault_module, audit, backup, importers, clipboard
from . import session as session_module


class UserInterface:
    """Holds the data directory and runs the screens."""

    def __init__(self, data_directory):
        self.data_directory = data_directory
        self.session = None

    # =================================================================
    # Top level
    # =================================================================

    def run(self, show_banner=True):
        """
        Start the program.

        Three possibilities:
          * no vault at all              -> set one up
          * vault exists, locked         -> login screen
          * the user gets in             -> main menu
        """
        try:
            self.data_directory.ensure_exists()
        except storage.StorageError as problem:
            utils.error(str(problem))
            return 1

        if show_banner:
            utils.banner()
            utils.info("Vault folder: " + self.data_directory.describe())
            print("")

        try:
            if not self.data_directory.meta_exists() or not self.data_directory.vault_exists():
                if not self._first_run():
                    utils.info("No vault was created. Nothing was saved.")
                    return 0
            else:
                if not self._login():
                    utils.info("Goodbye.")
                    return 0
        except KeyboardInterrupt:
            print("")
            utils.info("Interrupted. Goodbye.")
            return 130

        try:
            while True:
                outcome = self._main_menu()

                # "locked" means the auto lock fired, which is not the same
                # as asking to quit. Offer the login screen again rather than
                # throwing the user out of the program.
                if outcome == "locked":
                    self.session = None
                    utils.print_wrapped(
                        "The vault locked itself. Log in again to carry on, "
                        "or press Ctrl-C to leave.", 70
                    )
                    if not self._login():
                        break
                    continue

                break
        except KeyboardInterrupt:
            print("")
            utils.info("Interrupted. Closing the vault.")
        finally:
            if self.session is not None:
                self.session.finish()
            clipboard.cancel_pending_wipe()

        utils.print_wrapped("The vault is closed. Clipboard timers are cancelled.", 70)
        return 0

    # =================================================================
    # First run
    # =================================================================

    def _first_run(self):
        """
        Set up a vault for the first time.

        The order matters: the master password first, because everything
        else is protected by it, and the recovery code immediately after,
        because a recovery code that is never shown is not a recovery code.
        """
        utils.header("FIRST RUN: LET US SET UP YOUR VAULT")

        utils.print_wrapped(
            "You are about to create a vault. It will live in "
            + self.data_directory.path + " and it will be encrypted with a "
            "password that you choose now. There is no way to read the vault "
            "without that password or the recovery code that comes next.",
            70
        )
        print("")

        while True:
            password = utils.ask_password("Choose a master password: ")
            if password == "":
                warning_text = "The password cannot be empty."
                utils.warning(warning_text)
                continue

            problems = auth.validate_new_master_password(password)
            if problems:
                for problem in problems:
                    utils.warning(problem)
                continue

            analysis = strength.analyse(password)
            utils.info("Strength: " + analysis["grade"] + " (" + analysis["label"]
                       + "), score " + str(analysis["score"]) + "/100.")

            if analysis["score"] < 50:
                utils.warning("That is on the weak side for a master password.")
                if not utils.ask_yes_no("Use it anyway?", default=False):
                    continue

            confirm = utils.ask_password("Type it again to confirm: ")
            if confirm != password:
                utils.error("The two passwords do not match. Let us try again.")
                continue

            break

        utils.print_wrapped(
            "A long phrase is better than a short complicated word. "
            "Write your master password down while you are setting things up, "
            "then keep that piece of paper somewhere that is not this computer.",
            70
        )
        print("")

        try:
            key, meta, recovery_code = auth.setup_new_vault(self.data_directory, password)
        except auth.AuthError as problem:
            utils.error(str(problem))
            return False
        except storage.StorageError as problem:
            utils.error(str(problem))
            return False

        open_vault_object = vault_module.Vault.create(self.data_directory, key, meta)

        utils.success("Vault created.")
        print("")
        utils.header("YOUR RECOVERY CODE")
        print("")
        utils.error("This is shown once. Write it down now.")
        print("")
        print("    " + utils.style(recovery_code, "yellow", bold=True))
        print("")
        utils.print_wrapped(
            "This code can reset your master password. It cannot be recovered "
            "if you lose it, and it will be replaced whenever you use it. "
            "Type it in later without the dashes if that is easier.",
            70
        )
        print("")

        if utils.ask_yes_no("Save an emergency kit file with this code in it?",
                            default=True):
            try:
                fingerprint = crypto.fingerprint(key)
                path = backup.write_emergency_kit(
                    self.data_directory, meta, recovery_code, fingerprint
                )
                utils.success("Emergency kit written to " + path)
                utils.warning("Print it. Then delete or move the file.")
            except backup.BackupError as problem:
                utils.error(str(problem))

        utils.pause("Press Enter once you have written the code down...")

        self.session = session_module.Session(
            self.data_directory, open_vault_object, meta
        )
        self.session.log("first_run_complete", "")
        utils.success("You are in. Here is the menu.")
        return True

    # =================================================================
    # Login
    # =================================================================

    def _login(self):
        """
        The login screen.

        It handles all three passwords:
          1. the duress password, checked first, which opens the decoy
          2. the master password
          3. the recovery route, if the master password is forgotten
        """
        utils.header("UNLOCK YOUR VAULT")

        try:
            meta = self.data_directory.read_meta()
        except storage.StorageError as problem:
            utils.error(str(problem))
            return False

        locked, remaining = auth.is_locked_out(meta)
        if locked:
            utils.error("This vault is locked for another " + utils.human_duration(remaining) + ".")
            utils.info("The lockout is stored on disk, so restarting does not clear it.")
            return False

        utils.info("Vault: " + self.data_directory.describe())
        if meta.get("counters"):
            unlocks = meta["counters"].get("unlocks", 0)
            if unlocks:
                utils.info("Unlocked " + str(unlocks) + " time(s) before.")
        print("")

        while True:
            password = utils.ask_password("Master password: ")

            if password == "":
                utils.error("Nothing was typed.")
                if not utils.ask_yes_no("Try again?", default=True):
                    return False
                continue

            # Duress first. If this is the duress password, no attempt is
            # counted and nothing is written to the log, so somebody looking
            # over your shoulder sees an ordinary login.
            duress_key = auth.check_duress_password(meta, password)
            if duress_key is not None:
                try:
                    decoy_vault = auth.open_decoy_vault(self.data_directory, duress_key, meta)
                except (auth.AuthError, vault_module.VaultError):
                    decoy_vault = vault_module.Vault.create(
                        self.data_directory, duress_key, meta, is_decoy=True
                    )
                self.session = session_module.Session(
                    self.data_directory, decoy_vault, meta, is_decoy=True
                )
                utils.success("Welcome back.")
                return True

            try:
                key, meta = auth.unlock(self.data_directory, password)
            except auth.LockedOutError as problem:
                utils.error(str(problem))
                utils.info("Wait it out, or ask the doctor command to clear the lockout.")
                return False
            except auth.AuthError as problem:
                utils.error(str(problem))
                # Re-read meta so the attempt counter we display is current.
                try:
                    meta = self.data_directory.read_meta()
                except storage.StorageError:
                    pass
                utils.info(auth.describe_lockout(meta))

                print("")
                utils.bullet("1. Try again")
                utils.bullet("2. I forgot my master password (use the recovery code)")
                utils.bullet("3. Quit")
                choice = utils.ask("Choose", default="1")

                if choice == "2":
                    if self._recovery_flow(meta):
                        return True
                    try:
                        meta = self.data_directory.read_meta()
                    except storage.StorageError:
                        return False
                    continue

                if choice == "3":
                    return False
                continue

            try:
                open_vault_object = auth.open_vault(self.data_directory, key, meta)
            except auth.AuthError as problem:
                utils.error(str(problem))
                return False

            self.session = session_module.Session(self.data_directory, open_vault_object, meta)
            utils.success("Unlocked. " + self.session.stats_line())
            return True

    def _recovery_flow(self, meta):
        """
        Reset the master password with the recovery code.

        On success the new recovery code is shown once, for the same reason
        as on first run: the old one has just been used up.
        """
        utils.header("RECOVERY")

        if not auth.has_recovery(meta):
            utils.error("This vault has no recovery code registered.")
            utils.print_wrapped(
                "Without a recovery code, a forgotten master password means "
                "the vault cannot be opened. The data is still there and "
                "still encrypted, but there is no key.",
                70
            )
            return False

        utils.print_wrapped(
            "Type the recovery code from your emergency kit. Dashes and "
            "spaces do not matter.",
            70
        )
        print("")

        code = utils.ask("Recovery code")
        if code.strip() == "":
            utils.info("Cancelled.")
            return False

        while True:
            new_password = utils.ask_password("New master password: ")
            problems = auth.validate_new_master_password(new_password)
            if problems:
                for problem in problems:
                    utils.warning(problem)
                continue
            confirm = utils.ask_password("Again: ")
            if confirm != new_password:
                utils.error("They do not match.")
                continue
            break

        try:
            open_vault_object, new_recovery_code = auth.reset_with_recovery(
                self.data_directory, meta, code, new_password
            )
        except auth.AuthError as problem:
            utils.error(str(problem))
            return False
        except vault_module.VaultError as problem:
            utils.error("The vault could not be rewritten: " + str(problem))
            return False

        self.session = session_module.Session(self.data_directory, open_vault_object, meta)

        utils.success("Master password reset. Your entries are all still here.")
        print("")
        utils.header("YOUR NEW RECOVERY CODE")
        print("")
        print("    " + utils.style(new_recovery_code, "yellow", bold=True))
        print("")
        utils.warning("The old code no longer works. Write this one down.")

        if utils.ask_yes_no("Write a new emergency kit file?", default=True):
            try:
                path = backup.write_emergency_kit(
                    self.data_directory, meta, new_recovery_code,
                    crypto.fingerprint(open_vault_object.key)
                )
                utils.success("Written to " + path)
            except backup.BackupError as problem:
                utils.error(str(problem))

        utils.pause()
        return True

    # =================================================================
    # The main menu
    # =================================================================

    def _main_menu(self):
        """
        The screen you come back to fifty times a session.

        Returns "quit" when the user asked to leave, and "locked" when the
        auto lock fired. The caller treats those two very differently.
        """
        session = self.session
        if session is None:
            return "quit"

        while True:
            if session.should_auto_lock():
                utils.warning("The vault locked itself after "
                              + utils.human_duration(session.auto_lock_seconds)
                              + " of inactivity.")
                session.lock()
                return "locked"

            session.touch()
            self._draw_main_menu()

            choice = utils.ask("Choose an option", default="0")

            if choice in ("0", "q", "quit", "exit"):
                utils.info("Closing the vault.")
                return "quit"

            elif choice == "1":
                self._screen_all_entries()
            elif choice == "2":
                self._screen_add_entry()
            elif choice == "3":
                self._screen_search()
            elif choice == "4":
                self._screen_generator()
            elif choice == "5":
                self._screen_health()
            elif choice == "6":
                self._screen_totp()
            elif choice == "7":
                self._screen_tags()
            elif choice == "8":
                self._screen_trash()
            elif choice == "9":
                self._screen_backups()
            elif choice == "10":
                self._screen_import_export()
            elif choice == "11":
                self._screen_settings()
            elif choice == "12":
                self._screen_tools()
            elif choice == "13":
                self._screen_help()
            elif choice == "14":
                self._screen_about()
            else:
                utils.warning("There is no option " + choice + ".")

    def _draw_main_menu(self):
        session = self.session
        utils.clear_screen()
        utils.header(constants.APP_NAME.upper())

        if session.is_decoy:
            # Deliberately subtle: nothing on this screen should look
            # different from the normal one to somebody watching.
            pass

        print("  " + utils.style(utils.truncate(session.vault.data.get("name", ""), 60), "grey"))
        print("  " + audit.headline(session.vault))
        print("  " + utils.style(session.stats_line()
                                + "  |  auto lock in " + utils.human_duration(session.seconds_until_lock()),
                                "grey"))
        print("")

        for message in session.take_messages():
            utils.info(message)

        self._draw_attention_line(session)

        print(utils.style("  VAULT", "cyan", bold=True))
        utils.bullet("1. All entries")
        utils.bullet("2. Add an entry")
        utils.bullet("3. Search")
        utils.bullet("4. Password generator")

        print(utils.style("  INSIGHT", "cyan", bold=True))
        utils.bullet("5. Health report")
        utils.bullet("6. Two factor codes")
        utils.bullet("7. Tags")
        utils.bullet("8. Trash")

        print(utils.style("  HOUSEKEEPING", "cyan", bold=True))
        utils.bullet("9. Backups")
        utils.bullet("10. Import and export")
        utils.bullet("11. Settings and security")
        utils.bullet("12. Tools")

        print(utils.style("  OTHER", "cyan", bold=True))
        utils.bullet("13. Help")
        utils.bullet("14. About")
        utils.bullet("0. Lock and quit")
        print("")

    def _draw_attention_line(self, session):
        """
        One line about things that need attention, or nothing at all.

        Only the three things that are actually urgent. If it listed every
        finding, it would become wallpaper.
        """
        problems = []
        if audit.common_password_entries(session.vault):
            problems.append("leaked passwords")
        if audit.reused_password_groups(session.vault):
            problems.append("reused passwords")
        if audit.expired_entries(session.vault):
            problems.append("expired entries")

        if problems:
            utils.warning("Needs attention: " + utils.join_with_commas(problems)
                          + ". See the health report (5).")

        if backup.backup_is_stale(self.data_directory):
            utils.warning("No recent backup. See Backups (9).")

        expiring = session.vault.entries_expiring_soon(3)
        if expiring:
            utils.warning(str(len(expiring)) + " entr(y/ies) expire within three days.")

    # =================================================================
    # All entries
    # =================================================================

    def _screen_all_entries(self, entries=None, title="ALL ENTRIES"):
        """A list, with a way into each entry's detail screen."""
        session = self.session
        utils.clear_screen()

        if entries is None:
            entries = session.vault.sorted_entries()

        utils.header(title)

        if not entries:
            utils.info("Nothing here yet.")
            if session.vault.is_empty():
                utils.print_wrapped(
                    "Use option 2 on the main menu to add your first entry.", 70
                )
            utils.pause()
            return

        self._print_entry_table(entries)

        utils.bullet("0. Back")
        number = utils.ask_number("Open entry number", 0, len(entries), default=0)
        if number == 0:
            return

        self._screen_entry(entries[number - 1])

    def _print_entry_table(self, entries):
        """
        Print a compact table of entries.

        Column widths are guessed from the data with caps, so a very long
        site name gets truncated instead of pushing everything off screen.
        """
        widths = [4, 26, 22, 16, 12]
        headers = ["#", "Site", "Username", "Tags", "Age"]

        rows = []
        for index, entry in enumerate(entries, start=1):
            marker = "*" if entry.get("favorite") else " "
            rows.append([
                str(index) + marker,
                entry["site"],
                entry["username"] or "-",
                ", ".join(entry["tags"]) or "-",
                utils.days_since(entry["password_changed_at"]).__str__() + "d",
            ])

        utils.table(headers, rows, widths)
        print("")
        print("  " + utils.style("* = favourite", "grey")
              + "   " + utils.style("d = days since the password changed", "grey"))
        print("")

    def _screen_entry(self, entry):
        """The detail screen for one entry."""
        session = self.session

        while True:
            utils.clear_screen()
            utils.header(entry["site"])

            if entry.get("favorite"):
                utils.info("Marked as a favourite.")
            if entry.get("expires_at"):
                utils.warning("This entry expires on " + utils.human_datetime(entry["expires_at"]))

            print("")
            self._field("Username", entry["username"] or "-")
            self._field("Password", "********  (" + str(len(entry["password"])) + " characters)")
            self._field("Address", entry["url"] or "-")
            self._field("Tags", ", ".join(entry["tags"]) or "-")
            self._field("Created", utils.human_datetime(entry["created_at"])
                        + " (" + utils.time_ago(entry["created_at"]) + ")")
            self._field("Changed", utils.human_datetime(entry["password_changed_at"])
                        + " (" + utils.time_ago(entry["password_changed_at"]) + ")")

            if entry.get("last_used_at"):
                self._field("Last used", utils.human_datetime(entry["last_used_at"])
                            + " (" + utils.time_ago(entry["last_used_at"]) + ")")
            else:
                self._field("Last used", "never")

            if entry.get("use_count"):
                self._field("Times used", str(entry["use_count"]) + " (copied or revealed)")

            analysis = strength.analyse(entry["password"], entry["site"], entry["username"])
            self._field("Strength", strength.describe_score(analysis["score"])
                        + "  " + str(analysis["score"]) + "/100")

            if entry.get("totp_secret"):
                self._field("Two factor", "a code is stored for this entry")

            if entry["notes"]:
                print("")
                print("  " + utils.style("Notes", "cyan", bold=True))
                utils.print_wrapped(entry["notes"], 70, "      ")

            if entry.get("history"):
                print("")
                print("  " + utils.style(str(len(entry["history"]))
                                         + " old password(s) kept", "grey"))

            if entry.get("attachments"):
                print("")
                print("  " + utils.style(str(len(entry["attachments"]))
                                         + " attachment(s)", "grey"))

            print("")
            utils.sub_header("ACTIONS")
            utils.bullet("1. Copy password to clipboard")
            utils.bullet("2. Show password on screen")
            utils.bullet("3. Copy username")
            utils.bullet("4. Copy address")
            utils.bullet("5. Two factor code")
            utils.bullet("6. Edit details")
            utils.bullet("7. Change password")
            utils.bullet("8. Tags")
            utils.bullet("9. Password history")
            utils.bullet("10. Attachments")
            utils.bullet("11. Share this entry")
            utils.bullet("12. Favourite: " + ("on" if entry.get("favorite") else "off"))
            utils.bullet("13. Delete")
            utils.bullet("0. Back")

            choice = utils.ask("Choose", default="0")

            if choice == "0":
                return
            elif choice == "1":
                ok, message = session.copy_password(entry)
                if ok:
                    utils.success(message)
                    utils.print_wrapped(
                        "Paste it into the site now. The clipboard clears itself.",
                        70
                    )
                else:
                    utils.error(message)
                    utils.info("Use option 2 to read it instead.")
                utils.pause()
            elif choice == "2":
                self._reveal_password(entry)
            elif choice == "3":
                if entry["username"]:
                    ok, message = session.copy_text(entry["username"], "Username")
                    utils.success(message) if ok else utils.error(message)
                else:
                    utils.warning("There is no username saved for this entry.")
                utils.pause()
            elif choice == "4":
                if entry["url"]:
                    ok, message = session.copy_text(entry["url"], "Address")
                    utils.success(message) if ok else utils.error(message)
                else:
                    utils.warning("There is no address saved for this entry.")
                utils.pause()
            elif choice == "5":
                self._screen_entry_totp(entry)
            elif choice == "6":
                self._edit_entry(entry)
            elif choice == "7":
                self._change_entry_password(entry)
            elif choice == "8":
                self._screen_entry_tags(entry)
            elif choice == "9":
                self._screen_entry_history(entry)
            elif choice == "10":
                self._screen_attachments(entry)
            elif choice == "11":
                self._screen_share(entry)
            elif choice == "12":
                new_state = session.vault.toggle_favorite(entry["id"])
                utils.success("Favourite is now " + ("on" if new_state else "off") + ".")
                utils.pause()
            elif choice == "13":
                if self._delete_entry(entry):
                    return
            else:
                utils.warning("There is no option " + choice + ".")

    def _field(self, label, value):
        print("  " + utils.style(label.ljust(13), "grey") + ": " + str(value))

    def _reveal_password(self, entry):
        """Show a password on screen for a few seconds."""
        utils.clear_screen()
        utils.header("PASSWORD FOR " + entry["site"].upper())
        print("")

        scores = strength.analyse(entry["password"], entry["site"], entry["username"])
        chunks = generator.syllables_for_pronunciation(entry["password"])

        print("  " + utils.style(entry["password"], "yellow", bold=True))
        print("")
        utils.info("Read in chunks: " + " ".join(chunks))
        utils.info("Strength: " + strength.describe_score(scores["score"]))
        print("")
        utils.warning("This is on your screen now. Look around you.")

        self.session.vault.mark_used(entry["id"])
        self.session.log("password_revealed", entry["site"])
        utils.pause("Press Enter to hide it...")
        utils.clear_screen()

    # =================================================================
    # Adding an entry
    # =================================================================

    def _screen_add_entry(self):
        session = self.session
        utils.clear_screen()
        utils.header("ADD AN ENTRY")

        site = utils.ask("Site or app name")
        if site.strip() == "":
            utils.warning("An entry without a site name is not much use. Cancelled.")
            utils.pause()
            return

        existing = [entry for entry in session.vault.entries
                    if entry["site"].lower() == site.lower()]
        if existing:
            utils.warning("You already have " + str(len(existing))
                          + " entr(y/ies) for " + site + ".")
            if not utils.ask_yes_no("Add another one anyway?", default=True):
                return

        url = utils.ask("Address (optional)")
        username = utils.ask("Username or email (optional)")

        print("")
        utils.bullet("1. Type a password")
        utils.bullet("2. Generate one now")
        utils.bullet("3. Go back")
        choice = utils.ask("Choose", default="2")

        if choice == "3":
            return

        if choice == "2":
            password = self._quick_generate()
            if password is None:
                return
        else:
            password = utils.ask_password("Password: ")
            confirm = utils.ask_password("Again: ")
            if password != confirm:
                utils.error("Those do not match. Nothing was saved.")
                utils.pause()
                return

        if password == "":
            utils.error("An empty password cannot be saved.")
            utils.pause()
            return

        analysis = strength.analyse(password, site, username)
        utils.info("Strength: " + strength.describe_score(analysis["score"]))
        if analysis["score"] < 50:
            utils.warning("That password is weak-ish.")
            for problem in analysis["problems"][:3]:
                utils.bullet(problem)
            if not utils.ask_yes_no("Save it anyway?", default=False):
                utils.info("Not saved.")
                utils.pause()
                return

        tags = utils.ask("Tags, separated by commas (optional)")
        tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()] if tags else []

        notes = utils.ask("Notes (optional)")
        expiry = self._ask_expiry()

        totp_secret = ""
        if utils.ask_yes_no("Add a two factor code for this entry?", default=False):
            totp_secret = self._ask_totp_secret()
            if totp_secret:
                try:
                    first_code = totp.totp(totp_secret)
                    utils.success("That secret works. Current code: "
                                  + totp.format_code(first_code))
                except totp.TotpError as problem:
                    utils.error("That secret did not work: " + str(problem))
                    totp_secret = ""

        try:
            entry = session.vault.add_entry(
                site=site,
                username=username,
                password=password,
                url=url,
                notes=notes,
                tags=tag_list,
                totp_secret=totp_secret,
                expires_at=expiry,
            )
        except vault_module.VaultError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        session.log("entry_added", site)
        utils.success("Saved. Entry id " + entry["id"] + ".")
        utils.pause()

    def _ask_expiry(self):
        """
        Optionally give an entry a self destruct date.

        Using days from now keeps the question short. Dates with years in
        them are ambiguous across the world, days are not.
        """
        if not utils.ask_yes_no("Should this entry delete itself after a while?",
                                default=False):
            return None

        days = utils.ask_number("Delete it after how many days", 1, 3650, default=30)
        expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)
        utils.warning("This entry will be destroyed on "
                      + utils.human_date(expires.replace(microsecond=0).isoformat())
                      + " when the vault is opened.")
        return expires.replace(microsecond=0).isoformat()

    def _ask_totp_secret(self):
        """Ask for a TOTP secret, accepting either the secret or a link."""
        utils.info("Paste the secret from the site, or the whole otpauth:// link.")
        raw = utils.ask("Secret")

        if raw.strip() == "":
            return ""

        if raw.lower().startswith("otpauth://"):
            try:
                parsed = totp.parse_otpauth_uri(raw)
                utils.success("Read the link for " + (parsed["issuer"] or "this account") + ".")
                return parsed["secret"]
            except totp.TotpError as problem:
                utils.error(str(problem))
                return ""

        if not totp.is_probably_a_secret(raw):
            utils.warning("That does not look like a Base32 secret.")
            return ""

        return totp.normalise_secret(raw)

    def _quick_generate(self):
        """Generate a password inside another flow, without leaving the screen."""
        utils.sub_header("GENERATOR")
        utils.bullet("1. Balanced, 20 characters")
        utils.bullet("2. Paranoid, 32 characters")
        utils.bullet("3. Passphrase, 5 words")
        utils.bullet("4. PIN, 6 digits")
        utils.bullet("0. Cancel")
        choice = utils.ask("Choose", default="1")

        presets = {"1": constants.PRESET_BALANCED, "2": constants.PRESET_PARANOID,
                   "3": constants.PRESET_PASSPHRASE, "4": constants.PRESET_PIN}
        if choice not in presets:
            return None

        try:
            made = generator.generate_from_preset(presets[choice])
        except generator.GeneratorError as problem:
            utils.error(str(problem))
            return None

        print("")
        print("  " + utils.style(made["password"], "yellow", bold=True))
        print("")
        utils.info(made["description"])
        self.session.log("generated", "preset " + presets[choice])

        if utils.ask_yes_no("Use this one?", default=True):
            return made["password"]
        return self._quick_generate()

    # =================================================================
    # Editing
    # =================================================================

    def _edit_entry(self, entry):
        """Edit the non-password fields of an entry."""
        utils.clear_screen()
        utils.header("EDIT " + entry["site"].upper())

        print("")
        utils.bullet("1. Site name        (" + entry["site"] + ")")
        utils.bullet("2. Username         (" + (entry["username"] or "-") + ")")
        utils.bullet("3. Address          (" + (entry["url"] or "-") + ")")
        utils.bullet("4. Tags             (" + (", ".join(entry["tags"]) or "-") + ")")
        utils.bullet("5. Notes            (" + str(len(entry["notes"])) + " characters)")
        utils.bullet("6. Two factor secret (" + ("set" if entry["totp_secret"] else "none") + ")")
        utils.bullet("7. Expiry date      (" + str(entry["expires_at"] or "none") + ")")
        utils.bullet("0. Back")
        choice = utils.ask("Which field", default="0")

        try:
            if choice == "1":
                value = utils.ask("New site name", default=entry["site"])
                self.session.vault.update_entry(entry["id"], site=value)
            elif choice == "2":
                value = utils.ask("New username", default=entry["username"])
                self.session.vault.update_entry(entry["id"], username=value)
            elif choice == "3":
                value = utils.ask("New address", default=entry["url"])
                self.session.vault.update_entry(entry["id"], url=value)
            elif choice == "4":
                current = ", ".join(entry["tags"])
                value = utils.ask("Tags, separated by commas", default=current)
                tags = [tag.strip() for tag in value.split(",") if tag.strip()]
                self.session.vault.update_entry(entry["id"], tags=tags)
            elif choice == "5":
                utils.info("Notes can be several sentences. Press Enter to finish.")
                value = utils.ask("New notes", default=entry["notes"])
                self.session.vault.update_entry(entry["id"], notes=value)
            elif choice == "6":
                secret = self._ask_totp_secret()
                self.session.vault.update_entry(entry["id"], totp_secret=secret)
            elif choice == "7":
                if entry.get("expires_at"):
                    if utils.ask_yes_no("Remove the expiry date?", default=True):
                        self.session.vault.update_entry(entry["id"], expires_at=None)
                        utils.success("Expiry removed.")
                        utils.pause()
                        return
                new_expiry = self._ask_expiry()
                self.session.vault.update_entry(entry["id"], expires_at=new_expiry)
            else:
                return
        except vault_module.VaultError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        self.session.log("entry_edited", entry["site"])
        utils.success("Saved.")
        utils.pause()

    def _change_entry_password(self, entry):
        """Replace the password, with a strength check and a history push."""
        utils.clear_screen()
        utils.header("CHANGE PASSWORD FOR " + entry["site"].upper())

        print("")
        utils.bullet("1. Type a new password")
        utils.bullet("2. Generate one")
        utils.bullet("0. Cancel")
        choice = utils.ask("Choose", default="2")

        if choice == "0":
            return

        if choice == "2":
            new_password = self._quick_generate()
            if new_password is None:
                return
        else:
            new_password = utils.ask_password("New password: ")
            again = utils.ask_password("Again: ")
            if new_password != again:
                utils.error("They do not match. Nothing changed.")
                utils.pause()
                return

        if new_password == "":
            utils.error("That was empty. Nothing changed.")
            utils.pause()
            return

        analysis = strength.analyse(new_password, entry["site"], entry["username"])
        utils.info("New strength: " + strength.describe_score(analysis["score"]))
        if analysis["score"] < 50:
            if not utils.ask_yes_no("That is weak. Use it anyway?", default=False):
                return

        try:
            self.session.vault.update_entry(entry["id"], password=new_password)
        except vault_module.VaultError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        self.session.log("password_changed", entry["site"])

        utils.success("Password changed. The old one is in the history.")
        utils.warning("The password has been changed HERE. You still have to change "
                      "it on the website itself.")
        utils.pause()

    def _screen_entry_tags(self, entry):
        """Add or remove tags on one entry."""
        utils.clear_screen()
        utils.header("TAGS FOR " + entry["site"].upper())

        if entry["tags"]:
            for tag in entry["tags"]:
                utils.bullet(tag)
        else:
            utils.info("No tags yet.")

        print("")
        utils.bullet("1. Add a tag")
        utils.bullet("2. Remove a tag")
        utils.bullet("0. Back")
        choice = utils.ask("Choose", default="0")

        try:
            if choice == "1":
                tag = utils.ask("Tag")
                if tag.strip():
                    self.session.vault.add_tag(entry["id"], tag)
                    utils.success("Added.")
            elif choice == "2":
                if not entry["tags"]:
                    return
                tag = utils.ask("Which tag")
                self.session.vault.remove_tag(entry["id"], tag)
                utils.success("Removed.")
        except vault_module.VaultError as problem:
            utils.error(str(problem))

        utils.pause()

    def _screen_entry_history(self, entry):
        """Old passwords for one entry."""
        utils.clear_screen()
        utils.header("PASSWORD HISTORY FOR " + entry["site"].upper())

        if not entry["history"]:
            utils.info("No old passwords were kept for this entry.")
            utils.pause()
            return

        rows = []
        for index, item in enumerate(entry["history"], start=1):
            rows.append([
                str(index),
                strength.mask(item.get("password", "")),
                utils.human_date(item.get("changed_at", "")),
            ])
        utils.table(["#", "Old password", "Replaced"], rows, [4, 30, 16])
        print("")
        utils.info("Passwords are kept so you can undo a mistake, not for browsing.")

        number = utils.ask_number("Reveal which one (0 to go back)", 0, len(entry["history"]),
                                  default=0)
        if number > 0:
            item = entry["history"][number - 1]
            print("")
            print("  " + utils.style(item.get("password", ""), "yellow", bold=True))
            utils.warning("If this is still used anywhere, change it there.")
        utils.pause()

    # =================================================================
    # Attachments
    # =================================================================

    def _screen_attachments(self, entry):
        """
        Store small files inside an entry.

        This screen loops, unlike the edit screen, because attaching a file
        is the sort of thing people do two or three times in a row.
        """
        while True:
            utils.clear_screen()
            utils.header("ATTACHMENTS FOR " + entry["site"].upper())

            attachments = entry.get("attachments", [])
            if attachments:
                rows = []
                for index, item in enumerate(attachments, start=1):
                    rows.append([
                        str(index),
                        item.get("name", "?"),
                        storage.human_bytes(item.get("size", 0)),
                        utils.human_date(item.get("added_at", "")),
                    ])
                utils.table(["#", "File", "Size", "Added"], rows, [4, 32, 10, 14])
            else:
                utils.info("No files attached to this entry.")

            print("")
            utils.bullet("1. Attach a file")
            utils.bullet("2. Save an attachment to disk")
            utils.bullet("3. Delete an attachment")
            utils.bullet("0. Back")
            choice = utils.ask("Choose", default="0")

            if choice == "0":
                return
            elif choice == "1":
                self._attach_file(entry)
            elif choice == "2":
                self._save_attachment(entry, attachments)
            elif choice == "3":
                self._delete_attachment(entry, attachments)

    def _attach_file(self, entry):
        path = utils.ask("Path to the file")
        path = os.path.expanduser(path.strip())

        if not os.path.isfile(path):
            utils.error("There is no file at that path.")
            utils.pause()
            return

        size = os.path.getsize(path)
        if size > vault_module.MAX_ATTACHMENT_BYTES:
            utils.error("That file is " + storage.human_bytes(size)
                        + ". The limit is 2 MB.")
            utils.pause()
            return

        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except OSError as problem:
            utils.error("Could not read the file: " + str(problem))
            utils.pause()
            return

        try:
            self.session.vault.attach_file(entry["id"], os.path.basename(path), raw)
        except vault_module.VaultError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        self.session.log("attachment_added", entry["site"])
        utils.success("Attached " + os.path.basename(path) + " (encrypted).")
        utils.pause()

    def _save_attachment(self, entry, attachments):
        if not attachments:
            utils.pause()
            return

        number = utils.ask_number("Which attachment", 1, len(attachments), default=1)
        item = attachments[number - 1]

        default_name = os.path.join(os.path.expanduser("~"), item.get("name", "attachment.bin"))
        target = utils.ask("Save it as", default=default_name)
        target = os.path.expanduser(target.strip())

        if os.path.exists(target):
            utils.error("That file already exists. Pick another name.")
            utils.pause()
            return

        try:
            raw = self.session.vault.read_attachment(entry["id"], item["id"])
        except vault_module.VaultError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        try:
            with open(target, "wb") as handle:
                handle.write(raw)
        except OSError as problem:
            utils.error("Could not write the file: " + str(problem))
            utils.pause()
            return

        utils.success("Saved to " + target)
        utils.warning("That copy is NOT encrypted. Delete it when you are done.")
        utils.pause()

    def _delete_attachment(self, entry, attachments):
        if not attachments:
            utils.pause()
            return

        number = utils.ask_number("Which attachment", 1, len(attachments), default=1)
        item = attachments[number - 1]

        if not utils.ask_yes_no("Delete " + item.get("name", "it") + " permanently?",
                                default=False):
            return

        try:
            self.session.vault.remove_attachment(entry["id"], item["id"])
        except vault_module.VaultError as problem:
            utils.error(str(problem))
        else:
            utils.success("Deleted.")
        utils.pause()

    # =================================================================
    # Deleting
    # =================================================================

    def _delete_entry(self, entry):
        """
        Delete an entry, with a confirmation that scales with how bad the
        mistake would be.

        Returns True if the entry is gone, so the caller can go back a screen
        (the detail screen no longer has an entry to show).
        """
        utils.print_wrapped(
            "This moves the entry to the trash. You can restore it from there "
            "until the trash is emptied.",
            70
        )
        if not utils.ask_yes_no("Move '" + entry["site"] + "' to the trash?",
                                default=False):
            utils.info("Nothing was deleted.")
            return False

        try:
            self.session.vault.delete_entry(entry["id"])
        except vault_module.VaultError as problem:
            utils.error(str(problem))
            utils.pause()
            return False

        self.session.log("entry_deleted", entry["site"])
        utils.success("Moved to the trash.")
        if utils.ask_yes_no("Delete it permanently instead?", default=False):
            try:
                self.session.vault.purge_entry(entry["id"])
                utils.success("Destroyed. That cannot be undone.")
            except vault_module.VaultError as problem:
                utils.error(str(problem))

        utils.pause()
        return True

    # =================================================================
    # Search
    # =================================================================

    def _screen_search(self):
        """Fuzzy search over everything."""
        utils.clear_screen()
        utils.header("SEARCH")

        utils.print_wrapped(
            "Type part of a site, a username, a tag or a note. Small typos "
            "are forgiven, so 'githb' finds GitHub.",
            70
        )

        query = utils.ask("Search for")
        if query.strip() == "":
            return

        results = self.session.vault.search(query)
        self.session.log("search", utils.truncate(query, 60))

        utils.clear_screen()
        utils.header("RESULTS FOR: " + query.upper())

        if not results:
            utils.info("Nothing matched.")
            utils.print_wrapped(
                "Tip: search only looks inside the site, username, address, "
                "tags and notes, never inside passwords.",
                70
            )
            utils.pause()
            return

        utils.info(str(len(results)) + " result(s).")
        print("")
        self._print_entry_table(results)

        number = utils.ask_number("Open which result (0 to go back)", 0, len(results), default=0)
        if number > 0:
            self._screen_entry(results[number - 1])

    # =================================================================
    # Generator
    # =================================================================

    def _screen_generator(self):
        """The generator, with presets, options and a strength readout."""
        while True:
            utils.clear_screen()
            utils.header("PASSWORD GENERATOR")

            utils.print_wrapped(
                "Every password here comes from the operating system's random "
                "source, not from Python's random module.",
                70
            )
            print("")
            utils.bullet("1. Balanced (20 characters, no look-alikes)")
            utils.bullet("2. Paranoid (32 characters, everything allowed)")
            utils.bullet("3. Passphrase (5 random words)")
            utils.bullet("4. Memorable (readable syllables)")
            utils.bullet("5. PIN")
            utils.bullet("6. Custom recipe")
            utils.bullet("7. Batch of ten")
            utils.bullet("8. Check a password's strength")
            utils.bullet("9. Password studio (repeatable)")
            utils.bullet("0. Back")
            choice = utils.ask("Choose", default="0")

            if choice == "0":
                return

            try:
                if choice in ("1", "2", "3", "4", "5"):
                    preset_map = {
                        "1": constants.PRESET_BALANCED,
                        "2": constants.PRESET_PARANOID,
                        "3": constants.PRESET_PASSPHRASE,
                        "4": constants.PRESET_MEMORABLE,
                        "5": constants.PRESET_PIN,
                    }
                    made = generator.generate_from_preset(preset_map[choice])
                    self._show_generated(made["password"], made["description"])
                elif choice == "6":
                    self._custom_recipe()
                elif choice == "7":
                    self._batch_generate()
                elif choice == "8":
                    self._strength_checker()
                elif choice == "9":
                    self._password_studio()
                else:
                    utils.warning("There is no option " + choice + ".")
            except generator.GeneratorError as problem:
                utils.error(str(problem))
                utils.pause()

    def _show_generated(self, password, description):
        """
        Show a generated password and offer to save it.

        The screen shows the password in a colour that stands out, plus its
        strength, plus a chunked version for reading out loud. Then it asks
        what to do with it, because a generated password that is never saved
        is a password lost.
        """
        utils.clear_screen()
        utils.header("YOUR NEW PASSWORD")
        print("")
        print("  " + utils.style(password, "yellow", bold=True))
        print("")

        analysis = strength.analyse(password)
        utils.info(description)
        utils.info("Length: " + str(analysis["length"])
                   + "   Strength: " + strength.describe_score(analysis["score"]))
        utils.info("Estimated time to crack offline: "
                   + analysis["crack_times"]["fast_hash"])
        utils.info("Read aloud: " + " ".join(generator.syllables_for_pronunciation(password)))

        self.session.log("generated", utils.truncate(description, 60))
        self.session.meta.setdefault("counters", {})
        self.session.meta["counters"]["generated"] = int(
            self.session.meta["counters"].get("generated", 0)
        ) + 1
        self.data_directory.write_meta(self.session.meta)

        print("")
        utils.bullet("1. Copy it")
        utils.bullet("2. Save it as a new entry")
        utils.bullet("3. Generate another")
        utils.bullet("0. Done")
        choice = utils.ask("Choose", default="0")

        if choice == "1":
            try:
                clipboard.copy_text(password, self.session.clipboard_seconds)
                utils.success(clipboard.copy_hint(self.session.clipboard_seconds))
            except clipboard.ClipboardError as problem:
                utils.error(str(problem))
            utils.pause()
        elif choice == "2":
            self._save_generated_entry(password)
        elif choice == "3":
            utils.info("Run the generator again from the menu.")

    def _save_generated_entry(self, password):
        """Save a generated password straight into the vault."""
        site = utils.ask("Which site is this for")
        if site.strip() == "":
            utils.warning("Cancelled: no site name.")
            utils.pause()
            return

        username = utils.ask("Username or email")
        url = utils.ask("Address (optional)")
        tags = utils.ask("Tags, separated by commas (optional)")
        tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()] if tags else []

        try:
            entry = self.session.vault.add_entry(
                site=site, username=username, password=password,
                url=url, tags=tag_list,
            )
        except vault_module.VaultError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        self.session.log("generated_and_saved", site)
        utils.success("Saved. Entry id " + entry["id"] + ".")
        utils.pause()

    def _custom_recipe(self):
        """Build a password from the individual options."""
        utils.sub_header("CUSTOM RECIPE")

        length = utils.ask_number("Length", 8, 128, default=24)
        use_lower = utils.ask_yes_no("Include lower case letters?", default=True)
        use_upper = utils.ask_yes_no("Include upper case letters?", default=True)
        use_digits = utils.ask_yes_no("Include numbers?", default=True)
        use_symbols = utils.ask_yes_no("Include symbols?", default=True)
        avoid = utils.ask_yes_no("Avoid letters that look alike (O and 0)?", default=False)

        password = generator.generate_password(
            length=length,
            use_lower=use_lower,
            use_upper=use_upper,
            use_digits=use_digits,
            use_symbols=use_symbols,
            avoid_ambiguous=avoid,
        )

        self._show_generated(password, "Custom recipe, " + str(length) + " characters")

    def _batch_generate(self):
        """Ten at a time, for when you are setting up a lot of accounts."""
        utils.sub_header("BATCH")

        length = utils.ask_number("Length of each", 8, 64, default=20)
        count = utils.ask_number("How many", 1, 20, default=10)

        try:
            passwords = generator.generate_batch(count, length=length)
        except generator.GeneratorError as problem:
            utils.error(str(problem))
            return

        utils.clear_screen()
        utils.header("BATCH OF " + str(count))
        print("")
        for index, password in enumerate(passwords, start=1):
            print("  " + str(index).rjust(2) + ". " + utils.style(password, "yellow"))
        print("")
        utils.warning("These are not saved anywhere. Copy the ones you need now.")
        utils.pause()

    def _strength_checker(self):
        """The standalone strength checker, for a password you are thinking about."""
        utils.clear_screen()
        utils.header("STRENGTH CHECKER")

        password = utils.ask_password("Type or paste a password: ")
        if password == "":
            return

        analysis = strength.analyse(password)
        self._print_analysis(analysis)
        utils.pause()

    def _print_analysis(self, analysis):
        """Print a strength analysis in a consistent layout."""
        utils.sub_header("RESULT")
        print("")

        colour = "green"
        if analysis["score"] < 55:
            colour = "yellow"
        if analysis["score"] < 35:
            colour = "red"

        print("  " + utils.style(analysis["grade"] + "  " + analysis["label"].upper(),
                                 colour, bold=True)
              + "   score " + str(analysis["score"]) + "/100  "
              + utils.star_rating(analysis["score"]))
        print("  " + utils.bar(analysis["score"], 100, 40) + "  " + str(analysis["score"]) + "%")
        print("")
        utils.bullet("Length: " + str(analysis["length"]) + " characters")
        utils.bullet("Character types: " + str(analysis["classes"]) + " of 4")
        utils.bullet("Estimated entropy: " + str(analysis["adjusted_bits"]) + " bits")
        print("")
        utils.bullet("Guessing online, rate limited: "
                     + analysis["crack_times"]["throttled"])
        utils.bullet("Guessing online, no limits: "
                     + analysis["crack_times"]["online"])
        utils.bullet("Guessing offline, good graphics card: "
                     + analysis["crack_times"]["fast_hash"])

        if analysis["problems"]:
            print("")
            utils.sub_header("PROBLEMS")
            for problem in analysis["problems"]:
                utils.bullet(problem, "red")

        if analysis["suggestions"]:
            print("")
            utils.sub_header("SUGGESTIONS")
            for suggestion in analysis["suggestions"]:
                utils.bullet(suggestion, "yellow")

    def _password_studio(self):
        """
        The deterministic password studio.

        This generates a password from a phrase and a label, using PBKDF2,
        without storing anything. The same two inputs always produce the same
        password. It means you can regenerate a password on a machine that
        has never seen your vault, as long as you remember the phrase.

        It also means the phrase is now as valuable as the password, and if
        you forget it, the password is gone. That is a real trade-off, and
        the screen says so before doing anything.
        """
        utils.clear_screen()
        utils.header("PASSWORD STUDIO")
        utils.print_wrapped(
            "This makes the same password every time for the same two inputs. "
            "Nothing is stored, so there is nothing to back up. There is also "
            "nothing to recover if you forget the phrase.",
            70
        )
        utils.warning("Use this for accounts you might need to get into from "
                      "a machine without your vault. Do not use it for your bank.")
        print("")

        if not utils.ask_yes_no("Continue?", default=False):
            return

        phrase = utils.ask_password("Secret phrase (not stored): ")
        if len(phrase) < 8:
            utils.warning("Use at least 8 characters for the phrase.")
            return

        label = utils.ask("What is it for (e.g. github.com)")
        if label.strip() == "":
            return

        counter = utils.ask_number("Version number (bump it to change the password)",
                                   1, 999, default=1)
        length = utils.ask_number("Length", 12, 64, default=20)
        symbols = utils.ask_yes_no("Include symbols?", default=True)
        avoid = utils.ask_yes_no("Avoid look-alike characters?", default=True)

        password = generate_deterministic_password(
            phrase, label, counter, length=length,
            use_symbols=symbols, avoid_ambiguous=avoid
        )

        analysis = strength.analyse(password)
        utils.clear_screen()
        utils.header("STUDIO RESULT")
        print("")
        print("  " + utils.style(password, "yellow", bold=True))
        print("")
        utils.info("For: " + label + "   version " + str(counter))
        utils.info("Strength: " + strength.describe_score(analysis["score"]))
        print("")
        utils.warning("Write down the phrase and the version number. Without both, "
                      "you cannot reproduce this password.")
        utils.warning("If a site forces a password change, bump the version.")
        utils.pause()

    # =================================================================
    # Health
    # =================================================================

    def _screen_health(self):
        """The full vault health report."""
        utils.clear_screen()
        utils.header("VAULT HEALTH REPORT")

        vault_object = self.session.vault
        if vault_object.is_empty():
            utils.info("There is nothing to audit yet.")
            utils.pause()
            return

        report = audit.full_report(vault_object)

        print("")
        colour = "red"
        if report["overall_score"] >= 55:
            colour = "yellow"
        if report["overall_score"] >= 75:
            colour = "green"

        print("  " + utils.style("OVERALL: " + report["grade"] + "  "
                                 + report["label"].upper(), colour, bold=True)
              + "    " + str(report["overall_score"]) + "/100")
        print("  " + utils.bar(report["overall_score"], 100, 45))
        utils.info(audit.headline(vault_object))

        print("")
        utils.table(
            ["Measure", "Value"],
            [
                ["Entries", str(report["total_entries"])],
                ["In the trash", str(report["total_trash"])],
                ["Average password score", str(report["average_score"]) + "/100"],
                ["Vault age", str(report["vault_age_days"]) + " days"],
                ["With two factor codes", str(len(report["with_two_factor"]))],
                ["Favourites", str(len(report["favourites"]))],
                ["Tags", str(len(report["tags"]))],
            ],
            [30, 24]
        )

        utils.sub_header("FINDINGS")
        self._finding_line(report["common"], "Passwords that appear in leak lists")
        self._finding_line(report["reused_groups"], "Passwords reused across accounts")
        self._finding_line(report["weak"], "Weak passwords")
        self._finding_line(report["old"], "Passwords older than "
                           + str(constants.PASSWORD_AGE_WARNING_DAYS) + " days")
        self._finding_line(report["never_used"], "Entries never used")
        self._finding_line(report["expired"], "Expired entries still present")
        self._finding_line(report["expiring_soon"], "Expiring in the next 7 days")

        utils.sub_header("WHAT TO DO, IN ORDER")
        for suggestion in audit.recommendations(report):
            utils.print_wrapped(suggestion, 70, "   ")

        if report["weak"]:
            print("")
            utils.sub_header("THE TEN WEAKEST PASSWORDS")
            rows = []
            for item in report["weak"][:10]:
                rows.append([
                    item["entry"]["site"],
                    str(item["analysis"]["score"]),
                    item["analysis"]["grade"],
                    strength.mask(item["entry"]["password"], 2),
                ])
            utils.table(["Site", "Score", "Grade", "Password"], rows, [26, 6, 6, 22])

        if report["reused_groups"]:
            print("")
            utils.sub_header("REUSED PASSWORDS")
            for group in report["reused_groups"]:
                sites = [entry["site"] for entry in group]
                print("  " + utils.style(str(len(sites)) + " accounts:", "red")
                      + " " + utils.join_with_commas(sites))

        print("")
        utils.bullet("1. Show the weakest entry")
        utils.bullet("2. Save this report to a file (no passwords)")
        utils.bullet("0. Back")
        choice = utils.ask("Choose", default="0")

        if choice == "1" and report["weak"]:
            self._screen_entry(report["weak"][0]["entry"])
        elif choice == "2":
            self._save_health_report(report)

    def _finding_line(self, items, label):
        """One line of 'found X things' in the health report."""
        count = len(items)
        if count == 0:
            print("  " + utils.style("OK", "green") + "   " + label)
        else:
            print("  " + utils.style(str(count), "yellow") + "    " + label)

    def _save_health_report(self, report):
        """Write a report with no passwords in it to a text file."""
        default = os.path.join(os.path.expanduser("~"), "vault-health.txt")
        path = utils.ask("Save as", default=default)
        path = os.path.expanduser(path.strip())

        if os.path.exists(path):
            utils.error("That file exists already.")
            utils.pause()
            return

        lines = []
        lines.append("SECUREVAULT HEALTH REPORT")
        lines.append("Generated: " + utils.human_datetime(report["generated_at"]))
        lines.append("")
        lines.append("Overall: " + report["grade"] + " (" + report["label"] + "), "
                     + str(report["overall_score"]) + "/100")
        lines.append("Entries: " + str(report["total_entries"]))
        lines.append("")
        lines.append("Findings")
        lines.append("  Leaked passwords:  " + str(len(report["common"])))
        lines.append("  Reused passwords:  " + str(len(report["reused_groups"])) + " groups")
        lines.append("  Weak passwords:    " + str(len(report["weak"])))
        lines.append("  Old passwords:     " + str(len(report["old"])))
        lines.append("  Never used:        " + str(len(report["never_used"])))
        lines.append("  Expired:           " + str(len(report["expired"])))
        lines.append("")
        lines.append("Accounts with weak passwords")
        for item in report["weak"]:
            lines.append("  " + item["entry"]["site"]
                         + " (score " + str(item["analysis"]["score"]) + ")")
        lines.append("")
        lines.append("No passwords are included in this file.")

        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
        except OSError as problem:
            utils.error("Could not write: " + str(problem))
            utils.pause()
            return

        if os.name != "nt":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass

        utils.success("Saved to " + path)
        utils.pause()

    # =================================================================
    # Two factor codes
    # =================================================================

    def _screen_totp(self):
        """A list of entries with authenticator codes."""
        utils.clear_screen()
        utils.header("TWO FACTOR CODES")

        entries = audit.entries_with_two_factor(self.session.vault)

        if not entries:
            utils.info("No entries have a two factor code stored.")
            utils.print_wrapped(
                "Open an entry, choose Edit details, then option 6 to add the "
                "secret from the site. If the site shows a QR code, look for "
                "the 'can't scan' link, which gives you the secret as text.",
                70
            )
            utils.pause()
            return

        rows = []
        for entry in entries:
            try:
                code = totp.format_code(totp.totp(entry["totp_secret"]))
            except totp.TotpError:
                code = "broken"
            rows.append([entry["site"], entry["username"] or "-", code])

        utils.table(["Site", "Username", "Current code"], rows, [28, 24, 16])
        print("")
        utils.info("Codes change every 30 seconds.")

        utils.bullet("1. Watch one in real time")
        utils.bullet("0. Back")
        choice = utils.ask("Choose", default="0")

        if choice != "1":
            return

        number = utils.ask_number("Which entry", 1, len(entries), default=1)
        self._watch_totp(entries[number - 1])

    def _screen_entry_totp(self, entry):
        """The code for one entry, optionally watched live."""
        if not entry.get("totp_secret"):
            utils.warning("No two factor secret is stored for this entry.")
            if utils.ask_yes_no("Add one now?", default=True):
                secret = self._ask_totp_secret()
                if secret:
                    try:
                        self.session.vault.update_entry(entry["id"], totp_secret=secret)
                        utils.success("Saved.")
                    except vault_module.VaultError as problem:
                        utils.error(str(problem))
            utils.pause()
            return

        self._watch_totp(entry)

    def _watch_totp(self, entry):
        """
        Show a code and a countdown, refreshing until the user presses Enter.

        select() lets us look at the keyboard without blocking on it. On
        Windows select only works on sockets, so there we fall back to a
        plain loop with a short sleep and no way to break out except Ctrl-C.
        """
        utils.clear_screen()
        utils.header("TWO FACTOR: " + entry["site"].upper())

        print("")
        print("  " + utils.style("Press Enter to stop watching.", "grey"))
        print("")

        try:
            secret = entry["totp_secret"]
            last_code = None

            while True:
                code = totp.totp(secret)
                remaining = totp.seconds_remaining()

                line_text = ("  " + utils.style(totp.format_code(code), "yellow", bold=True)
                             + "   " + totp.progress_bar_for_code()
                             + "   " + str(remaining) + "s")

                # Carriage return so the line updates in place instead of
                # filling the screen with a hundred copies of the code.
                print("\r" + line_text + " " * 10, end="", flush=True)

                if code != last_code:
                    last_code = code

                if _enter_was_pressed(1.0):
                    break

                if remaining <= 1:
                    print("")
                    print("  " + utils.style("(new code)", "grey"))

        except KeyboardInterrupt:
            pass
        except totp.TotpError as problem:
            utils.error(str(problem))

        print("")
        print("")
        self.session.log("totp_viewed", entry["site"])
        utils.pause()

    # =================================================================
    # Tags
    # =================================================================

    def _screen_tags(self):
        """Browse and manage tags."""
        while True:
            utils.clear_screen()
            utils.header("TAGS")

            tags = self.session.vault.all_tags()
            if not tags:
                utils.info("No tags are in use yet.")
                utils.print_wrapped(
                    "Tags are words you attach to entries: work, personal, "
                    "banking. Open an entry and choose Tags to add one.",
                    70
                )
                utils.pause()
                return

            rows = [[tag, str(count)] for tag, count in tags]
            utils.table(["Tag", "Entries"], rows, [30, 10])

            print("")
            utils.bullet("1. Open a tag")
            utils.bullet("2. Rename a tag")
            utils.bullet("3. Delete a tag from every entry")
            utils.bullet("0. Back")
            choice = utils.ask("Choose", default="0")

            if choice == "0":
                return

            if choice == "1":
                tag = utils.ask("Which tag")
                entries = self.session.vault.entries_with_tag(tag)
                if not entries:
                    utils.warning("There is no tag called " + tag + ".")
                    utils.pause()
                    continue
                self._screen_all_entries(entries, "TAG: " + tag.upper())

            elif choice == "2":
                old = utils.ask("Which tag")
                new = utils.ask("New name for it")
                if old.strip() and new.strip():
                    changed = self.session.vault.rename_tag_everywhere(old, new)
                    utils.success("Renamed on " + str(changed) + " entr(y/ies).")
                utils.pause()

            elif choice == "3":
                tag = utils.ask("Which tag")
                entries = self.session.vault.entries_with_tag(tag)
                if not entries:
                    utils.warning("There is no tag called " + tag + ".")
                    utils.pause()
                    continue
                if utils.ask_yes_no("Remove '" + tag + "' from "
                                    + str(len(entries)) + " entr(y/ies)?", default=False):
                    for entry in entries:
                        try:
                            self.session.vault.remove_tag(entry["id"], tag)
                        except vault_module.VaultError:
                            pass
                    utils.success("Removed.")
                utils.pause()

    # =================================================================
    # Trash
    # =================================================================

    def _screen_trash(self):
        """The trash: restore, destroy, or empty everything."""
        while True:
            utils.clear_screen()
            utils.header("TRASH")

            trash = self.session.vault.trash
            if not trash:
                utils.info("The trash is empty.")
                utils.pause()
                return

            rows = []
            for index, entry in enumerate(trash, start=1):
                rows.append([
                    str(index),
                    entry["site"],
                    entry["username"] or "-",
                    utils.time_ago(entry.get("deleted_at", "")),
                ])
            utils.table(["#", "Site", "Username", "Deleted"], rows, [4, 28, 24, 18])

            print("")
            utils.bullet("1. Restore an entry")
            utils.bullet("2. Destroy one entry for good")
            utils.bullet("3. Empty the whole trash")
            utils.bullet("0. Back")
            choice = utils.ask("Choose", default="0")

            if choice == "0":
                return
            if choice == "1":
                number = utils.ask_number("Which entry", 1, len(trash), default=1)
                entry = trash[number - 1]
                try:
                    self.session.vault.restore_entry(entry["id"])
                    utils.success(entry["site"] + " restored.")
                except vault_module.VaultError as problem:
                    utils.error(str(problem))
                utils.pause()
            elif choice == "2":
                number = utils.ask_number("Which entry", 1, len(trash), default=1)
                entry = trash[number - 1]
                if utils.ask_yes_no("Destroy '" + entry["site"] + "' permanently?",
                                    default=False):
                    try:
                        self.session.vault.purge_entry(entry["id"])
                        utils.success("Destroyed.")
                    except vault_module.VaultError as problem:
                        utils.error(str(problem))
                utils.pause()
            elif choice == "3":
                if utils.confirm_dangerous_action(
                    "EMPTY",
                    "This destroys every entry in the trash, including their attachments. "
                    "There is no undo."
                ):
                    count = self.session.vault.empty_trash()
                    self.session.log("trash_emptied", str(count) + " entries")
                    utils.success("Destroyed " + str(count) + " entr(y/ies).")
                utils.pause()

    # =================================================================
    # Backups
    # =================================================================

    def _screen_backups(self):
        """Make, verify, restore and prune backups."""
        while True:
            utils.clear_screen()
            utils.header("BACKUPS")

            described = backup.describe_backup_files(self.data_directory)

            if described:
                rows = []
                for item in described:
                    rows.append([
                        item["name"],
                        str(item["entry_count"]),
                        storage.human_bytes(item["size"]),
                        utils.human_date(item["created_at"]) if item["created_at"] else "?",
                        item["note"] or "-",
                    ])
                utils.table(["File", "Entries", "Size", "Made", "Note"],
                            rows, [30, 7, 9, 12, 18])
            else:
                utils.info("There are no backups yet.")
                utils.print_wrapped(
                    "A backup is the only protection against a dead disk. "
                    "Make one now. Use a passphrase that is different from "
                    "your master password, and write that passphrase down.",
                    70
                )

            print("")
            utils.bullet("1. Make a backup")
            utils.bullet("2. Verify a backup")
            utils.bullet("3. Restore from a backup")
            utils.bullet("4. Delete old backups")
            utils.bullet("5. Make a new emergency kit")
            utils.bullet("0. Back")
            choice = utils.ask("Choose", default="0")

            if choice == "0":
                return
            elif choice == "1":
                self._make_backup()
            elif choice == "2":
                self._verify_backup(described)
            elif choice == "3":
                self._restore_backup(described)
            elif choice == "4":
                self._prune_backups(described)
            elif choice == "5":
                self._remake_emergency_kit()

    def _make_backup(self):
        """Ask for a passphrase and write an encrypted backup."""
        utils.sub_header("NEW BACKUP")

        utils.print_wrapped(
            "Use a passphrase you can write down and keep somewhere else. "
            "Four or five random words is ideal. This passphrase is the only "
            "way to open the backup, and it is NOT your master password.",
            70
        )
        print("")

        if utils.ask_yes_no("Generate a strong passphrase for me?", default=True):
            words = utils.ask_number("How many words", 4, 8, default=5)
            passphrase = generator.generate_passphrase(words, "-", True, True)
            print("")
            print("  Backup passphrase: " + utils.style(passphrase, "yellow", bold=True))
            print("")
            utils.warning("Write this down NOW. It is not stored anywhere.")
            utils.pause("Press Enter once it is written down...")
        else:
            passphrase = utils.ask_password("Backup passphrase: ")
            confirm = utils.ask_password("Again: ")
            if passphrase != confirm:
                utils.error("They do not match. No backup was made.")
                utils.pause()
                return

        note = utils.ask("A short note for the file name listing (optional)")

        try:
            name, path = backup.make_backup(
                self.data_directory, self.session.vault, passphrase, note
            )
        except backup.BackupError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        utils.success("Backup written: " + name)
        utils.info("Location: " + path)
        utils.info("Size: " + storage.human_bytes(os.path.getsize(path)))

        utils.print_wrapped(
            "Copy this file somewhere that is not this computer. A backup on "
            "the same disk as the vault protects you from a mistake, not from "
            "a broken laptop.",
            70
        )

        if utils.ask_yes_no("Check that the backup opens right now?", default=True):
            try:
                summary = backup.verify_backup(self.data_directory, name, passphrase)
                if summary["ok"]:
                    utils.success("Verified: " + str(summary["entry_count"])
                                  + " entries read back cleanly.")
                else:
                    utils.warning("The backup opened but has odd entries:")
                    for problem in summary["problems"]:
                        utils.bullet(problem)
            except backup.BackupError as problem:
                utils.error("Verification failed: " + str(problem))

        utils.pause()

    def _verify_backup(self, described):
        if not described:
            utils.pause()
            return

        name = self._pick_backup(described)
        if name is None:
            return

        passphrase = utils.ask_password("Backup passphrase: ")
        try:
            summary = backup.verify_backup(self.data_directory, name, passphrase)
        except backup.BackupError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        utils.success("The backup opens.")
        utils.info("Made: " + utils.human_datetime(summary["created_at"]))
        utils.info("Entries: " + str(summary["entry_count"])
                   + "   Trash: " + str(summary["trash_count"]))
        utils.info("Fingerprint: " + str(summary["fingerprint"]))
        if summary["problems"]:
            utils.warning("Some entries look odd:")
            for problem in summary["problems"]:
                utils.bullet(problem)
        else:
            utils.success("Every entry has a site name and a password.")
        utils.pause()

    def _restore_backup(self, described):
        if not described:
            utils.pause()
            return

        name = self._pick_backup(described)
        if name is None:
            return

        passphrase = utils.ask_password("Backup passphrase: ")
        try:
            payload = backup.read_backup(self.data_directory, name, passphrase)
        except backup.BackupError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        count = len(payload.get("entries", []))
        utils.info("That backup contains " + str(count) + " entries.")
        print("")
        utils.bullet("1. Merge: keep what is in the vault and add what is missing")
        utils.bullet("2. Replace: throw away the vault and use the backup")
        utils.bullet("0. Cancel")
        choice = utils.ask("Choose", default="0")

        if choice == "0":
            return

        if choice == "2":
            if not utils.confirm_dangerous_action(
                "REPLACE",
                "This deletes every entry currently in the vault and puts the "
                "backup in its place. Anything added since that backup is lost."
            ):
                return
            replace = True
        else:
            replace = False

        try:
            result = backup.restore_backup(self.session.vault, payload, replace=replace)
        except backup.BackupError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        self.session.log("backup_restored", name + (" replace" if replace else " merge"))
        utils.success("Restored. Added " + str(result["added"])
                      + ", skipped " + str(result["skipped"]) + " duplicates.")
        utils.pause()

    def _prune_backups(self, described):
        if not described:
            utils.pause()
            return

        keep = utils.ask_number("How many recent backups should be kept", 1, 100, default=10)
        try:
            removed = backup.prune_old_backups(self.data_directory, keep)
        except backup.BackupError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        if not removed:
            utils.info("Nothing needed pruning.")
        else:
            utils.success("Deleted " + str(len(removed)) + " old backup(s).")
        utils.pause()

    def _pick_backup(self, described):
        """Ask which backup from the list."""
        options = [item["name"] + "   (" + str(item["entry_count"]) + " entries, "
                   + storage.human_bytes(item["size"]) + ")" for item in described]
        index = utils.ask_choice("Which backup", options)
        if index is None or index < 0:
            return None
        return described[index]["name"]

    def _remake_emergency_kit(self):
        """
        Write a fresh emergency kit by generating a new recovery code.

        The old code stops working immediately, which is the point.
        """
        utils.sub_header("NEW EMERGENCY KIT")
        utils.warning("This replaces your recovery code. The old code stops working.")
        if not utils.ask_yes_no("Continue?", default=False):
            return

        password = utils.ask_password("Master password, to confirm: ")
        if not auth.verify_master_password(self.session.meta, password):
            utils.error("That is not the master password.")
            utils.pause()
            return

        code = auth.regenerate_recovery_code(
            self.data_directory, self.session.meta, self.session.vault.key
        )
        try:
            path = backup.write_emergency_kit(
                self.data_directory, self.session.meta, code,
                crypto.fingerprint(self.session.vault.key)
            )
        except backup.BackupError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        utils.success("New kit written to " + path)
        print("")
        print("  " + utils.style(code, "yellow", bold=True))
        print("")
        utils.warning("Print it and delete the file.")
        utils.pause()

    # =================================================================
    # Import and export
    # =================================================================

    def _screen_import_export(self):
        while True:
            utils.clear_screen()
            utils.header("IMPORT AND EXPORT")

            utils.bullet("1. Import from a CSV file")
            utils.bullet("2. Import from the old version's passwords.json")
            utils.bullet("3. Export to CSV (plain text, dangerous)")
            utils.bullet("4. Export to JSON (plain text, keeps everything)")
            utils.bullet("5. Write a printable account list (no passwords)")
            utils.bullet("0. Back")
            choice = utils.ask("Choose", default="0")

            if choice == "0":
                return
            elif choice == "1":
                self._import_csv()
            elif choice == "2":
                self._import_legacy()
            elif choice == "3":
                self._export_csv()
            elif choice == "4":
                self._export_json()
            elif choice == "5":
                self._export_printable()

    def _import_csv(self):
        path = utils.ask("Path to the CSV file")
        path = os.path.expanduser(path.strip())
        if path == "":
            return

        try:
            preview = importers.preview_csv(path)
        except importers.ImportError_ as problem:
            utils.error(str(problem))
            utils.pause()
            return

        utils.sub_header("PREVIEW")
        utils.info("Rows in file: " + str(preview["row_count"]))
        utils.info("Columns recognised: " + utils.join_with_commas(sorted(preview["mapping"].keys())))

        if not preview["has_password_column"]:
            utils.error("No password column was found. This import would be useless.")
            utils.pause()
            return

        print("")
        utils.table(["Header"], [[header] for header in preview["header"]], [30])
        print("")
        if preview["samples"]:
            utils.table(["Sample row"], [[", ".join(row)] for row in preview["samples"]], [70])

        print("")
        if not utils.ask_yes_no("Import this file?", default=False):
            return

        tags = utils.ask("Add a tag to everything imported (optional)")
        default_tags = [tags.strip()] if tags.strip() else []

        try:
            result = importers.import_from_file(
                self.session.vault, path, default_tags=default_tags
            )
        except importers.ImportError_ as problem:
            utils.error(str(problem))
            utils.pause()
            return

        self.session.log("imported", str(result.get("added", 0)) + " from CSV")
        utils.success("Added " + str(result.get("added", 0))
                      + ", skipped " + str(result.get("skipped", 0)) + ".")
        utils.pause()

    def _import_legacy(self):
        utils.print_wrapped(
            "The first version of this project saved an unencrypted "
            "passwords.json file. Point me at it and I will move everything "
            "into the encrypted vault.",
            70
        )
        path = utils.ask("Path to passwords.json")
        path = os.path.expanduser(path.strip())
        if path == "":
            return

        try:
            result = importers.import_from_file(self.session.vault, path)
        except importers.ImportError_ as problem:
            utils.error(str(problem))
            utils.pause()
            return

        self.session.log("imported_legacy", str(result.get("added", 0)))
        utils.success("Imported " + str(result.get("added", 0)) + " entries.")
        utils.warning("The old file is still on disk, unencrypted. "
                      "Delete it once you are sure the import worked.")
        utils.pause()

    def _export_csv(self):
        utils.sub_header("EXPORT TO CSV")
        utils.warning("A CSV export is plain text. Any program on this computer "
                      "can read it. Anyone you email it to has all your passwords.")
        utils.print_wrapped(
            "Use this to move to another password manager, then delete the "
            "file. Do not keep it around.",
            70
        )

        if not utils.confirm_dangerous_action("EXPORT", "Type EXPORT to continue."):
            return

        default = os.path.join(os.path.expanduser("~"), "vault-export.csv")
        path = utils.ask("Save as", default=default)
        path = os.path.expanduser(path.strip())

        try:
            count = importers.export_csv(self.session.vault, path)
        except importers.ExportError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        self.session.log("exported_csv", str(count) + " entries")
        utils.success("Exported " + str(count) + " entries to " + path)
        utils.warning("Delete that file when you are done with it.")
        utils.pause()

    def _export_json(self):
        utils.sub_header("EXPORT TO JSON")
        utils.warning("Also plain text, and it keeps notes, tags and history.")

        if not utils.confirm_dangerous_action("EXPORT", "Type EXPORT to continue."):
            return

        default = os.path.join(os.path.expanduser("~"), "vault-export.json")
        path = utils.ask("Save as", default=default)
        path = os.path.expanduser(path.strip())

        try:
            count = importers.export_json(self.session.vault, path)
        except importers.ExportError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        self.session.log("exported_json", str(count) + " entries")
        utils.success("Exported " + str(count) + " entries to " + path)
        utils.pause()

    def _export_printable(self):
        default = os.path.join(os.path.expanduser("~"), "accounts.txt")
        path = utils.ask("Save as", default=default)
        path = os.path.expanduser(path.strip())

        try:
            importers.export_printable_notes(self.session.vault, path)
        except importers.ExportError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        self.session.log("exported_printable", "account list")
        utils.success("Written to " + path)
        utils.info("No passwords in that file. It is safe to print.")
        utils.pause()

    # =================================================================
    # Settings
    # =================================================================

    def _screen_settings(self):
        while True:
            utils.clear_screen()
            utils.header("SETTINGS AND SECURITY")

            # While the decoy vault is open, the settings screen must not
            # advertise the duress feature or how much history exists in the
            # real vault. It simply shows the ordinary values.
            if self.session.is_decoy:
                duress_state = "off"
                audit_state = "0 actions"
            else:
                duress_state = ("enabled" if auth.has_duress(self.session.meta) else "off")
                audit_state = str(len(self.session.meta.get("audit_log", []))) + " actions"

            utils.table(
                ["Setting", "Value"],
                [
                    ["Auto lock", utils.human_duration(self.session.auto_lock_seconds)],
                    ["Clipboard clear", str(self.session.clipboard_seconds) + " seconds"],
                    ["Vault folder", self.data_directory.describe()],
                    ["Key fingerprint", self.session.key_fingerprint()],
                    ["Recovery code", "yes" if auth.has_recovery(self.session.meta) else "NO"],
                    ["Duress password", duress_state],
                    ["Audit log", audit_state],
                ],
                [22, 44]
            )

            print("")
            utils.bullet("1. Auto lock timer")
            utils.bullet("2. Clipboard clear timer")
            utils.bullet("3. Change master password")
            utils.bullet("4. Recovery code and emergency kit")
            utils.bullet("5. Duress password and decoy vault")
            utils.bullet("6. View the audit log")
            utils.bullet("7. Run the doctor")
            utils.bullet("8. Reset the login lockout")
            utils.bullet("0. Back")
            choice = utils.ask("Choose", default="0")

            if choice == "0":
                return

            if self.session.is_decoy and choice in ("3", "4", "5"):
                # These three all touch meta.json in ways that belong to the
                # real vault. Running them from the decoy would either break
                # the real login or reveal that a decoy exists.
                utils.warning("That option is not available in this vault.")
                utils.pause()
                continue

            if choice == "1":
                self._setting_auto_lock()
            elif choice == "2":
                self._setting_clipboard()
            elif choice == "3":
                self._change_master()
            elif choice == "4":
                self._recovery_settings()
            elif choice == "5":
                self._duress_settings()
            elif choice == "6":
                self._screen_audit_log()
            elif choice == "7":
                self._screen_doctor()
            elif choice == "8":
                if utils.ask_yes_no("Clear the failed login counter?", default=True):
                    auth.clear_lockout(self.data_directory, self.session.meta)
                    utils.success("Cleared.")
                utils.pause()

    def _setting_auto_lock(self):
        seconds = utils.ask_number(
            "Lock the vault after how many seconds of inactivity",
            constants.MIN_AUTO_LOCK_SECONDS,
            constants.MAX_AUTO_LOCK_SECONDS,
            default=self.session.auto_lock_seconds,
        )
        self.session.set_setting("auto_lock_seconds", seconds)
        self.session.touch()
        utils.success("Auto lock set to " + utils.human_duration(seconds) + ".")
        utils.pause()

    def _setting_clipboard(self):
        seconds = utils.ask_number(
            "Clear the clipboard after how many seconds (0 for never)",
            0, 300, default=self.session.clipboard_seconds
        )
        self.session.set_setting("clipboard_seconds", seconds)
        if seconds == 0:
            utils.warning("The clipboard will keep passwords until something replaces them.")
        else:
            utils.success("Clipboard clears after " + str(seconds) + " seconds.")
        utils.pause()

    def _change_master(self):
        utils.sub_header("CHANGE MASTER PASSWORD")
        utils.print_wrapped(
            "Every attachment has to be re-encrypted, so this can take a "
            "second or two. Your recovery code will be replaced as well.",
            70
        )
        print("")

        current = utils.ask_password("Current master password: ")

        while True:
            new_password = utils.ask_password("New master password: ")
            problems = auth.validate_new_master_password(new_password)
            if problems:
                for problem in problems:
                    utils.warning(problem)
                continue
            analysis = strength.analyse(new_password)
            utils.info("New strength: " + strength.describe_score(analysis["score"]))
            if analysis["score"] < 60:
                if not utils.ask_yes_no("That is not very strong. Use it?", default=False):
                    continue
            confirm = utils.ask_password("Again: ")
            if confirm != new_password:
                utils.error("They do not match.")
                continue
            break

        try:
            new_code = auth.change_master_password(
                self.data_directory, self.session.vault, self.session.meta,
                current, new_password
            )
        except auth.AuthError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        utils.success("Master password changed.")
        print("")
        utils.header("YOUR NEW RECOVERY CODE")
        print("")
        print("  " + utils.style(new_code, "yellow", bold=True))
        print("")
        utils.warning("The old recovery code no longer works. Write this one down.")

        if utils.ask_yes_no("Write a new emergency kit?", default=True):
            try:
                path = backup.write_emergency_kit(
                    self.data_directory, self.session.meta, new_code,
                    crypto.fingerprint(self.session.vault.key)
                )
                utils.success("Written to " + path)
            except backup.BackupError as problem:
                utils.error(str(problem))

        utils.pause()

    def _recovery_settings(self):
        utils.clear_screen()
        utils.header("RECOVERY")

        if auth.has_recovery(self.session.meta):
            created = self.session.meta["recovery"].get("created_at", "")
            utils.info("A recovery code has been registered.")
            if created:
                utils.info("Created " + utils.human_datetime(created)
                           + " (" + utils.time_ago(created) + ").")
        else:
            utils.warning("There is no recovery code on this vault.")
            utils.print_wrapped(
                "That means a forgotten master password is a lost vault. "
                "Making one now requires the master password.",
                70
            )

        print("")
        utils.bullet("1. Write a new emergency kit (replaces the code)")
        utils.bullet("2. Check that a code works")
        utils.bullet("0. Back")
        choice = utils.ask("Choose", default="0")

        if choice == "1":
            self._remake_emergency_kit()
        elif choice == "2":
            code = utils.ask("Recovery code")
            ok, _key = auth.verify_recovery_code(self.session.meta, code)
            if ok:
                utils.success("That code works.")
            else:
                utils.error("That code does not match this vault.")
            utils.pause()

    def _duress_settings(self):
        utils.clear_screen()
        utils.header("DURESS PASSWORD")

        utils.print_wrapped(
            "A duress password is an ordinary password that opens a second, "
            "separate vault. Nothing in that vault is related to your real "
            "one. If you are ever forced to open your password manager, you "
            "type this one, and the person forcing you sees a password "
            "manager with a few boring accounts in it.",
            70
        )
        print("")
        utils.warning("This is not a replacement for the police. It is a way to "
                      "avoid a worse situation, nothing more.")

        if auth.has_duress(self.session.meta):
            utils.info("Status: enabled.")
            if utils.ask_yes_no("Turn it off and delete the decoy vault?",
                                default=False):
                auth.remove_duress(self.data_directory, self.session.meta)
                utils.success("Duress mode disabled and decoy deleted.")
                utils.pause()
            return

        utils.info("Status: not in use.")
        if not utils.ask_yes_no("Set up a duress password?", default=False):
            return

        print("")
        utils.print_wrapped(
            "Pick something you will remember under pressure, and something "
            "that is different from your master password. The decoy vault "
            "starts empty. You may want to put two or three ordinary looking "
            "entries in it, because an empty vault is suspicious.",
            70
        )
        print("")

        password = utils.ask_password("Duress password: ")
        confirm = utils.ask_password("Again: ")
        if password != confirm:
            utils.error("They do not match. Nothing was changed.")
            utils.pause()
            return

        try:
            decoy, key = auth.setup_duress(
                self.data_directory, self.session.meta, password
            )
        except auth.AuthError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        utils.success("Duress password set. The decoy vault is empty.")
        utils.info("Type the duress password on the login screen to open it.")
        utils.warning("You will not be able to tell from inside that it is the decoy, "
                      "apart from the entries being different. Keep a couple of "
                      "harmless entries in it.")
        utils.pause()

    def _screen_audit_log(self):
        utils.clear_screen()
        utils.header("AUDIT LOG")

        if self.session.is_decoy:
            utils.info("There is no action log for this vault.")
            utils.pause()
            return

        log = self.session.meta.get("audit_log", [])
        if not log:
            utils.info("Nothing recorded yet.")
            utils.pause()
            return

        rows = []
        for item in reversed(log[-60:]):
            rows.append([
                utils.human_datetime(item.get("at", "")),
                item.get("event", ""),
                utils.truncate(item.get("detail", ""), 34),
            ])
        utils.table(["When", "Event", "Detail"], rows, [20, 26, 34])
        print("")
        utils.info("Newest first. " + str(len(log)) + " recorded in total.")
        utils.info("The log records actions, never passwords.")
        utils.pause()

    # =================================================================
    # Tools
    # =================================================================

    def _screen_tools(self):
        while True:
            utils.clear_screen()
            utils.header("TOOLS")

            utils.bullet("1. Open a share code")
            utils.bullet("2. What is my key fingerprint?")
            utils.bullet("3. Show the decoy vault status")
            utils.bullet("4. Purge expired entries now")
            utils.bullet("5. Show vault file information")
            utils.bullet("0. Back")
            choice = utils.ask("Choose", default="0")

            if choice == "0":
                return
            elif choice == "1":
                self._open_share_code()
            elif choice == "2":
                print("")
                utils.info("Fingerprint: " + self.session.key_fingerprint())
                utils.print_wrapped(
                    "The fingerprint identifies the key without revealing it. "
                    "If it changes, you are opening a different vault.",
                    70
                )
                utils.pause()
            elif choice == "3":
                if self.session.is_decoy:
                    # Never confirm what this vault is. To somebody holding
                    # the decoy password, it is an ordinary empty-ish vault
                    # with no duress feature configured.
                    utils.info("No duress password is set up.")
                elif auth.has_duress(self.session.meta):
                    utils.info("A duress password is enabled.")
                    utils.info("Decoy vault file: "
                               + ("present" if self.data_directory.decoy_exists() else "missing"))
                else:
                    utils.info("No duress password is set up.")
                utils.pause()
            elif choice == "4":
                expired = self.session.vault.purge_expired()
                if expired:
                    utils.success("Removed " + str(len(expired)) + " expired entr(y/ies).")
                else:
                    utils.info("Nothing was expired.")
                utils.pause()
            elif choice == "5":
                self._vault_file_info()

    def _vault_file_info(self):
        utils.clear_screen()
        utils.header("VAULT FILE INFORMATION")

        path = self.data_directory.vault_path
        if not os.path.exists(path):
            utils.error("There is no vault file.")
            utils.pause()
            return

        size = os.path.getsize(path)
        modified = datetime.datetime.fromtimestamp(os.path.getmtime(path))

        rows = [
            ["Path", path],
            ["Size", storage.human_bytes(size)],
            ["Last written", modified.strftime("%d %b %Y, %H:%M")],
            ["Entries", str(self.session.vault.count())],
            ["Trash", str(self.session.vault.trash_count())],
            ["Attachments", str(self.data_directory.attachment_count())],
            ["Revision", str(self.session.vault.data.get("revision", 0))],
            ["Fingerprint", self.session.key_fingerprint()],
        ]
        utils.table(["Field", "Value"], rows, [18, 50])

        print("")
        utils.info("The vault file is encrypted. Its size tells you roughly "
                   "how much is in it, and nothing else.")
        utils.pause()

    def _screen_share(self, entry):
        """
        Turn one entry into a share code protected by a passphrase.

        The passphrase is separate from everything else. It should be told to
        the receiver over a different channel from the code: send the code in
        chat, say the passphrase on the phone.
        """
        utils.clear_screen()
        utils.header("SHARE " + entry["site"].upper())

        utils.print_wrapped(
            "The other person gets a blob of text and a passphrase. The blob "
            "is useless without the passphrase, so send them by different "
            "routes. The share code does not expire, so treat the passphrase "
            "as the thing that protects it.",
            70
        )
        print("")

        if utils.ask_yes_no("Generate a passphrase for me?", default=True):
            words = utils.ask_number("How many words", 4, 8, default=5)
            passphrase = generator.generate_passphrase(words, "-", True, True)
        else:
            passphrase = utils.ask_password("Sharing passphrase: ")
            confirm = utils.ask_password("Again: ")
            if passphrase != confirm:
                utils.error("They do not match.")
                utils.pause()
                return

        try:
            code = crypto.make_share_code(entry, passphrase)
        except crypto.CryptoError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        utils.clear_screen()
        utils.header("SHARE CODE")
        print("")
        utils.warning("Send this text to the other person:")
        print("")
        print(utils.style(code, "cyan"))
        print("")
        utils.warning("Tell them this passphrase separately:")
        print("")
        print("  " + utils.style(passphrase, "yellow", bold=True))
        print("")

        if utils.ask_yes_no("Copy the code to the clipboard?", default=True):
            try:
                clipboard.copy_text(code, self.session.clipboard_seconds)
                utils.success("Copied. It is long, so paste carefully.")
            except clipboard.ClipboardError as problem:
                utils.error(str(problem))

        self.session.log("share_code_made", entry["site"])
        utils.pause()

    def _open_share_code(self):
        """Paste a share code and get an entry back."""
        utils.clear_screen()
        utils.header("OPEN A SHARE CODE")
        utils.info("Paste the whole thing, starting with " + constants.SHARE_CODE_PREFIX)

        code = utils.ask("Share code")
        if code.strip() == "":
            return

        passphrase = utils.ask_password("Passphrase: ")
        try:
            payload = crypto.open_share_code(code, passphrase)
        except crypto.ShareCodeError as problem:
            utils.error(str(problem))
            utils.pause()
            return

        utils.clear_screen()
        utils.header("SHARED ENTRY")
        print("")
        self._field("Site", payload.get("site", "?"))
        self._field("Username", payload.get("username", "") or "-")
        self._field("Password", "********  (" + str(len(payload.get("password", ""))) + ")")
        if payload.get("url"):
            self._field("Address", payload["url"])
        print("")

        utils.bullet("1. Show the password")
        utils.bullet("2. Save it as a new entry")
        utils.bullet("0. Done")
        choice = utils.ask("Choose", default="0")

        if choice == "1":
            print("")
            print("  " + utils.style(payload.get("password", ""), "yellow", bold=True))
            utils.pause()
        elif choice == "2":
            try:
                self.session.vault.add_entry(
                    site=payload.get("site") or "shared entry",
                    username=payload.get("username", ""),
                    password=payload.get("password", ""),
                    url=payload.get("url", ""),
                    notes="Imported from a share code.",
                )
                utils.success("Saved.")
            except vault_module.VaultError as problem:
                utils.error(str(problem))
            utils.pause()

    # =================================================================
    # Doctor
    # =================================================================

    def _screen_doctor(self):
        """Run every environment check and print the results."""
        utils.clear_screen()
        utils.header("DOCTOR")

        findings = audit.doctor_report(
            self.data_directory, self.session.meta, self.session.vault
        )

        if self.session.is_decoy:
            # The doctor reads meta.json, which the real vault also writes.
            # The duress row would give the game away.
            findings = [item for item in findings
                        if "duress" not in item["title"].lower()]

        counts = {"ok": 0, "warn": 0, "fail": 0}
        for finding in findings:
            level = finding["level"]
            counts[level] = counts.get(level, 0) + 1

            if level == "ok":
                marker = utils.style("PASS", "green")
            elif level == "warn":
                marker = utils.style("WARN", "yellow")
            else:
                marker = utils.style("FAIL", "red")

            print("  " + marker + "  " + finding["title"].ljust(24)
                  + "  " + utils.truncate(finding["detail"], 40))

        print("")
        utils.info(str(counts["ok"]) + " passed, " + str(counts["warn"])
                   + " warnings, " + str(counts["fail"]) + " failures.")
        utils.pause()

    # =================================================================
    # Help and about
    # =================================================================

    def _screen_help(self):
        utils.clear_screen()
        utils.header("HELP")

        utils.sub_header("THE BASICS")
        utils.print_wrapped(
            "Add an entry with option 2. Everything you save is encrypted with "
            "your master password before it is written to disk. Nothing is "
            "sent anywhere: this program does not talk to the network at all.",
            70
        )

        utils.sub_header("IF YOU FORGET YOUR MASTER PASSWORD")
        utils.print_wrapped(
            "Use the recovery code that was shown when you created the vault. "
            "On the login screen, choose option 2. If you have lost both the "
            "master password and the recovery code, the vault cannot be "
            "opened. That is not a bug, it is what encryption means.",
            70
        )

        utils.sub_header("WHY THE PASSWORDS LOOK LIKE GIBBERISH")
        utils.print_wrapped(
            "Because gibberish is hard to guess. A random 20 character "
            "password is not something anybody can remember, which is exactly "
            "why it lives in the vault and not in your head.",
            70
        )

        utils.sub_header("KEYBOARD SHORTCUTS")
        utils.bullet("Ctrl-C  Stop the current operation, or leave the program")
        utils.bullet("Enter   Accept the default value shown in brackets")
        utils.bullet("0       Always means 'go back' in a list")

        utils.sub_header("FILES")
        utils.bullet("vault.enc        the encrypted vault")
        utils.bullet("meta.json        settings, salts and the audit log")
        utils.bullet("backups/         encrypted backup files")
        utils.bullet("emergency_kit.txt your recovery code, if you asked for a kit")

        utils.sub_header("HONEST LIMITATIONS")
        utils.print_wrapped(
            "This program cannot protect you from malware running as you, or "
            "from somebody reading the memory of the Python process, or from "
            "a compromised keyboard. It protects the file on disk, which is "
            "the part that gets stolen, backed up and forgotten on old drives.",
            70
        )
        utils.pause()

    def _screen_about(self):
        utils.clear_screen()
        utils.header("ABOUT")

        print("")
        utils.info(constants.APP_NAME + " version " + constants.APP_VERSION)
        utils.info("Data format version " + str(constants.SCHEMA_VERSION))
        utils.info("Python " + _python_version())
        utils.info("Vault folder: " + self.data_directory.path)

        utils.sub_header("WHAT IS IN THE BOX")
        utils.bullet("PBKDF2-HMAC-SHA256 key derivation, "
                     + str(constants.DEFAULT_ITERATIONS) + " iterations")
        utils.bullet("Fernet encryption (AES-128-CBC with HMAC-SHA256)")
        utils.bullet("TOTP authenticator codes, computed locally")
        utils.bullet("Encrypted backups with independent passphrases")
        utils.bullet("Recovery codes that can reset a forgotten password")
        utils.bullet("An optional duress password with a decoy vault")

        utils.sub_header("WHAT IT DOES NOT DO")
        utils.bullet("No network access. No telemetry. No accounts.")
        utils.bullet("No browser extension, no mobile app, no sync")
        utils.bullet("No auto-fill, which would need all of the above")

        utils.sub_header("A THANK YOU")
        utils.print_wrapped(
            "To the Python documentation, to the cryptography library's "
            "excellent warnings, and to everybody who has ever written a "
            "README that explained the limitations of their own project.",
            70
        )
        utils.pause()


# =====================================================================
# Module level helpers
# =====================================================================

def _enter_was_pressed(timeout):
    """
    Wait for at most timeout seconds. Returns True if Enter was pressed.

    select lets us watch the keyboard without blocking. On Windows, select
    does not work on stdin, so there we just sleep. The TOTP screen still
    refreshes, you just cannot stop it early with Enter (Ctrl-C works).
    """
    try:
        ready, _w, _x = select.select([sys_stdin()], [], [], timeout)
    except (OSError, ValueError, AttributeError):
        time.sleep(timeout)
        return False

    if not ready:
        return False

    # Something was typed. read a line so the terminal does not keep it.
    try:
        line = sys_stdin().readline()
    except Exception:
        return True

    return True if line is not None else True


def sys_stdin():
    """A tiny wrapper so the import of sys stays at the top of this function."""
    import sys
    return sys.stdin


def _python_version():
    import sys
    return sys.version.split()[0]


def generate_deterministic_password(phrase, label, counter, length=20,
                                    use_symbols=True, avoid_ambiguous=True):
    """
    Make a password that can be made again from the same inputs.

    This is the one generator in the project that is not random. It uses
    PBKDF2 over the phrase, the label and a version number, then maps the
    derived bytes onto a character set.

    Why a version number? Because some sites force a password change every
    ninety days. Bump the version, get a completely different password, keep
    the same phrase.

    The result is deterministic, which also means anybody who learns the
    phrase AND the label can generate it. The phrase is the secret. Treat it
    like one.
    """
    import hashlib

    if length < 12:
        length = 12
    if length > 64:
        length = 64

    phrase = str(phrase)
    label = str(label).strip().lower()
    counter = int(counter)

    if len(phrase) < 8:
        raise generator.GeneratorError("The phrase needs at least 8 characters.")

    material = (phrase + "|" + label + "|" + str(counter) + "|"
                + constants.DETERMINISTIC_PEPPER).encode("utf-8")

    # 256 rounds is enough here because the phrase is meant to be long and
    # this runs on a machine the user is sitting at, not on a server. The
    # salt is built from the label so that the same phrase gives different
    # passwords for different sites.
    digest = hashlib.pbkdf2_hmac(
        "sha256", material, ("securevault-studio|" + label).encode("utf-8"), 4096
    )

    lowercase = constants.LOWERCASE_LETTERS
    uppercase = constants.UPPERCASE_LETTERS
    digits = constants.DIGITS
    symbols = constants.SYMBOLS if use_symbols else ""

    if avoid_ambiguous:
        # One pass over each pool, removing the characters that are easy to
        # confuse when reading a password off a screen.
        lowercase = "".join(c for c in lowercase if c not in constants.AMBIGUOUS_CHARACTERS)
        uppercase = "".join(c for c in uppercase if c not in constants.AMBIGUOUS_CHARACTERS)
        digits = "".join(c for c in digits if c not in constants.AMBIGUOUS_CHARACTERS)
        symbols = "".join(c for c in symbols if c not in constants.AMBIGUOUS_CHARACTERS)

    pool = lowercase + uppercase + digits + symbols
    if pool == "":
        raise generator.GeneratorError("The character pool is empty.")

    # Expand the digest if a long password was asked for. Each extra round
    # of PBKDF2 gives another 32 bytes of usable material.
    usable = bytearray(digest)
    rounds = 0
    while len(usable) < length * 2 and rounds < 8:
        digest = hashlib.pbkdf2_hmac(
            "sha256", digest, ("more|" + label).encode("utf-8"), 1024
        )
        usable.extend(digest)
        rounds += 1

    # Turn bytes into characters with rejection sampling, so that every
    # character in the pool is equally likely. Using byte % len(pool) would
    # make the first few characters slightly more likely, which is a real
    # (if tiny) weakness. This loop throws away values that would bias it.
    characters = []
    index = 0
    limit = 256 - (256 % len(pool))
    while len(characters) < length:
        if index >= len(usable):
            digest = hashlib.sha256(bytes(usable)).digest()
            usable.extend(digest)
        value = usable[index]
        index += 1
        if value >= limit:
            continue
        characters.append(pool[value % len(pool)])

    password = "".join(characters)

    # Guarantee one of each group so that websites stop complaining.
    required = [lowercase, uppercase, digits]
    if symbols:
        required.append(symbols)

    for position, group in enumerate(required):
        if position >= len(password):
            break
        if not any(character in group for character in password):
            replacement = group[usable[position] % len(group)]
            password = password[:position] + replacement + password[position + 1:]

    return password
