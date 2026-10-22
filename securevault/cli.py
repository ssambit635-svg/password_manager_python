"""
cli.py

The front door. This file turns command line arguments into calls to the
rest of the program.

Running with no arguments starts the interactive menus, which is what most
people will do. The subcommands exist for scripts, for quick one liners and
for the times when you want one password without a menu.

    python password_manager.py
    python password_manager.py generate --preset paranoid
    python password_manager.py list
    python password_manager.py show github
    python password_manager.py doctor

Two environment variables are understood, both of them documented in the
README:

    SECUREVAULT_HOME       where the vault folder lives
    SECUREVAULT_PASSWORD   the master password, for non-interactive commands

The second one is a convenience for scripts and a bad idea in a shared
shell. The program warns if it sees it.
"""

import os
import json
import argparse

from . import constants, utils, auth, storage, strength, generator, crypto
from . import vault as vault_module, audit, backup, importers, clipboard
from . import totp
from .ui import UserInterface


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser():
    """Build the argparse parser. Kept in its own function so tests can use it."""
    # A tiny parent parser with the two global options on it. Each subcommand
    # inherits these, which means both of these work:
    #
    #     password_manager.py --no-color list
    #     password_manager.py list --no-color
    #
    # SUPPRESS is important here. Without it, the subparser would overwrite
    # the value the main parser already stored with its own default, and
    # --data-dir given before the subcommand would be silently ignored.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS)
    common.add_argument("--data-dir", metavar="PATH", default=argparse.SUPPRESS)

    parser = argparse.ArgumentParser(
        prog="password_manager.py",
        description="SecureVault: a command line password manager that tries very hard.",
        epilog=(
            "Run with no arguments for the interactive menus. "
            "The vault folder defaults to ~/.securevault and can be changed "
            "with the SECUREVAULT_HOME environment variable or --data-dir."
        ),
    )

    parser.add_argument("--data-dir", metavar="PATH",
                        help="use this folder instead of ~/.securevault")
    parser.add_argument("--no-color", action="store_true",
                        help="plain text output, no escape codes")
    parser.add_argument("--version", action="store_true",
                        help="show the version and exit")

    subparsers = parser.add_subparsers(dest="command")

    # -- generate ------------------------------------------------------
    generate_parser = subparsers.add_parser(
        "generate", help="make a password without opening the vault",
        parents=[common]
    )
    generate_parser.add_argument("--length", type=int, default=None,
                                 help="characters for a random password (default 20)")
    generate_parser.add_argument("--preset", default=constants.PRESET_BALANCED,
                                 choices=constants.GENERATOR_PRESETS,
                                 help="balanced, paranoid, memorable, pin or passphrase")
    generate_parser.add_argument("--words", type=int, default=5,
                                 help="number of words for a passphrase")
    generate_parser.add_argument("--count", type=int, default=1,
                                 help="how many to generate (1-20)")
    generate_parser.add_argument("--no-symbols", action="store_true",
                                 help="letters and digits only")
    generate_parser.add_argument("--avoid-ambiguous", action="store_true",
                                 help="leave out letters that look like each other")
    generate_parser.add_argument("--copy", action="store_true",
                                 help="copy the first result to the clipboard")
    generate_parser.add_argument("--json", action="store_true",
                                 help="output as JSON")

    # -- check ---------------------------------------------------------
    check_parser = subparsers.add_parser(
        "check", help="score a password's strength", parents=[common]
    )
    check_parser.add_argument("--password", help="the password (omit to be prompted)")
    check_parser.add_argument("--json", action="store_true", help="output as JSON")

    # -- list ----------------------------------------------------------
    list_parser = subparsers.add_parser(
        "list", help="list entries (needs the vault)", parents=[common]
    )
    list_parser.add_argument("--tag", help="only entries with this tag")
    list_parser.add_argument("--favourites", action="store_true",
                             help="only favourites")
    list_parser.add_argument("--sort", default="site",
                             choices=["site", "updated", "created", "oldest",
                                      "health", "uses"])
    list_parser.add_argument("--json", action="store_true", help="output as JSON")

    # -- show ----------------------------------------------------------
    show_parser = subparsers.add_parser(
        "show", help="print one entry's password", parents=[common]
    )
    show_parser.add_argument("site", help="site name (or part of it)")
    show_parser.add_argument("--field", default="password",
                             choices=["password", "username", "url", "notes", "totp"],
                             help="which field to print")
    show_parser.add_argument("--copy", action="store_true",
                             help="copy the field to the clipboard instead of printing")

    # -- import / export -----------------------------------------------
    import_parser = subparsers.add_parser(
        "import", help="import a CSV or old JSON file", parents=[common]
    )
    import_parser.add_argument("path", help="the file to import")
    import_parser.add_argument("--tag", help="tag to add to every imported entry")
    import_parser.add_argument("--dry-run", action="store_true",
                               help="look at the file but do not change the vault")

    export_parser = subparsers.add_parser(
        "export", help="export entries as CSV or JSON", parents=[common]
    )
    export_parser.add_argument("path", help="where to write the file")
    export_parser.add_argument("--format", default="json", choices=["csv", "json"])
    export_parser.add_argument("--yes", action="store_true",
                               help="do not ask for confirmation")

    # -- backups -------------------------------------------------------
    backup_parser = subparsers.add_parser(
        "backup", help="write an encrypted backup", parents=[common]
    )
    backup_parser.add_argument("--note", default="", help="a note stored in the file")
    backup_parser.add_argument("--keep", type=int, default=10,
                               help="delete backups beyond this many (default 10)")

    subparsers.add_parser(
        "recover", help="reset the master password with a recovery code", parents=[common]
    )
    subparsers.add_parser(
        "reset-lockout", help="clear the failed login counter", parents=[common]
    )
    subparsers.add_parser(
        "doctor", help="check the installation and the files", parents=[common]
    )
    subparsers.add_parser(
        "info", help="show where the vault is and what is in it", parents=[common]
    )

    subparsers.add_parser(
        "share", help="make a share code for one entry", parents=[common]
    )
    share_open = subparsers.add_parser(
        "open-share", help="open a share code", parents=[common]
    )
    share_open.add_argument("--code", help="the share code, or omit to paste it")

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv=None):
    """Parse arguments and dispatch. Returns an exit code."""
    parser = build_parser()
    arguments = parser.parse_args(argv)

    if arguments.version:
        print(constants.APP_NAME + " " + constants.APP_VERSION)
        return 0

    utils.set_colour_enabled(utils.should_use_colour())
    if getattr(arguments, "no_color", False):
        utils.set_colour_enabled(False)

    data_directory = storage.DataDirectory(getattr(arguments, "data_dir", None))

    command = getattr(arguments, "command", None)

    try:
        if command is None:
            interface = UserInterface(data_directory)
            return interface.run()

        if command == "generate":
            return _command_generate(arguments)
        if command == "check":
            return _command_check(arguments, data_directory)
        if command == "list":
            return _command_list(arguments, data_directory)
        if command == "show":
            return _command_show(arguments, data_directory)
        if command == "import":
            return _command_import(arguments, data_directory)
        if command == "export":
            return _command_export(arguments, data_directory)
        if command == "backup":
            return _command_backup(arguments, data_directory)
        if command == "recover":
            return _command_recover(data_directory)
        if command == "reset-lockout":
            return _command_reset_lockout(data_directory)
        if command == "doctor":
            return _command_doctor(data_directory)
        if command == "info":
            return _command_info(data_directory)
        if command == "share":
            return _command_share(data_directory)
        if command == "open-share":
            return _command_open_share(arguments, data_directory)

    except KeyboardInterrupt:
        print("")
        utils.info("Interrupted.")
        return 130
    except Exception as problem:
        # A last resort. A traceback in a password manager looks alarming
        # and usually hides a simple message in the middle of it.
        utils.error("Something unexpected happened: " + str(problem))
        if os.environ.get("SECUREVAULT_DEBUG"):
            raise
        utils.info("Set SECUREVAULT_DEBUG=1 to see the full traceback.")
        return 1

    parser.print_help()
    return 2


# ---------------------------------------------------------------------------
# Unlocking helper
# ---------------------------------------------------------------------------

def _get_master_password(prompt="Master password: "):
    """
    Read the master password from the environment or from the terminal.

    The environment variable exists for scripts. It is checked first, and a
    warning is printed, because on a shared machine it is visible in the
    process list of anybody who runs ps at the wrong moment.
    """
    from_env = os.environ.get("SECUREVAULT_PASSWORD")
    if from_env:
        utils.warning("Using SECUREVAULT_PASSWORD from the environment. "
                      "That variable is visible to other programs.")
        return from_env

    return utils.ask_password(prompt)


def _unlock(data_directory):
    """
    Read the password, unlock the vault, return (vault, meta).

    Exits the program with code 1 on failure, because every command that
    calls this needs a vault and none of them have anything useful to do
    without one.
    """
    if not data_directory.meta_exists() or not data_directory.vault_exists():
        utils.error("There is no vault in " + data_directory.describe() + ".")
        utils.info("Run the program with no arguments to create one.")
        raise SystemExit(1)

    password = _get_master_password()

    try:
        key, meta = auth.unlock(data_directory, password)
    except auth.LockedOutError as problem:
        utils.error(str(problem))
        raise SystemExit(1)
    except auth.AuthError as problem:
        utils.error(str(problem))
        raise SystemExit(1)

    try:
        open_vault_object = auth.open_vault(data_directory, key, meta)
    except auth.AuthError as problem:
        utils.error(str(problem))
        raise SystemExit(1)

    return open_vault_object, meta


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _command_generate(arguments):
    """Generate passwords and print them, or copy one."""
    try:
        if arguments.preset == constants.PRESET_PASSPHRASE:
            passwords = [
                generator.generate_passphrase(arguments.words)
                for _ in range(max(1, min(20, arguments.count)))
            ]
        elif arguments.preset == constants.PRESET_PIN:
            passwords = [
                generator.generate_pin(arguments.length or 6)
                for _ in range(max(1, min(20, arguments.count)))
            ]
        elif arguments.count and arguments.count > 1:
            passwords = []
            for _ in range(max(1, min(20, arguments.count))):
                passwords.append(generator.generate_from_preset(
                    arguments.preset, length=arguments.length
                )["password"])
        else:
            if arguments.length or arguments.no_symbols or arguments.avoid_ambiguous:
                passwords = [
                    generator.generate_password(
                        length=arguments.length or 20,
                        use_symbols=not arguments.no_symbols,
                        avoid_ambiguous=arguments.avoid_ambiguous,
                    )
                ]
            else:
                made = generator.generate_from_preset(arguments.preset)
                passwords = [made["password"]]
    except generator.GeneratorError as problem:
        utils.error(str(problem))
        return 1

    if arguments.json:
        print(json.dumps({"passwords": passwords}, indent=2))
    else:
        for password in passwords:
            print(password)

    if arguments.copy and passwords:
        try:
            clipboard.copy_text(passwords[0], 20)
            utils.info("Copied the first one. It clears in 20 seconds.")
        except clipboard.ClipboardError as problem:
            utils.error(str(problem))

    return 0


def _command_check(arguments, data_directory):
    """Score a password."""
    password = arguments.password
    if password is None:
        password = utils.ask_password("Password to check: ")

    if password == "":
        utils.error("There is nothing to check.")
        return 1

    analysis = strength.analyse(password)

    if arguments.json:
        # The password itself is deliberately left out of the JSON output.
        clean = dict(analysis)
        clean.pop("password", None)
        print(json.dumps(clean, indent=2))
        return 0

    utils.header("STRENGTH")
    print("")
    print("  Grade:   " + analysis["grade"] + " (" + analysis["label"] + ")")
    print("  Score:   " + str(analysis["score"]) + "/100 "
          + utils.star_rating(analysis["score"]))
    print("  Length:  " + str(analysis["length"]))
    print("  Types:   " + str(analysis["classes"]) + " of 4")
    print("  Entropy: " + str(analysis["adjusted_bits"]) + " bits")
    print("")
    print("  Time to crack (offline, fast hash): "
          + analysis["crack_times"]["fast_hash"])

    if analysis["problems"]:
        print("")
        for problem in analysis["problems"]:
            utils.bullet(problem, "red")

    return 0


def _command_list(arguments, data_directory):
    """List entries without showing passwords."""
    open_vault_object, meta = _unlock(data_directory)

    entries = open_vault_object.sorted_entries(
        sort_by=arguments.sort,
        only_favorites=arguments.favourites,
        tag=arguments.tag,
    )

    if arguments.json:
        rows = []
        for entry in entries:
            rows.append({
                "id": entry["id"],
                "site": entry["site"],
                "username": entry["username"],
                "url": entry["url"],
                "tags": entry["tags"],
                "favorite": entry["favorite"],
                "updated_at": entry["updated_at"],
                "password_changed_at": entry["password_changed_at"],
            })
        print(json.dumps(rows, indent=2))
        return 0

    if not entries:
        print("No entries.")
        return 0

    rows = []
    for entry in entries:
        rows.append([
            entry["site"],
            entry["username"] or "-",
            ", ".join(entry["tags"]) or "-",
            utils.human_date(entry["password_changed_at"]),
        ])

    utils.table(["Site", "Username", "Tags", "Password changed"], rows, [28, 24, 18, 16])
    print("")
    print(str(len(entries)) + " entries.")
    return 0


def _command_show(arguments, data_directory):
    """Print or copy one field of one entry."""
    open_vault_object, meta = _unlock(data_directory)

    results = open_vault_object.search(arguments.site)
    if not results:
        utils.error("No entry matches '" + arguments.site + "'.")
        return 1

    if len(results) > 1:
        utils.warning("'" + arguments.site + "' matches " + str(len(results)) + " entries:")
        for entry in results:
            utils.bullet(entry["site"] + " (" + (entry["username"] or "no username") + ")")
        utils.info("Be more specific.")
        return 1

    entry = results[0]
    value = entry.get(arguments.field, "")

    if arguments.field == "totp":
        if not entry.get("totp_secret"):
            utils.error("That entry has no two factor secret.")
            return 1
        value = totp.totp(entry["totp_secret"])

    if value == "":
        utils.error("That field is empty for this entry.")
        return 1

    if arguments.copy:
        try:
            clipboard.copy_text(value, 20)
        except clipboard.ClipboardError as problem:
            utils.error(str(problem))
            return 1
        utils.info("Copied. It clears in 20 seconds.")
        return 0

    print(value)

    if arguments.field == "password":
        open_vault_object.mark_used(entry["id"])
        utils.warning("That password is now in your shell history if you redirect output.")

    return 0


def _command_import(arguments, data_directory):
    """Import a file, optionally without touching the vault."""
    open_vault_object, meta = _unlock(data_directory)

    tags = [arguments.tag] if arguments.tag else []

    try:
        result = importers.import_from_file(
            open_vault_object, arguments.path,
            default_tags=tags, dry_run=arguments.dry_run
        )
    except importers.ImportError_ as problem:
        utils.error(str(problem))
        return 1

    if arguments.dry_run:
        utils.info("Dry run: " + json.dumps(result, indent=2))
        return 0

    data_directory.log_and_save(meta, "imported_cli", str(result.get("added", 0)))
    utils.success("Added " + str(result.get("added", 0))
                  + ", skipped " + str(result.get("skipped", 0)) + ".")
    return 0


def _command_export(arguments, data_directory):
    """Export to CSV or JSON, with a confirmation unless --yes."""
    if not arguments.yes:
        utils.warning("Exports are plain text. Anybody who reads the file has "
                      "your passwords.")
        if not utils.ask_yes_no("Continue?", default=False):
            return 0

    open_vault_object, meta = _unlock(data_directory)

    try:
        if arguments.format == "csv":
            count = importers.export_csv(open_vault_object, arguments.path)
        else:
            count = importers.export_json(open_vault_object, arguments.path)
    except importers.ExportError as problem:
        utils.error(str(problem))
        return 1

    data_directory.log_and_save(meta, "exported_cli", str(count) + " entries")
    utils.success("Exported " + str(count) + " entries to " + arguments.path)
    utils.warning("Delete that file once it has been used.")
    return 0


def _command_backup(arguments, data_directory):
    """Write an encrypted backup and prune the old ones."""
    open_vault_object, meta = _unlock(data_directory)

    if utils.ask_yes_no("Generate a backup passphrase?", default=True):
        passphrase = generator.generate_passphrase(5, "-", True, True)
        print("")
        print("  Backup passphrase: " + utils.style(passphrase, "yellow", bold=True))
        print("")
        utils.warning("Write it down. It is not stored anywhere.")
    else:
        passphrase = utils.ask_password("Backup passphrase: ")
        confirm = utils.ask_password("Again: ")
        if passphrase != confirm:
            utils.error("They do not match.")
            return 1

    try:
        name, path = backup.make_backup(
            data_directory, open_vault_object, passphrase, arguments.note
        )
        summary = backup.verify_backup(data_directory, name, passphrase)
        removed = backup.prune_old_backups(data_directory, arguments.keep)
    except backup.BackupError as problem:
        utils.error(str(problem))
        return 1

    utils.success("Backup written: " + path)
    utils.info("Verified: " + str(summary["entry_count"]) + " entries read back.")
    if removed:
        utils.info("Pruned " + str(len(removed)) + " old backup(s).")

    return 0


def _command_recover(data_directory):
    """Reset the master password non-interactively."""
    if not data_directory.meta_exists():
        utils.error("There is no vault in " + data_directory.describe() + ".")
        return 1

    meta = data_directory.read_meta()

    if not auth.has_recovery(meta):
        utils.error("This vault has no recovery code registered.")
        return 1

    code = utils.ask("Recovery code")
    new_password = utils.ask_password("New master password: ")
    confirm = utils.ask_password("Again: ")
    if new_password != confirm:
        utils.error("They do not match.")
        return 1

    try:
        open_vault_object, new_code = auth.reset_with_recovery(
            data_directory, meta, code, new_password
        )
    except auth.AuthError as problem:
        utils.error(str(problem))
        return 1
    except vault_module.VaultError as problem:
        utils.error(str(problem))
        return 1

    utils.success("Master password reset. " + str(open_vault_object.count())
                  + " entries are intact.")
    print("")
    utils.warning("NEW RECOVERY CODE (write it down): " + new_code)

    if utils.ask_yes_no("Write a new emergency kit?", default=True):
        try:
            path = backup.write_emergency_kit(
                data_directory, meta, new_code,
                crypto.fingerprint(open_vault_object.key)
            )
            utils.success("Written to " + path)
        except backup.BackupError as problem:
            utils.error(str(problem))

    return 0


def _command_reset_lockout(data_directory):
    """Clear the failed attempt counter."""
    if not data_directory.meta_exists():
        utils.error("There is no vault here.")
        return 1

    meta = data_directory.read_meta()
    auth.clear_lockout(data_directory, meta)
    utils.success("Lockout cleared.")
    utils.warning("This does not prove you know the password, it only resets the counter.")
    return 0


def _command_doctor(data_directory):
    """Run the environment checks."""
    meta = None
    if data_directory.meta_exists():
        try:
            meta = data_directory.read_meta()
        except storage.StorageError as problem:
            utils.error(str(problem))

    findings = audit.doctor_report(data_directory, meta, None)

    utils.header("DOCTOR")
    for finding in findings:
        if finding["level"] == "ok":
            marker = utils.style("PASS", "green")
        elif finding["level"] == "warn":
            marker = utils.style("WARN", "yellow")
        else:
            marker = utils.style("FAIL", "red")
        print("  " + marker + "  " + finding["title"].ljust(26) + "  "
              + utils.truncate(finding["detail"], 44))

    failures = len([item for item in findings if item["level"] == "fail"])
    return 1 if failures else 0


def _command_info(data_directory):
    """Describe the data folder without needing the password."""
    print(constants.APP_NAME + " " + constants.APP_VERSION)
    print("")
    print("Data folder:  " + data_directory.path)

    if not data_directory.exists():
        print("Status:       no vault yet, the folder does not exist")
        return 0

    print("Vault file:   " + ("present" if data_directory.vault_exists() else "missing"))
    print("Settings:     " + ("present" if data_directory.meta_exists() else "missing"))
    print("Backups:      " + str(len(data_directory.list_backups())))
    print("Attachments:  " + str(data_directory.attachment_count()))
    print("Skip list:    " + ("present" if os.path.exists(
        os.path.join(data_directory.path, ".gitignore")) else "missing"))

    if data_directory.meta_exists():
        try:
            meta = data_directory.read_meta()
            print("Created:      " + utils.human_datetime(meta.get("created_at", "")))
            counters = meta.get("counters", {})
            print("Unlocks:      " + str(counters.get("unlocks", 0)))
            print("Backups made: " + str(counters.get("backups", 0)))
            print("Recovery:     " + ("yes" if auth.has_recovery(meta) else "no"))
            print("Duress:       " + ("yes" if auth.has_duress(meta) else "no"))
            locked, remaining = auth.is_locked_out(meta)
            if locked:
                print("Lockout:      " + utils.human_duration(remaining) + " remaining")
        except storage.StorageError as problem:
            print("Settings:     unreadable (" + str(problem) + ")")

    return 0


def _command_share(data_directory):
    """Make a share code from the command line."""
    open_vault_object, meta = _unlock(data_directory)

    query = utils.ask("Which site")
    results = open_vault_object.search(query)
    if not results:
        utils.error("No entry matches.")
        return 1
    if len(results) > 1:
        utils.warning("That matches " + str(len(results)) + " entries. Be more specific.")
        return 1

    passphrase = generator.generate_passphrase(5, "-", True, True)
    try:
        code = crypto.make_share_code(results[0], passphrase)
    except crypto.CryptoError as problem:
        utils.error(str(problem))
        return 1

    print(code)
    print("")
    print("Passphrase: " + passphrase)
    utils.warning("Send the code and the passphrase by different routes.")

    data_directory.log_and_save(meta, "share_code_made", results[0]["site"])
    return 0


def _command_open_share(arguments, data_directory):
    """Open a share code and print the entry."""
    code = arguments.code
    if not code:
        code = utils.ask("Share code")

    passphrase = utils.ask_password("Passphrase: ")

    try:
        payload = crypto.open_share_code(code, passphrase)
    except crypto.ShareCodeError as problem:
        utils.error(str(problem))
        return 1

    print("")
    print("Site:     " + str(payload.get("site", "")))
    print("Username: " + str(payload.get("username", "")))
    print("Password: " + str(payload.get("password", "")))
    if payload.get("url"):
        print("Address:  " + str(payload["url"]))

    return 0
