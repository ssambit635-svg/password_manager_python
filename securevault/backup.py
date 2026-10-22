"""
backup.py

Backups, and the piece of paper that saves you when everything else fails.

A backup is a copy of the vault, encrypted with a DIFFERENT passphrase from
the master password. That is deliberate. If a backup used the same password
as the vault, then losing the password would lose the backups too, and a
backup that only works when nothing has gone wrong is not a backup.

The passphrase for a backup should be longer than the master password,
because it is typed less often. A five word passphrase from the generator is
the right sort of thing. Write it down. Put it somewhere that is not the
same place as the computer.

Then there is the emergency kit. It is a plain text file with the recovery
code in it, and it is the only thing this program produces that is meant to
be printed. Print it, fold it, put it in a drawer. If your house burns down
and the kit burns with it, that is the trade-off, and it is the same
trade-off every password manager makes.
"""

import os
import json
import datetime

from . import constants, crypto, utils


class BackupError(Exception):
    """A backup could not be made, read or restored."""
    pass


BACKUP_FORMAT = "securevault-backup"
BACKUP_FORMAT_VERSION = 1


# ---------------------------------------------------------------------------
# Making a backup
# ---------------------------------------------------------------------------

def backup_file_name(when=None):
    """
    Backups are named by the moment they were made, so sorting the folder
    sorts them by age. vault-20261022-170800.svbackup
    """
    if when is None:
        when = datetime.datetime.now()
    return "vault-" + when.strftime("%Y%m%d-%H%M%S") + ".svbackup"


def _available_backup_name(data_directory):
    """
    A file name that is not taken yet.

    The timestamp only goes down to the second, and a person (or a test
    suite) can absolutely make three backups inside one second. Rather than
    overwrite the earlier ones, which would be a terrible surprise, we add a
    counter: vault-20261022-170800-2.svbackup.
    """
    base = backup_file_name()
    stamp = base[:-len(".svbackup")]

    candidate = base
    counter = 2
    while os.path.exists(data_directory.backup_path(candidate)):
        candidate = stamp + "-" + str(counter) + ".svbackup"
        counter += 1
        if counter > 200:
            raise BackupError("There are far too many backups with the same timestamp.")

    return candidate


def make_backup(data_directory, open_vault_object, passphrase, note=""):
    """
    Write an encrypted backup and return its file name.

    The backup contains the entries and the trash, and nothing else. The
    settings and the audit log stay in meta.json, because they are about
    this installation, not about your passwords, and a restore should not
    overwrite them.
    """
    passphrase = str(passphrase)
    if len(passphrase) < 8:
        raise BackupError("Use a backup passphrase of at least 8 characters. Longer is better.")

    payload = {
        "format": BACKUP_FORMAT,
        "version": BACKUP_FORMAT_VERSION,
        "app_version": constants.APP_VERSION,
        "created_at": utils.now_iso(),
        "note": str(note)[:200],
        "fingerprint": crypto.fingerprint(open_vault_object.key),
        "entries": open_vault_object.data.get("entries", []),
        "trash": open_vault_object.data.get("trash", []),
    }

    try:
        plain = json.dumps(payload, ensure_ascii=False)
    except (TypeError, ValueError) as problem:
        raise BackupError("Could not turn the vault into JSON for backup: " + str(problem))

    salt = crypto.generate_salt()
    key = crypto.derive_key(passphrase, salt, constants.BACKUP_ITERATIONS)
    encrypted = crypto.encrypt_text(plain, key)

    envelope = {
        "format": "securevault-backup-envelope",
        "version": 1,
        "created_at": payload["created_at"],
        "iterations": constants.BACKUP_ITERATIONS,
        "salt": crypto.salt_to_text(salt),
        "fingerprint": payload["fingerprint"],
        "entry_count": len(payload["entries"]),
        "note": payload["note"],
        "blob": encrypted,
    }

    name = _available_backup_name(data_directory)
    path = data_directory.write_backup(name, json.dumps(envelope, indent=2))

    open_vault_object.meta.setdefault("counters", {})
    open_vault_object.meta["counters"]["backups"] = int(
        open_vault_object.meta["counters"].get("backups", 0)
    ) + 1
    data_directory.append_audit(
        open_vault_object.meta, "backup_created",
        name + " (" + str(len(payload["entries"])) + " entries)"
    )
    data_directory.write_meta(open_vault_object.meta)

    return name, path


# ---------------------------------------------------------------------------
# Reading a backup
# ---------------------------------------------------------------------------

def describe_backup_files(data_directory):
    """
    Return a list of dictionaries describing the backups on disk, newest
    first. Used by the backup menu, so the user sees the note and the entry
    count without having to decrypt anything.

    Reading the envelope is safe: the envelope is not secret, only the blob
    inside it is.
    """
    described = []
    for name in data_directory.list_backups():
        item = {
            "name": name,
            "size": data_directory.backup_size_bytes(name),
            "created_at": "",
            "entry_count": "?",
            "note": "",
            "readable": True,
        }
        try:
            text = data_directory.read_backup(name)
            envelope = json.loads(text)
            item["created_at"] = envelope.get("created_at", "")
            item["entry_count"] = envelope.get("entry_count", "?")
            item["note"] = envelope.get("note", "")
        except (ValueError, TypeError, AttributeError):
            item["readable"] = False
        described.append(item)
    return described


def read_backup(data_directory, name, passphrase):
    """
    Decrypt a backup and return its payload dictionary.

    A wrong passphrase and a tampered file give the same message, for the
    same reason as everywhere else in this project: the difference is a tiny
    hint that an attacker does not need to have.
    """
    text = data_directory.read_backup(name)
    if text is None:
        raise BackupError("There is no backup called " + str(name) + ".")

    try:
        envelope = json.loads(text)
    except ValueError:
        raise BackupError("That backup file is damaged and cannot be parsed.")

    if not isinstance(envelope, dict) or "blob" not in envelope or "salt" not in envelope:
        raise BackupError("That file is not a SecureVault backup.")

    try:
        salt = crypto.salt_from_text(envelope["salt"])
        iterations = int(envelope.get("iterations", constants.BACKUP_ITERATIONS))
        key = crypto.derive_key(str(passphrase), salt, iterations)
        plain = crypto.decrypt_text(envelope["blob"], key)
        payload = json.loads(plain)
    except crypto.WrongPasswordError:
        raise BackupError("The backup passphrase is wrong, or the file was altered.")
    except crypto.CryptoError as problem:
        raise BackupError(str(problem))
    except ValueError:
        raise BackupError("The decrypted backup is not valid JSON.")

    if not isinstance(payload, dict) or payload.get("format") != BACKUP_FORMAT:
        raise BackupError("That backup contains something unexpected.")

    return payload


def verify_backup(data_directory, name, passphrase):
    """
    Check that a backup opens AND that it makes sense. Returns a summary.

    This exists because an unverified backup is a rumour. The backup menu
    offers to run this immediately after making one.
    """
    payload = read_backup(data_directory, name, passphrase)

    entries = payload.get("entries", [])
    if not isinstance(entries, list):
        raise BackupError("The backup's entry list is not a list.")

    problems = []
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append("one entry is not a dictionary")
            continue
        if not entry.get("site"):
            problems.append("an entry has no site name")
        if not entry.get("password"):
            problems.append("an entry has no password")

    return {
        "name": name,
        "created_at": payload.get("created_at", ""),
        "entry_count": len(entries),
        "trash_count": len(payload.get("trash", []) or []),
        "fingerprint": payload.get("fingerprint", ""),
        "note": payload.get("note", ""),
        "problems": problems[:10],
        "ok": len(problems) == 0,
    }


# ---------------------------------------------------------------------------
# Restoring
# ---------------------------------------------------------------------------

def restore_backup(open_vault_object, payload, replace=False):
    """
    Put a backup's entries into the open vault.

    Two modes:
      merge   - add everything that is not already there. Safe default.
      replace - throw away what is in the vault and use the backup instead.

    Returns a dictionary of counts so the menu can report something useful.
    """
    entries = payload.get("entries", [])
    if not isinstance(entries, list):
        raise BackupError("The backup does not contain a usable entry list.")

    result = {
        "added": 0,
        "skipped": 0,
        "kept": 0,
    }

    if replace:
        result["kept"] = 0
        open_vault_object.data["entries"] = []

    added, skipped = open_vault_object.add_many(entries)
    result["added"] = added
    result["skipped"] = skipped

    if not replace:
        result["kept"] = len(open_vault_object.entries) - added

    return result


def prune_old_backups(data_directory, keep=10):
    """
    Delete the oldest backups beyond a limit. Returns the names removed.

    Backups pile up quickly if you make one every day. Keeping ten is a
    reasonable compromise between "safe" and "a folder full of files that
    nobody ever looks at".
    """
    keep = int(keep)
    if keep < 1:
        raise BackupError("Keep at least one backup.")

    names = data_directory.list_backups()  # newest first
    if len(names) <= keep:
        return []

    removed = []
    for name in names[keep:]:
        if data_directory.delete_backup(name):
            removed.append(name)

    return removed


# ---------------------------------------------------------------------------
# The emergency kit
# ---------------------------------------------------------------------------

def build_emergency_kit(meta, recovery_code, fingerprint, data_directory):
    """
    Build the text of the emergency kit.

    The kit contains the recovery code in plain text, which is why it is a
    file that the user is supposed to print and then think hard about where
    it lives. Putting the recovery code in the vault would be circular.
    """
    created = utils.human_datetime(utils.now_iso())
    vault_location = data_directory.path

    lines = []
    lines.append("=" * 70)
    lines.append("SECUREVAULT EMERGENCY KIT")
    lines.append("=" * 70)
    lines.append("")
    lines.append("Created:          " + created)
    lines.append("Program version:  " + constants.APP_VERSION)
    lines.append("Vault folder:     " + vault_location)
    lines.append("Key fingerprint:  " + str(fingerprint))
    lines.append("")
    lines.append("-" * 70)
    lines.append("YOUR RECOVERY CODE")
    lines.append("-" * 70)
    lines.append("")
    lines.append("    " + str(recovery_code))
    lines.append("")
    lines.append("Type this code, without the dashes if you prefer, when the")
    lines.append("program asks for a recovery code. You can only use it once:")
    lines.append("it sets a new master password, and a new recovery code is")
    lines.append("generated when you do.")
    lines.append("")
    lines.append("-" * 70)
    lines.append("HOW TO GET BACK IN")
    lines.append("-" * 70)
    lines.append("")
    lines.append("1. Run the program:  python password_manager.py")
    lines.append("2. On the login screen, choose 'Forgot master password'.")
    lines.append("3. Type the recovery code above.")
    lines.append("4. Choose a new master password.")
    lines.append("5. Write the new recovery code on a fresh copy of this page.")
    lines.append("")
    lines.append("Your saved passwords are NOT in this file. This page only")
    lines.append("unlocks the vault. If somebody finds it and also has your")
    lines.append("vault folder, they can open it. Keep it somewhere else.")
    lines.append("")
    lines.append("-" * 70)
    lines.append("IF YOU THINK THIS LEAKED")
    lines.append("-" * 70)
    lines.append("")
    lines.append("Open the vault, go to Settings, Security, and choose")
    lines.append("'Regenerate recovery code'. That makes this page useless.")
    lines.append("")
    if meta.get("duress"):
        lines.append("A duress password is enabled on this vault.")
        lines.append("")
    lines.append("=" * 70)
    lines.append("Do not store a photo of this page in the same place as a")
    lines.append("backup of your vault.")
    lines.append("=" * 70)
    lines.append("")

    return "\n".join(lines)


def write_emergency_kit(data_directory, meta, recovery_code, fingerprint):
    """Write the emergency kit next to the vault and return its path."""
    text = build_emergency_kit(meta, recovery_code, fingerprint, data_directory)
    path = data_directory.emergency_kit_path
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        if os.name != "nt":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    except OSError as problem:
        raise BackupError("Could not write the emergency kit: " + str(problem))

    data_directory.append_audit(meta, "emergency_kit_written", "kit file created")
    data_directory.write_meta(meta)

    return path


# ---------------------------------------------------------------------------
# A quick safety check
# ---------------------------------------------------------------------------

def backup_is_stale(data_directory, days=30):
    """
    True when there has been no backup in the last N days. Used by the start
    up health line, because the most common way to lose a vault is to never
    make a backup at all.
    """
    names = data_directory.list_backups()
    if not names:
        return True

    newest = names[0]
    # vault-YYYYMMDD-HHMMSS.svbackup, sometimes with a -2 suffix.
    # Only the first fifteen characters are the timestamp.
    stamp = newest.replace("vault-", "").split(".svbackup")[0][:15]
    try:
        made = datetime.datetime.strptime(stamp, "%Y%m%d-%H%M%S")
    except ValueError:
        return False
    age = datetime.datetime.now() - made
    return age.days >= int(days)
