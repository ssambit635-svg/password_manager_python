"""
importers.py

Getting passwords in and out of other programs.

Everybody who has used a browser has passwords in it, and everybody who
switches password managers has to move them across. The format that every
tool agrees on is CSV, which is a terrible format for passwords (it is
plain text, and commas and quotes in a password will break a naive parser)
but it is what exists.

There are two things in here that are worth knowing about:

  * Header detection. Every program names its columns differently. Chrome
    says "name", Bitwarden says "login_uri", LastPass says "url", 1Password
    says "Title". The importer looks at the header row and works out which
    column is which, instead of insisting on one exact layout.

  * The old format. The first version of this project wrote a plain
    passwords.json file. There is a reader for that here, because anybody
    upgrading deserves to keep their data.

Export is plain text, and it is the most dangerous thing this program can
do. The menu that calls it makes you type a word to confirm, and the export
is written with owner-only permissions where the operating system allows it.
"""

import os
import csv
import json
import io

from . import utils, vault as vault_module


class ImportError_(Exception):
    """Raised for anything that goes wrong while importing.

    The trailing underscore is because "ImportError" is a built-in Python
    exception name and shadowing it is a bad habit that causes confusing
    bugs later.
    """
    pass


class ExportError(Exception):
    """Raised for anything that goes wrong while exporting."""
    pass


# Column names, grouped by what they mean. Everything is lower case and
# stripped of spaces, dashes and underscores before comparison, so
# "Login URI", "login_uri" and "loginuri" all match.
SITE_COLUMNS = [
    "name", "site", "title", "website", "web", "service", "app",
    "account", "loginuri", "login_uri", "url", "uri", "hostname",
]

USERNAME_COLUMNS = [
    "username", "user", "login", "loginname", "email", "account",
    "userid", "user_id", "login_username", "loginusername", "loginemail",
]

PASSWORD_COLUMNS = [
    "password", "pass", "passwd", "secret", "pwd", "login_password",
    "loginpassword",
]

NOTES_COLUMNS = [
    "notes", "note", "comment", "comments", "extra", "memo",
]

URL_COLUMNS = [
    "url", "uri", "website", "web", "loginuri", "login_uri", "loginhref",
    "hostname",
]

TOTP_COLUMNS = [
    "totp", "otp", "otpauth", "twofactor", "two_factor", "authenticator",
    "login_totp", "logintotp",
]

TAG_COLUMNS = ["tags", "tag", "folder", "group", "category", "collection"]

FAVORITE_COLUMNS = ["favorite", "favourite", "starred"]


def _normalise_header(text):
    """Lower case, and strip anything that is not a letter or a digit."""
    cleaned = ""
    for character in str(text).lower():
        if character.isalnum():
            cleaned += character
    return cleaned


def _read_text_file(path):
    """
    Read a text file without caring too much about encoding.

    Browser exports are usually UTF-8 with a byte order mark at the start.
    Some Windows tools write Latin-1. Trying a couple of encodings and
    falling back is more useful than crashing on a stray accent.
    """
    if not os.path.exists(path):
        raise ImportError_("There is no file at " + str(path) + ".")

    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as problem:
        raise ImportError_("Could not read the file: " + str(problem))

    if len(raw) > 20 * 1024 * 1024:
        raise ImportError_("That file is bigger than 20 MB. Are you sure it is a password export?")

    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue

    raise ImportError_("The file could not be read as text.")


def detect_format(path):
    """
    Guess what kind of file this is.

    Returns one of: "csv", "legacy-json", "securevault-json", "json", "unknown".
    """
    text = _read_text_file(path).strip()

    if text == "":
        return "unknown"

    if text.startswith("{") or text.startswith("["):
        try:
            data = json.loads(text)
        except ValueError:
            return "unknown"

        if isinstance(data, dict) and data.get("format") == "securevault-backup":
            return "securevault-backup"
        if isinstance(data, dict) and "entries" in data:
            return "securevault-json"
        if isinstance(data, list):
            # The old version of this project wrote a bare list of entries.
            if data and isinstance(data[0], dict) and "site" in data[0]:
                return "legacy-json"
        return "json"

    # Anything with a comma in the first line is probably CSV. A very simple
    # check, but it catches the real cases and refuses binary garbage.
    first_line = text.split("\n")[0]
    if "," in first_line:
        return "csv"

    return "unknown"


def detect_columns(header_row):
    """
    Work out which column in a CSV is which.

    Returns a dictionary like {"site": 0, "username": 1, "password": 2}.
    Missing columns are simply absent from the dictionary.

    Site is picked before url because most exports have both and the human
    readable name makes a better entry title than the raw address.
    """
    normalised = [_normalise_header(header) for header in header_row]

    mapping = {}

    def first_match(candidates, exclude=None):
        for index, name in enumerate(normalised):
            if exclude and index in exclude:
                continue
            for candidate in candidates:
                if name == candidate:
                    return index
        return None

    site_index = first_match(SITE_COLUMNS)
    if site_index is not None:
        mapping["site"] = site_index

    url_index = first_match(URL_COLUMNS, exclude=set(mapping.values()))
    if url_index is not None:
        mapping["url"] = url_index

    username_index = first_match(USERNAME_COLUMNS)
    if username_index is not None:
        mapping["username"] = username_index

    password_index = first_match(PASSWORD_COLUMNS)
    if password_index is not None:
        mapping["password"] = password_index

    notes_index = first_match(NOTES_COLUMNS)
    if notes_index is not None:
        mapping["notes"] = notes_index

    totp_index = first_match(TOTP_COLUMNS)
    if totp_index is not None:
        mapping["totp"] = totp_index

    tags_index = first_match(TAG_COLUMNS)
    if tags_index is not None:
        mapping["tags"] = tags_index

    favourite_index = first_match(FAVORITE_COLUMNS)
    if favourite_index is not None:
        mapping["favorite"] = favourite_index

    return mapping


def preview_csv(path, limit=5):
    """
    Look at a CSV without importing it.

    Returns a dictionary with the header, the column mapping and a few
    sample rows, so the user can see that the importer understood the file
    before any data is written.
    """
    text = _read_text_file(path)

    try:
        reader = csv.reader(io.StringIO(text))
        rows = list(reader)
    except csv.Error as problem:
        raise ImportError_("That CSV could not be parsed: " + str(problem))

    if not rows:
        raise ImportError_("The file is empty.")

    header = rows[0]
    mapping = detect_columns(header)

    samples = []
    for row in rows[1:limit + 1]:
        # Never include the password column in a preview shown on screen.
        # It would be a shame to put a password on the screen just to check
        # that the import looks right.
        cleaned = []
        for index, cell in enumerate(row):
            if index == mapping.get("password"):
                cleaned.append("(hidden)")
            else:
                cleaned.append(utils.truncate(cell, 40))
        samples.append(cleaned)

    return {
        "header": header,
        "mapping": mapping,
        "row_count": max(0, len(rows) - 1),
        "samples": samples,
        "has_password_column": "password" in mapping,
    }


def read_csv_entries(path, default_tags=None, allow_empty_password=False):
    """
    Read a CSV file and turn it into a list of entry dictionaries.

    Rows that make no sense are skipped and counted, because refusing to
    import 400 good rows because of one broken one would be infuriating.
    """
    text = _read_text_file(path)

    try:
        reader = csv.reader(io.StringIO(text))
        rows = list(reader)
    except csv.Error as problem:
        raise ImportError_("That CSV could not be parsed: " + str(problem))

    if len(rows) < 2:
        raise ImportError_("The file has a header but no rows.")

    header = rows[0]
    mapping = detect_columns(header)

    if "password" not in mapping:
        raise ImportError_(
            "I could not find a password column in this file. "
            "The header was: " + ", ".join(str(cell) for cell in header)
        )

    entries = []
    skipped = 0

    for row in rows[1:]:
        # Skip completely blank lines, which appear at the end of exports.
        if not row or all(str(cell).strip() == "" for cell in row):
            continue

        def cells(key):
            index = mapping.get(key)
            if index is None or index >= len(row):
                return ""
            return str(row[index]).strip()

        password = cells("password")
        if password == "" and not allow_empty_password:
            skipped += 1
            continue

        site = cells("site")
        if site == "":
            # Fall back to the URL, then to the username, then to a label.
            site = cells("url") or cells("username") or "imported entry"

        entry = vault_module.new_entry(
            site=site,
            username=cells("username"),
            password=password,
            url=cells("url"),
            notes=cells("notes"),
        )

        totp_value = cells("totp")
        if totp_value:
            entry["totp_secret"] = totp_value

        raw_tags = cells("tags")
        tags = list(default_tags or [])
        if raw_tags:
            # Different tools separate tags with commas, semicolons or
            # spaces. Split on any of them and let the vault clean up.
            for piece in raw_tags.replace(";", ",").replace(" ", ",").split(","):
                if piece.strip():
                    tags.append(piece.strip())
        entry["tags"] = tags

        favourite_value = cells("favorite").lower()
        if favourite_value in ("1", "true", "yes", "y"):
            entry["favorite"] = True

        entries.append(entry)

    return entries, {"read": len(entries) + skipped, "skipped": skipped, "mapping": mapping}


def import_from_file(open_vault_object, path, default_tags=None, dry_run=False):
    """
    The one function the menu calls.

    Detects the file type and does the right thing. Returns a summary
    dictionary so the user interface can report what happened.
    """
    kind = detect_format(path)

    if kind == "csv":
        entries, stats = read_csv_entries(path, default_tags=default_tags)
        if dry_run:
            return {"kind": "csv", "would_add": len(entries),
                    "skipped": stats["skipped"], "mapping": stats["mapping"]}
        added, skipped = open_vault_object.add_many(entries)
        return {"kind": "csv", "added": added,
                "skipped": skipped + stats["skipped"],
                "mapping": stats["mapping"]}

    if kind == "legacy-json":
        entries = read_legacy_json(path)
        if dry_run:
            return {"kind": "legacy-json", "would_add": len(entries), "skipped": 0}
        added, skipped = open_vault_object.add_many(entries)
        return {"kind": "legacy-json", "added": added, "skipped": skipped}

    if kind == "securevault-json":
        entries = read_securevault_json(path)
        if dry_run:
            return {"kind": "securevault-json", "would_add": len(entries), "skipped": 0}
        added, skipped = open_vault_object.add_many(entries)
        return {"kind": "securevault-json", "added": added, "skipped": skipped}

    if kind == "securevault-backup":
        raise ImportError_(
            "That is an encrypted backup, not a plain export. "
            "Use the Backups menu to restore it, because it needs its passphrase."
        )

    raise ImportError_(
        "I could not work out what kind of file that is. Supported: CSV, "
        "an old passwords.json from version 1, or a SecureVault JSON export."
    )


def read_legacy_json(path):
    """
    Read the format the very first version of this project wrote.

    It was a bare JSON list of {"site", "username", "password"} objects,
    unencrypted, sitting next to the program. The names in the code were
    spelled with the same keys, so the migration is a straight rename.
    """
    text = _read_text_file(path)

    try:
        data = json.loads(text)
    except ValueError:
        raise ImportError_("That file is not valid JSON, so it is not an old vault file.")

    if isinstance(data, dict):
        data = data.get("entries", [])

    if not isinstance(data, list):
        raise ImportError_("That JSON file does not contain a list of entries.")

    entries = []
    for item in data:
        if not isinstance(item, dict):
            continue
        site = item.get("site") or item.get("name") or item.get("title") or ""
        password = item.get("password") or ""
        if not site or not password:
            continue
        entry = vault_module.new_entry(
            site=site,
            username=item.get("username") or item.get("email") or "",
            password=password,
            url=item.get("url") or "",
            notes=item.get("notes") or "",
        )
        entries.append(entry)

    if not entries:
        raise ImportError_("There were no usable entries in that file.")

    return entries


def read_securevault_json(path):
    """Read a JSON export made by this program (see export_json below)."""
    text = _read_text_file(path)
    try:
        data = json.loads(text)
    except ValueError:
        raise ImportError_("That file is not valid JSON.")

    if isinstance(data, dict):
        entries = data.get("entries", [])
    elif isinstance(data, list):
        entries = data
    else:
        raise ImportError_("That JSON file does not contain entries.")

    return [vault_module.normalise_entry(entry) for entry in entries
            if isinstance(entry, dict)]


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_csv(open_vault_object, path, include_notes=True, include_totp=True):
    """
    Write every entry to a CSV file.

    This is plain text. There is no encryption, no obfuscation, nothing.
    That is what makes it useful (browsers can import it) and that is what
    makes it dangerous (anybody who reads the file has everything).

    Returns the number of rows written.
    """
    _refuse_to_overwrite_without_thinking(path)

    header = ["name", "url", "username", "password"]
    if include_notes:
        header.append("notes")
    header.append("tags")
    if include_totp:
        header.append("totp")

    rows = []
    for entry in open_vault_object.entries:
        row = [
            entry["site"],
            entry["url"],
            entry["username"],
            entry["password"],
        ]
        if include_notes:
            row.append(entry["notes"])
        row.append(",".join(entry["tags"]))
        if include_totp:
            row.append(entry["totp_secret"])
        rows.append(row)

    try:
        with open(path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(header)
            writer.writerows(rows)
    except OSError as problem:
        raise ExportError("Could not write the file: " + str(problem))

    _tighten(path)
    return len(rows)


def export_json(open_vault_object, path, include_trash=False):
    """
    Write a JSON export that this program can read back in.

    Still plain text, still dangerous, but it keeps notes, tags, TOTP
    secrets and history, which CSV throws away.
    """
    _refuse_to_overwrite_without_thinking(path)

    payload = {
        "format": "securevault-json",
        "version": 1,
        "exported_at": utils.now_iso(),
        "entry_count": len(open_vault_object.entries),
        "entries": open_vault_object.data.get("entries", []),
    }
    if include_trash:
        payload["trash"] = open_vault_object.data.get("trash", [])

    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
    except OSError as problem:
        raise ExportError("Could not write the file: " + str(problem))

    _tighten(path)
    return len(payload["entries"])


def export_printable_notes(open_vault_object, path):
    """
    A plain text listing meant for printing and putting in a drawer.

    No passwords. Only the site names, usernames and notes, so that after a
    disaster you at least know which accounts existed. This is the file to
    keep somewhere obvious.
    """
    lines = []
    lines.append("ACCOUNT LIST")
    lines.append("Generated: " + utils.human_datetime(utils.now_iso()))
    lines.append("")
    lines.append("This list deliberately contains no passwords.")
    lines.append("It exists so you know which accounts you have.")
    lines.append("")
    lines.append("-" * 60)

    for entry in sorted(open_vault_object.entries, key=lambda item: item["site"].lower()):
        lines.append("")
        lines.append(entry["site"])
        if entry["username"]:
            lines.append("    username: " + entry["username"])
        if entry["url"]:
            lines.append("    address:  " + entry["url"])
        if entry["tags"]:
            lines.append("    tags:     " + ", ".join(entry["tags"]))
        if entry["notes"]:
            lines.append("    notes:    " + entry["notes"].replace("\n", " ")[:200])

    lines.append("")
    lines.append("-" * 60)
    lines.append(str(len(open_vault_object.entries)) + " accounts in total.")

    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    except OSError as problem:
        raise ExportError("Could not write the file: " + str(problem))

    _tighten(path)
    return path


def _refuse_to_overwrite_without_thinking(path):
    """
    Do not silently replace an existing export.

    An export might be the only copy somebody has. Making a mistake here is
    expensive, so it is refused rather than confirmed. The user can pick a
    different file name.
    """
    if os.path.exists(path):
        raise ExportError(
            "There is already a file at that path. Pick a different name, "
            "or move the old file first. This program does not overwrite exports."
        )


def _tighten(path):
    """Owner-only permissions, where supported."""
    if os.name == "nt":
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
