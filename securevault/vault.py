"""
vault.py

The vault itself: the list of entries, and what you can do to them.

The whole vault is one Python dictionary:

    {
        "schema": 2,
        "created_at": "...",
        "entries": [ ... one dictionary per saved item ... ],
        "trash": [ ... deleted items, waiting to be purged ... ],
        "revision": 12
    }

Every time anything changes, the whole dictionary is encrypted and written
out in one go. That sounds wasteful, and for a hundred entries it is
completely fine: the file is a few kilobytes. Doing it this way means there
is no such thing as a half-updated record, and it makes the backup and
restore code almost trivial.

Deleting an entry moves it to the trash rather than removing it, because
people delete things by accident and a password manager that loses data is
worse than useless.
"""

import copy
import base64
import hashlib
import secrets

from . import utils, crypto, strength, totp


class VaultError(Exception):
    """A vault operation could not be completed. Message is user friendly."""
    pass


# How many old passwords to keep per entry when the password is changed.
# Ten is enough to undo a mistake, and small enough not to bloat the file.
MAX_HISTORY_ENTRIES = 10

# Longest allowed field lengths. These are here so that a pasted novel or a
# stray binary blob does not end up inside the encrypted file forever.
MAX_SITE_LENGTH = 200
MAX_USERNAME_LENGTH = 200
MAX_PASSWORD_LENGTH = 512
MAX_URL_LENGTH = 500
MAX_NOTES_LENGTH = 5000
MAX_TAGS = 20
MAX_TAG_LENGTH = 32
MAX_ATTACHMENT_BYTES = 2 * 1024 * 1024  # 2 MB per attachment


def new_entry_id():
    """
    A short random id for an entry.

    Four bytes of randomness, so eight hex characters. Collisions are
    extremely unlikely at the scale of a personal vault, and the code below
    still checks for them.
    """
    return secrets.token_hex(4)


def new_entry(site, username, password, url="", notes="", tags=None, favorite=False):
    """
    Build a fresh entry dictionary.

    Everything gets filled in here so that no other part of the program has
    to remember which fields exist. Missing fields are the single most
    common cause of KeyError crashes in projects like this.
    """
    now = utils.now_iso()
    return {
        "id": new_entry_id(),
        "site": str(site).strip(),
        "url": str(url).strip(),
        "username": str(username).strip(),
        "password": str(password),
        "notes": str(notes).strip(),
        "tags": list(tags or []),
        "favorite": bool(favorite),
        "kind": "login",
        "totp_secret": "",
        "totp_issuer": "",
        "created_at": now,
        "updated_at": now,
        "password_changed_at": now,
        "last_used_at": None,
        "use_count": 0,
        "expires_at": None,
        "history": [],
        "attachments": [],
    }


def normalise_entry(raw):
    """
    Take an entry that came from disk (or from an import, or from a backup)
    and make sure it has every field the rest of the program expects.

    This function is deliberately forgiving. A vault from an older version
    should open, not crash. Unknown fields are kept so that a round trip
    through this program does not quietly destroy data from a newer one.
    """
    if not isinstance(raw, dict):
        raise VaultError("An entry in the vault is not a dictionary.")

    entry = dict(raw)

    entry["id"] = str(entry.get("id") or new_entry_id())
    entry["site"] = str(entry.get("site", "(no site)"))
    entry["url"] = str(entry.get("url", ""))
    entry["username"] = str(entry.get("username", ""))
    entry["password"] = str(entry.get("password", ""))
    entry["notes"] = str(entry.get("notes", ""))
    entry["kind"] = str(entry.get("kind", "login"))
    entry["totp_secret"] = str(entry.get("totp_secret", ""))
    entry["totp_issuer"] = str(entry.get("totp_issuer", ""))

    tags = entry.get("tags", [])
    if not isinstance(tags, list):
        tags = []
    entry["tags"] = [str(tag) for tag in tags if str(tag).strip()]

    entry["favorite"] = bool(entry.get("favorite", False))

    now = utils.now_iso()
    entry["created_at"] = entry.get("created_at") or now
    entry["updated_at"] = entry.get("updated_at") or entry["created_at"]
    entry["password_changed_at"] = entry.get("password_changed_at") or entry["created_at"]
    entry["last_used_at"] = entry.get("last_used_at") or None
    entry["expires_at"] = entry.get("expires_at") or None

    try:
        entry["use_count"] = int(entry.get("use_count", 0))
    except (TypeError, ValueError):
        entry["use_count"] = 0

    history = entry.get("history", [])
    if not isinstance(history, list):
        history = []
    entry["history"] = [item for item in history if isinstance(item, dict)]

    attachments = entry.get("attachments", [])
    if not isinstance(attachments, list):
        attachments = []
    entry["attachments"] = [item for item in attachments if isinstance(item, dict)]

    return entry


class Vault:
    """
    An open vault.

    You do not create one of these directly. Use Vault.create() the first
    time, and Vault.load() after that. Both of them need the encryption key,
    which only exists after the master password has been checked.
    """

    def __init__(self, data_directory, key, meta, is_decoy=False):
        self.data_directory = data_directory
        self.key = key
        self.meta = meta
        self.is_decoy = is_decoy
        self.data = {
            "schema": 2,
            "created_at": utils.now_iso(),
            "entries": [],
            "trash": [],
            "revision": 0,
        }
        self.dirty = False

    # -- creation and loading -------------------------------------------

    @classmethod
    def create(cls, data_directory, key, meta, is_decoy=False):
        """Start a brand new, empty vault."""
        vault = cls(data_directory, key, meta, is_decoy)
        vault.data["created_at"] = utils.now_iso()
        vault.save()
        return vault

    @classmethod
    def load(cls, data_directory, key, meta, is_decoy=False):
        """
        Open an existing vault.

        If the file is missing we start empty. If it exists but will not
        decrypt, the key is wrong and we say so clearly instead of writing
        an empty vault over the top of the real one.
        """
        vault = cls(data_directory, key, meta, is_decoy)

        if is_decoy:
            token = data_directory.read_decoy_token()
        else:
            token = data_directory.read_vault_token()

        if token is None:
            vault.data = {
                "schema": 2,
                "created_at": utils.now_iso(),
                "entries": [],
                "trash": [],
                "revision": 0,
            }
            return vault

        try:
            raw = crypto.decrypt_dict(token, key)
        except crypto.WrongPasswordError:
            raise VaultError(
                "The vault could not be decrypted. The master password does not match this vault file."
            )
        except crypto.CryptoError as problem:
            raise VaultError(str(problem))

        if "entries" not in raw or not isinstance(raw["entries"], list):
            raise VaultError("The vault file decrypted but does not contain an entry list.")

        vault.data = raw
        vault.data["trash"] = raw.get("trash", []) if isinstance(raw.get("trash"), list) else []
        vault.data["revision"] = int(raw.get("revision", 0))

        # Normalise every entry once, at load time. Then the rest of the
        # program can trust that the fields exist.
        vault.data["entries"] = [normalise_entry(entry) for entry in vault.data["entries"]]
        vault.data["trash"] = [
            normalise_entry(entry) for entry in vault.data["trash"] if isinstance(entry, dict)
        ]

        return vault

    # -- saving ---------------------------------------------------------

    def save(self):
        """
        Encrypt and write the whole vault.

        The revision number goes up on every save. It is not security, it is
        just a way to sanity check backup files and to see whether anything
        has actually changed.
        """
        self.data["revision"] = int(self.data.get("revision", 0)) + 1
        self.data["saved_at"] = utils.now_iso()

        try:
            token = crypto.encrypt_dict(self.data, self.key)
        except crypto.CryptoError as problem:
            raise VaultError("Could not encrypt the vault: " + str(problem))

        if self.is_decoy:
            self.data_directory.write_decoy_token(token)
        else:
            self.data_directory.write_vault_token(token)

        self.dirty = False
        return self.data["revision"]

    def export_for_backup(self):
        """
        A deep copy of everything, for the backup module to encrypt with a
        different passphrase. Deep copy matters: if the backup module holds
        on to a reference and we then edit an entry, the backup changes too.
        """
        return copy.deepcopy(self.data)

    # -- looking things up ----------------------------------------------

    @property
    def entries(self):
        return self.data["entries"]

    @property
    def trash(self):
        return self.data["trash"]

    def count(self):
        return len(self.data["entries"])

    def trash_count(self):
        return len(self.data["trash"])

    def is_empty(self):
        return len(self.data["entries"]) == 0

    def get(self, entry_id):
        """Find one entry by id, or None."""
        for entry in self.data["entries"]:
            if entry["id"] == entry_id:
                return entry
        return None

    def get_or_raise(self, entry_id):
        entry = self.get(entry_id)
        if entry is None:
            raise VaultError("There is no entry with that id. It may have been deleted.")
        return entry

    def index_of(self, entry_id):
        """The position of an entry in the list, or -1."""
        for index, entry in enumerate(self.data["entries"]):
            if entry["id"] == entry_id:
                return index
        return -1

    def all_tags(self):
        """
        Every tag in use, with a count, sorted by count then name.

        Returns a list of (tag, count) tuples. Using a dictionary first is
        the quick way to count things in Python.
        """
        counts = {}
        for entry in self.data["entries"]:
            for tag in entry["tags"]:
                counts[tag] = counts.get(tag, 0) + 1
        pairs = list(counts.items())
        pairs.sort(key=lambda pair: (-pair[1], pair[0].lower()))
        return pairs

    def entries_with_tag(self, tag):
        tag = str(tag).lower().strip()
        return [entry for entry in self.data["entries"]
                if tag in [item.lower() for item in entry["tags"]]]

    def favorites(self):
        return [entry for entry in self.data["entries"] if entry["favorite"]]

    def duplicate_sites(self):
        """
        Groups of entries that share a site name.

        Not the same as "same password", which is what audit checks. Two
        accounts on the same site is normal and fine; this is just useful
        when you are cleaning up.
        """
        groups = {}
        for entry in self.data["entries"]:
            key = entry["site"].lower().strip()
            groups.setdefault(key, []).append(entry)
        return {site: entries for site, entries in groups.items() if len(entries) > 1}

    # -- searching ------------------------------------------------------

    def search(self, query, include_trash=False, exact=False):
        """
        Find entries by typing almost anything.

        The search looks at the site, the url, the username, the notes and
        the tags. It is fuzzy, so "gtihub" still finds GitHub, and it does
        not care about capitals.
        """
        query = str(query).strip()
        if query == "":
            return []

        pool = list(self.data["entries"])
        if include_trash:
            pool += list(self.data["trash"])

        if exact:
            results = [entry for entry in pool if entry["site"].lower() == query.lower()]
        else:
            results = []
            for entry in pool:
                haystack = " ".join([
                    entry["site"],
                    entry["url"],
                    entry["username"],
                    entry["notes"],
                    " ".join(entry["tags"]),
                ])
                if utils.is_fuzzy_match(query, haystack):
                    results.append(entry)

        # Two pass sort: favourites first, then alphabetical. Python's sort
        # is stable, so the second sort keeps the favourites on top.
        results.sort(key=lambda entry: entry["site"].lower())
        results.sort(key=lambda entry: not entry["favorite"])
        return results

    def sorted_entries(self, sort_by="site", reverse=False, only_favorites=False,
                       tag=None):
        """
        The list as the user wants to see it.

        sort_by can be site, updated, created, oldest, health or uses.
        """
        entries = list(self.data["entries"])

        if only_favorites:
            entries = [entry for entry in entries if entry["favorite"]]

        if tag:
            entries = [entry for entry in entries
                       if str(tag).lower() in [item.lower() for item in entry["tags"]]]

        if sort_by == "site":
            entries.sort(key=lambda entry: entry["site"].lower(), reverse=reverse)
        elif sort_by == "updated":
            entries.sort(key=lambda entry: entry["updated_at"], reverse=not reverse)
        elif sort_by == "created":
            entries.sort(key=lambda entry: entry["created_at"], reverse=not reverse)
        elif sort_by == "oldest":
            entries.sort(key=lambda entry: entry["password_changed_at"])
        elif sort_by == "uses":
            entries.sort(key=lambda entry: entry["use_count"], reverse=not reverse)
        elif sort_by == "health":
            # Worst first. This needs a password score for every entry, so
            # it is the slowest sort, but a vault has tens of entries, not
            # millions, so who cares.
            entries.sort(
                key=lambda entry: strength.analyse(entry["password"], entry["site"],
                                                  entry["username"])["score"]
            )
        else:
            entries.sort(key=lambda entry: entry["site"].lower(), reverse=reverse)

        # Favourites float to the top in every sort except when sorting by
        # an explicit numeric field, because that would be confusing.
        if sort_by not in ("updated", "created", "uses") and not reverse:
            entries.sort(key=lambda entry: not entry["favorite"])

        return entries

    # -- adding and editing ---------------------------------------------

    def add_entry(self, site, username, password, url="", notes="", tags=None,
                  favorite=False, totp_secret="", expires_at=None):
        """
        Add a new entry and save. Returns the entry so the caller can show
        its id or its strength.
        """
        site = str(site).strip()
        if site == "":
            raise VaultError("An entry needs a site name.")
        if len(site) > MAX_SITE_LENGTH:
            raise VaultError("That site name is too long.")

        password = str(password)
        if password == "":
            raise VaultError("An entry needs a password. Use the generator if you need one.")
        if len(password) > MAX_PASSWORD_LENGTH:
            raise VaultError("That password is longer than any service accepts.")

        if username and len(str(username)) > MAX_USERNAME_LENGTH:
            raise VaultError("That username is too long.")

        entry = new_entry(site, username, password, url=url, notes=notes,
                          tags=tags, favorite=favorite)
        entry["totp_secret"] = totp.normalise_secret(totp_secret) if totp_secret else ""
        entry["expires_at"] = expires_at

        # Make sure the id is not already in use. It should never happen,
        # but "should never happen" is how you end up with two entries that
        # cannot be told apart.
        while self.get(entry["id"]) is not None:
            entry["id"] = new_entry_id()

        if len(entry["notes"]) > MAX_NOTES_LENGTH:
            entry["notes"] = entry["notes"][:MAX_NOTES_LENGTH]

        entry["tags"] = self._clean_tags(entry["tags"])

        self.data["entries"].append(entry)
        self.save()
        return entry

    def _clean_tags(self, tags):
        """Lower case, trim, remove empties and duplicates, cap the count."""
        cleaned = []
        for tag in tags or []:
            text = str(tag).strip().lower()
            if text == "":
                continue
            if len(text) > MAX_TAG_LENGTH:
                text = text[:MAX_TAG_LENGTH]
            if text not in cleaned:
                cleaned.append(text)
        return cleaned[:MAX_TAGS]

    def update_entry(self, entry_id, **changes):
        """
        Change some fields of an entry.

        The important bit: if the password changes, the old one is pushed
        onto the history list and password_changed_at is stamped. That is
        what makes the "you have not changed this password in two years"
        warning possible.
        """
        entry = self.get_or_raise(entry_id)
        now = utils.now_iso()

        allowed = [
            "site", "url", "username", "password", "notes", "tags",
            "favorite", "totp_secret", "totp_issuer", "expires_at",
        ]

        password_changed = False

        for field_name in allowed:
            if field_name not in changes:
                continue
            value = changes[field_name]

            if field_name == "password":
                value = str(value)
                if value == "":
                    raise VaultError("The password cannot be empty.")
                if len(value) > MAX_PASSWORD_LENGTH:
                    raise VaultError("That password is too long.")
                if value != entry["password"]:
                    self._push_history(entry)
                    entry["password_changed_at"] = now
                    password_changed = True
                entry["password"] = value

            elif field_name == "site":
                value = str(value).strip()
                if value == "":
                    raise VaultError("The site name cannot be empty.")
                if len(value) > MAX_SITE_LENGTH:
                    raise VaultError("That site name is too long.")
                entry["site"] = value

            elif field_name == "username":
                entry["username"] = str(value).strip()[:MAX_USERNAME_LENGTH]

            elif field_name == "url":
                entry["url"] = str(value).strip()[:MAX_URL_LENGTH]

            elif field_name == "notes":
                entry["notes"] = str(value)[:MAX_NOTES_LENGTH]

            elif field_name == "tags":
                entry["tags"] = self._clean_tags(value)

            elif field_name == "favorite":
                entry["favorite"] = bool(value)

            elif field_name == "totp_secret":
                entry["totp_secret"] = totp.normalise_secret(str(value)) if value else ""

            elif field_name == "totp_issuer":
                entry["totp_issuer"] = str(value).strip()

            elif field_name == "expires_at":
                entry["expires_at"] = value or None

        entry["updated_at"] = now
        self.save()
        return entry, password_changed

    def _push_history(self, entry):
        """Remember the password that is about to be replaced."""
        history = entry.get("history", [])
        history.append({
            "password": entry["password"],
            "changed_at": entry["updated_at"],
        })
        while len(history) > MAX_HISTORY_ENTRIES:
            history.pop(0)
        entry["history"] = history

    def set_password(self, entry_id, new_password):
        """A shortcut for the most common edit."""
        entry, changed = self.update_entry(entry_id, password=new_password)
        return entry, changed

    def rename_site(self, entry_id, new_site):
        return self.update_entry(entry_id, site=new_site)

    def toggle_favorite(self, entry_id):
        entry = self.get_or_raise(entry_id)
        entry["favorite"] = not entry["favorite"]
        entry["updated_at"] = utils.now_iso()
        self.save()
        return entry["favorite"]

    def mark_used(self, entry_id):
        """
        Called when somebody copies a password or reveals one. It is how
        "last used" and "never used" in the health report are worked out.
        """
        entry = self.get(entry_id)
        if entry is None:
            return
        entry["last_used_at"] = utils.now_iso()
        entry["use_count"] = int(entry.get("use_count", 0)) + 1
        self.save()

    def add_tag(self, entry_id, tag):
        entry = self.get_or_raise(entry_id)
        tags = list(entry["tags"])
        tags.append(tag)
        entry["tags"] = self._clean_tags(tags)
        entry["updated_at"] = utils.now_iso()
        self.save()
        return entry["tags"]

    def remove_tag(self, entry_id, tag):
        entry = self.get_or_raise(entry_id)
        tag = str(tag).lower().strip()
        entry["tags"] = [item for item in entry["tags"] if item.lower() != tag]
        entry["updated_at"] = utils.now_iso()
        self.save()
        return entry["tags"]

    def rename_tag_everywhere(self, old_tag, new_tag):
        """Rename a tag across every entry that uses it."""
        old_tag = str(old_tag).lower().strip()
        new_tag = str(new_tag).lower().strip()
        if new_tag == "":
            raise VaultError("The new tag cannot be empty.")

        changed = 0
        for entry in self.data["entries"]:
            lowered = [item.lower() for item in entry["tags"]]
            if old_tag in lowered:
                entry["tags"] = [new_tag if item.lower() == old_tag else item
                                 for item in entry["tags"]]
                entry["tags"] = self._clean_tags(entry["tags"])
                entry["updated_at"] = utils.now_iso()
                changed += 1

        if changed:
            self.save()
        return changed

    # -- deleting -------------------------------------------------------

    def delete_entry(self, entry_id, permanent=False):
        """
        Move an entry to the trash, or destroy it for real.

        Attachments owned by the entry are only removed from the disk when
        the entry is purged for real, otherwise restoring from the trash
        would give back an entry whose attachments had vanished.
        """
        index = self.index_of(entry_id)
        if index < 0:
            raise VaultError("That entry is not in the vault.")

        entry = self.data["entries"].pop(index)

        if permanent:
            self._delete_attachments_of(entry)
        else:
            entry["deleted_at"] = utils.now_iso()
            self.data["trash"].append(entry)

        self.save()
        return entry

    def restore_entry(self, entry_id):
        """Take an entry back out of the trash."""
        for index, entry in enumerate(self.data["trash"]):
            if entry["id"] == entry_id:
                removed = self.data["trash"].pop(index)
                removed.pop("deleted_at", None)
                self.data["entries"].append(removed)
                self.save()
                return removed
        raise VaultError("That entry is not in the trash.")

    def purge_entry(self, entry_id):
        """Destroy one entry from the trash, including its attachments."""
        for index, entry in enumerate(self.data["trash"]):
            if entry["id"] == entry_id:
                removed = self.data["trash"].pop(index)
                self._delete_attachments_of(removed)
                self.save()
                return removed
        raise VaultError("That entry is not in the trash.")

    def empty_trash(self):
        """
        Destroy every entry in the trash.

        Returns the number of entries destroyed. This one cannot be undone,
        which is why the menu asks you to type a word before calling it.
        """
        count = len(self.data["trash"])
        for entry in self.data["trash"]:
            self._delete_attachments_of(entry)
        self.data["trash"] = []
        self.save()
        return count

    def purge_expired(self):
        """
        Destroy entries whose expiry date has passed.

        This is the "mission impossible" feature: an entry that deletes
        itself. Useful for a temporary password you are passing to somebody,
        or for a shared account that is being retired.
        """
        import datetime

        now = datetime.datetime.now(datetime.timezone.utc)
        survivors = []
        expired_ids = []

        for entry in self.data["entries"]:
            expires_at = entry.get("expires_at")
            if not expires_at:
                survivors.append(entry)
                continue

            moment = utils.parse_iso(expires_at)
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=datetime.timezone.utc)

            if moment <= now:
                expired_ids.append(entry["id"])
                self._delete_attachments_of(entry)
            else:
                survivors.append(entry)

        if expired_ids:
            self.data["entries"] = survivors
            self.save()

        return expired_ids

    def entries_expiring_soon(self, days=7):
        """Entries that will expire within the next few days."""
        import datetime

        now = datetime.datetime.now(datetime.timezone.utc)
        limit = now + datetime.timedelta(days=days)
        soon = []

        for entry in self.data["entries"]:
            expires_at = entry.get("expires_at")
            if not expires_at:
                continue
            moment = utils.parse_iso(expires_at)
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=datetime.timezone.utc)
            if now < moment <= limit:
                soon.append(entry)

        return soon

    def _delete_attachments_of(self, entry):
        """Delete every attachment blob belonging to an entry."""
        for attachment in entry.get("attachments", []):
            blob_id = attachment.get("id")
            if blob_id:
                self.data_directory.delete_attachment(blob_id)

    # -- attachments ----------------------------------------------------

    def attach_file(self, entry_id, file_name, raw_bytes):
        """
        Store a file inside the vault.

        The bytes are encrypted with the same vault key and saved as a blob
        with a random name. Only the original file name, the size and a hash
        go into the entry itself, which is also encrypted.
        """
        entry = self.get_or_raise(entry_id)

        if len(raw_bytes) == 0:
            raise VaultError("That file is empty.")
        if len(raw_bytes) > MAX_ATTACHMENT_BYTES:
            raise VaultError("That file is bigger than the 2 MB limit.")

        encrypted_blob = _encrypt_bytes(raw_bytes, self.key)
        blob_id = self.data_directory.save_attachment(encrypted_blob)

        entry.setdefault("attachments", []).append({
            "id": blob_id,
            "name": str(file_name)[:200],
            "size": len(raw_bytes),
            "sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "added_at": utils.now_iso(),
        })
        entry["updated_at"] = utils.now_iso()
        self.save()
        return blob_id

    def read_attachment(self, entry_id, blob_id):
        """Return the decrypted bytes of an attachment."""
        entry = self.get_or_raise(entry_id)

        known = [attachment for attachment in entry.get("attachments", [])
                 if attachment.get("id") == blob_id]
        if not known:
            raise VaultError("That attachment is not part of this entry.")

        stored = self.data_directory.read_attachment(blob_id)
        raw = _decrypt_bytes(stored, self.key)

        expected = known[0].get("sha256")
        if expected:
            actual = hashlib.sha256(raw).hexdigest()
            if actual != expected:
                raise VaultError("The attachment is damaged: the checksum does not match.")

        return raw

    def remove_attachment(self, entry_id, blob_id):
        """Delete one attachment from an entry and from the disk."""
        entry = self.get_or_raise(entry_id)
        remaining = []
        removed = False

        for attachment in entry.get("attachments", []):
            if attachment.get("id") == blob_id:
                removed = True
            else:
                remaining.append(attachment)

        if not removed:
            raise VaultError("That attachment is not part of this entry.")

        entry["attachments"] = remaining
        entry["updated_at"] = utils.now_iso()
        self.data_directory.delete_attachment(blob_id)
        self.save()
        return True

    # -- importing ------------------------------------------------------

    def add_entry_object(self, entry, save=True):
        """
        Add an entry dictionary that came from somewhere else.

        Used by the CSV import and by the backup restore. Duplicates are
        checked on site plus username, because importing the same file twice
        should not double the vault.
        """
        candidate = normalise_entry(entry)

        for existing in self.data["entries"]:
            if (existing["site"].lower() == candidate["site"].lower()
                    and existing["username"].lower() == candidate["username"].lower()):
                raise VaultError(
                    "An entry for " + candidate["site"] + " / " + candidate["username"]
                    + " already exists."
                )

        while self.get(candidate["id"]) is not None:
            candidate["id"] = new_entry_id()

        self.data["entries"].append(candidate)
        if save:
            self.save()
        return candidate

    def add_many(self, entries):
        """Add a list of entry dictionaries, skipping duplicates. Returns counts."""
        added = 0
        skipped = 0
        for entry in entries:
            try:
                self.add_entry_object(entry, save=False)
                added += 1
            except VaultError:
                skipped += 1
        if added:
            self.save()
        return added, skipped


def _encrypt_bytes(raw_bytes, key):
    """
    Encrypt raw bytes by encoding them as base64 first.

    Fernet only encrypts text-ish payloads through our helper functions, and
    base64 turns any bytes into safe text. It costs about a third of the size
    and makes the code much simpler.
    """
    encoded = base64.b64encode(raw_bytes).decode("ascii")
    return crypto.encrypt_text(encoded, key)


def _decrypt_bytes(token, key):
    """The reverse of _encrypt_bytes."""
    encoded = crypto.decrypt_text(token, key)
    return base64.b64decode(encoded.encode("ascii"))


def summarise_entry(entry):
    """
    One line of text describing an entry. Used by the search results, the
    picker lists and the audit report.
    """
    pieces = [entry["site"]]
    if entry.get("username"):
        pieces.append("(" + entry["username"] + ")")
    if entry.get("favorite"):
        pieces.append("[favourite]")
    if entry.get("totp_secret"):
        pieces.append("[2fa]")
    if entry.get("expires_at"):
        pieces.append("[expires]")
    return " ".join(pieces)
