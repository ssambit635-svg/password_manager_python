"""
storage.py

All of the reading and writing of files happens here.

There are three kinds of file in the data directory:

  meta.json      - things that are NOT secret: the salt, the KDF settings,
                   the password verifier, the login attempt counter, the
                   settings and the audit log of actions.
  vault.enc      - the whole vault, encrypted as one Fernet token.
  backups/       - encrypted backup files, each with its own passphrase.

Plus an attachments folder, where encrypted file blobs live, and a decoy
vault for the duress feature.

Every write goes to a temporary file first and then gets moved into place
with os.replace. That is atomic on every platform we care about. Without
it, a crash halfway through a write leaves a half written vault, and half a
vault is worse than no vault at all.
"""

import os
import json
import stat
import uuid

from . import constants, utils


class StorageError(Exception):
    """Something went wrong with the files on disk."""
    pass


def _default_data_dir():
    """
    Work out where the data directory should be when the user does not say.

    Order of preference:
      1. SECUREVAULT_HOME environment variable.
      2. .securevault in the current user's home folder.
      3. .securevault next to the program (for weird sandboxes with no home).

    The original version of this project dropped passwords.json in whatever
    folder you happened to run it from, which meant you lost your vault the
    moment you ran it from somewhere else. That was a bad idea.
    """
    from_env = os.environ.get(constants.DATA_DIR_ENV_VAR)
    if from_env and from_env.strip():
        return os.path.abspath(os.path.expanduser(from_env.strip()))

    home = os.path.expanduser("~")
    if home and home != "~":
        return os.path.join(home, ".securevault")

    return os.path.join(os.getcwd(), ".securevault")


class DataDirectory:
    """
    A thin wrapper around the folder that holds the vault.

    This class knows about file names and atomic writes. It knows nothing
    about what is inside the vault, because that is the Vault's job. Keeping
    the two apart made both files much easier to test.
    """

    def __init__(self, path=None):
        self.path = os.path.abspath(os.path.expanduser(path or _default_data_dir()))

    # -- paths ------------------------------------------------------------

    @property
    def meta_path(self):
        return os.path.join(self.path, constants.META_FILE)

    @property
    def vault_path(self):
        return os.path.join(self.path, constants.VAULT_FILE)

    @property
    def decoy_path(self):
        return os.path.join(self.path, constants.DECOY_VAULT_FILE)

    @property
    def backup_dir(self):
        return os.path.join(self.path, constants.BACKUP_DIR)

    @property
    def attachments_dir(self):
        return os.path.join(self.path, "attachments")

    @property
    def emergency_kit_path(self):
        return os.path.join(self.path, constants.EMERGENCY_KIT_FILE)

    def exists(self):
        return os.path.isdir(self.path)

    def describe(self):
        """A short path with the home folder replaced by ~, for display."""
        home = os.path.expanduser("~")
        if home and self.path.startswith(home):
            return "~" + self.path[len(home):]
        return self.path

    # -- creating the directory ------------------------------------------

    def ensure_exists(self):
        """
        Create the data directory and everything in it, if needed.

        On Linux and macOS we also make the folder readable by the owner
        only. This does not stop an administrator, and it does nothing at
        all on Windows, but it is a cheap extra wall.
        """
        try:
            os.makedirs(self.path, exist_ok=True)
            os.makedirs(self.backup_dir, exist_ok=True)
            os.makedirs(self.attachments_dir, exist_ok=True)
        except OSError as problem:
            raise StorageError(
                "Could not create the data folder at " + self.path + ": " + str(problem)
            )

        self._tighten_permissions()
        self._write_ignore_files()

    def _tighten_permissions(self):
        """Make files owner-only where the operating system supports it."""
        if os.name == "nt":
            return
        for target in (self.path, self.backup_dir, self.attachments_dir):
            try:
                os.chmod(target, stat.S_IRWXU)  # 0700
            except OSError:
                # Some filesystems (a mounted USB stick, a network share)
                # simply do not support chmod. Not worth an error.
                pass

    def _write_ignore_files(self):
        """
        Drop a .gitignore inside the data folder.

        This is a small kindness for anybody who runs the program from
        inside a git repository. If the data folder ends up in a commit, the
        vault gets committed. A two line .gitignore in the right place stops
        that from being possible.
        """
        ignore_text = (
            "# Created by SecureVault. Do not commit any of this.\n"
            "*\n"
            "!.gitignore\n"
        )
        targets = [
            os.path.join(self.path, ".gitignore"),
            os.path.join(self.backup_dir, ".gitignore"),
            os.path.join(self.attachments_dir, ".gitignore"),
        ]
        for target in targets:
            if os.path.exists(target):
                continue
            try:
                with open(target, "w", encoding="utf-8") as handle:
                    handle.write(ignore_text)
            except OSError:
                pass

    # -- atomic file helpers ---------------------------------------------

    def _write_bytes_atomically(self, path, data):
        """
        Write bytes to a file, all or nothing.

        Steps: write to path.tmp, flush, fsync (so the data is really on the
        disk and not sitting in an operating system buffer), then rename.
        The rename is the atomic part.
        """
        folder = os.path.dirname(path) or "."
        try:
            os.makedirs(folder, exist_ok=True)
        except OSError as problem:
            raise StorageError("Could not create folder " + folder + ": " + str(problem))

        temporary_path = path + ".tmp"
        try:
            with open(temporary_path, "wb") as handle:
                handle.write(data)
                handle.flush()
                try:
                    os.fsync(handle.fileno())
                except OSError:
                    pass
            if os.name != "nt":
                try:
                    os.chmod(temporary_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
                except OSError:
                    pass
            os.replace(temporary_path, path)
        except OSError as problem:
            # Clean up the temporary file so we do not leave litter behind.
            try:
                if os.path.exists(temporary_path):
                    os.remove(temporary_path)
            except OSError:
                pass
            raise StorageError("Could not write " + path + ": " + str(problem))

    def _read_bytes(self, path):
        try:
            with open(path, "rb") as handle:
                return handle.read()
        except FileNotFoundError:
            return None
        except OSError as problem:
            raise StorageError("Could not read " + path + ": " + str(problem))

    def _write_text(self, path, text):
        self._write_bytes_atomically(path, text.encode("utf-8"))

    def _read_text(self, path):
        raw = self._read_bytes(path)
        if raw is None:
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise StorageError("The file " + os.path.basename(path) + " is not valid text.")

    # -- meta.json --------------------------------------------------------

    def default_meta(self):
        """The starting shape of meta.json."""
        return {
            "schema": constants.SCHEMA_VERSION,
            "app_version": constants.APP_VERSION,
            "created_at": utils.now_iso(),
            "updated_at": utils.now_iso(),
            "kdf": None,
            "verifier": None,
            "recovery": None,
            "duress": None,
            "attempts": {
                "count": 0,
                "locked_until": None,
                "last_failure": None,
            },
            "settings": {
                "auto_lock_seconds": constants.DEFAULT_AUTO_LOCK_SECONDS,
                "clipboard_seconds": constants.DEFAULT_CLIPBOARD_SECONDS,
                "colour": True,
                "confirm_before_delete": True,
                "show_health_on_start": True,
            },
            "counters": {
                "unlocks": 0,
                "generated": 0,
                "backups": 0,
                "wrong_passwords": 0,
            },
            "audit_log": [],
        }

    def read_meta(self):
        """
        Load meta.json, creating it if it is not there.

        If the file is damaged we raise, because guessing at security
        settings is a terrible idea. The caller can offer to reset.
        """
        text = self._read_text(self.meta_path)
        if text is None:
            meta = self.default_meta()
            self.write_meta(meta)
            return meta

        try:
            meta = json.loads(text)
        except ValueError:
            raise StorageError(
                "meta.json is damaged and cannot be parsed. "
                "You can move it aside, but you will need your recovery code to rebuild the vault."
            )

        if not isinstance(meta, dict):
            raise StorageError("meta.json does not contain an object. Something is very wrong.")

        return self._fill_missing_meta_fields(meta)

    def _fill_missing_meta_fields(self, meta):
        """
        Add any settings that an older version of the program did not know
        about. This is called a migration, and doing it defensively means a
        vault made in version 1 still opens in version 2.
        """
        defaults = self.default_meta()
        for key, value in defaults.items():
            if key not in meta:
                meta[key] = value

        for section in ("attempts", "settings", "counters"):
            if not isinstance(meta.get(section), dict):
                meta[section] = defaults[section]
            for key, value in defaults[section].items():
                if key not in meta[section]:
                    meta[section][key] = value

        if not isinstance(meta.get("audit_log"), list):
            meta["audit_log"] = []

        return meta

    def write_meta(self, meta):
        """Save meta.json atomically. Always updates updated_at."""
        if not isinstance(meta, dict):
            raise StorageError("Refusing to write meta data that is not a dictionary.")
        meta["updated_at"] = utils.now_iso()
        try:
            text = json.dumps(meta, indent=2, ensure_ascii=False)
        except (TypeError, ValueError) as problem:
            raise StorageError("Could not turn the settings into JSON: " + str(problem))
        self._write_text(self.meta_path, text)

    def meta_exists(self):
        return os.path.exists(self.meta_path)

    # -- the vault --------------------------------------------------------

    def vault_exists(self):
        return os.path.exists(self.vault_path)

    def read_vault_token(self):
        """The encrypted vault blob, or None if there is no vault yet."""
        text = self._read_text(self.vault_path)
        if text is None:
            return None
        return text.strip()

    def write_vault_token(self, token):
        if not token:
            raise StorageError("Refusing to write an empty vault.")
        self._write_text(self.vault_path, str(token) + "\n")

    def delete_vault(self):
        """Remove the vault file. Used by the 'nuke everything' command."""
        try:
            if os.path.exists(self.vault_path):
                os.remove(self.vault_path)
        except OSError as problem:
            raise StorageError("Could not delete the vault file: " + str(problem))

    # -- the decoy vault (duress feature) ---------------------------------

    def decoy_exists(self):
        return os.path.exists(self.decoy_path)

    def read_decoy_token(self):
        text = self._read_text(self.decoy_path)
        if text is None:
            return None
        return text.strip()

    def write_decoy_token(self, token):
        self._write_text(self.decoy_path, str(token) + "\n")

    def delete_decoy(self):
        try:
            if os.path.exists(self.decoy_path):
                os.remove(self.decoy_path)
        except OSError as problem:
            raise StorageError("Could not delete the decoy vault: " + str(problem))

    # -- attachments ------------------------------------------------------
    # A note about attachments: the encrypted blob is a normal file on disk
    # with a random name. The original file name is stored INSIDE the
    # encrypted vault entry, not in the file name. So a folder listing leaks
    # how many attachments exist and roughly how big they are, and nothing
    # else.

    def save_attachment(self, plain_bytes):
        """
        Store one attachment blob.

        The caller hands over either bytes or already-encrypted text. Text is
        encoded to bytes here so the rest of this class only deals in bytes.
        """
        if isinstance(plain_bytes, str):
            payload = plain_bytes.encode("utf-8")
        else:
            payload = bytes(plain_bytes)

        blob_id = uuid.uuid4().hex
        path = os.path.join(self.attachments_dir, blob_id + ".bin")
        self._write_bytes_atomically(path, payload)
        return blob_id

    def read_attachment(self, blob_id):
        # Sanity check the id before turning it into a path. Without this,
        # somebody could store "../meta.json" in the vault file and make the
        # program read the wrong file.
        if not _is_safe_blob_id(blob_id):
            raise StorageError("That attachment id is not valid.")
        path = os.path.join(self.attachments_dir, blob_id + ".bin")
        data = self._read_bytes(path)
        if data is None:
            raise StorageError("That attachment is missing from the data folder.")
        return data.decode("utf-8")

    def delete_attachment(self, blob_id):
        if not _is_safe_blob_id(blob_id):
            return False
        path = os.path.join(self.attachments_dir, blob_id + ".bin")
        try:
            if os.path.exists(path):
                os.remove(path)
                return True
        except OSError:
            pass
        return False

    def attachment_count(self):
        try:
            names = os.listdir(self.attachments_dir)
        except OSError:
            return 0
        return len([name for name in names if name.endswith(".bin")])

    # -- backups ----------------------------------------------------------

    def list_backups(self):
        """Return a list of backup file names, newest first."""
        try:
            names = os.listdir(self.backup_dir)
        except OSError:
            return []
        names = [name for name in names if name.endswith(".svbackup")]
        names.sort(reverse=True)
        return names

    def backup_path(self, name):
        """Resolve a backup file name, refusing anything with a path in it."""
        if "/" in name or "\\" in name or ".." in name:
            raise StorageError("That backup name is not valid.")
        return os.path.join(self.backup_dir, name)

    def write_backup(self, name, text):
        path = self.backup_path(name)
        self._write_text(path, text)
        return path

    def read_backup(self, name):
        return self._read_text(self.backup_path(name))

    def delete_backup(self, name):
        path = self.backup_path(name)
        try:
            os.remove(path)
            return True
        except OSError:
            return False

    def backup_size_bytes(self, name):
        try:
            return os.path.getsize(self.backup_path(name))
        except OSError:
            return 0

    # -- audit log --------------------------------------------------------
    # The audit log records what happened, not what was in the vault. Wrong
    # passwords, unlocks, exports, deletions. It is plain text in meta.json
    # on purpose: you can read it with cat when you are worried.

    def append_audit(self, meta, event, detail="", limit=constants.MAX_AUDIT_LOG_ENTRIES):
        entry = {
            "at": utils.now_iso(),
            "event": str(event),
            "detail": str(detail)[:200],
        }
        log = meta.setdefault("audit_log", [])
        log.append(entry)
        while len(log) > limit:
            log.pop(0)
        return meta

    def log_and_save(self, meta, event, detail=""):
        """Add an audit entry and write meta.json in one step."""
        self.append_audit(meta, event, detail)
        self.write_meta(meta)


def _is_safe_blob_id(blob_id):
    """
    True only for 32 lowercase hex characters.

    Attachments are addressed by the id the program generated itself, so
    there is no reason to accept anything else, and refusing anything else
    closes off a whole category of path trickery.
    """
    if not isinstance(blob_id, str):
        return False
    if len(blob_id) != 32:
        return False
    for character in blob_id:
        if character not in "0123456789abcdef":
            return False
    return True


def folder_is_writable(path):
    """
    Check whether we will be able to write to a folder, without creating
    anything permanment. Used by doctor.
    """
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        return False

    probe = os.path.join(path, ".write_probe_" + uuid.uuid4().hex)
    try:
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("probe")
        os.remove(probe)
        return True
    except OSError:
        return False


def human_bytes(number):
    """Turn a byte count into something readable."""
    if number is None:
        return "unknown"
    try:
        number = float(number)
    except (TypeError, ValueError):
        return "unknown"

    units = ["bytes", "KB", "MB", "GB", "TB"]
    index = 0
    while number >= 1024 and index < len(units) - 1:
        number = number / 1024.0
        index += 1

    if index == 0:
        return str(int(number)) + " bytes"
    return str(round(number, 1)) + " " + units[index]
