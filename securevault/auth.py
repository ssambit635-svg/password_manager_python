"""
auth.py

Everything about the master password: setting it, checking it, changing it,
and getting back in when it has been forgotten.

There are three ways into a vault and they are worth understanding before
reading the code:

  The master password.
      Typed every day. Derives the real key. Nothing about it is stored, only
      a verifier that lets us check a guess.

  The recovery code.
      Generated once when the vault is created, shown once, and meant to be
      printed and put somewhere safe. It does not replace the master
      password. What it does is unlock a second copy of the vault key, which
      was encrypted with the recovery code itself. That is what makes it
      possible to reset a forgotten master password WITHOUT losing the data.

  The duress password.
      Optional. A different password that opens a completely separate, empty
      looking vault. If somebody is forcing you to open your password
      manager, you give them that one.

The master password and the recovery code never touch the disk in a form
that can be checked directly. The duress password is stored the same way as
the master password, with its own salt.
"""

import base64
import datetime

from . import constants, crypto, utils, vault as vault_module


class AuthError(Exception):
    """A login problem. The message is safe to show to the user."""
    pass


class LockedOutError(AuthError):
    """Too many wrong passwords. Carries the wait time in seconds."""

    def __init__(self, message, seconds_remaining=0):
        AuthError.__init__(self, message)
        self.seconds_remaining = int(seconds_remaining)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _parse_moment(text):
    """Parse an ISO timestamp, always returning an aware UTC datetime."""
    moment = utils.parse_iso(text)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    return moment


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _pack_key(key):
    """Turn raw key bytes into text so Fernet can encrypt them."""
    return base64.b64encode(key).decode("ascii")


def _unpack_key(text):
    """The reverse of _pack_key."""
    try:
        key = base64.b64decode(str(text).encode("ascii"), validate=True)
    except Exception:
        raise AuthError("The stored key is damaged and cannot be read.")
    if len(key) != 32:
        raise AuthError("The stored key has the wrong length.")
    return key


def validate_new_master_password(password):
    """
    Complain about obviously terrible master passwords.

    Returns a list of problems. An empty list means it is fine. This is
    deliberately only a floor: the strength checker gives the real advice.
    """
    problems = []
    password = str(password or "")

    if len(password) < constants.MIN_MASTER_LENGTH:
        problems.append(
            "Use at least " + str(constants.MIN_MASTER_LENGTH) + " characters."
        )
    if password.strip() == "":
        problems.append("The password cannot be only spaces.")
    if password.lower() in constants.COMMON_PASSWORDS:
        problems.append("That password is one of the most common in the world.")
    if len(set(password)) == 1 and len(password) > 0:
        problems.append("A password made of one repeated character is not a password.")

    return problems


def master_password_score(password):
    """The strength score of a candidate master password, for the warning."""
    from . import strength
    return strength.analyse(password)["score"]


# ---------------------------------------------------------------------------
# Creating a vault for the first time
# ---------------------------------------------------------------------------

def setup_new_vault(data_directory, master_password, iterations=constants.DEFAULT_ITERATIONS):
    """
    Prepare a brand new vault.

    Steps:
      1. Random salt, then PBKDF2 to get the vault key.
      2. A verifier so future logins can check the password.
      3. A recovery code, and a copy of the vault key encrypted with it.
      4. Write meta.json.

    Returns (key, meta, recovery_code). The recovery code is only available
    right here, right now, so the caller must show it to the user before
    doing anything else.
    """
    problems = validate_new_master_password(master_password)
    if problems:
        raise AuthError(" ".join(problems))

    salt = crypto.generate_salt()
    key = crypto.derive_key(master_password, salt, iterations)

    if data_directory.meta_exists():
        meta = data_directory.read_meta()
    else:
        meta = data_directory.default_meta()

    meta["schema"] = constants.SCHEMA_VERSION
    meta["app_version"] = constants.APP_VERSION
    meta["created_at"] = meta.get("created_at") or utils.now_iso()
    meta["kdf"] = {
        "algorithm": "pbkdf2-hmac-sha256",
        "iterations": int(iterations),
        "salt": crypto.salt_to_text(salt),
    }
    meta["verifier"] = crypto.make_verifier(key, "vault")
    meta["attempts"] = {"count": 0, "locked_until": None, "last_failure": None}

    recovery_code = crypto.generate_recovery_code()
    meta["recovery"] = _build_recovery_record(recovery_code, key, iterations)

    data_directory.append_audit(meta, "vault_created", "new vault at " + data_directory.describe())
    data_directory.write_meta(meta)

    return key, meta, recovery_code


def _build_recovery_record(recovery_code, vault_key, iterations=constants.DEFAULT_ITERATIONS):
    """
    Make the recovery record stored in meta.json.

    It holds a salt, a verifier and the vault key encrypted with a key
    derived from the recovery code. Without the code, that encrypted key is
    useless. With it, the program can rebuild everything.
    """
    salt = crypto.generate_salt()
    recovery_key = crypto.derive_recovery_key(recovery_code, salt, iterations)

    encrypted_key = crypto.encrypt_text(_pack_key(vault_key), recovery_key)

    return {
        "algorithm": "pbkdf2-hmac-sha256",
        "iterations": int(iterations),
        "salt": crypto.salt_to_text(salt),
        "verifier": crypto.make_verifier(recovery_key, "recovery"),
        "wrapped_key": encrypted_key,
        "created_at": utils.now_iso(),
    }


# ---------------------------------------------------------------------------
# Unlocking
# ---------------------------------------------------------------------------

def is_locked_out(meta):
    """
    Returns (locked, seconds_remaining).

    The lockout is stored in meta.json, which means quitting and restarting
    the program does not reset it. It is not unbeatable: somebody who can
    edit meta.json can clear it. It raises the cost of casual guessing,
    which is the realistic threat for a file sitting on a laptop.
    """
    attempts = meta.get("attempts") or {}
    locked_until = attempts.get("locked_until")
    if not locked_until:
        return False, 0

    moment = _parse_moment(locked_until)
    remaining = (moment - _now()).total_seconds()
    if remaining <= 0:
        return False, 0
    return True, int(remaining)


def _record_failure(data_directory, meta, reason="wrong password"):
    """
    Count a failed attempt and lock the vault if there have been too many.

    The wait doubles each time the limit is passed: 30 seconds, a minute,
    two minutes, and so on up to an hour. The doubling is capped so that a
    person who really did just forget does not get locked out for a week.
    """
    attempts = meta.setdefault("attempts", {"count": 0, "locked_until": None,
                                            "last_failure": None})
    attempts["count"] = int(attempts.get("count", 0)) + 1
    attempts["last_failure"] = utils.now_iso()

    meta.setdefault("counters", {})
    meta["counters"]["wrong_passwords"] = int(meta["counters"].get("wrong_passwords", 0)) + 1

    over_limit = attempts["count"] - constants.MAX_LOGIN_ATTEMPTS
    if over_limit >= 0:
        wait = constants.LOCKOUT_BASE_SECONDS * (2 ** min(over_limit, 10))
        if wait > constants.LOCKOUT_MAX_SECONDS:
            wait = constants.LOCKOUT_MAX_SECONDS
        until = _now() + datetime.timedelta(seconds=wait)
        attempts["locked_until"] = until.replace(microsecond=0).isoformat()

    data_directory.append_audit(meta, "login_failed", reason)
    data_directory.write_meta(meta)


def _record_success(data_directory, meta, detail="master password"):
    """Clear the failure count after a good login."""
    meta["attempts"] = {"count": 0, "locked_until": None, "last_failure": None}
    meta.setdefault("counters", {})
    meta["counters"]["unlocks"] = int(meta["counters"].get("unlocks", 0)) + 1
    data_directory.append_audit(meta, "unlock", detail)
    data_directory.write_meta(meta)


def unlock(data_directory, master_password):
    """
    Check the master password and return (key, meta).

    Raises LockedOutError if the lockout is active, AuthError if the
    password is wrong.
    """
    if not data_directory.meta_exists():
        raise AuthError("There is no vault here yet. Create one first.")

    meta = data_directory.read_meta()

    if not meta.get("kdf") or not meta.get("verifier"):
        raise AuthError("This vault has no master password recorded. It may be damaged.")

    locked, remaining = is_locked_out(meta)
    if locked:
        raise LockedOutError(
            "Too many wrong passwords. Try again in " + utils.human_duration(remaining) + ".",
            remaining,
        )

    try:
        salt = crypto.salt_from_text(meta["kdf"]["salt"])
    except KeyError:
        raise AuthError("The vault settings are missing the salt. The file is damaged.")

    iterations = int(meta["kdf"].get("iterations", constants.DEFAULT_ITERATIONS))
    key = crypto.derive_key(str(master_password), salt, iterations)

    if not crypto.verifier_matches(meta.get("verifier"), key, "vault"):
        _record_failure(data_directory, meta)
        raise AuthError("Wrong master password.")

    _record_success(data_directory, meta, "master password")
    return key, meta


def verify_master_password(meta, master_password):
    """Check a password without touching the attempt counter or the disk."""
    if not meta.get("kdf") or not meta.get("verifier"):
        return False
    try:
        salt = crypto.salt_from_text(meta["kdf"]["salt"])
        iterations = int(meta["kdf"].get("iterations", constants.DEFAULT_ITERATIONS))
        key = crypto.derive_key(str(master_password), salt, iterations)
    except (KeyError, crypto.CryptoError):
        return False
    return crypto.verifier_matches(meta.get("verifier"), key, "vault")


def derive_key_for_meta(meta, master_password):
    """Turn a password into the vault key using the settings in meta."""
    salt = crypto.salt_from_text(meta["kdf"]["salt"])
    iterations = int(meta["kdf"].get("iterations", constants.DEFAULT_ITERATIONS))
    return crypto.derive_key(str(master_password), salt, iterations)


# ---------------------------------------------------------------------------
# Opening the vault after a successful login
# ---------------------------------------------------------------------------

def open_vault(data_directory, key, meta):
    """Load the vault, creating an empty one if this is the first time."""
    try:
        return vault_module.Vault.load(data_directory, key, meta)
    except vault_module.VaultError as problem:
        raise AuthError(str(problem))


# ---------------------------------------------------------------------------
# Changing the master password
# ---------------------------------------------------------------------------

def change_master_password(data_directory, open_vault_object, meta,
                           current_password, new_password,
                           iterations=constants.DEFAULT_ITERATIONS):
    """
    Re-key the vault.

    This is more work than it looks, because attachments are encrypted with
    the same key. Every attachment has to be decrypted with the old key and
    encrypted again with the new one, and its blob id changes. If we forgot
    that step, every attached file would become unreadable garbage the
    moment you changed your password.

    Returns (new_recovery_code). The recovery record has to be rebuilt too,
    because it wraps the key, and the key just changed.
    """
    if not verify_master_password(meta, current_password):
        _record_failure(data_directory, meta, "wrong password during change")
        raise AuthError("The current master password is not right.")

    problems = validate_new_master_password(new_password)
    if problems:
        raise AuthError(" ".join(problems))

    if str(new_password) == str(current_password):
        raise AuthError("The new password is the same as the old one.")

    old_key = open_vault_object.key

    new_salt = crypto.generate_salt()
    new_key = crypto.derive_key(new_password, new_salt, iterations)

    # Walk every entry and re-encrypt its attachments.
    rekeyed = _rekey_attachments(data_directory, open_vault_object, old_key, new_key)

    open_vault_object.key = new_key
    open_vault_object.save()

    meta["kdf"] = {
        "algorithm": "pbkdf2-hmac-sha256",
        "iterations": int(iterations),
        "salt": crypto.salt_to_text(new_salt),
    }
    meta["verifier"] = crypto.make_verifier(new_key, "vault")

    new_recovery_code = crypto.generate_recovery_code()
    meta["recovery"] = _build_recovery_record(new_recovery_code, new_key, iterations)
    meta["attempts"] = {"count": 0, "locked_until": None, "last_failure": None}

    data_directory.append_audit(
        meta, "master_password_changed",
        "attachments re-encrypted: " + str(rekeyed)
    )
    data_directory.write_meta(meta)

    return new_recovery_code


def _rekey_attachments(data_directory, open_vault_object, old_key, new_key):
    """Decrypt each attachment blob with the old key, save it under the new one."""
    from . import vault as vault_module

    moved = 0
    for entry in list(open_vault_object.entries) + list(open_vault_object.trash):
        for attachment in entry.get("attachments", []):
            old_blob = attachment.get("id")
            if not old_blob:
                continue
            try:
                stored = data_directory.read_attachment(old_blob)
                raw = vault_module._decrypt_bytes(stored, old_key)
                new_blob = data_directory.save_attachment(
                    vault_module._encrypt_bytes(raw, new_key)
                )
                attachment["id"] = new_blob
                data_directory.delete_attachment(old_blob)
                moved += 1
            except Exception:
                # A missing or damaged attachment should not stop a password
                # change. Leave it pointing at the old blob and carry on; the
                # doctor command will report it later.
                continue
    return moved


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------

def has_recovery(meta):
    return bool(meta.get("recovery") and meta["recovery"].get("wrapped_key"))


def verify_recovery_code(meta, recovery_code):
    """
    Check a recovery code against the stored verifier.

    Returns (ok, vault_key). The vault key is only returned if the code was
    right. It is available because the record holds it wrapped under the
    recovery key.
    """
    record = meta.get("recovery")
    if not record:
        return False, None

    try:
        salt = crypto.salt_from_text(record["salt"])
        iterations = int(record.get("iterations", constants.DEFAULT_ITERATIONS))
        recovery_key = crypto.derive_recovery_key(recovery_code, salt, iterations)
    except crypto.CryptoError:
        return False, None

    if not crypto.verifier_matches(record.get("verifier"), recovery_key, "recovery"):
        return False, None

    try:
        wrapped = crypto.decrypt_text(record["wrapped_key"], recovery_key)
        return True, _unpack_key(wrapped)
    except crypto.CryptoError:
        # The verifier matched but the key would not decrypt. That means the
        # file was edited by hand. Treat it as a failure.
        return False, None


def reset_with_recovery(data_directory, meta, recovery_code, new_password,
                        iterations=constants.DEFAULT_ITERATIONS):
    """
    Set a new master password using the recovery code.

    Returns (vault_object, new_recovery_code). The old master password is
    not needed, which is the whole point, and the data is not lost, because
    the vault key was recoverable from the recovery code.
    """
    ok, recovered_key = verify_recovery_code(meta, recovery_code)
    if not ok:
        _record_failure(data_directory, meta, "bad recovery code")
        raise AuthError("That recovery code is not right.")

    problems = validate_new_master_password(new_password)
    if problems:
        raise AuthError(" ".join(problems))

    # Open the vault with the recovered key, so we can rewrite it.
    open_vault_object = vault_module.Vault.load(data_directory, recovered_key, meta)
    open_vault_object.key = recovered_key

    new_salt = crypto.generate_salt()
    new_key = crypto.derive_key(new_password, new_salt, iterations)

    _rekey_attachments(data_directory, open_vault_object, recovered_key, new_key)

    open_vault_object.key = new_key
    open_vault_object.save()

    meta["kdf"] = {
        "algorithm": "pbkdf2-hmac-sha256",
        "iterations": int(iterations),
        "salt": crypto.salt_to_text(new_salt),
    }
    meta["verifier"] = crypto.make_verifier(new_key, "vault")

    fresh_recovery_code = crypto.generate_recovery_code()
    meta["recovery"] = _build_recovery_record(fresh_recovery_code, new_key, iterations)
    meta["attempts"] = {"count": 0, "locked_until": None, "last_failure": None}

    data_directory.append_audit(meta, "master_password_reset", "recovery code used")
    data_directory.write_meta(meta)

    return open_vault_object, fresh_recovery_code


def regenerate_recovery_code(data_directory, meta, vault_key):
    """Throw away the old recovery code and make a new one."""
    code = crypto.generate_recovery_code()
    meta["recovery"] = _build_recovery_record(code, vault_key)
    data_directory.append_audit(meta, "recovery_code_regenerated", "")
    data_directory.write_meta(meta)
    return code


# ---------------------------------------------------------------------------
# The duress password
# ---------------------------------------------------------------------------
# This is the feature nobody expects in a small project, and it is the one
# that gets the most questions. The idea is from the physical world: a
# "duress code" for a burglar alarm that opens the door but also silently
# calls the police, except here it opens a fake vault that looks completely
# ordinary.

def setup_duress(data_directory, meta, duress_password,
                 iterations=constants.DEFAULT_ITERATIONS):
    """
    Create the decoy vault and remember its password.

    The decoy is a real, valid, encrypted vault. It starts empty, and
    whatever the user puts in it later is genuinely saved. It is not a
    special mode that the program can enter by accident.
    """
    problems = validate_new_master_password(duress_password)
    if problems:
        raise AuthError(" ".join(problems))

    if verify_master_password(meta, duress_password):
        raise AuthError("The duress password cannot be the same as the master password.")

    salt = crypto.generate_salt()
    key = crypto.derive_key(duress_password, salt, iterations)

    meta["duress"] = {
        "enabled": True,
        "algorithm": "pbkdf2-hmac-sha256",
        "iterations": int(iterations),
        "salt": crypto.salt_to_text(salt),
        "verifier": crypto.make_verifier(key, "duress"),
        "created_at": utils.now_iso(),
    }

    decoy_vault = vault_module.Vault.create(data_directory, key, meta, is_decoy=True)

    data_directory.append_audit(meta, "duress_enabled", "")
    data_directory.write_meta(meta)

    return decoy_vault, key


def has_duress(meta):
    return bool(meta.get("duress") and meta["duress"].get("enabled"))


def check_duress_password(meta, password):
    """
    Returns the decoy key if the typed password is the duress password,
    otherwise None.

    This check does not count an attempt and does not write anything, on
    purpose. Somebody typing the duress password in a hurry should not leave
    a trail that a person watching the screen could notice.
    """
    record = meta.get("duress")
    if not record or not record.get("enabled"):
        return None

    try:
        salt = crypto.salt_from_text(record["salt"])
        iterations = int(record.get("iterations", constants.DEFAULT_ITERATIONS))
        key = crypto.derive_key(str(password), salt, iterations)
    except (KeyError, crypto.CryptoError):
        return None

    if crypto.verifier_matches(record.get("verifier"), key, "duress"):
        return key
    return None


def open_decoy_vault(data_directory, key, meta):
    """Load the decoy vault. Creates it empty if the file went missing."""
    try:
        return vault_module.Vault.load(data_directory, key, meta, is_decoy=True)
    except vault_module.VaultError:
        return vault_module.Vault.create(data_directory, key, meta, is_decoy=True)


def remove_duress(data_directory, meta):
    """
    Turn the duress feature off and delete the decoy vault file.

    Anything stored in the decoy is destroyed. That is the correct behaviour:
    the decoy only exists for one reason.
    """
    meta["duress"] = None
    data_directory.delete_decoy()
    data_directory.append_audit(meta, "duress_disabled", "decoy vault deleted")
    data_directory.write_meta(meta)
    return True


# ---------------------------------------------------------------------------
# Lockout helpers for the user interface
# ---------------------------------------------------------------------------

def attempts_left(meta):
    """How many tries before the lockout kicks in."""
    attempts = meta.get("attempts") or {}
    count = int(attempts.get("count", 0))
    left = constants.MAX_LOGIN_ATTEMPTS - count
    return max(0, left)


def describe_lockout(meta):
    """A short sentence about the current attempt situation."""
    locked, remaining = is_locked_out(meta)
    if locked:
        return "Locked for another " + utils.human_duration(remaining) + "."
    left = attempts_left(meta)
    if left <= 1:
        return "One more wrong password and the vault locks for a while."
    return str(left) + " attempts left before a lockout."


def clear_lockout(data_directory, meta):
    """
    Wipe the attempt counter. Undocumented, and used by the 'doctor'
    command, because a lockout on your own laptop with no attacker present
    is just annoying.
    """
    meta["attempts"] = {"count": 0, "locked_until": None, "last_failure": None}
    data_directory.append_audit(meta, "lockout_cleared", "by the user")
    data_directory.write_meta(meta)
    return True
