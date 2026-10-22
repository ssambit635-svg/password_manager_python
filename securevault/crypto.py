"""
crypto.py

This is the file that does the actual security. Everything else in the
project is just menus and text files.

The short version of how it works:

  1. You type a master password.
  2. We mix that password with a random "salt" using PBKDF2, hundreds of
     thousands of times. The result is a 32 byte key. The salt means that
     two people with the same password do not get the same key, and it means
     that pre-built tables of password hashes are useless.
  3. That key is used with Fernet (AES-128-CBC plus HMAC-SHA256) to encrypt
     the vault file. Fernet also authenticates the data, so if somebody
     edits the encrypted file by even one byte, decryption fails loudly
     instead of silently returning garbage.
  4. We never write the master password anywhere. Not even hashed. The only
     thing on disk is a "verifier": an HMAC of a fixed label using the
     derived key. If the derived key is right, the verifier matches.

A note on what PBKDF2 is doing. A SHA-256 hash of a password can be computed
billions of times per second on a graphics card, which is bad news. PBKDF2
deliberately makes each guess more expensive by repeating the mixing
hundreds of thousands of times. It does not make a terrible password safe,
but it does slow an attacker down enormously.
"""

import os
import json
import hmac
import base64
import hashlib
import secrets

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import constants


class CryptoError(Exception):
    """Something went wrong in this file. The message is safe to show."""
    pass


class WrongPasswordError(CryptoError):
    """The key we derived does not open the thing we tried to open."""
    pass


class ShareCodeError(CryptoError):
    """A share code was malformed or the passphrase was wrong."""
    pass


# ---------------------------------------------------------------------------
# Salts
# ---------------------------------------------------------------------------

def generate_salt(number_of_bytes=constants.SALT_BYTES):
    """Return a fresh random salt. os.urandom is the operating system's own
    cryptographically secure random source, which is what we want here."""
    return os.urandom(number_of_bytes)


def salt_to_text(salt):
    """Salts are bytes, JSON wants text, so base64 is the bridge."""
    return base64.b64encode(salt).decode("ascii")


def salt_from_text(text):
    """The reverse of salt_to_text. Bad input becomes a clear error."""
    try:
        return base64.b64decode(str(text).encode("ascii"), validate=True)
    except Exception:
        raise CryptoError("The salt in this file is damaged or not valid base64.")


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_key(password, salt, iterations=constants.DEFAULT_ITERATIONS):
    """
    Turn a master password plus a salt into a 32 byte encryption key.

    PBKDF2-HMAC-SHA256 is used because it ships with the cryptography
    library and has been around forever. Argon2id is arguably better these
    days, but it is an extra dependency, and the goal here is a project
    somebody can read and run without a build step.
    """
    if not isinstance(password, str):
        raise CryptoError("The password must be text.")
    if not isinstance(salt, (bytes, bytearray)):
        raise CryptoError("The salt must be bytes.")
    if len(salt) < 8:
        raise CryptoError("That salt is too short to be safe.")
    if iterations < 10000:
        raise CryptoError("That iteration count is too low to be safe.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(salt),
        iterations=int(iterations),
    )
    return kdf.derive(password.encode("utf-8"))


def key_to_fernet(key):
    """
    Fernet wants a url-safe base64 string of exactly 32 bytes, so we wrap
    the raw key. base64 is not encryption, it just makes the key fit the
    format Fernet expects.
    """
    if len(key) != 32:
        raise CryptoError("Fernet keys have to be 32 bytes.")
    return Fernet(base64.urlsafe_b64encode(key))


# ---------------------------------------------------------------------------
# Encrypting and decrypting
# ---------------------------------------------------------------------------

def encrypt_text(plain_text, key):
    """Encrypt a string. Returns a Fernet token as text."""
    fernet = key_to_fernet(key)
    token = fernet.encrypt(str(plain_text).encode("utf-8"))
    return token.decode("ascii")


def decrypt_text(token, key):
    """
    Decrypt a Fernet token.

    A wrong key and a tampered file both raise InvalidToken, so we turn that
    into one clear error. We do not try to guess which one it was, because
    telling an attacker "the key was right but the file changed" is a tiny
    bit of information they did not have before.
    """
    fernet = key_to_fernet(key)
    try:
        raw = fernet.decrypt(str(token).encode("ascii"))
    except InvalidToken:
        raise WrongPasswordError(
            "Could not decrypt the data. Either the password is wrong or the file was changed."
        )
    except Exception:
        raise CryptoError("The encrypted file looks damaged and cannot be read.")
    return raw.decode("utf-8")


def encrypt_dict(data, key):
    """JSON-encode a dictionary, then encrypt it."""
    try:
        text = json.dumps(data, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError) as problem:
        raise CryptoError("Could not turn the vault into JSON: " + str(problem))
    return encrypt_text(text, key)


def decrypt_dict(token, key):
    """Decrypt, then JSON-decode. The result must be a dictionary."""
    text = decrypt_text(token, key)
    try:
        data = json.loads(text)
    except ValueError:
        raise CryptoError("The decrypted vault is not valid JSON. The file is probably damaged.")
    if not isinstance(data, dict):
        raise CryptoError("The decrypted vault is the wrong shape. Expected an object.")
    return data


# ---------------------------------------------------------------------------
# The verifier
# ---------------------------------------------------------------------------
# We need a way to check a master password without storing the password or
# its hash. An HMAC with the derived key does the job: only somebody who
# derived the same key can produce the same HMAC, and the HMAC itself cannot
# be used to work backwards to the key.

def make_verifier(key, purpose="vault"):
    """A short, hex, keyed fingerprint used to check a password."""
    message = ("securevault-verifier-" + str(purpose)).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verifier_matches(stored_verifier, key, purpose="vault"):
    """
    Compare two verifiers without leaking how much of them matched.

    A normal == comparison returns as soon as it finds a difference, and the
    time that takes can tell an attacker how many characters were right.
    hmac.compare_digest always takes the same amount of time. This matters
    much more on a network service than in a terminal program, but it costs
    nothing to do it properly.
    """
    if not stored_verifier:
        return False
    expected = make_verifier(key, purpose)
    try:
        return hmac.compare_digest(str(stored_verifier), expected)
    except (TypeError, ValueError):
        return False


def fingerprint(key):
    """
    Eight hex characters that identify a vault key without revealing it.
    Handy for the emergency kit: if the fingerprint on the paper matches the
    one in the program, you know you wrote down the right master password.
    """
    digest = hashlib.sha256(b"securevault-fingerprint" + key).hexdigest()
    return digest[:8].upper()


# ---------------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------------
# A recovery code is a long random string, generated once, shown to you once,
# and stored only as a PBKDF2 verifier. If you forget your master password
# you can type the code, prove you are you, and set a new master password.
#
# The alphabet deliberately leaves out characters that look alike (0/O,
# 1/I/L) because these codes get written on paper and typed back in.

RECOVERY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
RECOVERY_GROUPS = 5
RECOVERY_GROUP_SIZE = 4


def generate_recovery_code():
    """
    Make a recovery code like ABCD-EFGH-JKMN-PQRS-TUVW.

    20 characters from a 31 symbol alphabet is about 99 bits of randomness.
    Guessing it is not happening.
    """
    groups = []
    for _ in range(RECOVERY_GROUPS):
        group = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(RECOVERY_GROUP_SIZE))
        groups.append(group)
    return "-".join(groups)


def normalise_recovery_code(code):
    """
    Make a typed recovery code comparable to a generated one.

    People type spaces, dashes, lowercase letters and occasionally a letter
    that looks like a number. We upper case everything and throw away
    anything that is not in the alphabet. That means "abcd efgh" and
    "ABCD-EFGH" end up the same.
    """
    text = str(code).upper()
    cleaned = ""
    for character in text:
        if character in RECOVERY_ALPHABET:
            cleaned += character
    return cleaned


def derive_recovery_key(code, salt, iterations=constants.DEFAULT_ITERATIONS):
    """Recovery codes go through the same KDF as master passwords."""
    cleaned = normalise_recovery_code(code)
    if len(cleaned) < 12:
        raise CryptoError("That recovery code is too short. Check it and try again.")
    return derive_key(cleaned, salt, iterations)


# ---------------------------------------------------------------------------
# Sharing a single password
# ---------------------------------------------------------------------------
# The idea: pick one entry, choose a passphrase, and get a blob of text.
# Send the blob over any chat app, tell the other person the passphrase over
# the phone. The blob on its own is useless. It is encrypted with a key made
# from the passphrase, and it carries its own salt so the receiver does not
# need anything from your vault.

def make_share_code(entry, passphrase):
    """
    Encrypt one entry into a portable share code.

    Only the fields that make sense to share are copied. Internal things
    like the entry id, the history and the notes stay in the vault.
    """
    if not passphrase or len(passphrase) < 6:
        raise CryptoError("The sharing passphrase needs at least 6 characters.")

    payload = {
        "site": entry.get("site", ""),
        "url": entry.get("url", ""),
        "username": entry.get("username", ""),
        "password": entry.get("password", ""),
        "shared_at": None,  # filled in by the caller if it wants to
    }

    salt = generate_salt()
    key = derive_key(passphrase, salt, constants.SHARE_CODE_ITERATIONS)
    encrypted = encrypt_dict(payload, key)

    envelope = {
        "v": 1,
        "salt": salt_to_text(salt),
        "iterations": constants.SHARE_CODE_ITERATIONS,
        "blob": encrypted,
    }

    raw = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    body = base64.urlsafe_b64encode(raw).decode("ascii")
    return constants.SHARE_CODE_PREFIX + body


def open_share_code(code, passphrase):
    """
    Turn a share code back into an entry dictionary.

    Every possible failure gets the same friendly-ish message so that a
    person cannot use the difference between errors to learn anything about
    the encrypted content.
    """
    text = str(code).strip()
    if not text.startswith(constants.SHARE_CODE_PREFIX):
        raise ShareCodeError("That does not look like a SecureVault share code.")

    body = text[len(constants.SHARE_CODE_PREFIX):]
    try:
        raw = base64.urlsafe_b64decode(body.encode("ascii"))
        envelope = json.loads(raw.decode("utf-8"))
    except Exception:
        raise ShareCodeError("The share code is damaged. Ask the sender to copy it again.")

    if not isinstance(envelope, dict) or "salt" not in envelope or "blob" not in envelope:
        raise ShareCodeError("The share code is missing information.")

    try:
        salt = salt_from_text(envelope["salt"])
        iterations = int(envelope.get("iterations", constants.SHARE_CODE_ITERATIONS))
        key = derive_key(passphrase, salt, iterations)
        payload = decrypt_dict(envelope["blob"], key)
    except WrongPasswordError:
        raise ShareCodeError("The passphrase is wrong, or the share code was altered.")
    except CryptoError:
        raise ShareCodeError("The share code could not be opened.")

    return payload


# ---------------------------------------------------------------------------
# Tiny helpers used by backups
# ---------------------------------------------------------------------------

def random_backup_salt():
    """A salt for a backup file. Same thing as generate_salt, clearer name."""
    return generate_salt()


def checksum_of_text(text):
    """SHA-256 of some text, as hex. Used by the doctor command."""
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()
