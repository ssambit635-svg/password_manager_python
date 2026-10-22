"""
totp.py

Two factor authentication codes, the six digit ones that change every
thirty seconds.

This is the same algorithm as Google Authenticator, Authy and every other
authenticator app. It is called TOTP: time based one time password. The
recipe is:

    1. You and the server share a secret (usually shown as a QR code).
    2. Both sides take the current time, divide it by 30 seconds, and round
       down. That number is the "time step".
    3. Both sides compute HMAC-SHA1 of the time step using the secret.
    4. Both sides take a few bytes out of that hash, turn them into a number,
       and print the last six digits.
    5. Because both sides used the same clock and the same secret, the
       numbers match, and the number changes on its own every 30 seconds.

Nothing is sent over the network. The code is only useful if you already
have the secret, which is why the secret lives in your encrypted vault.

The Base32 decoder is written by hand below because authenticator secrets
are usually given without the padding that Python's base64 module expects.
"""

import hmac
import time
import hashlib
import struct
import urllib.parse
import secrets

from . import constants


BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

# Convenient module level aliases, so other modules (and the tests) can say
# totp.TOTP_PERIOD instead of reaching into the constants module.
TOTP_PERIOD = constants.TOTP_PERIOD
TOTP_DIGITS = constants.TOTP_DIGITS
TOTP_SECRET_BYTES = constants.TOTP_SECRET_BYTES
TOTP_ALGORITHM = constants.TOTP_ALGORITHM



class TotpError(Exception):
    """The secret or the code did not make sense."""
    pass


# ---------------------------------------------------------------------------
# Base32
# ---------------------------------------------------------------------------

def decode_base32(secret):
    """
    Turn an authenticator secret into raw bytes.

    Base32 packs five bits per character and pads the end to a multiple of
    eight characters with "=". A lot of services leave the padding off, so
    we strip spaces, dashes and padding ourselves and then do the decoding
    by hand. It is short and it avoids a pile of edge cases.
    """
    text = str(secret).upper()
    cleaned = ""
    for character in text:
        if character in BASE32_ALPHABET:
            cleaned += character
        elif character in " =-":
            continue
        else:
            raise TotpError("The secret contains characters that are not valid Base32.")

    if not cleaned:
        raise TotpError("The secret is empty.")

    bits = ""
    for character in cleaned:
        value = BASE32_ALPHABET.index(character)
        bits += format(value, "05b")

    # Only whole bytes count. The leftover bits at the end are padding.
    usable = (len(bits) // 8) * 8
    output = bytearray()
    for index in range(0, usable, 8):
        output.append(int(bits[index:index + 8], 2))

    if not output:
        raise TotpError("That secret is too short to produce a code.")

    return bytes(output)


def encode_base32(raw_bytes):
    """The reverse: raw bytes to a Base32 string without padding."""
    bits = ""
    for byte in raw_bytes:
        bits += format(byte, "08b")

    # Pad the bit string so that its length is a multiple of five.
    while len(bits) % 5 != 0:
        bits += "0"

    output = ""
    for index in range(0, len(bits), 5):
        output += BASE32_ALPHABET[int(bits[index:index + 5], 2)]

    return output


def generate_secret(number_of_bytes=constants.TOTP_SECRET_BYTES):
    """
    Make a new authenticator secret.

    20 bytes is what most services use, which is 160 bits, and produces a
    32 character Base32 string. We show it in groups of four because a wall
    of 32 letters is horrible to copy by hand.
    """
    raw = secrets.token_bytes(number_of_bytes)
    encoded = encode_base32(raw)
    return group_secret(encoded)


def group_secret(secret):
    """Put spaces every four characters, purely for readability."""
    text = str(secret).replace(" ", "").upper()
    groups = []
    for index in range(0, len(text), 4):
        groups.append(text[index:index + 4])
    return " ".join(groups)


def normalise_secret(secret):
    """Remove spaces and dashes, upper case. What gets stored and hashed."""
    text = str(secret).upper()
    cleaned = ""
    for character in text:
        if character in BASE32_ALPHABET:
            cleaned += character
    return cleaned


# ---------------------------------------------------------------------------
# The codes themselves
# ---------------------------------------------------------------------------

def hotp(raw_secret, counter, digits=constants.TOTP_DIGITS):
    """
    The counter based version, which is the building block for the time
    based one. Counter is an integer that goes up every time you need a new
    code.
    """
    if counter < 0:
        raise TotpError("The counter cannot be negative.")

    # The counter has to be a big endian 64 bit integer. struct does that.
    message = struct.pack(">Q", int(counter))

    digest = hmac.new(raw_secret, message, hashlib.sha1).digest()

    # Dynamic truncation: the last four bits of the hash decide where to
    # start reading four bytes from. That is what the RFC says to do, and
    # all the apps do it this way.
    offset = digest[-1] & 0x0F
    chunk = digest[offset:offset + 4]

    number = struct.unpack(">I", chunk)[0] & 0x7FFFFFFF
    code = number % (10 ** digits)

    return str(code).zfill(digits)


def time_step(at_time=None, period=constants.TOTP_PERIOD):
    """Which 30 second window are we in."""
    if at_time is None:
        at_time = time.time()
    return int(at_time // period)


def totp(secret, at_time=None, period=constants.TOTP_PERIOD,
         digits=constants.TOTP_DIGITS):
    """The six digit code for a secret at a given moment."""
    raw = decode_base32(normalise_secret(secret))
    counter = time_step(at_time, period)
    return hotp(raw, counter, digits)


def seconds_remaining(at_time=None, period=constants.TOTP_PERIOD):
    """How many seconds until the current code stops working."""
    if at_time is None:
        at_time = time.time()
    return int(period - (int(at_time) % period))


def progress_bar_for_code(at_time=None, period=constants.TOTP_PERIOD, width=20):
    """A bar that shrinks as the code gets closer to expiring."""
    left = seconds_remaining(at_time, period)
    filled = int(round((left / float(period)) * width))
    if filled < 0:
        filled = 0
    if filled > width:
        filled = width
    return "[" + ("#" * filled) + ("." * (width - filled)) + "]"


def verify(secret, code, at_time=None, window=1, period=constants.TOTP_PERIOD,
           digits=constants.TOTP_DIGITS):
    """
    Check a code the way a server would.

    window=1 means we accept the previous code and the next code as well,
    because clocks drift and people type slowly. A window bigger than 1 gets
    generous with an attacker, so this is deliberately small.
    """
    cleaned = "".join(character for character in str(code) if character.isdigit())
    if len(cleaned) != digits:
        return False

    raw = decode_base32(normalise_secret(secret))
    counter = time_step(at_time, period)

    for drift in range(-abs(window), abs(window) + 1):
        if hmac.compare_digest(hotp(raw, counter + drift, digits), cleaned):
            return True

    return False


def format_code(code):
    """Show 123456 as 123 456, which is easier to read and type."""
    text = str(code)
    if len(text) == 6:
        return text[:3] + " " + text[3:]
    return text


# ---------------------------------------------------------------------------
# The otpauth:// link
# ---------------------------------------------------------------------------
# Services normally hand out a QR code, and a QR code is just an otpauth://
# URL. If a website shows you the QR code as a picture you can, in theory,
# decode it and get the link. More useful: some services show the link
# directly, and you can paste it here instead of typing the secret.

def make_otpauth_uri(secret, account="you", issuer=constants.APP_NAME):
    """Build the standard otpauth link for a secret."""
    normalised = normalise_secret(secret)
    if not normalised:
        raise TotpError("There is no secret to build a link from.")

    label = urllib.parse.quote(str(issuer) + ":" + str(account))
    parameters = [
        ("secret", normalised),
        ("issuer", str(issuer)),
        ("algorithm", constants.TOTP_ALGORITHM.upper()),
        ("digits", str(constants.TOTP_DIGITS)),
        ("period", str(constants.TOTP_PERIOD)),
    ]
    query = "&".join(key + "=" + urllib.parse.quote(value) for key, value in parameters)
    return "otpauth://totp/" + label + "?" + query


def parse_otpauth_uri(uri):
    """
    Read an otpauth link and pull out the useful parts.

    Returns a dictionary with secret, issuer, account, digits and period.
    Raises TotpError for anything that is not an otpauth totp link.
    """
    text = str(uri).strip()
    if not text.lower().startswith("otpauth://"):
        raise TotpError("That does not look like an otpauth link.")

    parsed = urllib.parse.urlparse(text)
    if parsed.netloc.lower() != "totp":
        raise TotpError("Only time based otpauth links are supported.")

    query = urllib.parse.parse_qs(parsed.query)
    if "secret" not in query:
        raise TotpError("That link does not contain a secret.")

    label = urllib.parse.unquote(parsed.path.lstrip("/"))
    issuer = query.get("issuer", [""])[0]
    account = label
    if ":" in label:
        parts = label.split(":", 1)
        if not issuer:
            issuer = parts[0]
        account = parts[1]

    try:
        digits = int(query.get("digits", [str(constants.TOTP_DIGITS)])[0])
        period = int(query.get("period", [str(constants.TOTP_PERIOD)])[0])
    except ValueError:
        raise TotpError("That link has an unreadable digits or period value.")

    return {
        "secret": normalise_secret(query["secret"][0]),
        "issuer": issuer,
        "account": account,
        "digits": digits,
        "period": period,
        "algorithm": query.get("algorithm", [constants.TOTP_ALGORITHM])[0].lower(),
    }


def is_probably_a_secret(text):
    """
    A quick check so the program can be friendly when somebody types a
    password into the secret field by mistake.
    """
    cleaned = normalise_secret(text)
    if len(cleaned) < 8:
        return False
    # Real Base32 secrets are all upper case letters and 2-7 numbers. A
    # password with symbols in it is not a secret.
    for character in str(text):
        if character.upper() not in BASE32_ALPHABET and character not in " -=":
            return False
    return True
