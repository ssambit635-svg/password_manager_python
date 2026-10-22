"""
strength.py

How good is a password, really?

There is a whole industry around this question and an excellent library
called zxcvbn that answers it better than this file ever will. This is a
from-scratch attempt because the point of the project is to show how the
pieces work. It does the things a person actually cares about:

  * how long is it, and how many different characters does it use
  * is it one of the classics from the leak lists
  * is it a word with a year bolted on the end
  * is it the site name with a number on the end
  * is it a keyboard walk like qwerty or 1q2w3e4r
  * does it repeat itself (aaaa, abcabcabc)

The output is a score from 0 to 100, a grade from A to F, an estimate of how
long it would take to crack, and a list of things to fix. The scoring is
opinionated and does not pretend to be a standard.
"""

import string
import re
import math

from . import constants, utils


# ---------------------------------------------------------------------------
# Published guesses per second
# ---------------------------------------------------------------------------
# These are rough numbers based on public benchmarks for different attack
# situations. They are here to make the crack time feel real. They are all
# guesses, and the real number depends on hardware and on how the service
# stores passwords. The important part is the size of the gap between them.

GUESS_RATES = {
    "throttled": 10,                 # an online login form with a delay
    "online": 1000,                  # an unthrottled API endpoint
    "slow_hash": 10000,              # bcrypt or argon2 with weak settings
    "fast_hash": 10000000000,        # unsalted SHA-256 on a good graphics card
}

GRADE_TABLE = [
    (90, "A", "excellent"),
    (75, "B", "strong"),
    (55, "C", "fair"),
    (35, "D", "weak"),
    (0, "F", "terrible"),
]


def grade_for_score(score):
    """Map a 0-100 score onto a letter and a word."""
    for threshold, letter, word in GRADE_TABLE:
        if score >= threshold:
            return letter, word
    return "F", "terrible"


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

def character_pool_size(password):
    """
    How many possible characters could this password have been built from?

    If it has a lowercase letter, we assume the whole lowercase alphabet was
    available, and so on. This over-estimates for passwords that only use a
    few letters, which is why the repeated character check below exists.
    """
    pool = 0
    if any(character in string.ascii_lowercase for character in password):
        pool += 26
    if any(character in string.ascii_uppercase for character in password):
        pool += 26
    if any(character in string.digits for character in password):
        pool += 10
    if any(character in string.punctuation or character == " " for character in password):
        pool += 33
    if any(ord(character) > 127 for character in password):
        pool += 100
    return pool


def entropy_bits(password):
    """
    Bits of entropy, the textbook way: log2(pool size) * length.

    For "correcthorsebatterystaple" this under-estimates badly, because it
    treats the password as random characters. The pattern penalties below
    roughly compensate.
    """
    if not password:
        return 0.0
    pool = character_pool_size(password)
    if pool <= 1:
        return 0.0
    return len(password) * math.log(pool, 2)


def guesses_for_entropy(bits):
    """
    Average number of guesses needed for a given number of bits.

    An attacker who tries half the space on average needs 2^(bits-1)
    guesses. We use that, and we cap the exponent so the numbers stay
    displayable instead of turning into Python's slow big integers.
    """
    try:
        exponent = float(bits) - 1.0
    except (TypeError, ValueError):
        return 1.0
    if exponent < 0:
        return 1.0
    if exponent > 1024:
        exponent = 1024
    return 2.0 ** exponent


def crack_time_seconds(bits, rate=GUESS_RATES["fast_hash"]):
    """Seconds to crack, at a given guesses-per-second rate."""
    if rate <= 0:
        return float("inf")
    return guesses_for_entropy(bits) / float(rate)


def human_crack_time(seconds):
    """
    A friendly version of the crack time.

    The generic formatter stops at "years", which is not dramatic enough for
    a password that would take longer than the universe has existed, so this
    adds a few of the classics.
    """
    if seconds == float("inf"):
        return "effectively forever"
    if seconds < 1:
        return "instantly"

    universe_age_seconds = 4.35e17  # about 13.8 billion years
    if seconds > universe_age_seconds * 1000:
        return "far longer than the universe has existed"
    if seconds > universe_age_seconds:
        return "longer than the universe has existed"

    return utils.human_duration(seconds)


# ---------------------------------------------------------------------------
# Pattern checks
# ---------------------------------------------------------------------------

def _normalise(password):
    return str(password).lower().strip()


def _leet_variants(password):
    """
    A few common substitutions people use to make a word "secure".

    a -> @, e -> 3, i -> 1, o -> 0, s -> 5 or $, t -> 7. We produce a small
    set of variants, not every combination, because that grows very fast and
    the classic substitutions are what actually show up in leaks.
    """
    variants = [password]
    swaps = {
        "@": "a", "4": "a",
        "3": "e",
        "1": "i", "!": "i",
        "0": "o",
        "5": "s", "$": "s",
        "7": "t", "+": "t",
    }
    plain = password
    for symbol, letter in swaps.items():
        plain = plain.replace(symbol, letter)
    if plain != password:
        variants.append(plain)
    return variants


def matches_common_password(password):
    """
    Is this one of the classics?

    We also try it with trailing digits and symbols removed, so
    "password123" and "P@ssw0rd!" still get caught. The trailing punctuation
    is stripped BEFORE the leet substitutions, because replacing a trailing
    "!" with "i" would otherwise turn "p@ssw0rd!" into "passwordi" and miss
    the match entirely. I know that because the test caught it.
    """
    text = _normalise(password)
    if not text:
        return False

    text = text.rstrip("!@#$%^&*._-")

    for variant in _leet_variants(text):
        if variant in constants.COMMON_PASSWORDS:
            return True

        trimmed = variant.rstrip("0123456789")
        if trimmed and trimmed in constants.COMMON_PASSWORDS:
            return True

        if variant[::-1] in constants.COMMON_PASSWORDS:
            return True

    return False


def looks_like_a_year(text):
    """Four digits that look like a birth year or a recent year."""
    if not re.fullmatch(r"(19|20)\d{2}", str(text)):
        return False
    year = int(text)
    return 1950 <= year <= 2100


def matches_site_or_user(password, site="", username=""):
    """
    People love using the site name as part of the password.

    "github2026", "GitHub_login", "amit@github" are all things that show up
    in real leaks, and all things that an attacker who knows what service
    they are attacking will try first.
    """
    text = _normalise(password)
    if len(text) < 4:
        return False

    candidates = []
    if site:
        site_text = _normalise(site)
        candidates.append(site_text)
        # Just the first word of the site, so "github.com" also checks
        # for "github".
        candidates.append(site_text.split(".")[0])
        candidates.append(site_text.split(" ")[0])
    if username:
        user_text = _normalise(username)
        candidates.append(user_text)
        # The part before the @ is what people actually put in passwords,
        # not the whole email address.
        candidates.append(user_text.split("@")[0])

    for candidate in candidates:
        if len(candidate) >= 4 and candidate in text:
            return True

    return False


def contains_sequence(password):
    """
    Keyboard walks and alphabet runs.

    qwerty, asdfgh, 123456, abcdef and the like. We look for runs of four
    or more characters that sit next to each other on a keyboard row or in
    the alphabet.
    """
    rows = [
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1234567890",
        "abcdefghijklmnopqrstuvwxyz",
    ]
    text = _normalise(password)

    for row in rows:
        for start in range(len(row) - 3):
            chunk = row[start:start + 4]
            if chunk in text:
                return True
            if chunk[::-1] in text:
                return True

    return False


def longest_repeat_run(password):
    """
    The length of the longest run of the same character. "aaa" is 3, "ab" is
    1. Used to punish "1234aaaa".
    """
    text = str(password)
    if not text:
        return 0
    longest = 1
    current = 1
    for index in range(1, len(text)):
        if text[index] == text[index - 1]:
            current += 1
            if current > longest:
                longest = current
        else:
            current = 1
    return longest


def has_repeated_block(password):
    """
    Does the password contain a block of two or more characters repeated
    three or more times? Catches "abcabcabc" and "passpasspass".
    """
    text = _normalise(password)
    length = len(text)
    for block_size in range(2, (length // 3) + 1):
        block = text[:block_size]
        if block * 3 in text:
            return True
    return False


def count_character_classes(password):
    """How many of the four main groups appear in this password."""
    classes = 0
    if any(character in string.ascii_lowercase for character in password):
        classes += 1
    if any(character in string.ascii_uppercase for character in password):
        classes += 1
    if any(character in string.digits for character in password):
        classes += 1
    if any(character in string.punctuation for character in password):
        classes += 1
    return classes


def looks_like_keyboard_mash(password):
    """
    A cheap attempt at spotting something typed with a closed fist.

    Very high consonant density with no vowels is usually either a random
    password or a cat on a keyboard. We count it as a penalty only when it
    is short, because a long random string is fine.
    """
    text = _normalise(password)
    if len(text) < 6:
        return False
    letters = [character for character in text if character.isalpha()]
    if not letters:
        return False
    vowels = sum(1 for character in letters if character in "aeiouy")
    vowel_ratio = vowels / float(len(letters))
    return vowel_ratio < 0.15


# ---------------------------------------------------------------------------
# The analysis
# ---------------------------------------------------------------------------

def analyse(password, site="", username=""):
    """
    Look at one password and return everything we know about it.

    The returned dictionary has:
        password        - the input (so callers do not have to pass it twice)
        length          - character count
        classes         - how many character types are used
        entropy_bits    - the raw estimate before penalties
        adjusted_bits   - the estimate after penalties
        score           - 0 to 100
        grade           - A to F
        label           - terrible / weak / fair / strong / excellent
        crack_times     - dict of attack type to human readable time
        problems        - list of strings explaining what is wrong
        suggestions     - list of strings explaining what to do
    """
    password = "" if password is None else str(password)
    problems = []
    suggestions = []

    length = len(password)
    classes = count_character_classes(password)
    raw_bits = entropy_bits(password)
    adjusted_bits = raw_bits

    # --- length ------------------------------------------------------
    # Length matters more than anything else, so it gets the biggest
    # penalty and the first suggestion.
    if length == 0:
        problems.append("There is no password here.")
        suggestions.append("Type something.")
    elif length < constants.MIN_NEW_PASSWORD_LENGTH:
        problems.append("Only " + str(length) + " characters long.")
        suggestions.append("Use at least 12 characters. 16 is better.")
    elif length < 12:
        problems.append("Shorter than the recommended 12 characters.")
        suggestions.append("Add a few more characters. Length helps more than symbols.")
    elif length < 16:
        suggestions.append("16 characters or more would be even harder to crack.")
    else:
        adjusted_bits += 5  # a small bonus, length is that important

    # --- character variety -------------------------------------------
    if length > 0 and classes <= 1 and length < 20:
        problems.append("Uses only one kind of character.")
        suggestions.append("Mix upper case, lower case, numbers and symbols.")
        adjusted_bits -= 8

    # --- the classics -------------------------------------------------
    if matches_common_password(password):
        problems.append("This is one of the most commonly leaked passwords.")
        suggestions.append("Pick something that has never appeared in a leak.")
        adjusted_bits = min(adjusted_bits, 12)

    # --- patterns -----------------------------------------------------
    if contains_sequence(password):
        problems.append("Contains a keyboard or alphabet sequence (qwerty, 1234, abcd).")
        suggestions.append("Avoid rows of keys and runs of letters.")
        adjusted_bits -= 10

    run = longest_repeat_run(password)
    if run >= 3:
        problems.append("Repeats the same character " + str(run) + " times in a row.")
        suggestions.append("Avoid repeating characters.")
        adjusted_bits -= (run - 2) * 3

    if has_repeated_block(password):
        problems.append("Contains a repeated block of characters.")
        suggestions.append("Avoid patterns like abcabcabc.")
        adjusted_bits -= 8

    if matches_site_or_user(password, site, username):
        problems.append("Contains the name of the site or the username.")
        suggestions.append("Do not build a password out of the site name.")
        adjusted_bits -= 12

    # --- dates --------------------------------------------------------
    # Look for a four digit year anywhere in the password.
    years = re.findall(r"(?:19|20)\d{2}", password)
    if years:
        problems.append("Contains what looks like a year (" + years[0] + ").")
        suggestions.append("Years are guessed early in every attack. Leave them out.")
        adjusted_bits -= 6

    # --- keyboard mash ------------------------------------------------
    if looks_like_keyboard_mash(password) and length < 12:
        problems.append("Looks like a random keyboard mash but it is too short.")
        suggestions.append("Either use a proper random generator, or a long passphrase.")

    # --- symbol placement ---------------------------------------------
    if length > 0 and password[-1] in "!@#$%^&*":
        problems.append("Ends with a symbol, which is the most predictable place for one.")
        suggestions.append("Move the symbol somewhere in the middle.")
        adjusted_bits -= 2

    if length > 0 and password[0].isupper() and password[1:].islower():
        problems.append("Capitalised like a normal word (Firstletter capitalised).")
        suggestions.append("Do not just capitalise the first letter of a word.")
        adjusted_bits -= 3

    # --- floors -------------------------------------------------------
    if adjusted_bits < 0:
        adjusted_bits = 0.0

    # --- score --------------------------------------------------------
    score = _bits_to_score(adjusted_bits)
    if length == 0:
        score = 0
    if matches_common_password(password):
        score = min(score, 5)

    grade, label = grade_for_score(score)

    crack_times = {}
    for attack, rate in GUESS_RATES.items():
        crack_times[attack] = human_crack_time(crack_time_seconds(adjusted_bits, rate))

    if score >= 90 and not problems:
        suggestions = ["Nothing to fix. Keep it in the vault, not in your head."]

    return {
        "password": password,
        "length": length,
        "classes": classes,
        "entropy_bits": round(raw_bits, 1),
        "adjusted_bits": round(adjusted_bits, 1),
        "score": int(score),
        "grade": grade,
        "label": label,
        "crack_times": crack_times,
        "problems": problems,
        "suggestions": suggestions,
    }


def _bits_to_score(bits):
    """
    Turn bits of entropy into a 0-100 score.

    The curve is deliberately generous at the low end and strict at the top.
    40 bits (about an 8 character random password) gets you around 35 points.
    60 bits, roughly 10 random characters, gets 60. 80 bits or more is a
    properly good password and scores in the nineties.
    """
    try:
        bits = float(bits)
    except (TypeError, ValueError):
        return 0

    if bits <= 0:
        return 0
    if bits >= 100:
        return 100

    # A simple piecewise curve. It is flat-ish below 30 bits, steep in the
    # middle, and flattens again above 80.
    if bits < 30:
        return int(round(bits * 0.8))
    if bits < 50:
        return int(round(24 + ((bits - 30) * 1.55)))
    if bits < 80:
        return int(round(55 + ((bits - 50) * 1.15)))
    return int(round(89.5 + ((bits - 80) * 0.5)))


def password_is_acceptable(password, site="", username=""):
    """
    A yes/no wrapper used before saving. Returns (ok, reason).

    This is intentionally not strict: it warns about the obvious disasters
    and lets everything else through. A password manager should not fight
    the person using it.
    """
    result = analyse(password, site, username)

    if result["length"] == 0:
        return False, "The password is empty."
    if matches_common_password(password):
        return False, "That is one of the most common passwords in the world. Please pick another."
    if result["score"] < 20:
        return False, "That password is too easy to guess. Try something longer."

    return True, ""


def describe_score(score):
    """A one line summary used in lists and the health report."""
    grade, label = grade_for_score(score)
    return grade + " (" + label + ") " + utils.star_rating(score)


def mask(password, visible=0):
    """
    Show a password as dots. The original version printed every password in
    full whenever you viewed the list, which defeats the point of a screen
    in an office.
    """
    text = str(password)
    if not text:
        return "(empty)"
    if visible <= 0:
        return "*" * len(text)
    if visible >= len(text):
        return text
    return text[:visible] + ("*" * (len(text) - visible))
