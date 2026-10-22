"""
generator.py

Making new passwords.

The old version used the random module. That is fine for dice in a game and
completely wrong for passwords, because random's output is predictable if
somebody can work out the starting state. This version uses secrets, which
asks the operating system for randomness (the same pool that generates
encryption keys).

Two other small decisions that matter more than they look:

  * We guarantee at least one character from every group the user asked
    for. A password that is supposed to have a symbol, but happens not to,
    will be rejected by the website, and the user will blame the generator.

  * We shuffle afterwards. If you just append "one of each" to the end, the
    last three characters are always the same group, which is a tiny but
    real pattern.
"""

import secrets

from . import constants


class GeneratorError(Exception):
    """The generator was asked for something it cannot do."""
    pass


def _secure_shuffle(items):
    """
    Shuffle a list using secrets instead of random.

    Fisher-Yates again, but picking the swap partner with
    secrets.randbelow so the shuffle itself is not predictable.
    """
    result = list(items)
    for index in range(len(result) - 1, 0, -1):
        swap_with = secrets.randbelow(index + 1)
        result[index], result[swap_with] = result[swap_with], result[index]
    return result


def _pick(alphabet):
    """One random character from a string, securely."""
    if not alphabet:
        raise GeneratorError("There are no characters to choose from.")
    return secrets.choice(alphabet)


def _strip_ambiguous(alphabet):
    """Remove characters that look like each other in most fonts."""
    cleaned = ""
    for character in alphabet:
        if character not in constants.AMBIGUOUS_CHARACTERS:
            cleaned += character
    return cleaned


def build_alphabet(use_lower=True, use_upper=True, use_digits=True,
                   use_symbols=True, avoid_ambiguous=False, extra_characters=""):
    """
    Assemble the pool of characters for a random password.

    Returns the pool. Raises if the pool is empty, because an empty pool
    means the caller asked for no character types at all.
    """
    parts = []
    if use_lower:
        parts.append(constants.LOWERCASE_LETTERS)
    if use_upper:
        parts.append(constants.UPPERCASE_LETTERS)
    if use_digits:
        parts.append(constants.DIGITS)
    if use_symbols:
        parts.append(constants.SYMBOLS)

    if not parts:
        raise GeneratorError("Pick at least one kind of character.")

    pool = "".join(parts)
    if avoid_ambiguous:
        pool = _strip_ambiguous(pool)
        if not pool:
            raise GeneratorError(
                "Removing the look-alike characters left nothing behind. "
                "Include another character type."
            )

    if extra_characters:
        for character in str(extra_characters):
            if character not in pool:
                pool += character

    return pool


def generate_password(length=20, use_lower=True, use_upper=True, use_digits=True,
                      use_symbols=True, avoid_ambiguous=False, require_each=True):
    """
    The workhorse. Returns a random password as a string.

    require_each=True means the result is guaranteed to contain at least one
    lower case letter, one upper case letter, one digit and one symbol (for
    whichever groups were requested), as long as the length allows it.
    """
    length = int(length)
    if length < 4:
        raise GeneratorError("A password shorter than four characters is not worth generating.")
    if length > 512:
        raise GeneratorError("That is longer than any website will accept.")

    pool = build_alphabet(use_lower, use_upper, use_digits, use_symbols, avoid_ambiguous)

    groups = []
    if use_lower:
        groups.append(constants.LOWERCASE_LETTERS)
    if use_upper:
        groups.append(constants.UPPERCASE_LETTERS)
    if use_digits:
        groups.append(constants.DIGITS)
    if use_symbols:
        groups.append(constants.SYMBOLS)

    if avoid_ambiguous:
        groups = [_strip_ambiguous(group) for group in groups]
        groups = [group for group in groups if group]

    if require_each and len(groups) > length:
        # Not enough room for one from every group. Fall back to filling
        # from the pool, which is still random and still fine.
        require_each = False

    characters = []
    if require_each:
        for group in groups:
            characters.append(_pick(group))

    while len(characters) < length:
        characters.append(_pick(pool))

    characters = _secure_shuffle(characters)
    return "".join(characters)


def generate_passphrase(number_of_words=5, separator="-", capitalise=False,
                        add_number=False, number_of_words_max=12):
    """
    A passphrase made of words from a small list.

    Five words from a list of roughly 900 gives about 49 bits of entropy,
    which is decent. Six words gives about 59, which is better than most
    short random passwords and much easier to remember. The number of words
    is capped so that the list cannot be used to generate something absurd.
    """
    try:
        number_of_words = int(number_of_words)
    except (TypeError, ValueError):
        raise GeneratorError("How many words? That needs to be a number.")

    if number_of_words < 3:
        raise GeneratorError("Three words is the minimum for a passphrase that is worth anything.")
    if number_of_words > number_of_words_max:
        raise GeneratorError("That is a lot of words. Try twelve or fewer.")
    if not constants.WORDLIST:
        raise GeneratorError("The word list is empty. That is a bug.")

    chosen = []
    for _ in range(number_of_words):
        # secrets.choice over a list is fine here. There are enough
        # combinations that repeats are harmless, and forbidding repeats
        # would leak a tiny bit of information about previous picks.
        chosen.append(secrets.choice(constants.WORDLIST))

    if capitalise:
        chosen = [word.capitalize() for word in chosen]

    phrase = separator.join(chosen)

    if add_number:
        phrase = phrase + separator + str(secrets.randbelow(90) + 10)

    return phrase


def generate_pin(length=6):
    """A numeric PIN. Useful for phone unlock codes and bank cards."""
    try:
        length = int(length)
    except (ValueError, TypeError):
        raise GeneratorError("The PIN length needs to be a number.")
    if length < 4:
        raise GeneratorError("A PIN shorter than four digits is not a PIN, it is a guess.")
    if length > 24:
        raise GeneratorError("That is a very long PIN. Twelve is plenty.")

    digits = ""
    for _ in range(length):
        digits += str(secrets.randbelow(10))
    return digits


def generate_memorable(length=16):
    """
    A password that is random but can just about be read out loud.

    Pattern: consonant-vowel pairs, then a symbol, then digits, then another
    pair. Something like "votegi#42zu". It is not a real word, so it will not
    be in a dictionary, but it is much easier to say than "Xk9#mQ2!".
    """
    consonants = "bcdfghjklmnprstvwz"
    vowels = "aeiou"

    length = int(length)
    if length < 10:
        length = 10

    pieces = []

    # Two syllable words, repeated until we have used about two thirds of
    # the requested length.
    target = max(2, (length * 2) // 3)
    while len("".join(pieces)) < target:
        syllable = _pick(consonants) + _pick(vowels) + _pick(consonants)
        pieces.append(syllable)

    body = "".join(pieces)

    symbol = _pick("#!?*+-=$@")
    digits = str(secrets.randbelow(90) + 10)

    result = body + symbol + digits

    # Pad with random vowels and consonants if we are short.
    while len(result) < length:
        if secrets.randbelow(2) == 0:
            result += _pick(vowels)
        else:
            result += _pick(consonants)

    # Guarantee some upper case and a bit of punctuation so that the
    # password passes the usual "must contain" rules on websites.
    if result:
        position = secrets.randbelow(min(4, len(result)))
        result = result[:position] + result[position].upper() + result[position + 1:]

    return result[:length] if len(result) > length else result


def generate_from_preset(preset, length=None, number_of_words=None):
    """
    Presets are just named bundles of the settings above.

    Returns a dictionary so the caller knows what it got, which is handy
    when saving the password and showing how it was made.
    """
    preset = str(preset).lower().strip()

    if preset == constants.PRESET_PARANOID:
        password = generate_password(
            length or 32,
            use_lower=True, use_upper=True, use_digits=True, use_symbols=True,
            avoid_ambiguous=False,
        )
        return {
            "password": password,
            "preset": preset,
            "description": "32 random characters, everything allowed",
            "type": "random",
        }

    if preset == constants.PRESET_BALANCED:
        password = generate_password(
            length or 20,
            use_lower=True, use_upper=True, use_digits=True, use_symbols=True,
            avoid_ambiguous=True,
        )
        return {
            "password": password,
            "preset": preset,
            "description": "20 random characters, no look-alike letters",
            "type": "random",
        }

    if preset == constants.PRESET_PIN:
        password = generate_pin(length or 6)
        return {
            "password": password,
            "preset": preset,
            "description": "Digits only, easy to type on a phone",
            "type": "pin",
        }

    if preset == constants.PRESET_MEMORABLE:
        password = generate_memorable(length or 16)
        return {
            "password": password,
            "preset": preset,
            "description": "Random syllables, readable out loud",
            "type": "memorable",
        }

    if preset == constants.PRESET_PASSPHRASE:
        password = generate_passphrase(
            number_of_words or 5,
            separator="-",
            capitalise=True,
            add_number=True,
        )
        return {
            "password": password,
            "preset": preset,
            "description": "Words from a list, joined with dashes",
            "type": "passphrase",
        }

    raise GeneratorError("There is no preset called " + preset + ".")


def generate_batch(count, length=20, **options):
    """Generate several passwords at once. Used by the batch menu."""
    count = int(count)
    if count < 1 or count > 20:
        raise GeneratorError("Generate between 1 and 20 passwords at once.")
    return [generate_password(length, **options) for _ in range(count)]


def syllables_for_pronunciation(password):
    """
    A very silly feature: split a password into chunks that can be read out
    loud over the phone. Not security, just a small kindness when somebody
    has to dictate a password to a colleague.
    """
    text = str(password)
    if not text:
        return []

    chunks = []
    current = ""
    for index, character in enumerate(text):
        current += character
        if len(current) >= 3:
            chunks.append(current)
            current = ""
        elif character in "-_ #":
            chunks.append(current)
            current = ""
    if current:
        chunks.append(current)
    return chunks
