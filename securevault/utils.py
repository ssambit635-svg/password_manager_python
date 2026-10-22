"""
utils.py

Small helpers that many other files need.

There is nothing clever in here. It is all "print a coloured line", "ask a
question until the answer makes sense", "turn a date into something a human
can read". I kept these separate so that the actual password code does not
have to be mixed up with formatting code.
"""

import os
import sys
import time
import shutil
import textwrap
import datetime

from . import constants


# ---------------------------------------------------------------------------
# Colour
# ---------------------------------------------------------------------------
# Terminals understand these escape codes. Windows understands them too these
# days, but if somebody pipes the output into a file we do not want escape
# codes in the middle of the text, so colours are switched off automatically
# in that case. There is also a --no-color flag in the command line.

COLOURS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "grey": "\033[90m",
}

# A single switch that everything below looks at. It starts as True and the
# command line can turn it off before any menu is shown.
_colour_enabled = True


def set_colour_enabled(enabled):
    """Turn colours on or off for the whole program."""
    global _colour_enabled
    _colour_enabled = bool(enabled)


def colour_is_enabled():
    return _colour_enabled


def should_use_colour():
    """
    Work out whether colours make sense right now.

    Rules, in order:
      * NO_COLOR in the environment means no. (This is a real convention.)
      * If the output is not a terminal, no.
      * On Windows before version 10 the old console does not understand
        the escape codes, so no.
    """
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt" and sys.getwindowsversion().major < 10:
        return False
    return True


def style(text, colour_name=None, bold=False, dim=False):
    """Wrap a piece of text in colour codes, if colours are switched on."""
    if not _colour_enabled:
        return str(text)

    pieces = []
    if colour_name and colour_name in COLOURS:
        pieces.append(COLOURS[colour_name])
    if bold:
        pieces.append(COLOURS["bold"])
    if dim:
        pieces.append(COLOURS["dim"])

    if not pieces:
        return str(text)

    return "".join(pieces) + str(text) + COLOURS["reset"]


# ---------------------------------------------------------------------------
# Printing
# ---------------------------------------------------------------------------
# Every message in the program goes through one of these functions. That way
# the layout stays the same everywhere and I only have to change the wording
# in one place if I want to.

def line(character="-", width=constants.MENU_WIDTH, colour_name=None):
    """Print a horizontal line."""
    text = character * width
    if colour_name:
        text = style(text, colour_name)
    print(text)


def blank_line():
    print("")


def header(title, width=constants.MENU_WIDTH):
    """
    Print a title with lines above and below it.

    The title is centred, because a menu that is not centred looks like a
    homework project. (Which, to be fair, this is.)
    """
    line("=", width, "cyan")
    print(style(title.center(width), "cyan", bold=True))
    line("=", width, "cyan")


def sub_header(title, width=constants.MENU_WIDTH):
    print("")
    print(style(title, "blue", bold=True))
    line("-", width, "blue")


def info(message):
    print(style("[i] ", "blue") + str(message))


def success(message):
    print(style("[+] ", "green") + str(message))


def warning(message):
    print(style("[!] ", "yellow") + str(message))


def error(message):
    print(style("[x] ", "red") + str(message))


def bullet(message, colour_name=None):
    print("  " + style("*", colour_name or "grey") + " " + str(message))


def print_wrapped(text, width=constants.MENU_WIDTH, indent="    "):
    """
    Print a long sentence without it running off the edge of the screen.
    textwrap handles the hard work, we just add the indent.
    """
    for paragraph in str(text).split("\n"):
        if paragraph.strip() == "":
            print("")
            continue
        wrapped = textwrap.wrap(paragraph, width=width - len(indent))
        for piece in wrapped:
            print(indent + piece)


def pause(message="Press Enter to continue..."):
    """Stop and wait, so that a wall of output does not fly past."""
    try:
        input(style(message, "grey"))
    except (EOFError, KeyboardInterrupt):
        # If the input is closed (piped output, for example) there is no
        # point in waiting forever. Just carry on.
        print("")


def clear_screen():
    """Clear the terminal, but never when the output is being piped."""
    if not sys.stdout.isatty():
        return
    command = "cls" if os.name == "nt" else "clear"
    try:
        os.system(command)
    except Exception:
        # Clearing the screen is a nicety. If it fails, it fails.
        pass


def banner():
    """The big title shown when the program starts."""
    art = r"""
   _____                          __      __         _ _
  / ____|                         \ \    / /        | | |
 | (___   ___  ___ _   _ _ __ ___  \ \  / /_ _ _   _| | |_
  \___ \ / _ \/ __| | | | '__/ _ \  \ \/ / _` | | | | | __|
  ____) |  __/ (__| |_| | | |  __/   \  / (_| | |_| | | |_
 |_____/ \___|\___|\__,_|_|  \___|    \/ \__,_|\__,_|_|\__|
"""
    # The art is ASCII only on purpose: emoji and box drawing characters
    # break in some terminals and in every plain text README ever.
    if _colour_enabled:
        print(style(art, "cyan"))
    else:
        print(art)
    print(style("  a password manager that tries very hard", "grey"))
    print(style("  version " + constants.APP_VERSION, "grey"))
    print("")


# ---------------------------------------------------------------------------
# Asking questions
# ---------------------------------------------------------------------------

def ask(question, default=""):
    """
    Ask a question and return the stripped answer.

    If the user just presses Enter we give back the default value, which is
    shown in the question so they know what they are agreeing to.
    """
    if default != "":
        prompt = question + " [" + str(default) + "]: "
    else:
        prompt = question + ": "

    try:
        answer = input(style(prompt, "white"))
    except EOFError:
        # No more input. Treat it as "the user walked away".
        print("")
        return default
    except KeyboardInterrupt:
        print("")
        return default

    answer = answer.strip()
    if answer == "":
        return default
    return answer


def ask_password(question):
    """
    Ask for a password without showing it on screen.

    getpass is the right tool for this. It needs a terminal though, and in
    some odd environments (an IDE console, a cron job, a test runner) there
    is no terminal and getpass either fails or echoes. In that case we fall
    back to a normal input and print a warning, because a password manager
    that refuses to start is not very useful.
    """
    try:
        import getpass
        return getpass.getpass(question)
    except (EOFError, KeyboardInterrupt):
        print("")
        raise KeyboardInterrupt
    except Exception:
        warning("Could not hide your typing here, so the password will be visible.")
        try:
            return input(question)
        except EOFError:
            return ""


def ask_yes_no(question, default=False):
    """
    Ask a yes/no question and keep asking until the answer is clear.

    Accepts y, yes, n, no, in any capitalisation. Pressing Enter gives the
    default. Anything else loops around with a short complaint.
    """
    if default:
        hint = "Y/n"
    else:
        hint = "y/N"

    while True:
        answer = ask(question + " (" + hint + ")", default="").lower()
        if answer == "":
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        warning("Please answer yes or no.")


def ask_number(question, minimum, maximum, default=None):
    """
    Ask for a whole number inside a range. Keeps asking until it gets one.
    """
    while True:
        raw = ask(question + " (" + str(minimum) + "-" + str(maximum) + ")",
                  default="" if default is None else str(default))
        try:
            number = int(raw)
        except (ValueError, TypeError):
            warning("That is not a number. Try again.")
            continue
        if number < minimum or number > maximum:
            warning("Please pick a number between " + str(minimum) + " and " + str(maximum) + ".")
            continue
        return number


def ask_choice(question, options, allow_back=True):
    """
    Show a numbered list and return the index the user picked.

    Returns -1 if the user picked the "back" option, and None if they typed
    something that makes no sense.

    options is a list of strings. The numbering starts at 1 because that is
    what humans expect.
    """
    print("")
    for position, option in enumerate(options, start=1):
        print("  " + style(str(position) + ")", "cyan", bold=True) + ". " + option)
    if allow_back:
        print("  " + style("0", "cyan", bold=True) + ". Back")

    raw = ask(question)
    try:
        choice = int(raw)
    except (ValueError, TypeError):
        warning("Please type the number of an option.")
        return None

    if choice == 0:
        return -1
    if choice < 1 or choice > len(options):
        warning("There is no option " + str(choice) + ".")
        return None
    return choice - 1


# ---------------------------------------------------------------------------
# Text and tables
# ---------------------------------------------------------------------------

def truncate(text, width):
    """Cut text to a length, adding ... when it had to be shortened."""
    text = str(text)
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[:width - 3] + "..."


def pad(text, width):
    """Pad text with spaces on the right. truncate + pad = tidy columns."""
    return truncate(text, width).ljust(width)


def table(headers, rows, widths=None):
    """
    Print a very simple text table.

    This is not a real table library. It does not merge cells, it does not
    wrap, it does not do borders. It just lines things up, which is all a
    terminal program needs. If a cell is too long it gets cut off with "...".
    """
    if widths is None:
        widths = []
        for index, title in enumerate(headers):
            longest = len(str(title))
            for row in rows:
                if index < len(row):
                    longest = max(longest, len(str(row[index])))
            widths.append(min(longest, 30))

    header_line = ""
    for index, title in enumerate(headers):
        header_line += pad(title, widths[index]) + "  "
    print(style(header_line.rstrip(), "cyan", bold=True))
    line("-", sum(widths) + (2 * (len(widths) - 1)), "grey")

    if not rows:
        print(style("  (nothing here)", "grey"))
        return

    for row in rows:
        pieces = []
        for index, width in enumerate(widths):
            cell = row[index] if index < len(row) else ""
            pieces.append(pad(cell, width))
        print(("  ".join(pieces)).rstrip())


def wrap_and_indent(text, width, indent):
    """Return a list of lines, wrapped and indented, instead of printing."""
    output = []
    for part in str(text).split("\n"):
        if part.strip() == "":
            output.append("")
            continue
        for wrapped in textwrap.wrap(part, width=width - len(indent)):
            output.append(indent + wrapped)
    return output


# ---------------------------------------------------------------------------
# Time and dates
# ---------------------------------------------------------------------------
# Times are stored in UTC, in ISO 8601 format, e.g. 2026-10-22T17:08:00+00:00
# Storing local time would break horribly the moment somebody travels or the
# clock changes for daylight saving. UTC always works.

def now_iso():
    """The current time, in UTC, as a string."""
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def parse_iso(text):
    """
    Turn a stored timestamp back into a datetime.

    Anything unreadable becomes "right now", because a broken date should
    not crash the program, it should just look new.
    """
    if not text:
        return datetime.datetime.now(datetime.timezone.utc)
    try:
        return datetime.datetime.fromisoformat(str(text))
    except (ValueError, TypeError):
        return datetime.datetime.now(datetime.timezone.utc)


def days_since(text):
    """How many whole days have passed since a stored timestamp."""
    moment = parse_iso(text)
    now = datetime.datetime.now(datetime.timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    difference = now - moment
    return max(0, difference.days)


def human_date(text):
    """Format a stored timestamp as something like '22 Oct 2026'."""
    moment = parse_iso(text)
    return moment.strftime("%d %b %Y")


def human_datetime(text):
    """Format a stored timestamp with the time included."""
    moment = parse_iso(text)
    return moment.strftime("%d %b %Y, %H:%M")


def time_ago(text):
    """
    Turn a timestamp into 'just now', '3 days ago', '2 months ago'.
    Approximate is fine here. Nobody needs '2 months, 4 days and 6 hours'.
    """
    moment = parse_iso(text)
    now = datetime.datetime.now(datetime.timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)

    seconds = (now - moment).total_seconds()
    if seconds < 0:
        return "in the future"
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        minutes = int(seconds // 60)
        return str(minutes) + " minute" + ("s" if minutes != 1 else "") + " ago"
    if seconds < 86400:
        hours = int(seconds // 3600)
        return str(hours) + " hour" + ("s" if hours != 1 else "") + " ago"
    days = int(seconds // 86400)
    if days < 30:
        return str(days) + " day" + ("s" if days != 1 else "") + " ago"
    months = int(days // 30)
    if months < 12:
        return str(months) + " month" + ("s" if months != 1 else "") + " ago"
    years = int(days // 365)
    return str(years) + " year" + ("s" if years != 1 else "") + " ago"


def human_duration(seconds):
    """
    Turn a number of seconds into '4 min 12 sec' or '2 hours 5 min'.
    Used by the auto lock countdown and the crack time estimate.
    """
    try:
        seconds = int(seconds)
    except (ValueError, TypeError):
        return "unknown"

    if seconds < 0:
        return "0 sec"
    if seconds < 1:
        return "less than a second"
    if seconds < 60:
        return str(seconds) + " sec"
    if seconds < 3600:
        minutes = seconds // 60
        remainder = seconds % 60
        text = str(minutes) + " min"
        if remainder:
            text += " " + str(remainder) + " sec"
        return text
    if seconds < 86400:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        text = str(hours) + " hour" + ("s" if hours != 1 else "")
        if minutes:
            text += " " + str(minutes) + " min"
        return text
    if seconds < 31536000:
        days = seconds // 86400
        return str(days) + " day" + ("s" if days != 1 else "")
    years = seconds // 31536000
    if years > 1000000000:
        return "longer than the sun has left"
    return str(years) + " year" + ("s" if years != 1 else "")


# ---------------------------------------------------------------------------
# Numbers and bars
# ---------------------------------------------------------------------------

def percentage(part, whole):
    """A safe percentage. Dividing by zero is how programs crash."""
    if whole == 0:
        return 0
    return int(round((part / float(whole)) * 100))


def bar(value, maximum, width=20):
    """
    Draw an ASCII progress bar, e.g. [#######-------------].

    Using '#' and '-' instead of fancy block characters is deliberate: they
    work in every font, every terminal and every README on the internet.
    """
    if maximum <= 0:
        return "[" + ("-" * width) + "]"

    filled = int(round((value / float(maximum)) * width))
    if filled < 0:
        filled = 0
    if filled > width:
        filled = width

    return "[" + ("#" * filled) + ("-" * (width - filled)) + "]"


def star_rating(score, maximum=5):
    """Return something like [***--] for a 0-100 score."""
    filled = int(round((score / 100.0) * maximum))
    if filled < 0:
        filled = 0
    if filled > maximum:
        filled = maximum
    return "[" + ("*" * filled) + ("-" * (maximum - filled)) + "]"


def shorten_number(number):
    """1234 -> 1.2K, 4500000 -> 4.5M. Used in the crack time display."""
    try:
        number = float(number)
    except (ValueError, TypeError):
        return "0"
    if number >= 1000000000000:
        return str(round(number / 1000000000000.0, 1)) + "T"
    if number >= 1000000000:
        return str(round(number / 1000000000.0, 1)) + "B"
    if number >= 1000000:
        return str(round(number / 1000000.0, 1)) + "M"
    if number >= 1000:
        return str(round(number / 1000.0, 1)) + "K"
    return str(int(number))


# ---------------------------------------------------------------------------
# Similarity, used by the fuzzy search
# ---------------------------------------------------------------------------

def levenshtein_distance(first, second):
    """
    The number of single character edits needed to turn one string into the
    other. This is the classic dynamic programming example, and I am using
    it so that searching for "githb" still finds "GitHub".

    The algorithm: build a table where cell [i][j] is the distance between
    the first i characters of one word and the first j of the other.
    """
    first = str(first).lower()
    second = str(second).lower()

    if first == second:
        return 0
    if len(first) == 0:
        return len(second)
    if len(second) == 0:
        return len(first)

    previous_row = list(range(len(second) + 1))

    for i in range(1, len(first) + 1):
        current_row = [i] + [0] * len(second)
        for j in range(1, len(second) + 1):
            if first[i - 1] == second[j - 1]:
                cost = 0
            else:
                cost = 1
            current_row[j] = min(
                current_row[j - 1] + 1,      # insert a character
                previous_row[j] + 1,          # delete a character
                previous_row[j - 1] + cost    # substitute a character
            )
        previous_row = current_row

    return previous_row[len(second)]


def is_fuzzy_match(needle, haystack, allowed_distance=None):
    """
    A forgiving match used by search.

    A short search word is only allowed one typo, a longer one gets a bit
    more room. Otherwise searching for "a" would match absolutely everything.
    """
    needle = str(needle).lower().strip()
    haystack = str(haystack).lower()

    if needle == "":
        return False
    if needle in haystack:
        return True

    if allowed_distance is None:
        if len(needle) <= 3:
            allowed_distance = 0
        elif len(needle) <= 6:
            allowed_distance = 1
        else:
            allowed_distance = 2

    # Compare against every word in the haystack, not just the whole thing,
    # otherwise "git hub" would never match "GitHub".
    words = haystack.split()
    words.append(haystack)
    for word in words:
        if levenshtein_distance(needle, word) <= allowed_distance:
            return True

    return False


# ---------------------------------------------------------------------------
# Odds and ends
# ---------------------------------------------------------------------------

def terminal_width(default=80):
    """The width of the terminal, or a sensible default."""
    try:
        width = shutil.get_terminal_size().columns
    except Exception:
        width = default
    if width < 40:
        width = 40
    return width


def sleep_shortly(seconds=0.4):
    """
    A tiny pause, used after big reveals so the screen does not jump.

    Sleep is never used to "secure" anything. It is only cosmetic.
    """
    try:
        time.sleep(seconds)
    except KeyboardInterrupt:
        pass


def confirm_dangerous_action(phrase, explanation):
    """
    Ask somebody to type a specific word before doing something they cannot
    undo. Used for deleting the whole vault, emptying the trash and plain
    text export. Typing "yes" is too easy; typing a whole word makes you
    stop and think for one second.
    """
    print("")
    warning(explanation)
    typed = ask('Type "' + phrase + '" to continue')
    return typed.strip().upper() == phrase.upper()


def open_path_hint(path):
    """Print a path in a way that is easy to copy (no quotes, no decoration)."""
    print("")
    info("File: " + str(path))


def join_with_commas(items):
    """Turn ['a', 'b', 'c'] into 'a, b, c'. Used for tags."""
    items = [str(item) for item in items if str(item).strip() != ""]
    return ", ".join(items)
