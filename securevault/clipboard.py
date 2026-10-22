"""
clipboard.py

Copying a password without leaving it on the clipboard all afternoon.

Every password manager has this problem. You copy a password, paste it into
a website, and then forget about it. It sits in the clipboard, where any
other program you open can read it, until the next time you copy something.

The fix is simple and a bit crude: copy, then start a background timer, and
when the timer fires, put the clipboard back to whatever it was before (or
to an empty string if we cannot read what was there).

We use the operating system's own clipboard tools rather than a Python
library, because a library means another dependency and another thing that
does not work on somebody else's machine:

    macOS     pbcopy / pbpaste
    Windows   clip (writing only, no way to read)
    Wayland   wl-copy / wl-paste
    X11       xclip or xsel
    Termux    termux-clipboard-set / termux-clipboard-get

If none of them exist, we do not pretend. The caller is told that copying
is not possible and the menu offers to show the password instead.
"""

import os
import shutil
import subprocess
import threading

from . import constants, utils


class ClipboardError(Exception):
    """Copying is not possible on this system, or the copy failed."""
    pass


# The clear timer needs to be cancellable, so we remember the current one.
# Only one clipboard timer is ever active at a time: copying a second
# password should cancel the first password's timer, otherwise the first
# timer would fire and wipe the second password off the clipboard early.
_timer_lock = threading.Lock()
_active_timer = None

# For tests, and for people who want to see what the module would do.
_last_copied = {"text": "", "copied_at": None}


def _which(names):
    """Return the first command in the list that exists, or None."""
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


def detect_tool():
    """
    Work out how to write to the clipboard on this machine.

    Returns a tuple (read_command, write_command). Either can be None: on
    Windows we can write with clip but not read, so read_command is None.
    """
    if os.name == "nt":
        return None, _which(["clip"])

    if shutil.which("pbcopy"):
        return _which(["pbpaste"]), _which(["pbcopy"])

    if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-copy"):
        return _which(["wl-paste"]), _which(["wl-copy"])

    if shutil.which("xclip"):
        return (
            [_which("xclip"), "-selection", "clipboard", "-o"],
            [_which("xclip"), "-selection", "clipboard"],
        )

    if shutil.which("xsel"):
        return (
            [_which("xsel"), "--clipboard", "--output"],
            [_which("xsel"), "--clipboard", "--input"],
        )

    if os.environ.get("TERMUX_VERSION"):
        return _which(["termux-clipboard-get"]), _which(["termux-clipboard-set"])

    return None, None


def is_available():
    """True if we have some way of writing to the clipboard."""
    _read, write = detect_tool()
    return write is not None


def describe_tool():
    """A short description for the doctor command."""
    read, write = detect_tool()
    if write is None:
        return "no clipboard tool found"
    name = os.path.basename(write if isinstance(write, str) else write[0])
    if read is None:
        return name + " (write only)"
    return name


def _run(command, input_text=None, timeout=3):
    """
    Run a clipboard command.

    Clipboard tools are small and finish immediately, so a three second
    timeout is generous. text=True because all of these tools deal in text.
    """
    if isinstance(command, str):
        command = [command]

    try:
        finished = subprocess.run(
            command,
            input=input_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise ClipboardError("The clipboard tool was not found.")
    except subprocess.TimeoutExpired:
        raise ClipboardError("The clipboard tool took too long to respond.")
    except OSError as problem:
        raise ClipboardError("Could not talk to the clipboard: " + str(problem))

    if finished.returncode != 0:
        message = (finished.stderr or "").strip()
        raise ClipboardError("The clipboard tool refused: " + (message or "unknown reason"))

    return finished.stdout or ""


def read_clipboard():
    """Read the clipboard as text, or return None if we cannot."""
    read, _write = detect_tool()
    if read is None:
        return None
    try:
        return _run(read)
    except ClipboardError:
        return None


def write_clipboard(text):
    """Put text on the clipboard. Raises ClipboardError if it cannot."""
    _read, write = detect_tool()
    if write is None:
        raise ClipboardError(
            "No clipboard tool found. Install xclip (Linux), or use the "
            "'show' option to read the password directly."
        )
    _run(write, input_text=str(text))


def copy_text(text, clear_after=constants.DEFAULT_CLIPBOARD_SECONDS):
    """
    Copy text and schedule a wipe.

    Returns the previous clipboard contents, so the caller can show a
    message like "restored what was there before".

    clear_after=0 means "do not clear automatically". That exists for people
    who know what they are doing, but the default is 20 seconds.
    """
    global _active_timer

    text = str(text)
    if text == "":
        raise ClipboardError("There is nothing to copy.")

    previous = read_clipboard()

    write_clipboard(text)

    _last_copied["text"] = text
    _last_copied["copied_at"] = utils.now_iso()

    with _timer_lock:
        # Cancel any wipe that is still pending from an earlier copy.
        if _active_timer is not None:
            _active_timer.cancel()
            _active_timer = None

        if clear_after and int(clear_after) > 0:
            timer = threading.Timer(float(clear_after), _wipe_clipboard,
                                    args=(text, previous))
            # A daemon thread does not keep the program alive. If the user
            # quits, the timer dies with the process, which is fine: the
            # clipboard contents go with the session anyway on most systems.
            timer.daemon = True
            timer.start()
            _active_timer = timer

    return previous


def _wipe_clipboard(copied_text, previous_text):
    """
    The timer callback. Called from a background thread.

    It only clears the clipboard if the clipboard still contains what we
    put there. If the user has copied something else in the meantime,
    wiping would destroy their work, so we leave it alone.
    """
    try:
        current = read_clipboard()
        if current is not None and current.strip() != copied_text.strip():
            return

        if previous_text:
            write_clipboard(previous_text)
        else:
            write_clipboard("")
    except ClipboardError:
        # Nothing useful to do from a background thread. The user has
        # already been told about clipboard problems when they copied.
        pass
    finally:
        _last_copied["text"] = ""


def cancel_pending_wipe():
    """Stop the wipe timer, e.g. when the program is exiting."""
    global _active_timer
    with _timer_lock:
        if _active_timer is not None:
            _active_timer.cancel()
            _active_timer = None


def clear_now():
    """Wipe the clipboard immediately, if we can."""
    try:
        write_clipboard("")
        return True
    except ClipboardError:
        return False


def last_copied():
    """Diagnostics for the doctor command. Never shows the copied text."""
    if _last_copied["text"]:
        return "a password was copied at " + str(_last_copied["copied_at"])
    return "nothing copied this session"


def copy_hint(seconds=constants.DEFAULT_CLIPBOARD_SECONDS, tty=True):
    """
    The line printed after a successful copy.

    This exists so the wording is identical everywhere, which matters more
    than it sounds: six different menus that all copy a password should not
    each invent their own sentence.
    """
    if not tty:
        return "Copied. Paste it, then clear your clipboard when you are done."
    return ("Copied. It will be cleared in " + str(int(seconds))
            + " seconds, or when you copy something else.")
