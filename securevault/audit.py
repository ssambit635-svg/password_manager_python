"""
audit.py

The health report. This is the part of the program that tells you things you
would rather not hear.

It looks for the problems that actually cause account takeovers:

  * passwords reused on more than one site (the single biggest one)
  * passwords that are famous for being leaked
  * passwords that are short or built out of obvious patterns
  * passwords that have not changed in years
  * entries that have never been used, which are usually accounts you
    forgot you had
  * entries with no two factor code, where the site probably supports one
  * entries that are about to expire

Every finding comes with a plain English explanation and a suggested next
step. The report is generated on demand and never stored anywhere, because
a summary of your weak passwords is itself a secret.
"""

import os
import hashlib
import shutil
import datetime

from . import constants, utils, strength
from . import backup as backup_module
from . import clipboard as clipboard_module


def group_by_password(vault):
    """
    Group entries that share a password.

    We group on the SHA-256 of the password rather than the password itself,
    so the grouping structure never accidentally ends up in a log or an
    error message. (The passwords are in memory anyway, but it is a good
    habit: a hash is safe to print, the password is not.)
    """
    groups = {}
    for entry in vault.entries:
        digest = hashlib.sha256(entry["password"].encode("utf-8")).hexdigest()
        groups.setdefault(digest, []).append(entry)
    return groups


def reused_password_groups(vault):
    """Only the groups with two or more entries."""
    groups = group_by_password(vault)
    return [entries for entries in groups.values() if len(entries) > 1]


def weak_entries(vault, threshold=55):
    """
    Entries whose password scores below a threshold.

    The threshold of 55 is roughly "fair but not good enough". Lower it if
    the report feels too noisy; the number is a judgement call.
    """
    weak = []
    for entry in vault.entries:
        analysis = strength.analyse(entry["password"], entry["site"], entry["username"])
        if analysis["score"] < threshold:
            weak.append({"entry": entry, "analysis": analysis})
    weak.sort(key=lambda item: item["analysis"]["score"])
    return weak


def common_password_entries(vault):
    """Entries whose password appears in the local list of leaked classics."""
    found = []
    for entry in vault.entries:
        if strength.matches_common_password(entry["password"]):
            found.append(entry)
    return found


def old_entries(vault, days=constants.PASSWORD_AGE_WARNING_DAYS):
    """Entries whose password has not changed in a long time."""
    old = []
    for entry in vault.entries:
        age = utils.days_since(entry.get("password_changed_at"))
        if age >= int(days):
            old.append({"entry": entry, "age_days": age})
    old.sort(key=lambda item: item["age_days"], reverse=True)
    return old


def never_used_entries(vault):
    """Entries that have never been copied or revealed."""
    return [entry for entry in vault.entries if not entry.get("last_used_at")]


def entries_without_two_factor(vault):
    """
    Entries with no TOTP secret stored.

    Careful with the wording in the report: not every site supports two
    factor authentication, and plenty of sites support it but not with a
    standard authenticator app. The report says "no code stored", not "you
    are doing it wrong".
    """
    return [entry for entry in vault.entries if not entry.get("totp_secret")]


def entries_with_two_factor(vault):
    return [entry for entry in vault.entries if entry.get("totp_secret")]


def site_duplicates(vault):
    """Site names that appear more than once. Returns list of (site, entries)."""
    groups = vault.duplicate_sites()
    pairs = list(groups.items())
    pairs.sort(key=lambda pair: pair[0])
    return pairs


def expired_entries(vault):
    """Entries whose expiry date has already passed but that are still there."""
    now = datetime.datetime.now(datetime.timezone.utc)
    found = []
    for entry in vault.entries:
        expires_at = entry.get("expires_at")
        if not expires_at:
            continue
        moment = utils.parse_iso(expires_at)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=datetime.timezone.utc)
        if moment <= now:
            found.append(entry)
    return found


def vault_age_days(vault):
    """How long the vault has existed."""
    return utils.days_since(vault.data.get("created_at"))


def average_score(vault):
    """The mean strength score across every entry, to one decimal place."""
    if not vault.entries:
        return 0.0
    total = 0
    for entry in vault.entries:
        total += strength.analyse(entry["password"], entry["site"], entry["username"])["score"]
    return round(total / float(len(vault.entries)), 1)


def overall_score(vault):
    """
    A single number for the whole vault.

    It starts from the average password score, then takes deductions for
    structural problems: reused passwords, leaked classics, stale passwords
    and abandoned accounts. A vault full of individually strong passwords
    that are all the same password is not a healthy vault, and this is where
    that shows up.
    """
    if not vault.entries:
        return 0

    score = average_score(vault)

    reused = reused_password_groups(vault)
    score -= min(25, len(reused) * 6)

    common = common_password_entries(vault)
    score -= min(30, len(common) * 10)

    old = old_entries(vault)
    score -= min(10, len(old) * 2)

    unused = never_used_entries(vault)
    if vault.entries:
        unused_ratio = len(unused) / float(len(vault.entries))
        score -= int(unused_ratio * 5)

    if score < 0:
        score = 0
    if score > 100:
        score = 100

    return int(round(score))


def overall_grade(score):
    """Reuse the strength module's letter grades so the whole app agrees."""
    letter, label = strength.grade_for_score(score)
    return letter, label


def headline(vault):
    """
    One sentence about the state of the vault, used on the main menu.

    Keeping this short matters. A wall of warnings every time you open the
    program gets ignored within a week.
    """
    if vault.is_empty():
        return "The vault is empty. Add something and I will have an opinion about it."

    score = overall_score(vault)
    letter, label = overall_grade(score)

    problems = []
    if reused_password_groups(vault):
        problems.append("reused passwords")
    if common_password_entries(vault):
        problems.append("leaked passwords")
    if len(weak_entries(vault)) > len(vault.entries) // 2:
        problems.append("a lot of weak passwords")

    if not problems:
        return "Vault health: " + str(score) + "/100 (" + label + "). Nothing urgent."

    return ("Vault health: " + str(score) + "/100 (" + label + "). Watch out for "
            + utils.join_with_commas(problems) + ".")


def full_report(vault):
    """Everything the report screen needs, in one dictionary."""
    analysed = []
    for entry in vault.entries:
        analysed.append({
            "entry": entry,
            "analysis": strength.analyse(entry["password"], entry["site"], entry["username"]),
        })
    analysed.sort(key=lambda item: item["analysis"]["score"])

    reused = reused_password_groups(vault)
    overall = overall_score(vault)
    letter, label = overall_grade(overall)

    return {
        "generated_at": utils.now_iso(),
        "total_entries": len(vault.entries),
        "total_trash": len(vault.trash),
        "vault_age_days": vault_age_days(vault),
        "average_score": average_score(vault),
        "overall_score": overall,
        "grade": letter,
        "label": label,
        "analysed": analysed,
        "weak": weak_entries(vault),
        "reused_groups": reused,
        "reused_entry_count": sum(len(group) for group in reused),
        "common": common_password_entries(vault),
        "old": old_entries(vault),
        "never_used": never_used_entries(vault),
        "no_two_factor": entries_without_two_factor(vault),
        "with_two_factor": entries_with_two_factor(vault),
        "expiring_soon": vault.entries_expiring_soon(7),
        "expired": expired_entries(vault),
        "site_duplicates": site_duplicates(vault),
        "favourites": vault.favorites(),
        "tags": vault.all_tags(),
    }


def recommendations(report):
    """
    Turn the findings into a short, ordered list of things to do.

    Ordered by what actually matters. Reusing a password is worse than
    having an old one, so it comes first. This ordering is the whole point
    of the report: a list of forty warnings is not advice.
    """
    suggestions = []

    if report["common"]:
        suggestions.append(
            "Change the " + str(len(report["common"]))
            + " password(s) that appear in leak lists. These are guessed first by every tool."
        )

    if report["reused_groups"]:
        worst = max(len(group) for group in report["reused_groups"])
        suggestions.append(
            "Break up " + str(len(report["reused_groups"]))
            + " reused password(s). One is shared by " + str(worst)
            + " accounts, so one leak exposes all of them."
        )

    if report["weak"]:
        suggestions.append(
            "Replace the " + str(len(report["weak"]))
            + " weakest passwords, starting with the top of the list."
        )

    if report["old"]:
        suggestions.append(
            "Update " + str(len(report["old"]))
            + " password(s) that have not changed in over "
            + str(constants.PASSWORD_AGE_WARNING_DAYS) + " days."
        )

    if report["expired"]:
        suggestions.append(
            "Clean up " + str(len(report["expired"]))
            + " expired entr(y/ies). They were meant to disappear."
        )

    if report["no_two_factor"] and report["total_entries"] > 0:
        suggestions.append(
            "Store authenticator codes for the accounts that support them. "
            + str(len(report["with_two_factor"])) + " of "
            + str(report["total_entries"]) + " entries have one."
        )

    if report["never_used"]:
        suggestions.append(
            "Look at the " + str(len(report["never_used"]))
            + " entr(y/ies) you have never used. Old accounts are the ones that get forgotten."
        )

    if report["site_duplicates"]:
        suggestions.append(
            "There are duplicate site names. That may be fine (two accounts on "
            "the same site) or it may be a sign of clutter."
        )

    if not suggestions:
        suggestions.append("Nothing to fix. That is rare. Have a nice day.")

    return suggestions


# ---------------------------------------------------------------------------
# The doctor
# ---------------------------------------------------------------------------
# A separate check that looks at the installation rather than the passwords.
# The name comes from the usual Unix convention: a program that diagnoses
# itself and prints a list of things with pass, warn or fail next to them.

def doctor_report(data_directory, meta=None, open_vault_object=None):
    """
    Run every environment check and return a list of dictionaries.

    Each item: {"level": "ok"|"warn"|"fail", "title": ..., "detail": ...}
    The vault can be locked; most checks still work because they only need
    meta.json and the folder.
    """
    findings = []

    def add(level, title, detail):
        findings.append({"level": level, "title": title, "detail": detail})

    # -- the folder -----------------------------------------------------
    if data_directory.exists():
        add("ok", "Data folder", data_directory.path)
    else:
        add("warn", "Data folder", "Does not exist yet. It will be created on first use.")

    if os_writable(data_directory.path):
        add("ok", "Folder is writable", "The program can save changes here.")
    else:
        add("fail", "Folder is not writable", data_directory.path)

    free = _disk_free(data_directory.path)
    if free is None:
        add("warn", "Free space", "Could not work out how much space is left.")
    elif free < 10 * 1024 * 1024:
        add("warn", "Free space", "Less than 10 MB free. That is tight.")
    else:
        add("ok", "Free space", _human_bytes(free) + " available.")

    # -- meta -----------------------------------------------------------
    if meta is None and data_directory.meta_exists():
        try:
            meta = data_directory.read_meta()
            add("ok", "Settings file", "meta.json reads cleanly.")
        except Exception as problem:
            add("fail", "Settings file", str(problem))

    if meta:
        kdf = meta.get("kdf") or {}
        iterations = int(kdf.get("iterations", 0) or 0)
        if iterations >= 200000:
            add("ok", "Key derivation", str(iterations) + " iterations of PBKDF2.")
        elif iterations > 0:
            add("warn", "Key derivation",
                str(iterations) + " iterations is low by modern standards.")
        else:
            add("warn", "Key derivation", "No key derivation settings found.")

        if meta.get("recovery"):
            add("ok", "Recovery code", "A recovery code is registered for this vault.")
        else:
            add("warn", "Recovery code",
                "No recovery code. If the master password is lost, so is the vault.")

        if meta.get("duress"):
            add("ok", "Duress password", "A decoy vault is set up.")
        else:
            add("ok", "Duress password", "Not in use. That is the normal case.")

        if backup_module.backup_is_stale(data_directory):
            add("warn", "Backups", "No backup in the last 30 days.")
        else:
            names = data_directory.list_backups()
            add("ok", "Backups", str(len(names)) + " backup file(s). Newest: " + names[0])

        audit_entries = meta.get("audit_log", [])
        add("ok", "Audit log", str(len(audit_entries)) + " recent action(s) recorded.")

        locked = meta.get("attempts", {})
        if locked.get("locked_until"):
            add("warn", "Login lockout", "A lockout is currently recorded in the settings.")
        else:
            add("ok", "Login lockout", "No lockout recorded.")

    # -- clipboard ------------------------------------------------------
    if clipboard_module.is_available():
        add("ok", "Clipboard", "Using " + clipboard_module.describe_tool() + ".")
    else:
        add("warn", "Clipboard",
            "No clipboard tool found. Passwords can still be shown on screen.")

    # -- attachments ----------------------------------------------------
    if open_vault_object is not None:
        total = 0
        unreadable = 0
        for entry in open_vault_object.entries:
            for attachment in entry.get("attachments", []):
                total += 1
                try:
                    open_vault_object.read_attachment(entry["id"], attachment["id"])
                except Exception:
                    unreadable += 1

        if total == 0:
            add("ok", "Attachments", "None stored.")
        elif unreadable == 0:
            add("ok", "Attachments", str(total) + " stored, all readable.")
        else:
            add("fail", "Attachments",
                str(unreadable) + " of " + str(total) + " could not be decrypted.")

        add("ok", "Vault", str(open_vault_object.count()) + " entries, revision "
            + str(open_vault_object.data.get("revision", 0)) + ".")

    return findings


def os_writable(path):
    """Check writability without leaving anything behind."""
    if not os.path.isdir(path):
        return False
    probe_name = ".sv_probe_" + hashlib.sha256(str(datetime.datetime.now()).encode()).hexdigest()[:8]
    probe = os.path.join(path, probe_name)
    try:
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("probe")
        os.remove(probe)
        return True
    except OSError:
        return False


def _disk_free(path):
    try:
        return shutil.disk_usage(path).free
    except (OSError, AttributeError):
        return None


def _human_bytes(number):
    if number is None:
        return "unknown"
    number = float(number)
    for unit in ("bytes", "KB", "MB", "GB"):
        if number < 1024:
            return str(round(number, 1)) + " " + unit
        number = number / 1024.0
    return str(round(number, 1)) + " TB"
