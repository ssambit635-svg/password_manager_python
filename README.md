# SecureVault

A password manager that runs in your terminal, stores everything in one
encrypted file, and does not need a server, an account, a subscription or an
internet connection.

```
   _____                          __      __         _ _
  / ____|                         \ \    / /        | | |
 | (___   ___  ___ _   _ _ __ ___  \ \  / /_ _ _   _| | |_
  \___ \ / _ \/ __| | | | '__/ _ \  \ \/ / _` | | | | | __|
  ____) |  __/ (__| |_| | | |  __/   \  / (_| | |_| | | |_
 |_____/ \___|\___|\__,_|_|  \___|    \/ \__,_|\__,_|_|\__|
```

Version 2.0.0. Python 3.8 or newer. One dependency. 273 tests.

---

## Table of contents

1. [What this is](#what-this-is)
2. [The short version](#the-short-version)
3. [Features](#features)
4. [The ridiculous features](#the-ridiculous-features)
5. [Quick start](#quick-start)
6. [What it looks like](#what-it-looks-like)
7. [How the encryption works](#how-the-encryption-works)
8. [Threat model, stated honestly](#threat-model-stated-honestly)
9. [Where your files live](#where-your-files-live)
10. [Command line reference](#command-line-reference)
11. [The five passwords you might have](#the-five-passwords-you-might-have)
12. [Backups, recovery and the piece of paper](#backups-recovery-and-the-piece-of-paper)
13. [Health report](#health-report)
14. [Running the tests](#running-the-tests)
15. [Project layout](#project-layout)
16. [Design decisions, and why](#design-decisions-and-why)
17. [Upgrading from version 1](#upgrading-from-version-1)
18. [Limitations](#limitations)
19. [FAQ](#faq)
20. [Security policy](#security-policy)
21. [License](#license)

---

## What this is

SecureVault is a command line password manager written in Python. You run it,
type a master password, and get a menu. Behind the menu is a single encrypted
file containing your logins, notes, tags, authenticator secrets and small
attachments.

It is also a learning project that got out of hand. The first version was one
495 line file with a few bugs and a README that told you to run a file name
that did not exist. This is the rewrite: the encryption and the menus live in
different files, the random passwords come from a real random source, the
vault is written atomically, and there are tests. Quite a lot of tests.

It deliberately does not have a browser extension, a mobile app, cloud sync or
auto-fill. Every one of those things would mean either a server or a much
larger pile of code, and both of those are how password managers get breached.

## The short version

```
git clone <this repository>
cd password_manager_python
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python password_manager.py
```

That is it. The vault is created in `~/.securevault` the first time you run
it, and you are asked to choose a master password and to write down a
recovery code.

## Features

### The practical bits

| Feature | Where |
| --- | --- |
| Encrypted vault, one file | `securevault/crypto.py` |
| Add, edit, delete, restore | `securevault/vault.py` |
| Fuzzy search across sites, usernames, tags and notes | `vault.py` |
| Random password generator with presets and a custom recipe | `generator.py` |
| Password strength scoring with crack time estimates | `strength.py` |
| Trash with restore, so a mis-click is not a disaster | `vault.py` |
| Password history, ten versions per entry | `vault.py` |
| Tags, favourites, notes, per-entry expiry | `vault.py` |
| TOTP two factor codes, computed offline | `totp.py` |
| Encrypted file attachments, up to 2 MB each | `vault.py` |
| CSV and JSON import and export | `importers.py` |
| Encrypted backups with their own passphrases | `backup.py` |
| Vault health report with a single 0 to 100 score | `audit.py` |
| A `doctor` command that checks the whole installation | `audit.py` |
| Auto lock after a period of inactivity | `session.py` |
| Clipboard that clears itself | `clipboard.py` |

### The details that matter more than they look

- **Atomic writes.** Everything is written to a temporary file, flushed,
  fsynced and then renamed. A crash mid-write cannot leave you with half a
  vault.
- **Owner-only permissions.** Files are created `0600` and the folder `0700`
  on any system that supports it.
- **A `.gitignore` inside the data folder.** If you ever run the program
  inside a git repository, your vault cannot be committed by accident.
- **Search never looks inside passwords.** You cannot leak a password by
  searching for part of it in a room full of people.
- **Passwords are masked by default.** The first version printed every
  password in full whenever you viewed the list.
- **Attempt throttling with an increasing delay.** Five wrong passwords and
  the vault locks for 30 seconds, then a minute, then two, up to an hour. The
  counter is on disk, so quitting and restarting does not reset it.
- **No network code at all.** Not one import of `socket`, `urllib` or
  `requests` in the runtime path. You can run this with the network cable
  unplugged and nothing changes.

## The ridiculous features

These are the ones that make people say "why". Every one of them is real,
tested, and documented.

### 1. A duress password that opens a decoy vault

Set a second password. Type it at the login screen and you get a completely
different, perfectly ordinary looking vault. Type your real password and you
get the real one.

The decoy is a real vault with real encryption. It starts empty. Put two or
three boring entries in it, because an empty password manager is suspicious.

What it is for: the situation where somebody is standing behind you and
asking you to open your password manager. What it is not for: anything
involving violence. It is a way to avoid making a bad situation worse, and
nothing more. Use your judgement, and if you are in danger, call the police.

While the decoy is open, the program behaves like an ordinary, slightly
empty vault: the duress setting reads "off", the audit log comes back empty,
and the screens for changing the master password or the recovery code are
disabled. Those three options write to shared settings that belong to the real
vault, so allowing them from the decoy would either break the real login or
give the game away.

Two honest caveats remain. First, the decoy lives in the same folder as the
real vault (`decoy_vault.enc`), so somebody who knows this program well will
see the file and work out what is going on. Second, the decoy's contents are
whatever you put in it; an empty password manager is suspicious, so put a few
boring entries in. It stops a person, not a forensic examiner.

### 2. Entries that delete themselves

Give an entry an expiry date and it is destroyed the next time the vault is
opened after that date. Useful for a temporary password you are passing to a
contractor, or an account that is being closed. The main menu warns you when
something expires within three days.

### 3. A share code for one password

Pick an entry, pick a passphrase, get a blob of text. The other person pastes
the blob into SecureVault, types the passphrase, and gets the login. Send the
blob by chat and say the passphrase on the phone; either one alone is useless.

The blob is encrypted with PBKDF2 and AES, carries its own salt, and contains
only the site, address, username and password. Your notes, tags and history
stay home.

### 4. The password studio

A generator that is not random. It derives a password from a phrase, a label
and a version number, using PBKDF2. Same three inputs, same password, forever,
on any machine, with nothing stored.

This is the "I need to log in from a computer that is not mine" feature. It is
also a sharp knife: the phrase is now as valuable as the password, there is no
backup, and if you forget the phrase the password is gone. The screen tells
you this before it does anything. Do not use it for your bank.

### 5. Readable passwords for dictating out loud

Every generated password can be shown in chunks (`XbU`, `!JP`, `&Z^`) so you
can read it to a colleague over the phone without saying "capital k, no, the
other one".

### 6. A `doctor` that checks the installation

```
python password_manager.py doctor
```

Checks the folder permissions, free space, key derivation strength, whether a
recovery code exists, when the last backup was made, whether the clipboard
tool works, and whether every attachment still decrypts. Prints PASS, WARN or
FAIL for each, and exits non-zero if anything failed, so it can be used in a
script.

### 7. The health report

A single number from 0 to 100 that combines the average password strength with
structural problems: reused passwords, leaked passwords, stale passwords and
accounts you have never used. Plus a "what to do, in order" list that puts the
things that actually matter at the top instead of dumping forty warnings on
you.

## Quick start

### Requirements

- Python 3.8 or newer
- The `cryptography` package (`pip install -r requirements.txt`)
- Windows, macOS or Linux. No administrator rights needed.

### Install

```bash
python3 -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### First run

```bash
python password_manager.py
```

1. Choose a master password. At least eight characters, and the program will
   tell you if it is one of the classics. A long phrase beats a short puzzle.
2. Write down the recovery code it shows you. It is shown once. There is no
   way to see it again, only to replace it.
3. Say yes to the emergency kit if you have a printer or a safe place.
4. Add your first entry. The generator is option 4 on the main menu and option
   2 while adding an entry.

### Put the vault somewhere else

```bash
python password_manager.py --data-dir /media/usb/my-vault
# or
export SECUREVAULT_HOME=/media/usb/my-vault
```

The folder is created if it does not exist.

## What it looks like

The main menu, after a bit of use:

```
======================================================================
                             SECUREVAULT
======================================================================

  Vault health: 82/100 (strong). Watch out for reused passwords.
  12 entries, 1 in trash  |  auto lock in 4 min

  VAULT
  * 1. All entries
  * 2. Add an entry
  * 3. Search
  * 4. Password generator
  INSIGHT
  * 5. Health report
  * 6. Two factor codes
  * 7. Tags
  * 8. Trash
  HOUSEKEEPING
  * 9. Backups
  * 10. Import and export
  * 11. Settings and security
  * 12. Tools
  OTHER
  * 13. Help
  * 14. About
  * 0. Lock and quit
```

One entry:

```
======================================================================
                                GitHub
======================================================================

  Username     : amit2
  Password     : ********  (20 characters)
  Address      : https://github.com
  Tags         : work, dev
  Created      : 22 Oct 2026, 17:19 (3 days ago)
  Changed      : 22 Oct 2026, 17:19 (3 days ago)
  Last used    : never
  Strength     : A (excellent) [*****]  100/100
  Two factor   : a code is stored for this entry
```

The health report:

```
  OVERALL: A  EXCELLENT    95/100
  [###########################################--]

Measure                         Value
--------------------------------------------------------
Entries                         12
In the trash                    1
Average password score          88.4/100
Vault age                       210 days
With two factor codes           4
Favourites                      3
Tags                            6

FINDINGS
----------------------------------------------------------------------
  OK   Passwords that appear in leak lists
  2    Passwords reused across accounts
  3    Weak passwords
  5    Passwords older than 180 days
  1    Expired entries still present
```

The doctor:

```
  PASS  Data folder                 /home/you/.securevault
  PASS  Folder is writable          The program can save changes here.
  PASS  Key derivation              320000 iterations of PBKDF2.
  PASS  Recovery code               A recovery code is registered.
  PASS  Backups                     3 backup file(s).
  WARN  Clipboard                   No clipboard tool found.
  PASS  Attachments                 2 stored, all readable.
```

## How the encryption works

This is the part worth reading carefully, because if you are going to trust a
password manager written by a stranger on the internet, you should at least
know what it does.

```
   master password
          |
          |  +  random salt (16 bytes, stored in meta.json)
          v
   PBKDF2-HMAC-SHA256, 320,000 iterations
          |
          v
   32 byte key
          |
          +--> Fernet key (base64, 44 chars)
          |         |
          |         v
          |    AES-128-CBC + HMAC-SHA256  --->  vault.enc
          |
          +--> HMAC verifier (stored in meta.json, cannot be reversed)
          |
          +--> wrapped copy under the recovery code (also in meta.json)
```

### The key

Your master password is mixed with a random salt using PBKDF2 for 320,000
iterations. That takes a fraction of a second on a laptop and makes each guess
about 320,000 times more expensive for an attacker. The salt is random per
vault, so two people with the same password get different keys, and tables of
pre-computed hashes are useless.

The result is a 32 byte key. It is never written to disk.

### The vault

The whole vault is one JSON document: entries, trash, revision counter. It is
encrypted with Fernet, which is AES-128 in CBC mode plus an HMAC-SHA256 tag
over the ciphertext. The HMAC is why tampering fails loudly instead of
producing garbage.

```
vault.enc = Fernet_token( JSON( {entries: [...], trash: [...], revision: 7} ) )
```

### The verifier

To check a password at login we need something stored. What is stored is an
HMAC of a fixed label using the derived key:

```
verifier = HMAC-SHA256(key, "securevault-verifier-vault")
```

You cannot work backwards from the verifier to the key, and without the key
you cannot produce the verifier. Comparison uses a constant time function, so
the time it takes does not leak how much of the value matched.

### The recovery code

A 20 character code (about 99 bits of randomness) is generated when the vault
is created. A key is derived from it, and that key encrypts a copy of the vault
key:

```
wrapped_key = Fernet( base64(vault_key), key = PBKDF2(recovery_code, salt) )
```

That is what makes a forgotten master password recoverable without weakening
the vault: the recovery code must be present to unwrap the key, and it is only
ever printed once. Using it re-keys everything and issues a new code.

### Attachments

Each attachment is encrypted with the same vault key, base64 encoded, and
stored as a blob with a random 32 character hex name. The original file name,
size and SHA-256 checksum live inside the encrypted entry. A directory listing
leaks how many attachments exist and roughly how big they are, and nothing
else.

When you change your master password, every attachment is decrypted with the
old key and re-encrypted with the new one. If that step were missing, changing
your password would silently destroy every attached file. There is a test for
exactly that.

### Backups

A backup is encrypted with a passphrase you choose at backup time. It is not
the master password and not derived from it. A backup that only opens with the
password you have already lost is not a backup.

## Threat model, stated honestly

### What it protects against

- **Somebody steals the disk or the laptop.** The vault file is useless
  without the master password or the recovery code.
- **Somebody finds an old backup.** Same thing, with the backup passphrase.
- **Somebody copies the folder to another machine.** Same thing.
- **Casual snooping over your shoulder.** Passwords are masked, search never
  matches on password content, and the clipboard clears itself.
- **You leaving the vault open.** It locks itself.
- **You deleting something by accident.** The trash and the password history.
- **You forgetting the master password.** The recovery code.
- **You being forced to open it.** The duress password, imperfectly.

### What it does not protect against

- **Malware running as you.** A keylogger sees the master password. A process
  that can read your memory can read the decrypted vault. No password manager
  written in Python can fix that.
- **Somebody watching you type.** Nothing here helps.
- **A compromised Python interpreter or a tampered copy of this code.** Read
  the source. It is not that big.
- **The recovery code being found next to the vault.** If both are in the same
  drawer, the drawer is the security boundary.
- **A weak master password.** PBKDF2 raises the cost of guessing a lot. It does
  not turn `password123` into a secret.
- **Filesystem metadata.** The file sizes and modification times of the vault,
  backups and attachments are visible. File names of exported CSVs are your
  problem.

If your threat model includes a government with forensic labs, use something
audited, like KeePassXC or Bitwarden, and get expert advice. This program is
honest about being a small project.

## Where your files live

Default: `~/.securevault/`

```
~/.securevault/
  meta.json            settings, salt, verifier, recovery record, audit log
  vault.enc            the encrypted vault
  decoy_vault.enc      only if you enabled the duress password
  emergency_kit.txt    only if you asked for one: your recovery code, once
  backups/
    vault-20261022-172020.svbackup
    ...
  attachments/
    <32 random hex>.bin    encrypted blobs
  .gitignore           "*" inside the data folder, so git ignores it
```

Three notes:

1. `meta.json` is not secret, but it is sensitive: it contains the salt, the
   verifier, the wrapped key and the attempt counter. Do not publish it.
2. The audit log lives in `meta.json`. It records actions like "unlock",
   "backup created", "password copied" with timestamps, and never passwords.
   It is capped at the last 200 actions.
3. `emergency_kit.txt` contains the recovery code in plain text. Print it,
   then delete or move the file. It is written with `0600` permissions, which
   helps with other users on the machine and not at all with a stolen laptop.

## Command line reference

```
python password_manager.py                       interactive menus
python password_manager.py --help                every option
python password_manager.py --version             version number
python password_manager.py --no-color            plain text
python password_manager.py --data-dir PATH       use another folder
```

### Commands that do not need the vault

```
generate [--preset balanced|paranoid|memorable|pin|passphrase]
         [--length N] [--words N] [--count N]
         [--no-symbols] [--avoid-ambiguous] [--copy] [--json]

check [--password TEXT] [--json]      score a password
doctor                                installation check, exits 1 on failure
info                                  where the vault is and what is in it
```

### Commands that need the master password

```
list [--tag TAG] [--favourites] [--sort site|updated|created|oldest|health|uses] [--json]
show SITE [--field password|username|url|notes|totp] [--copy]
import PATH [--tag TAG] [--dry-run]
export PATH [--format csv|json] [--yes]
backup [--note TEXT] [--keep N]
share                                 make a share code, prints it
open-share [--code CODE]              open a share code
```

### Commands that manage access

```
recover          reset the master password with the recovery code
reset-lockout    clear the failed attempt counter
```

### Environment variables

| Variable | Meaning |
| --- | --- |
| `SECUREVAULT_HOME` | data folder, same as `--data-dir` |
| `SECUREVAULT_PASSWORD` | master password for scripts; prints a warning |
| `SECUREVAULT_DEBUG` | show full tracebacks instead of friendly errors |
| `NO_COLOR` | disable colours, the usual convention |

`SECUREVAULT_PASSWORD` is convenient in a cron job and a bad idea on a shared
machine, because other users can see environment variables of processes they
own. The program warns every time it uses it.

### Examples

```bash
# a 32 character password, straight to stdout
python password_manager.py generate --preset paranoid

# six word passphrase
python password_manager.py generate --preset passphrase --words 6

# what does my list look like?
python password_manager.py list --sort health

# one field of one entry
python password_manager.py show github --field username

# nightly backup that prunes to the last 14
python password_manager.py backup --note nightly --keep 14

# move from a browser, dry run first
python password_manager.py import ~/Downloads/passwords.csv --dry-run
python password_manager.py import ~/Downloads/passwords.csv --tag imported
```

## The five passwords you might have

This trips people up, so here it is in one place.

| Password | What it opens | Stored as |
| --- | --- | --- |
| Master password | the vault | verifier only, never recoverable |
| Recovery code | a reset of the master password | verifier + wrapped vault key |
| Duress password | the decoy vault | verifier only |
| Backup passphrase | one backup file | nothing; it is only in your head/paper |
| Studio phrase | regenerates determined passwords | nothing, ever |

Lose the master password and you have two options: the recovery code, or
nothing. Lose the recovery code too and the vault is mathematically closed.
That is what "encrypted" means, and no amount of wishing changes it.

## Backups, recovery and the piece of paper

The single most common way to lose a vault is not an attack. It is a dead
disk, a stolen laptop where the backup was on the same machine, or a person
who never made a backup at all.

The backup menu (option 9) does four things:

1. **Make a backup** with its own passphrase. It offers to generate a five
   word passphrase and makes you press Enter once you have written it down.
2. **Verify a backup** by decrypting it and checking that every entry has a
   site and a password. An unverified backup is a rumour.
3. **Restore**, either merging (add what is missing) or replacing (throw away
   the current vault and use the backup). Replacing asks you to type a word.
4. **Prune** old backups, keeping however many you like, default ten.

Then there is the emergency kit, which is the only thing this program produces
that is meant to be printed:

```
============================================================
SECUREVAULT EMERGENCY KIT
============================================================

Created:          22 Oct 2026, 17:21
Key fingerprint:  6883E166

------------------------------------------------------------
YOUR RECOVERY CODE
------------------------------------------------------------

    YPYM-DM6Q-893M-4QBN-G3F8
```

Put the printed page somewhere that is not the computer, and not the same bag
as the USB stick with the backup. If both are stolen together, the attacker
has the lock and the key.

## Health report

The report is generated on demand and never saved unless you ask for a text
version, which contains no passwords. It looks at:

- **Reuse.** Entries grouped by the SHA-256 of their password, so the grouping
  structure itself never contains a password. Reuse is the biggest single
  cause of account takeovers: one breached site exposes every other site with
  the same password.
- **Leaked classics.** A local list of the usual suspects, with common
  substitutions handled (`P@ssw0rd!` is caught), trailing digits and symbols
  stripped, and reversed words tried.
- **Strength.** Each password is scored on length, character variety, keyboard
  walks, repeats, site name inclusion and years. The score is a curve from
  entropy bits after penalties.
- **Age.** Passwords unchanged for 180 days get a mention.
- **Dormancy.** Entries that have never been copied or revealed. Old accounts
  are the ones nobody watches.
- **Two factor coverage.** How many entries have an authenticator secret.
- **Expiry.** Entries that expired and entries expiring soon.

The overall score starts from the average password score and takes deductions
for the structural problems. It is opinionated, and the thresholds are
constants at the top of `audit.py` if you disagree.

Crack time estimates use four rates: 10 guesses per second (a throttled login
form), 1,000 per second (an unthrottled API), 10,000 per second (a weak slow
hash) and 10 billion per second (a graphics card against a fast hash). They are
rough by nature, and the report says so.

## Running the tests

```bash
python -m unittest discover -s tests -t .     # no extra dependencies
python -m pytest tests                        # if you prefer pytest
```

273 tests, no network, no long sleeps, and every test
gets its own temporary vault folder. The suite covers:

- encryption round trips, wrong keys, tampering, verifiers, salts
- the RFC 6238 test vectors for TOTP, so authenticator codes are checked
  against the standard and not against my own assumptions
- generator lengths, character classes, ambiguity filtering, passphrase words
- strength scoring, pattern detection, common password variants
- vault CRUD, history, tags, search, sorting, trash, attachments, expiry
- login, lockout timing, recovery, duress, re-keying attachments
- backups, verification, merging, pruning, the emergency kit
- CSV and JSON import and export, including quoted commas
- the doctor's findings
- the session clock, auto locking, settings and clipboard failures
- the command line front end, including its JSON output and exit codes

There is also a deliberate test that the vault file does not contain a site
name in plain text, because "it looked encrypted" is not a test.

## Project layout

```
password_manager.py         the entry point: parse arguments, call the package
securevault/
  __init__.py               the story of the package
  constants.py              every number, file name and word list
  utils.py                  colours, prompts, tables, dates, fuzzy matching
  crypto.py                 PBKDF2, Fernet, verifiers, recovery, share codes
  storage.py                atomic file writes, meta.json, attachments, backups
  vault.py                  entries, trash, history, tags, search, uploads
  generator.py              random passwords, passphrases, PINs, memorable
  strength.py               scoring, patterns, crack time estimates
  totp.py                   RFC 6238 authenticator codes and otpauth links
  audit.py                  health report and the doctor
  importers.py              CSV and JSON in, CSV and JSON out
  backup.py                 encrypted backups and the emergency kit
  clipboard.py              copy, then wipe, using the system's own tools
  auth.py                   master password, lockout, recovery, duress
  session.py                the open vault, settings and the auto lock clock
  ui.py                     every screen, and nothing else
  cli.py                    argument parsing and the non-interactive commands
tests/
  support.py                a temporary folder per test
  test_crypto.py            the important one
  test_generator.py
  test_strength.py
  test_totp.py              includes the RFC vectors
  test_vault.py
  test_auth.py
  test_storage_backup_audit.py
  test_session.py           settings, auto lock, locking
  test_cli.py               the subcommands, output and exit codes
```

If you want to read the code, start with `constants.py`, then `crypto.py`,
then `storage.py`. Skip `ui.py` until you care about menus.

## Design decisions, and why

**Why one encrypted blob instead of a database?**
A personal vault has tens or hundreds of entries. One file of a few kilobytes
can be written atomically, backed up by copying, and verified as a whole.
SQLite would add concurrency features nobody needs and a second way for the
data to be half-written.

**Why Fernet instead of inventing a format?**
Fernet is AES-128-CBC with an HMAC-SHA256 tag and a timestamp, implemented and
maintained by the `cryptography` library. Rolling my own authenticated
encryption is exactly the kind of thing that ends up on a security mailing
list. AES-128 is not the weak part of a password manager; the password is.

**Why PBKDF2 and not Argon2?**
PBKDF2 ships with the library already required for Fernet. Argon2id is the
better choice today and would need another dependency and a build step on some
platforms. The iteration count is in `constants.py` and gets stored per vault,
so it can be raised later without breaking old vaults.

**Why is there no password recovery without the recovery code?**
Because the alternative is a backdoor. Any design where the program can reset
your password without a secret is a design where somebody else can too.

**Why no auto-fill or browser integration?**
Those need a local server, a native messaging host, or a browser extension
with permission to read every page. Each of those expands the attack surface
by more than the convenience is worth for a project this size.

**Why so much prose in the code?**
The first version had comments like `# ENCRYPTION & DECRYPTION` and nothing
else. Six months later I could not tell you which function the menu was
supposed to call. The comments explain the reasoning, not the syntax, because
the syntax is the part Python already tells you.

**Why does the version 1 file have a typo?**
It was called `passowrd_manager.py` while the README said
`password_manager.py`. Nobody who followed the README ever ran it. The typo is
gone; the story stays in this README as a warning about testing your own
instructions.

## Upgrading from version 1

Version 1 wrote two files next to the script: `master.json` (a SHA-256 hash of
the master password) and `passwords.json` (the entries, in plain text despite
the README claiming they were encrypted). Neither is compatible with version 2.

There are two things you can do:

1. **Import the entries.** Menu 10, option 2 ("Import from the old version's
   passwords.json"), or:

   ```bash
   python password_manager.py import ./passwords.json
   ```

   It accepts the old list format `[{"site": ..., "username": ...,
   "password": ...}]` and anything else shaped like it.

2. **Delete the old files afterwards.** They are plain text. Shredding is
   unreliable on modern disks; at minimum delete them, and consider whether
   any password in them needs changing, because it sat unencrypted on a disk.

The old `master.json` is not imported, because a SHA-256 hash of a password is
not a key and the old vault was never actually encrypted with it anyway.

## Limitations

Worth repeating in a list of its own, because a README that only lists
strengths is marketing:

- Python cannot reliably erase strings from memory. The key is dropped when
  the vault locks, and that is the most a script can honestly promise.
- Attachments are capped at 2 MB each. There is no streaming and no
  compression.
- The entry list is loaded entirely into memory. Fine for thousands of entries,
  not for millions.
- No sync. Copying the folder to another machine works, but two machines
  editing the same vault will overwrite each other, last writer wins. The
  backups are your safety net.
- The duress feature is a decoy, not a panic button. It does not erase
  anything.
- The health report only knows the passwords in this vault. It cannot tell you
  that a password was breached last week, because checking that would mean
  asking the internet.
- CSV import handles the common layouts. Extremely exotic exports (nested
  JSON, KeePass XML) are not supported.
- No accessibility work has been done beyond plain text and colour being
  optional. If you use a screen reader and it is awkward, that is a bug worth
  filing.
- Windows support is real but least tested. The clipboard is write-only there,
  so the "restore what was there before" nicety does not happen.

## FAQ

**Is my vault uploaded anywhere?**
No. There is no network code. The only standard library module that even
mentions the network is `urllib.parse`, which is used to build and read
`otpauth://` strings; it cannot open a connection. Nothing imports `socket`,
`requests`, `http.client` or anything else that talks to a remote machine.

**What happens if I forget the master password?**
Use the recovery code from your emergency kit. That resets the master password
and re-encrypts everything. If you have lost both, the vault is closed for
good. There is no support line to call, which is also why nobody can be
pressured into opening it.

**Can I use the same vault on two computers?**
Yes, if you copy the folder and never edit it in both places at once. There is
no merge; the last save wins. Backup before you move the folder around.

**Why does the clipboard say "cleared" but still contain my password?**
The clear is best effort. It reads the clipboard back, and it only wipes when
the clipboard still contains what it put there. If another program keeps
re-setting the clipboard, or if there is no clipboard tool at all, nothing is
wiped. The message does not appear in that case, but do not rely on the
clipboard as a security boundary.

**Why is there an audit log, and can I clear it?**
It records actions so you can answer "was that me?" It never records
passwords. There is no menu option to clear it; editing `meta.json` is the
honest way, and it is your file.

**Does the duress password really look normal?**
Inside the decoy vault, everything looks ordinary, but it is empty unless you
populate it. Populate it. Add three boring accounts: a shopping site, an old
forum, a utility bill.

**Can I run this on a server?**
You can, but the interactive menus assume a terminal. The subcommands work
fine in scripts. Reading a password from `SECUREVAULT_PASSWORD` in a shared
environment is discouraged for the reasons printed on screen.

**Why 320,000 PBKDF2 iterations?**
It is a compromise between security and the two seconds you are willing to
wait. The OWASP recommendation moves over time; raise it in `constants.py` if
your machine is fast and your patience is not.

**Is the generated password really random?**
`secrets.choice` reads from the operating system's cryptographic random
source, the same one used for encryption keys. The generator also guarantees
one character from every requested group and shuffles afterwards, so there is
no "last three characters are always symbols" pattern.

**What is the version field at the bottom of a share code?**
`SVSHARE1.` marks the format version. If the format ever changes, old codes
will still be recognised by their prefix.

## Security policy

If you find a vulnerability, please open a GitHub issue with the word
SECURITY at the start, or contact the maintainer privately if the issue
template offers that. Do not publish exploit details before there has been a
chance to fix them.

Things that are known and accepted rather than vulnerabilities:

- An attacker who can run code as you can read the decrypted vault.
- An attacker who can edit `meta.json` can clear the attempt counter and the
  audit log, and can replace the recovery record with their own, which locks
  you out. Editing that file is not prevented, by design; it is your file.
- The duress decoy is detectable from the filesystem, as described above.
- Timing attacks against PBKDF2 and Fernet are out of scope; the relevant
  comparisons use constant time already.

## License

MIT. See `LICENSE`.

## Credits and thanks

- The Python documentation, especially `secrets`, `getpass` and `textwrap`.
- The `cryptography` project, for making correct encryption the easy option.
- RFC 6238 and RFC 4226, for the TOTP algorithm and its test vectors.
- Every password manager that came before, for showing which features people
  actually use and which ones they look at once and ignore.
- The person who pointed out that the README told you to run a file that did
  not exist. That was the start of this rewrite.

---

*Built with a terminal, a text editor, and an unreasonable number of
comments. If something here is wrong, the source is in the same folder and the
tests will tell you where to look.*
