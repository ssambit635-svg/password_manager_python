"""
SecureVault - a little command line password manager that tries very hard.

This package is split into small files because the first version of this
project was one giant file and, honestly, it became impossible to find
anything in it. Every file does one job:

    constants.py   - numbers, file names and word lists that never change
    utils.py       - boring helpers (colours, prompts, formatting)
    crypto.py      - the part that actually keeps the secrets secret
    storage.py     - reading and writing files on the disk
    vault.py       - adding / editing / deleting the entries themselves
    generator.py   - making new passwords
    strength.py    - guessing how good (or bad) a password is
    totp.py        - the two factor authenticator codes
    audit.py       - the "how healthy is my vault" report
    importers.py   - CSV import and export
    backup.py      - encrypted backups and the emergency kit
    clipboard.py   - copy a password without it living there forever
    auth.py        - master password, duress password, recovery code
    session.py     - the open vault and the auto lock timer
    ui.py          - all of the menus
    cli.py         - the entry point and the command line arguments

If you only want to run the program, you do not need to read any of this.
Just run: python password_manager.py
"""

APP_NAME = "SecureVault"
APP_VERSION = "2.0.0"

# Bumped whenever the shape of the vault data changes. It lets an older
# install notice that the file on disk is newer than it understands.
SCHEMA_VERSION = 2

__version__ = APP_VERSION
