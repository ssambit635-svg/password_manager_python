#!/usr/bin/env python3
"""
password_manager.py

This is the file you run. That is all it does.

    python password_manager.py                  start the program
    python password_manager.py --help           see every option
    python password_manager.py generate         make a password
    python password_manager.py doctor           check the installation

All of the actual work lives in the securevault package next to this file.
That was a deliberate change from the first version of this project, which
was one 500 line file where the encryption, the menus and the file handling
were all mixed together. Splitting it up means:

    * the security code can be read on its own (securevault/crypto.py)
    * the menus cannot accidentally break the encryption
    * there are real tests for each piece (see the tests folder)

If you are learning Python and want to read this project, the order I would
suggest is:

    1. securevault/constants.py  - small, no logic, shows the shape of things
    2. securevault/utils.py      - helpers, nothing dangerous
    3. securevault/crypto.py     - the important file, read it slowly
    4. securevault/storage.py    - how files get written safely
    5. securevault/vault.py      - how entries are stored
    6. securevault/ui.py         - only menus and printing

There is one more thing worth saying here. The old file in this repository
was called "passowrd_manager.py", with the letters in the wrong order, while
the README told people to run "password_manager.py". That is why the README
never worked for anybody who followed it exactly. The misspelled file has
been removed and this correctly spelled one replaces it.

Usage notes:

  * The vault lives in ~/.securevault by default.
  * Set SECUREVAULT_HOME to put it somewhere else.
  * Nothing in this program ever opens a network connection.
"""

import sys

# The package lives next to this file. If somebody runs the script from
# another folder, Python still has to be able to find it. Adding the script's
# own folder to sys.path is the standard way to handle that.
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from securevault.cli import main  # noqa: E402  (import after the path fix)


if __name__ == "__main__":
    try:
        exit_code = main(sys.argv[1:])
    except KeyboardInterrupt:
        # Ctrl-C anywhere that is not already handled. Exit quietly, with
        # the conventional code for "interrupted by a signal".
        print("")
        exit_code = 130

    sys.exit(exit_code)
