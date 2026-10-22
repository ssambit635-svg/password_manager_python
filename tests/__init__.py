"""
Tests for SecureVault.

Run them from the repository root with:

    python -m unittest discover -s tests -t .

or with pytest if you prefer:

    python -m pytest tests

The tests use only the standard library's unittest, so no extra dependency
is needed to check that the program works. The only third party dependency
in the whole project is the cryptography library, which the tests need too,
because they exercise the real encryption.
"""


# Make the repository root importable no matter where the test runner was
# started from. Doing it in the package __init__ means the individual test
# modules do not each need their own copy of this trick.
import os as _os
import sys as _sys

_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)
