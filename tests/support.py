"""
Shared helpers for the tests.

Every test gets its own temporary folder, so one test can never see another
test's vault. That is the single most important thing about a test suite
that deals with files: isolation.
"""

import os
import sys
import shutil
import tempfile
import unittest

# Make sure the package can be imported when the tests are run from the
# repository root with `python -m unittest discover -s tests`.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


class TempFolderTestCase(unittest.TestCase):
    """A test case with a fresh temporary folder and a DataDirectory."""

    def setUp(self):
        from securevault import storage

        self.temp_folder = tempfile.mkdtemp(prefix="securevault-test-")
        self.data_directory = storage.DataDirectory(self.temp_folder)
        self.data_directory.ensure_exists()
        self.storage = storage

    def tearDown(self):
        shutil.rmtree(self.temp_folder, ignore_errors=True)

    # -- helpers -------------------------------------------------------

    def make_vault(self, master_password="a good long master password",
                   entries=None):
        """
        Create a vault and return (vault, meta, recovery_code).

        The default master password is long enough to pass validation and
        is used by most tests.
        """
        from securevault import auth, vault

        key, meta, recovery_code = auth.setup_new_vault(
            self.data_directory, master_password
        )
        open_vault = vault.Vault.create(self.data_directory, key, meta)

        for entry in (entries or []):
            open_vault.add_entry(**entry)

        return open_vault, meta, recovery_code
