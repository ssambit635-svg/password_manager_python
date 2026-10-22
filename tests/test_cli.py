"""
Tests for the command line front end.

These do not run a subprocess. They call cli.main() directly with a list of
arguments and capture the printed output, which is faster and gives better
failure messages when something is wrong.
"""

import io
import os
import json
import unittest
from contextlib import redirect_stdout, redirect_stderr

from tests.support import TempFolderTestCase

from securevault import cli, constants


def run_cli(arguments):
    """Call cli.main with captured output. Returns (exit_code, stdout)."""
    buffer = io.StringIO()
    error_buffer = io.StringIO()
    with redirect_stdout(buffer), redirect_stderr(error_buffer):
        try:
            code = cli.main(arguments)
        except SystemExit as exit_request:
            code = exit_request.code if isinstance(exit_request.code, int) else 1
    return code, buffer.getvalue()


class ParserTests(unittest.TestCase):

    def test_no_arguments_means_interactive(self):
        parser = cli.build_parser()
        arguments = parser.parse_args([])
        self.assertIsNone(arguments.command)

    def test_data_dir(self):
        parser = cli.build_parser()
        arguments = parser.parse_args(["--data-dir", "/tmp/example"])
        self.assertEqual(arguments.data_dir, "/tmp/example")

    def test_generate_defaults(self):
        parser = cli.build_parser()
        arguments = parser.parse_args(["generate"])
        self.assertEqual(arguments.command, "generate")
        self.assertEqual(arguments.count, 1)
        self.assertEqual(arguments.preset, constants.PRESET_BALANCED)

    def test_unknown_command_is_rejected(self):
        parser = cli.build_parser()
        with self.assertRaises(SystemExit):
            with redirect_stderr(io.StringIO()):
                parser.parse_args(["nonsense"])


class GenerateCommandTests(unittest.TestCase):

    def test_prints_one_password(self):
        code, output = run_cli(["generate", "--length", "24", "--no-color"])
        self.assertEqual(code, 0)
        self.assertEqual(len(output.strip().splitlines()), 1)
        self.assertEqual(len(output.strip()), 24)

    def test_json_output(self):
        code, output = run_cli(["generate", "--length", "16", "--json", "--no-color"])
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual(len(data["passwords"]), 1)
        self.assertEqual(len(data["passwords"][0]), 16)

    def test_count(self):
        code, output = run_cli(["generate", "--count", "5", "--no-color"])
        self.assertEqual(code, 0)
        self.assertEqual(len(output.strip().splitlines()), 5)

    def test_passphrase(self):
        code, output = run_cli([
            "generate", "--preset", "passphrase", "--words", "4", "--no-color"
        ])
        self.assertEqual(code, 0)
        self.assertEqual(len(output.strip().split("-")), 4)

    def test_pin(self):
        code, output = run_cli([
            "generate", "--preset", "pin", "--length", "6", "--no-color"
        ])
        self.assertEqual(code, 0)
        self.assertEqual(len(output.strip()), 6)
        self.assertTrue(output.strip().isdigit())


class CheckCommandTests(unittest.TestCase):

    def test_human_output(self):
        code, output = run_cli(["check", "--password", "password123", "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("Grade", output)
        self.assertIn("Time to crack", output)

    def test_json_output_has_no_password(self):
        code, output = run_cli(["check", "--password", "kR7#mQ2!xL9$", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertNotIn("password", data)
        self.assertIn("score", data)
        self.assertIn("grade", data)


class InfoCommandTests(TempFolderTestCase):

    def test_info_on_empty_folder(self):
        code, output = run_cli(["--data-dir", self.temp_folder, "info", "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn(self.temp_folder, output)
        self.assertIn("SecureVault", output)

    def test_info_after_setup(self):
        self.make_vault()
        code, output = run_cli(["--data-dir", self.temp_folder, "info", "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("Vault file:   present", output)
        self.assertIn("Recovery:     yes", output)

    def test_doctor_on_empty_folder(self):
        code, output = run_cli(["--data-dir", self.temp_folder, "doctor", "--no-color"])
        self.assertIn("DOCTOR", output)
        self.assertIn("Data folder", output)

    def test_version(self):
        code, output = run_cli(["--version"])
        self.assertEqual(code, 0)
        self.assertIn(constants.APP_VERSION, output)


class VaultCommandTests(TempFolderTestCase):

    def setUp(self):
        TempFolderTestCase.setUp(self)
        os.environ["SECUREVAULT_PASSWORD"] = "a good long master password"
        self.open_vault, self.meta, self.code = self.make_vault()
        self.open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$", tags=["work"])

    def tearDown(self):
        os.environ.pop("SECUREVAULT_PASSWORD", None)
        TempFolderTestCase.tearDown(self)

    def test_list(self):
        code, output = run_cli(["--data-dir", self.temp_folder, "list", "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("GitHub", output)
        self.assertNotIn("kR7#mQ2!xL9$", output)

    def test_list_json(self):
        code, output = run_cli([
            "--data-dir", self.temp_folder, "list", "--json"
        ])
        self.assertEqual(code, 0)
        # Skip the warning line about SECUREVAULT_PASSWORD, which also
        # starts with a bracket.
        data = json.loads(output[output.index("[\n"):])
        self.assertEqual(data[0]["site"], "GitHub")
        self.assertNotIn("password", data[0])

    def test_show(self):
        code, output = run_cli([
            "--data-dir", self.temp_folder, "show", "github", "--no-color"
        ])
        self.assertEqual(code, 0)
        self.assertIn("kR7#mQ2!xL9$", output)

    def test_show_username(self):
        code, output = run_cli([
            "--data-dir", self.temp_folder, "show", "github",
            "--field", "username", "--no-color"
        ])
        self.assertEqual(code, 0)
        self.assertIn("amit", output)

    def test_show_no_match(self):
        code, output = run_cli([
            "--data-dir", self.temp_folder, "show", "nothing-matches-this", "--no-color"
        ])
        self.assertEqual(code, 1)

    def test_wrong_password_is_reported(self):
        os.environ["SECUREVAULT_PASSWORD"] = "definitely the wrong password"
        code, output = run_cli(["--data-dir", self.temp_folder, "list", "--no-color"])
        self.assertEqual(code, 1)
        self.assertIn("Wrong master password", output)

    def test_export_and_import(self):
        target = os.path.join(self.temp_folder, "export.csv")
        code, output = run_cli([
            "--data-dir", self.temp_folder, "export", target,
            "--format", "csv", "--yes", "--no-color"
        ])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(target))

        code, output = run_cli([
            "--data-dir", self.temp_folder, "import", target,
            "--dry-run", "--no-color"
        ])
        self.assertEqual(code, 0)
        self.assertIn("would_add", output)


class EmptyFolderTests(TempFolderTestCase):

    def test_commands_without_a_vault_fail_cleanly(self):
        os.environ.pop("SECUREVAULT_PASSWORD", None)
        code, output = run_cli(["--data-dir", self.temp_folder, "list", "--no-color"])
        self.assertEqual(code, 1)
        self.assertIn("no vault", output.lower())


class ResetLockoutTests(TempFolderTestCase):

    def test_reset_lockout(self):
        self.make_vault()
        code, output = run_cli([
            "--data-dir", self.temp_folder, "reset-lockout", "--no-color"
        ])
        self.assertEqual(code, 0)
        self.assertIn("cleared", output.lower())
