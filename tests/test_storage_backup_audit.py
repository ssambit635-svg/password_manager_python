"""Tests for storage, backups, audit and the importer."""

import os
import json
import unittest

from tests.support import TempFolderTestCase

from securevault import storage, backup, audit, importers, constants
from securevault import vault as vault_module


class DataDirectoryTests(TempFolderTestCase):

    def test_ensure_exists_creates_folders(self):
        self.assertTrue(os.path.isdir(self.data_directory.path))
        self.assertTrue(os.path.isdir(self.data_directory.backup_dir))
        self.assertTrue(os.path.isdir(self.data_directory.attachments_dir))

    def test_gitignore_is_written(self):
        path = os.path.join(self.data_directory.path, ".gitignore")
        self.assertTrue(os.path.exists(path))
        with open(path, encoding="utf-8") as handle:
            self.assertIn("*", handle.read())

    def test_default_meta(self):
        meta = self.data_directory.default_meta()
        self.assertEqual(meta["schema"], constants.SCHEMA_VERSION)
        self.assertIn("settings", meta)
        self.assertEqual(meta["attempts"]["count"], 0)

    def test_meta_round_trip(self):
        meta = self.data_directory.default_meta()
        meta["settings"]["auto_lock_seconds"] = 120
        self.data_directory.write_meta(meta)
        reloaded = self.data_directory.read_meta()
        self.assertEqual(reloaded["settings"]["auto_lock_seconds"], 120)

    def test_meta_gets_missing_fields(self):
        partial = {"schema": 2, "settings": {"colour": True}}
        with open(self.data_directory.meta_path, "w", encoding="utf-8") as handle:
            json.dump(partial, handle)

        meta = self.data_directory.read_meta()
        self.assertIn("attempts", meta)
        self.assertIn("auto_lock_seconds", meta["settings"])
        self.assertEqual(meta["settings"]["colour"], True)

    def test_broken_meta_raises(self):
        with open(self.data_directory.meta_path, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        with self.assertRaises(storage.StorageError):
            self.data_directory.read_meta()

    def test_audit_log_is_capped(self):
        meta = self.data_directory.default_meta()
        for index in range(constants.MAX_AUDIT_LOG_ENTRIES + 20):
            self.data_directory.append_audit(meta, "event", str(index))
        self.assertEqual(len(meta["audit_log"]), constants.MAX_AUDIT_LOG_ENTRIES)

    def test_attachment_id_must_be_hex(self):
        with self.assertRaises(storage.StorageError):
            self.data_directory.read_attachment("../../meta")
        with self.assertRaises(storage.StorageError):
            self.data_directory.read_attachment("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")

    def test_backup_names_reject_paths(self):
        with self.assertRaises(storage.StorageError):
            self.data_directory.backup_path("../something")

    def test_human_bytes(self):
        self.assertEqual(storage.human_bytes(512), "512 bytes")
        self.assertEqual(storage.human_bytes(2048), "2.0 KB")
        self.assertEqual(storage.human_bytes(None), "unknown")

    def test_folder_is_writable(self):
        self.assertTrue(storage.folder_is_writable(self.temp_folder))


class DefaultLocationTests(unittest.TestCase):

    def test_environment_variable_is_used(self):
        old = os.environ.get(constants.DATA_DIR_ENV_VAR)
        try:
            os.environ[constants.DATA_DIR_ENV_VAR] = "/tmp/some-vault-place"
            directory = storage.DataDirectory()
            self.assertEqual(directory.path, "/tmp/some-vault-place")
        finally:
            if old is None:
                os.environ.pop(constants.DATA_DIR_ENV_VAR, None)
            else:
                os.environ[constants.DATA_DIR_ENV_VAR] = old

    def test_explicit_path_wins(self):
        directory = storage.DataDirectory("/tmp/explicit-place")
        self.assertEqual(directory.path, "/tmp/explicit-place")


class BackupTests(TempFolderTestCase):

    def setUp(self):
        TempFolderTestCase.setUp(self)
        self.open_vault, self.meta, self.code = self.make_vault()
        self.entry = self.open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        self.passphrase = "a backup passphrase with words"

    def test_make_and_verify(self):
        name, path = backup.make_backup(
            self.data_directory, self.open_vault, self.passphrase, "test note"
        )
        self.assertTrue(os.path.exists(path))
        self.assertTrue(name.endswith(".svbackup"))

        summary = backup.verify_backup(self.data_directory, name, self.passphrase)
        self.assertTrue(summary["ok"])
        self.assertEqual(summary["entry_count"], 1)
        self.assertEqual(summary["note"], "test note")

    def test_backup_is_encrypted(self):
        name, path = backup.make_backup(
            self.data_directory, self.open_vault, self.passphrase
        )
        with open(path, "r", encoding="utf-8") as handle:
            raw = handle.read()
        self.assertNotIn("GitHub", raw)
        self.assertNotIn("kR7#mQ2!xL9$", raw)

    def test_wrong_passphrase(self):
        name, path = backup.make_backup(
            self.data_directory, self.open_vault, self.passphrase
        )
        with self.assertRaises(backup.BackupError):
            backup.read_backup(self.data_directory, name, "the wrong passphrase")

    def test_short_passphrase_refused(self):
        with self.assertRaises(backup.BackupError):
            backup.make_backup(self.data_directory, self.open_vault, "short")

    def test_missing_backup(self):
        with self.assertRaises(backup.BackupError):
            backup.read_backup(self.data_directory, "nothing.svbackup", "whatever")

    def test_list_is_newest_first(self):
        for index in range(3):
            backup.make_backup(self.data_directory, self.open_vault, self.passphrase,
                               "note " + str(index))
        names = self.data_directory.list_backups()
        self.assertEqual(len(names), 3)
        self.assertEqual(names, sorted(names, reverse=True))

    def test_restore_merge(self):
        name, path = backup.make_backup(
            self.data_directory, self.open_vault, self.passphrase
        )
        self.open_vault.add_entry("Reddit", "amit", "another!1")
        payload = backup.read_backup(self.data_directory, name, self.passphrase)

        result = backup.restore_backup(self.open_vault, payload, replace=False)
        self.assertEqual(result["added"], 0)
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(self.open_vault.count(), 2)

    def test_restore_replace(self):
        name, path = backup.make_backup(
            self.data_directory, self.open_vault, self.passphrase
        )
        self.open_vault.add_entry("Reddit", "amit", "another!1")
        payload = backup.read_backup(self.data_directory, name, self.passphrase)

        backup.restore_backup(self.open_vault, payload, replace=True)
        self.assertEqual(self.open_vault.count(), 1)
        self.assertEqual(self.open_vault.entries[0]["site"], "GitHub")

    def test_prune(self):
        for index in range(12):
            backup.make_backup(self.data_directory, self.open_vault, self.passphrase)
        removed = backup.prune_old_backups(self.data_directory, 5)
        self.assertEqual(len(removed), 7)
        self.assertEqual(len(self.data_directory.list_backups()), 5)

    def test_stale_detection(self):
        self.assertTrue(backup.backup_is_stale(self.data_directory))
        backup.make_backup(self.data_directory, self.open_vault, self.passphrase)
        self.assertFalse(backup.backup_is_stale(self.data_directory))

    def test_emergency_kit_contains_the_code(self):
        path = backup.write_emergency_kit(
            self.data_directory, self.meta, self.code, "AABBCCDD"
        )
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn(self.code, text)
        self.assertIn("AABBCCDD", text)
        self.assertIn("RECOVERY CODE", text)

    def test_emergency_kit_has_no_passwords(self):
        path = backup.write_emergency_kit(
            self.data_directory, self.meta, self.code, "AABBCCDD"
        )
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        self.assertNotIn("kR7#mQ2!xL9$", text)


class AuditTests(TempFolderTestCase):

    def test_empty_vault(self):
        open_vault, meta, code = self.make_vault()
        self.assertEqual(audit.overall_score(open_vault), 0)
        self.assertIn("empty", audit.headline(open_vault).lower())

    def test_reused_passwords_found(self):
        open_vault, meta, code = self.make_vault()
        open_vault.add_entry("A", "x", "kR7#mQ2!xL9$")
        open_vault.add_entry("B", "y", "kR7#mQ2!xL9$")
        groups = audit.reused_password_groups(open_vault)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0]), 2)

    def test_common_passwords_found(self):
        open_vault, meta, code = self.make_vault()
        open_vault.add_entry("A", "x", "password123")
        open_vault.add_entry("B", "y", "kR7#mQ2!xL9$")
        self.assertEqual(len(audit.common_password_entries(open_vault)), 1)

    def test_weak_entries(self):
        open_vault, meta, code = self.make_vault()
        open_vault.add_entry("Weak", "x", "abc123")
        open_vault.add_entry("Strong", "y", "kR7#mQ2!xL9$vT4&zB8@p")
        weak = audit.weak_entries(open_vault)
        self.assertEqual(len(weak), 1)
        self.assertEqual(weak[0]["entry"]["site"], "Weak")

    def test_never_used(self):
        open_vault, meta, code = self.make_vault()
        one = open_vault.add_entry("Used", "x", "kR7#mQ2!xL9$")
        open_vault.add_entry("Not used", "y", "kR7#mQ2!xL9$")
        open_vault.mark_used(one["id"])
        self.assertEqual(len(audit.never_used_entries(open_vault)), 1)

    def test_full_report_structure(self):
        open_vault, meta, code = self.make_vault()
        open_vault.add_entry("A", "x", "kR7#mQ2!xL9$")
        report = audit.full_report(open_vault)
        for key in ("total_entries", "overall_score", "grade", "weak", "common",
                    "reused_groups", "old", "never_used", "analysed"):
            self.assertIn(key, report)
        self.assertEqual(report["total_entries"], 1)

    def test_recommendations_are_never_empty(self):
        open_vault, meta, code = self.make_vault()
        open_vault.add_entry("A", "x", "kR7#mQ2!xL9$vT4&zB8@p")
        report = audit.full_report(open_vault)
        self.assertTrue(audit.recommendations(report))

    def test_old_passwords(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("A", "x", "kR7#mQ2!xL9$")
        entry["password_changed_at"] = "2015-01-01T00:00:00+00:00"
        open_vault.save()
        self.assertEqual(len(audit.old_entries(open_vault)), 1)

    def test_doctor_finds_no_failures_on_a_healthy_vault(self):
        open_vault, meta, code = self.make_vault()
        meta["recovery"] = meta.get("recovery") or {"wrapped_key": "x"}
        findings = audit.doctor_report(self.data_directory, meta, open_vault)
        failures = [item for item in findings if item["level"] == "fail"]
        self.assertEqual(failures, [])

    def test_doctor_reports_missing_folder(self):
        missing = self.storage.DataDirectory(self.temp_folder + "-nope")
        findings = audit.doctor_report(missing, None, None)
        self.assertTrue(findings)


class ImporterTests(TempFolderTestCase):

    def write_file(self, name, text):
        path = os.path.join(self.temp_folder, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def test_detect_csv(self):
        path = self.write_file("a.csv", "name,url,username,password\nGitHub,x,amit,secret\n")
        self.assertEqual(importers.detect_format(path), "csv")

    def test_detect_legacy_json(self):
        path = self.write_file(
            "passwords.json",
            json.dumps([{"site": "GitHub", "username": "amit", "password": "x"}])
        )
        self.assertEqual(importers.detect_format(path), "legacy-json")

    def test_detect_unknown(self):
        path = self.write_file("a.txt", "just some words\n")
        self.assertEqual(importers.detect_format(path), "unknown")

    def test_column_detection_chrome_style(self):
        mapping = importers.detect_columns(["name", "url", "username", "password"])
        self.assertEqual(mapping["site"], 0)
        self.assertEqual(mapping["username"], 2)
        self.assertEqual(mapping["password"], 3)

    def test_column_detection_bitwarden_style(self):
        mapping = importers.detect_columns(
            ["folder", "favorite", "type", "name", "notes", "login_uri",
             "login_username", "login_password", "login_totp"]
        )
        self.assertEqual(mapping["site"], 3)
        self.assertEqual(mapping["username"], 6)
        self.assertEqual(mapping["password"], 7)
        self.assertEqual(mapping["totp"], 8)

    def test_preview_hides_passwords(self):
        path = self.write_file(
            "a.csv", "name,username,password\nGitHub,amit,supersecret\n"
        )
        preview = importers.preview_csv(path)
        flat = json.dumps(preview)
        self.assertNotIn("supersecret", flat)
        self.assertIn("(hidden)", flat)

    def test_import_csv(self):
        open_vault, meta, code = self.make_vault()
        path = self.write_file(
            "a.csv",
            "name,url,username,password,notes,tags\n"
            "GitHub,https://github.com,amit,secret1,a note,\"work,dev\"\n"
            "Reddit,,bob,secret2,,\n"
        )
        result = importers.import_from_file(open_vault, path)
        self.assertEqual(result["added"], 2)
        self.assertEqual(open_vault.count(), 2)

        github = [entry for entry in open_vault.entries if entry["site"] == "GitHub"][0]
        self.assertEqual(github["username"], "amit")
        self.assertEqual(sorted(github["tags"]), ["dev", "work"])

    def test_import_skips_blank_rows_and_missing_passwords(self):
        open_vault, meta, code = self.make_vault()
        path = self.write_file(
            "a.csv",
            "name,username,password\n"
            "Good,amit,secret1\n"
            "Bad,amit,\n"
            ",,,\n"
        )
        result = importers.import_from_file(open_vault, path)
        self.assertEqual(result["added"], 1)
        self.assertEqual(result["skipped"], 1)

    def test_import_requires_a_password_column(self):
        open_vault, meta, code = self.make_vault()
        path = self.write_file("a.csv", "name,username\nGitHub,amit\n")
        with self.assertRaises(importers.ImportError_):
            importers.import_from_file(open_vault, path)

    def test_import_legacy(self):
        open_vault, meta, code = self.make_vault()
        path = self.write_file(
            "passwords.json",
            json.dumps([
                {"site": "GitHub", "username": "amit", "password": "secret1"},
                {"site": "Reddit", "username": "bob", "password": "secret2"},
                {"site": "", "username": "nothing", "password": ""},
            ])
        )
        result = importers.import_from_file(open_vault, path)
        self.assertEqual(result["added"], 2)

    def test_export_csv_and_reimport(self):
        open_vault, meta, code = self.make_vault()
        open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$", notes="a, comma note")
        path = os.path.join(self.temp_folder, "export.csv")

        count = importers.export_csv(open_vault, path)
        self.assertEqual(count, 1)

        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("kR7#mQ2!xL9$", text)

        other_directory = self.storage.DataDirectory(self.temp_folder + "-import")
        other_directory.ensure_exists()
        from securevault import auth
        key, other_meta, _code = auth.setup_new_vault(
            other_directory, "a different master password"
        )
        other_vault = vault_module.Vault.create(other_directory, key, other_meta)
        result = importers.import_from_file(other_vault, path)
        self.assertEqual(result["added"], 1)
        self.assertEqual(other_vault.entries[0]["notes"], "a, comma note")

    def test_export_refuses_to_overwrite(self):
        open_vault, meta, code = self.make_vault()
        open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        path = self.write_file("existing.csv", "do not touch")
        with self.assertRaises(importers.ExportError):
            importers.export_csv(open_vault, path)

    def test_export_json_round_trip(self):
        open_vault, meta, code = self.make_vault()
        open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$", tags=["work"])
        path = os.path.join(self.temp_folder, "export.json")

        importers.export_json(open_vault, path)
        entries = importers.read_securevault_json(path)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["tags"], ["work"])

    def test_printable_list_has_no_passwords(self):
        open_vault, meta, code = self.make_vault()
        open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        path = os.path.join(self.temp_folder, "accounts.txt")
        importers.export_printable_notes(open_vault, path)

        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("GitHub", text)
        self.assertNotIn("kR7#mQ2!xL9$", text)

    def test_missing_file(self):
        with self.assertRaises(importers.ImportError_):
            importers.detect_format("/tmp/there-is-no-such-file-anywhere.txt")
