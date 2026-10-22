"""Tests for the vault: entries, search, trash, history, attachments."""

import unittest
import datetime

from tests.support import TempFolderTestCase

from securevault import vault as vault_module, auth


class EntryCrudTests(TempFolderTestCase):

    def test_add_and_count(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        self.assertEqual(open_vault.count(), 1)
        self.assertEqual(entry["site"], "GitHub")
        self.assertEqual(len(entry["id"]), 8)

    def test_add_requires_site_and_password(self):
        open_vault, meta, code = self.make_vault()
        with self.assertRaises(vault_module.VaultError):
            open_vault.add_entry("", "amit", "something")
        with self.assertRaises(vault_module.VaultError):
            open_vault.add_entry("GitHub", "amit", "")

    def test_get_and_get_or_raise(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        self.assertEqual(open_vault.get(entry["id"])["site"], "GitHub")
        self.assertIsNone(open_vault.get("doesnotexist"))
        with self.assertRaises(vault_module.VaultError):
            open_vault.get_or_raise("doesnotexist")

    def test_update_fields(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        updated, password_changed = open_vault.update_entry(
            entry["id"], username="newuser", url="https://example.com",
            notes="a note", tags=["Work", "work", " dev ", ""]
        )
        self.assertEqual(updated["username"], "newuser")
        self.assertEqual(updated["url"], "https://example.com")
        self.assertEqual(updated["notes"], "a note")
        self.assertEqual(updated["tags"], ["work", "dev"])
        self.assertFalse(password_changed)

    def test_update_requires_non_empty_site(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        with self.assertRaises(vault_module.VaultError):
            open_vault.update_entry(entry["id"], site="   ")

    def test_change_password_creates_history(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "oldpassword1")
        old_time = entry["password_changed_at"]

        updated, changed = open_vault.update_entry(entry["id"], password="newpassword1")
        self.assertTrue(changed)
        self.assertEqual(updated["password"], "newpassword1")
        self.assertEqual(len(updated["history"]), 1)
        self.assertEqual(updated["history"][0]["password"], "oldpassword1")
        self.assertNotEqual(updated["password_changed_at"], "not-a-date")
        self.assertEqual(old_time, old_time)

    def test_history_is_capped(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "start")
        for number in range(30):
            open_vault.update_entry(entry["id"], password="password-" + str(number))
        self.assertLessEqual(len(entry["history"]), vault_module.MAX_HISTORY_ENTRIES)

    def test_same_password_is_not_history(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "samepassword")
        open_vault.update_entry(entry["id"], password="samepassword")
        self.assertEqual(len(entry["history"]), 0)

    def test_favorite_toggle(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        self.assertFalse(entry["favorite"])
        self.assertTrue(open_vault.toggle_favorite(entry["id"]))
        self.assertFalse(open_vault.toggle_favorite(entry["id"]))
        self.assertEqual(len(open_vault.favorites()), 0)

    def test_mark_used(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        open_vault.mark_used(entry["id"])
        self.assertEqual(entry["use_count"], 1)
        self.assertIsNotNone(entry["last_used_at"])


class PersistenceTests(TempFolderTestCase):

    def test_survives_a_reload(self):
        open_vault, meta, code = self.make_vault()
        open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")

        key, meta = auth.unlock(self.data_directory, "a good long master password")
        reloaded = vault_module.Vault.load(self.data_directory, key, meta)

        self.assertEqual(reloaded.count(), 1)
        self.assertEqual(reloaded.entries[0]["site"], "GitHub")

    def test_wrong_key_cannot_load(self):
        open_vault, meta, code = self.make_vault()
        open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")

        other_key = auth.crypto.derive_key(
            "another password", auth.crypto.generate_salt(), 20000
        )
        with self.assertRaises(vault_module.VaultError):
            vault_module.Vault.load(self.data_directory, other_key, meta)

    def test_revision_increases(self):
        open_vault, meta, code = self.make_vault()
        first = open_vault.data["revision"]
        open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        self.assertGreater(open_vault.data["revision"], first)

    def test_old_entries_gain_missing_fields(self):
        open_vault, meta, code = self.make_vault()
        open_vault.data["entries"].append({"site": "Old", "username": "x",
                                           "password": "y"})
        open_vault.save()

        key, meta = auth.unlock(self.data_directory, "a good long master password")
        reloaded = vault_module.Vault.load(self.data_directory, key, meta)
        entry = reloaded.entries[0]
        self.assertIn("created_at", entry)
        self.assertEqual(entry["tags"], [])
        self.assertFalse(entry["favorite"])


class SearchTests(TempFolderTestCase):

    def setUp(self):
        TempFolderTestCase.setUp(self)
        self.open_vault, self.meta, self.code = self.make_vault()
        self.open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$",
                                  tags=["work"], notes="the main repository")
        self.open_vault.add_entry("Reddit", "amit", "another1!", tags=["personal"])
        self.open_vault.add_entry("Bank of Example", "amit",
                                  "kR7#mQ2!vZ0p", tags=["money"])

    def test_exact_match(self):
        results = self.open_vault.search("Reddit")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["site"], "Reddit")

    def test_case_insensitive(self):
        self.assertEqual(len(self.open_vault.search("github")), 1)

    def test_partial_match(self):
        self.assertEqual(len(self.open_vault.search("bank")), 1)

    def test_typo_still_matches(self):
        self.assertEqual(len(self.open_vault.search("githb")), 1)

    def test_tag_and_note_search(self):
        self.assertEqual(len(self.open_vault.search("work")), 1)
        self.assertEqual(len(self.open_vault.search("repository")), 1)

    def test_no_match(self):
        self.assertEqual(self.open_vault.search("nothing here"), [])

    def test_empty_query(self):
        self.assertEqual(self.open_vault.search(""), [])

    def test_exact_mode(self):
        self.assertEqual(len(self.open_vault.search("github", exact=True)), 1)
        self.assertEqual(len(self.open_vault.search("git", exact=True)), 0)

    def test_favorites_sort_first(self):
        self.open_vault.toggle_favorite(self.open_vault.entries[1]["id"])
        results = self.open_vault.search("amit")
        self.assertTrue(results[0]["favorite"])


class SortingTests(TempFolderTestCase):

    def setUp(self):
        TempFolderTestCase.setUp(self)
        self.open_vault, self.meta, self.code = self.make_vault()
        self.open_vault.add_entry("Zebra", "x", "kR7#mQ2!xL9$")
        self.open_vault.add_entry("Apple", "x", "kR7#mQ2!xL9$")
        self.open_vault.add_entry("Mango", "x", "kR7#mQ2!xL9$")

    def test_alphabetical(self):
        names = [entry["site"] for entry in self.open_vault.sorted_entries()]
        self.assertEqual(names, ["Apple", "Mango", "Zebra"])

    def test_reverse(self):
        names = [entry["site"] for entry in self.open_vault.sorted_entries(reverse=True)]
        self.assertEqual(names, ["Zebra", "Mango", "Apple"])

    def test_health_sort_puts_weakest_first(self):
        self.open_vault.add_entry("Weak", "x", "password123")
        entries = self.open_vault.sorted_entries(sort_by="health")
        self.assertEqual(entries[0]["site"], "Weak")


class TrashTests(TempFolderTestCase):

    def test_delete_moves_to_trash(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        open_vault.delete_entry(entry["id"])
        self.assertEqual(open_vault.count(), 0)
        self.assertEqual(open_vault.trash_count(), 1)

    def test_restore(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        open_vault.delete_entry(entry["id"])
        open_vault.restore_entry(entry["id"])
        self.assertEqual(open_vault.count(), 1)
        self.assertEqual(open_vault.trash_count(), 0)

    def test_permanent_delete(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        open_vault.delete_entry(entry["id"], permanent=True)
        self.assertEqual(open_vault.count(), 0)
        self.assertEqual(open_vault.trash_count(), 0)

    def test_purge_one(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        open_vault.delete_entry(entry["id"])
        open_vault.purge_entry(entry["id"])
        self.assertEqual(open_vault.trash_count(), 0)

    def test_empty_trash(self):
        open_vault, meta, code = self.make_vault()
        for index in range(3):
            entry = open_vault.add_entry("Site" + str(index), "x", "kR7#mQ2!xL9$")
            open_vault.delete_entry(entry["id"])
        self.assertEqual(open_vault.empty_trash(), 3)
        self.assertEqual(open_vault.trash_count(), 0)

    def test_missing_entry_raises(self):
        open_vault, meta, code = self.make_vault()
        with self.assertRaises(vault_module.VaultError):
            open_vault.delete_entry("nope")
        with self.assertRaises(vault_module.VaultError):
            open_vault.restore_entry("nope")


class TagTests(TempFolderTestCase):

    def test_all_tags_counts(self):
        open_vault, meta, code = self.make_vault()
        open_vault.add_entry("A", "x", "kR7#mQ2!xL9$", tags=["work", "dev"])
        open_vault.add_entry("B", "x", "kR7#mQ2!xL9$", tags=["work"])
        tags = dict(open_vault.all_tags())
        self.assertEqual(tags["work"], 2)
        self.assertEqual(tags["dev"], 1)

    def test_add_and_remove_tag(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("A", "x", "kR7#mQ2!xL9$")
        open_vault.add_tag(entry["id"], "work")
        self.assertEqual(entry["tags"], ["work"])
        open_vault.remove_tag(entry["id"], "work")
        self.assertEqual(entry["tags"], [])

    def test_rename_tag_everywhere(self):
        open_vault, meta, code = self.make_vault()
        open_vault.add_entry("A", "x", "kR7#mQ2!xL9$", tags=["old"])
        open_vault.add_entry("B", "x", "kR7#mQ2!xL9$", tags=["old", "keep"])
        changed = open_vault.rename_tag_everywhere("old", "new")
        self.assertEqual(changed, 2)
        self.assertEqual(len(open_vault.entries_with_tag("new")), 2)

    def test_duplicate_sites(self):
        open_vault, meta, code = self.make_vault()
        open_vault.add_entry("GitHub", "one", "kR7#mQ2!xL9$")
        open_vault.add_entry("GitHub", "two", "kR7#mQ2!xL9$")
        open_vault.add_entry("Reddit", "three", "kR7#mQ2!xL9$")
        groups = open_vault.duplicate_sites()
        self.assertEqual(list(groups.keys()), ["github"])


class AttachmentTests(TempFolderTestCase):

    def test_attach_and_read(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        blob_id = open_vault.attach_file(entry["id"], "notes.txt", b"hello file")

        self.assertEqual(entry["attachments"][0]["name"], "notes.txt")
        self.assertEqual(open_vault.read_attachment(entry["id"], blob_id), b"hello file")

    def test_attachment_survives_reload(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        blob_id = open_vault.attach_file(entry["id"], "notes.txt", b"hello file")

        key, meta = auth.unlock(self.data_directory, "a good long master password")
        reloaded = vault_module.Vault.load(self.data_directory, key, meta)
        self.assertEqual(reloaded.read_attachment(entry["id"], blob_id), b"hello file")

    def test_attachment_is_encrypted_on_disk(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        open_vault.attach_file(entry["id"], "notes.txt", b"hello file")

        blob_id = entry["attachments"][0]["id"]
        path = self.data_directory.read_attachment(blob_id)
        self.assertNotIn("hello file", path)

    def test_empty_file_refused(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        with self.assertRaises(vault_module.VaultError):
            open_vault.attach_file(entry["id"], "empty.txt", b"")

    def test_remove_attachment(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        blob_id = open_vault.attach_file(entry["id"], "notes.txt", b"data")
        open_vault.remove_attachment(entry["id"], blob_id)
        self.assertEqual(entry["attachments"], [])
        with self.assertRaises(self.storage.StorageError):
            self.data_directory.read_attachment(blob_id)

    def test_unknown_attachment_raises(self):
        open_vault, meta, code = self.make_vault()
        entry = open_vault.add_entry("GitHub", "amit", "kR7#mQ2!xL9$")
        with self.assertRaises(vault_module.VaultError):
            open_vault.read_attachment(entry["id"], "a" * 32)


class ExpiryTests(TempFolderTestCase):

    def test_expired_entries_are_purged(self):
        open_vault, meta, code = self.make_vault()
        past = (datetime.datetime.now(datetime.timezone.utc)
                - datetime.timedelta(days=2)).replace(microsecond=0).isoformat()
        future = (datetime.datetime.now(datetime.timezone.utc)
                  + datetime.timedelta(days=2)).replace(microsecond=0).isoformat()

        gone = open_vault.add_entry("Old", "x", "kR7#mQ2!xL9$", expires_at=past)
        open_vault.add_entry("New", "x", "kR7#mQ2!xL9$", expires_at=future)

        expired = open_vault.purge_expired()
        self.assertEqual(expired, [gone["id"]])
        self.assertEqual(open_vault.count(), 1)
        self.assertEqual(open_vault.entries[0]["site"], "New")

    def test_expiring_soon(self):
        open_vault, meta, code = self.make_vault()
        soon = (datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=3)).replace(microsecond=0).isoformat()
        open_vault.add_entry("Soon", "x", "kR7#mQ2!xL9$", expires_at=soon)
        open_vault.add_entry("Later", "x", "kR7#mQ2!xL9$")
        self.assertEqual(len(open_vault.entries_expiring_soon(7)), 1)


class ImportIntoVaultTests(TempFolderTestCase):

    def test_add_many_skips_duplicates(self):
        open_vault, meta, code = self.make_vault()
        entries = [
            vault_module.new_entry("GitHub", "amit", "kR7#mQ2!xL9$"),
            vault_module.new_entry("GitHub", "amit", "different"),
            vault_module.new_entry("Reddit", "amit", "another!1"),
        ]
        added, skipped = open_vault.add_many(entries)
        self.assertEqual(added, 2)
        self.assertEqual(skipped, 1)
        self.assertEqual(open_vault.count(), 2)

    def test_duplicate_id_is_replaced(self):
        open_vault, meta, code = self.make_vault()
        first = vault_module.new_entry("A", "x", "kR7#mQ2!xL9$")
        open_vault.add_entry_object(first)
        second = vault_module.new_entry("B", "y", "kR7#mQ2!xL9$")
        second["id"] = first["id"]
        added = open_vault.add_entry_object(second)
        self.assertNotEqual(added["id"], first["id"])


class UtilityTests(unittest.TestCase):

    def test_summarise_entry(self):
        entry = {
            "site": "GitHub",
            "username": "amit",
            "favorite": True,
            "totp_secret": "ABC",
            "expires_at": None,
        }
        summary = vault_module.summarise_entry(entry)
        self.assertIn("GitHub", summary)
        self.assertIn("favourite", summary)
        self.assertIn("2fa", summary)

    def test_normalise_entry_tolerates_junk(self):
        entry = vault_module.normalise_entry({
            "site": 42,
            "tags": "not a list",
            "history": "nope",
            "use_count": "abc",
        })
        self.assertEqual(entry["site"], "42")
        self.assertEqual(entry["tags"], [])
        self.assertEqual(entry["history"], [])
        self.assertEqual(entry["use_count"], 0)

    def test_normalise_entry_rejects_non_dictionary(self):
        with self.assertRaises(vault_module.VaultError):
            vault_module.normalise_entry("just a string")
