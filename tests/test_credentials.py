"""Tests for sesame.credentials."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sesame.credentials import (
    CRED_FILE,
    EXPORT_MAGIC,
    CredentialStore,
    _decrypt,
    _derive_key,
    _derive_key_from_passphrase,
    _encrypt,
)


def _make_fake_ssh_key(tmp_dir: str) -> Path:
    """Create a fake SSH key file for testing."""
    key_path = Path(tmp_dir) / "fake_id_rsa"
    key_path.write_bytes(b"fake-ssh-private-key-content-for-testing")
    return key_path


class TestEncryptDecrypt(unittest.TestCase):
    """Tests for low-level _encrypt / _decrypt."""

    def test_roundtrip(self):
        key = os.urandom(32)
        plaintext = b"hello world, this is a test"
        encrypted = _encrypt(plaintext, key)
        decrypted = _decrypt(encrypted, key)
        self.assertEqual(decrypted, plaintext)

    def test_roundtrip_empty(self):
        key = os.urandom(32)
        plaintext = b""
        encrypted = _encrypt(plaintext, key)
        decrypted = _decrypt(encrypted, key)
        self.assertEqual(decrypted, plaintext)

    def test_roundtrip_large(self):
        key = os.urandom(32)
        plaintext = os.urandom(10000)
        encrypted = _encrypt(plaintext, key)
        decrypted = _decrypt(encrypted, key)
        self.assertEqual(decrypted, plaintext)

    def test_different_iv_each_time(self):
        key = os.urandom(32)
        plaintext = b"same content"
        enc1 = _encrypt(plaintext, key)
        enc2 = _encrypt(plaintext, key)
        self.assertNotEqual(enc1, enc2)  # different IVs
        self.assertEqual(_decrypt(enc1, key), _decrypt(enc2, key))

    def test_wrong_key_fails(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        encrypted = _encrypt(b"secret", key1)
        with self.assertRaises(ValueError):
            _decrypt(encrypted, key2)

    def test_tampered_data_fails(self):
        key = os.urandom(32)
        encrypted = _encrypt(b"secret", key)
        tampered = bytearray(encrypted)
        tampered[20] ^= 0xFF
        with self.assertRaises(ValueError):
            _decrypt(bytes(tampered), key)

    def test_truncated_data_fails(self):
        key = os.urandom(32)
        with self.assertRaises(ValueError):
            _decrypt(b"short", key)


class TestDeriveKey(unittest.TestCase):
    """Tests for key derivation functions."""

    def test_derive_key_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_path = _make_fake_ssh_key(tmp)
            k1 = _derive_key(key_path)
            k2 = _derive_key(key_path)
            self.assertEqual(k1, k2)
            self.assertEqual(len(k1), 32)

    def test_derive_key_different_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            p1 = Path(tmp) / "key1"
            p2 = Path(tmp) / "key2"
            p1.write_bytes(b"key-content-one")
            p2.write_bytes(b"key-content-two")
            self.assertNotEqual(_derive_key(p1), _derive_key(p2))

    def test_derive_key_from_passphrase_deterministic(self):
        salt = b"test-salt-value-32-bytes-long!?!"
        k1 = _derive_key_from_passphrase("mypassphrase", salt)
        k2 = _derive_key_from_passphrase("mypassphrase", salt)
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 32)

    def test_derive_key_from_passphrase_different_salt(self):
        k1 = _derive_key_from_passphrase("same", b"salt1" * 6)
        k2 = _derive_key_from_passphrase("same", b"salt2" * 6)
        self.assertNotEqual(k1, k2)

    def test_derive_key_from_passphrase_different_passphrase(self):
        salt = b"fixed-salt-for-this-test-xxxxxx!"
        k1 = _derive_key_from_passphrase("pass1", salt)
        k2 = _derive_key_from_passphrase("pass2", salt)
        self.assertNotEqual(k1, k2)


class TestCredentialStore(unittest.TestCase):
    """Tests for CredentialStore CRUD operations."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.key_path = _make_fake_ssh_key(self.tmp_dir)
        # Patch CRED_FILE and CONFIG_DIR to use temp directory
        self.cred_file = Path(self.tmp_dir) / "credentials.enc"
        self.patcher_cred = mock.patch(
            "sesame.credentials.CRED_FILE", self.cred_file
        )
        self.patcher_dir = mock.patch(
            "sesame.credentials.CONFIG_DIR", Path(self.tmp_dir)
        )
        self.patcher_cred.start()
        self.patcher_dir.start()

    def tearDown(self):
        self.patcher_cred.stop()
        self.patcher_dir.stop()
        import shutil
        shutil.rmtree(self.tmp_dir)

    def _store(self) -> CredentialStore:
        return CredentialStore(ssh_key_path=self.key_path)

    def test_empty_store(self):
        store = self._store()
        self.assertEqual(store.list_all(), [])
        self.assertIsNone(store.lookup("user", "host"))

    def test_save_and_lookup(self):
        store = self._store()
        store.save("admin", "192.168.1.10", "password1")
        self.assertEqual(store.lookup("admin", "192.168.1.10"), "password1")

    def test_save_multiple(self):
        store = self._store()
        store.save("admin", "host1", "pw1")
        store.save("root", "host2", "pw2")
        self.assertEqual(store.list_all(), ["admin@host1", "root@host2"])

    def test_save_overwrite(self):
        store = self._store()
        store.save("admin", "host", "old")
        store.save("admin", "host", "new")
        self.assertEqual(store.lookup("admin", "host"), "new")

    def test_save_by_key(self):
        store = self._store()
        store.save_by_key("admin@host", "password")
        self.assertEqual(store.lookup_by_key("admin@host"), "password")

    def test_save_many(self):
        store = self._store()
        store.save_many({"a@h1": "p1", "b@h2": "p2"})
        self.assertEqual(store.list_all(), ["a@h1", "b@h2"])
        self.assertEqual(store.lookup_by_key("a@h1"), "p1")

    def test_save_many_empty(self):
        store = self._store()
        store.save_many({})
        self.assertEqual(store.list_all(), [])

    def test_remove(self):
        store = self._store()
        store.save("admin", "host", "pw")
        self.assertTrue(store.remove("admin", "host"))
        self.assertIsNone(store.lookup("admin", "host"))
        self.assertEqual(store.list_all(), [])

    def test_remove_nonexistent(self):
        store = self._store()
        self.assertFalse(store.remove("admin", "host"))

    def test_remove_by_key(self):
        store = self._store()
        store.save_by_key("admin@host", "pw")
        self.assertTrue(store.remove_by_key("admin@host"))
        self.assertEqual(store.list_all(), [])

    def test_remove_by_key_nonexistent(self):
        store = self._store()
        self.assertFalse(store.remove_by_key("admin@host"))

    def test_clear_all(self):
        store = self._store()
        store.save("a", "h1", "p1")
        store.save("b", "h2", "p2")
        store.clear_all()
        self.assertEqual(store.list_all(), [])

    def test_clear_all_no_file(self):
        store = self._store()
        store.clear_all()  # should not raise

    def test_persistence_across_instances(self):
        s1 = self._store()
        s1.save("admin", "host", "pw")
        s2 = self._store()
        self.assertEqual(s2.lookup("admin", "host"), "pw")

    def test_wrong_key_returns_empty(self):
        """If SSH key changes, store returns empty (can't decrypt)."""
        s1 = self._store()
        s1.save("admin", "host", "pw")
        other_key = Path(self.tmp_dir) / "other_key"
        other_key.write_bytes(b"different-key-content")
        s2 = CredentialStore(ssh_key_path=other_key)
        self.assertEqual(s2.list_all(), [])


class TestCredentialStoreExportImport(unittest.TestCase):
    """Tests for export/import functionality."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.key_path = _make_fake_ssh_key(self.tmp_dir)
        self.cred_file = Path(self.tmp_dir) / "credentials.enc"
        self.export_file = Path(self.tmp_dir) / "export.enc"
        self.patcher_cred = mock.patch(
            "sesame.credentials.CRED_FILE", self.cred_file
        )
        self.patcher_dir = mock.patch(
            "sesame.credentials.CONFIG_DIR", Path(self.tmp_dir)
        )
        self.patcher_cred.start()
        self.patcher_dir.start()

    def tearDown(self):
        self.patcher_cred.stop()
        self.patcher_dir.stop()
        import shutil
        shutil.rmtree(self.tmp_dir)

    def _store(self) -> CredentialStore:
        return CredentialStore(ssh_key_path=self.key_path)

    def test_export_empty_store(self):
        store = self._store()
        count = store.export_to_file(self.export_file, "passphrase")
        self.assertEqual(count, 0)
        self.assertFalse(self.export_file.exists())

    def test_export_creates_file(self):
        store = self._store()
        store.save("admin", "host", "pw")
        count = store.export_to_file(self.export_file, "passphrase")
        self.assertEqual(count, 1)
        self.assertTrue(self.export_file.exists())

    def test_export_file_has_magic(self):
        store = self._store()
        store.save("admin", "host", "pw")
        store.export_to_file(self.export_file, "passphrase")
        data = self.export_file.read_bytes()
        self.assertTrue(data.startswith(EXPORT_MAGIC))

    def test_export_import_roundtrip(self):
        store = self._store()
        store.save("admin", "host1", "pw1")
        store.save("root", "host2", "pw2")
        store.export_to_file(self.export_file, "mypass")

        store.clear_all()
        self.assertEqual(store.list_all(), [])

        imported, skipped = store.import_from_file(self.export_file, "mypass")
        self.assertEqual(imported, 2)
        self.assertEqual(skipped, 0)
        self.assertEqual(store.lookup("admin", "host1"), "pw1")
        self.assertEqual(store.lookup("root", "host2"), "pw2")

    def test_import_skip_existing(self):
        store = self._store()
        store.save("admin", "host", "original")
        store.export_to_file(self.export_file, "pass")

        # Modify local
        store.save("admin", "host", "modified")

        imported, skipped = store.import_from_file(
            self.export_file, "pass", overwrite=False
        )
        self.assertEqual(imported, 0)
        self.assertEqual(skipped, 1)
        self.assertEqual(store.lookup("admin", "host"), "modified")

    def test_import_overwrite_existing(self):
        store = self._store()
        store.save("admin", "host", "original")
        store.export_to_file(self.export_file, "pass")

        store.save("admin", "host", "modified")

        imported, skipped = store.import_from_file(
            self.export_file, "pass", overwrite=True
        )
        self.assertEqual(imported, 1)
        self.assertEqual(skipped, 0)
        self.assertEqual(store.lookup("admin", "host"), "original")

    def test_import_merge_new_and_existing(self):
        store = self._store()
        store.save("admin", "host1", "pw1")
        store.save("root", "host2", "pw2")
        store.export_to_file(self.export_file, "pass")

        store.clear_all()
        store.save("admin", "host1", "local_pw")

        imported, skipped = store.import_from_file(
            self.export_file, "pass", overwrite=False
        )
        self.assertEqual(imported, 1)  # root@host2
        self.assertEqual(skipped, 1)  # admin@host1
        self.assertEqual(store.lookup("admin", "host1"), "local_pw")
        self.assertEqual(store.lookup("root", "host2"), "pw2")

    def test_import_wrong_passphrase(self):
        store = self._store()
        store.save("admin", "host", "pw")
        store.export_to_file(self.export_file, "correct")
        with self.assertRaises(ValueError) as ctx:
            store.import_from_file(self.export_file, "wrong")
        self.assertIn("wrong passphrase", str(ctx.exception).lower())

    def test_import_invalid_file(self):
        bad_file = Path(self.tmp_dir) / "bad.enc"
        bad_file.write_bytes(b"not a valid export file")
        store = self._store()
        with self.assertRaises(ValueError) as ctx:
            store.import_from_file(bad_file, "pass")
        self.assertIn("magic", str(ctx.exception).lower())

    def test_import_truncated_file(self):
        trunc_file = Path(self.tmp_dir) / "trunc.enc"
        trunc_file.write_bytes(EXPORT_MAGIC + b"short")
        store = self._store()
        with self.assertRaises(ValueError):
            store.import_from_file(trunc_file, "pass")

    def test_export_different_ssh_key_can_still_import(self):
        """Export is SSH-key-independent (passphrase-based)."""
        store1 = self._store()
        store1.save("admin", "host", "pw")
        store1.export_to_file(self.export_file, "shared_pass")

        other_key = Path(self.tmp_dir) / "other_key"
        other_key.write_bytes(b"completely-different-key")
        # New cred file for second store
        cred2 = Path(self.tmp_dir) / "credentials2.enc"
        with mock.patch("sesame.credentials.CRED_FILE", cred2):
            store2 = CredentialStore(ssh_key_path=other_key)
            imported, skipped = store2.import_from_file(
                self.export_file, "shared_pass"
            )
            self.assertEqual(imported, 1)
            self.assertEqual(store2.lookup("admin", "host"), "pw")


if __name__ == "__main__":
    unittest.main()
