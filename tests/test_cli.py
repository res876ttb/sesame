"""Tests for sesame.cli."""

from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sesame.cli import (
    _extract_target_hosts,
    _handle_management,
    _load_aliases,
    _resolve_alias,
    _resolve_ssh_user,
    _save_aliases,
    ssm_main,
)
from sesame.credentials import CredentialStore


class TestHandleManagement(unittest.TestCase):
    """Tests for _handle_management() in cli.py."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.key_path = Path(self.tmp_dir) / "fake_key"
        self.key_path.write_bytes(b"fake-key-for-test")
        self.cred_file = Path(self.tmp_dir) / "credentials.enc"
        self.patcher_cred = mock.patch(
            "sesame.credentials.CRED_FILE", self.cred_file
        )
        self.patcher_dir = mock.patch(
            "sesame.credentials.CONFIG_DIR", Path(self.tmp_dir)
        )
        self.patcher_find = mock.patch(
            "sesame.credentials._find_ssh_key", return_value=self.key_path
        )
        self.patcher_cred.start()
        self.patcher_dir.start()
        self.patcher_find.start()

    def tearDown(self):
        self.patcher_cred.stop()
        self.patcher_dir.stop()
        self.patcher_find.stop()
        import shutil
        shutil.rmtree(self.tmp_dir)

    def test_help(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            result = _handle_management(["--help"])
        self.assertTrue(result)
        self.assertIn("SSH wrapper", out.getvalue())

    def test_help_short(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            result = _handle_management(["-h"])
        self.assertTrue(result)

    def test_version(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            result = _handle_management(["--version"])
        self.assertTrue(result)
        self.assertIn("0.1.0", out.getvalue())

    def test_list_empty(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            result = _handle_management(["--list"])
        self.assertTrue(result)
        self.assertIn("No stored credentials", out.getvalue())

    def test_list_with_entries(self):
        store = CredentialStore()
        store.save("admin", "host", "pw")
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            result = _handle_management(["--list"])
        self.assertTrue(result)
        self.assertIn("admin@host", out.getvalue())

    def test_forget(self):
        store = CredentialStore()
        store.save("admin", "host", "pw")
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            result = _handle_management(["--forget", "admin@host"])
        self.assertTrue(result)
        self.assertIn("Removed", out.getvalue())
        self.assertEqual(store.list_all(), [])

    def test_forget_nonexistent(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            result = _handle_management(["--forget", "nobody@nowhere"])
        self.assertTrue(result)
        self.assertIn("Not found", out.getvalue())

    def test_forget_no_argument(self):
        """--forget without USER@HOST should error out."""
        with self.assertRaises(SystemExit):
            _handle_management(["--forget"])

    def test_forget_all(self):
        store = CredentialStore()
        store.save("a", "h1", "p1")
        store.save("b", "h2", "p2")
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            result = _handle_management(["--forget-all"])
        self.assertTrue(result)
        self.assertIn("All credentials and aliases removed", out.getvalue())
        self.assertEqual(CredentialStore().list_all(), [])

    def test_export_and_import(self):
        store = CredentialStore()
        store.save("admin", "host", "secret")
        export_path = Path(self.tmp_dir) / "test_export.enc"

        with mock.patch("getpass.getpass", side_effect=["mypass", "mypass"]):
            with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
                result = _handle_management(["--export", str(export_path)])
        self.assertTrue(result)
        self.assertIn("Exported 1", out.getvalue())
        self.assertTrue(export_path.exists())

        store.clear_all()

        with mock.patch("getpass.getpass", return_value="mypass"):
            with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
                result = _handle_management(["--import", str(export_path)])
        self.assertTrue(result)
        self.assertIn("Imported 1", out.getvalue())
        self.assertEqual(CredentialStore().lookup("admin", "host"), "secret")

    def test_import_with_overwrite(self):
        store = CredentialStore()
        store.save("admin", "host", "original")
        export_path = Path(self.tmp_dir) / "test_export.enc"

        with mock.patch("getpass.getpass", side_effect=["pass", "pass"]):
            _handle_management(["--export", str(export_path)])

        store.save("admin", "host", "modified")

        with mock.patch("getpass.getpass", return_value="pass"):
            with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
                result = _handle_management(
                    ["--import", "--overwrite", str(export_path)]
                )
        self.assertTrue(result)
        self.assertIn("Imported 1", out.getvalue())
        self.assertEqual(CredentialStore().lookup("admin", "host"), "original")

    def test_export_empty_store(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            result = _handle_management(
                ["--export", str(Path(self.tmp_dir) / "out.enc")]
            )
        self.assertTrue(result)
        self.assertIn("No credentials to export", out.getvalue())

    def test_empty_args_not_handled(self):
        self.assertFalse(_handle_management([]))

    def test_unknown_flag_not_handled(self):
        self.assertFalse(_handle_management(["--unknown"]))


class TestResolveSshUser(unittest.TestCase):
    """Tests for _resolve_ssh_user()."""

    @mock.patch("sesame.cli.subprocess.run")
    def test_reads_user_from_ssh_config(self, mock_run):
        """ssh -G output should be parsed for the User line."""
        mock_run.return_value = mock.Mock(
            returncode=0,
            stdout="user admin\nhostname 10.0.0.1\nport 22\n",
        )
        self.assertEqual(_resolve_ssh_user("myserver"), "admin")
        mock_run.assert_called_once_with(
            ["ssh", "-G", "myserver"],
            capture_output=True, text=True, timeout=5,
        )

    @mock.patch("sesame.cli.subprocess.run")
    def test_falls_back_to_current_user(self, mock_run):
        """If ssh -G fails, fall back to getpass.getuser()."""
        mock_run.side_effect = FileNotFoundError
        with mock.patch("sesame.cli.getpass.getuser", return_value="me"):
            self.assertEqual(_resolve_ssh_user("host"), "me")

    @mock.patch("sesame.cli.subprocess.run")
    def test_handles_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="ssh", timeout=5)
        with mock.patch("sesame.cli.getpass.getuser", return_value="me"):
            self.assertEqual(_resolve_ssh_user("host"), "me")


@mock.patch("sesame.cli._resolve_ssh_user", return_value="me")
class TestExtractTargetHosts(unittest.TestCase):
    """Tests for _extract_target_hosts()."""

    def test_ssh_user_at_host(self, _):
        self.assertEqual(
            _extract_target_hosts(["user@host"], "ssh"),
            ["user@host"],
        )

    def test_ssh_bare_host(self, _):
        """Host without user@ should resolve via ssh -G / fallback."""
        self.assertEqual(
            _extract_target_hosts(["192.168.1.92"], "ssh"),
            ["me@192.168.1.92"],
        )

    def test_ssh_with_jump(self, _):
        self.assertEqual(
            _extract_target_hosts(["-J", "jump", "target"], "ssh"),
            ["me@jump", "me@target"],
        )

    def test_ssh_jump_user_at(self, _):
        self.assertEqual(
            _extract_target_hosts(["-J", "admin@jump", "root@target"], "ssh"),
            ["admin@jump", "root@target"],
        )

    def test_ssh_multi_jump(self, _):
        self.assertEqual(
            _extract_target_hosts(
                ["-J", "a@j1,b@j2", "c@target"], "ssh"
            ),
            ["a@j1", "b@j2", "c@target"],
        )

    def test_ssh_with_options(self, _):
        """Options like -p should be skipped."""
        self.assertEqual(
            _extract_target_hosts(["-p", "2222", "admin@host"], "ssh"),
            ["admin@host"],
        )

    def test_scp_remote_path(self, _):
        self.assertEqual(
            _extract_target_hosts(
                ["local.txt", "admin@host:/tmp/"], "scp"
            ),
            ["admin@host"],
        )

    def test_rsync_remote_path(self, _):
        self.assertEqual(
            _extract_target_hosts(
                ["-avz", "dir/", "admin@host:/remote/"], "rsync"
            ),
            ["admin@host"],
        )

    def test_deduplicates(self, _):
        """Same host appearing twice should be deduplicated."""
        self.assertEqual(
            _extract_target_hosts(
                ["-J", "admin@host", "admin@host"], "ssh"
            ),
            ["admin@host"],
        )

    def test_proxy_jump_option(self, _):
        self.assertEqual(
            _extract_target_hosts(
                ["-o", "ProxyJump=admin@jump", "root@target"], "ssh"
            ),
            ["admin@jump", "root@target"],
        )

    def test_explicit_l_option(self, _resolve):
        """-l user should override ssh -G resolution."""
        self.assertEqual(
            _extract_target_hosts(["-l", "admin", "myhost"], "ssh"),
            ["admin@myhost"],
        )
        # _resolve_ssh_user should NOT have been called for this host
        _resolve.assert_not_called()


class _SfMainTestBase(unittest.TestCase):
    """Common setUp/tearDown for tests that invoke ssm_main()."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.key_path = Path(self.tmp_dir) / "fake_key"
        self.key_path.write_bytes(b"fake-key-for-test")
        self.cred_file = Path(self.tmp_dir) / "credentials.enc"
        self.patcher_cred = mock.patch(
            "sesame.credentials.CRED_FILE", self.cred_file
        )
        self.patcher_dir = mock.patch(
            "sesame.credentials.CONFIG_DIR", Path(self.tmp_dir)
        )
        self.patcher_find = mock.patch(
            "sesame.credentials._find_ssh_key", return_value=self.key_path
        )
        self.patcher_cred.start()
        self.patcher_dir.start()
        self.patcher_find.start()

    def tearDown(self):
        self.patcher_cred.stop()
        self.patcher_dir.stop()
        self.patcher_find.stop()
        import shutil
        shutil.rmtree(self.tmp_dir)


class TestStrictHostKeyChecking(_SfMainTestBase):
    """Tests that sf injects StrictHostKeyChecking=accept-new."""

    @mock.patch("sesame.cli.getpass.getpass", return_value="testpw")
    @mock.patch("sesame.cli.run_command", return_value=0)
    def test_ssh_injects_strict_host_key(self, mock_run, _gp):
        """sf user@host should inject -o StrictHostKeyChecking=accept-new."""
        with mock.patch("sys.argv", ["sf", "user@host"]):
            with self.assertRaises(SystemExit):
                ssm_main()
        cmd = mock_run.call_args[0][0]
        self.assertIn("-o", cmd)
        idx = cmd.index("-o")
        self.assertEqual(cmd[idx + 1], "StrictHostKeyChecking=accept-new")

    @mock.patch("sesame.cli.getpass.getpass", return_value="testpw")
    @mock.patch("sesame.cli.run_command", return_value=0)
    def test_ssh_respects_user_strict(self, mock_run, _gp):
        """If user sets StrictHostKeyChecking, sf should not override."""
        with mock.patch(
            "sys.argv",
            ["sf", "-o", "StrictHostKeyChecking=ask", "user@host"],
        ):
            with self.assertRaises(SystemExit):
                ssm_main()
        cmd = mock_run.call_args[0][0]
        strict_values = [
            cmd[i + 1]
            for i, a in enumerate(cmd)
            if a == "-o" and i + 1 < len(cmd) and "StrictHostKeyChecking" in cmd[i + 1]
        ]
        self.assertEqual(strict_values, ["StrictHostKeyChecking=ask"])

    @mock.patch("sesame.cli.getpass.getpass", return_value="testpw")
    @mock.patch("sesame.cli.run_command", return_value=0)
    def test_scp_injects_strict_host_key(self, mock_run, _gp):
        """sf cp should inject -o StrictHostKeyChecking=accept-new."""
        with mock.patch(
            "sys.argv", ["sf", "cp", "local.txt", "user@host:/tmp/"]
        ):
            with self.assertRaises(SystemExit):
                ssm_main()
        cmd = mock_run.call_args[0][0]
        self.assertIn("-o", cmd)
        idx = cmd.index("-o")
        self.assertEqual(cmd[idx + 1], "StrictHostKeyChecking=accept-new")

    @mock.patch("sesame.cli.getpass.getpass", return_value="testpw")
    @mock.patch("sesame.cli.run_command", return_value=0)
    def test_rsync_injects_strict_via_e(self, mock_run, _gp):
        """sf sync should inject StrictHostKeyChecking via -e ssh option."""
        with mock.patch(
            "sys.argv",
            ["sf", "sync", "-avz", "local/", "user@host:/remote/"],
        ):
            with self.assertRaises(SystemExit):
                ssm_main()
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[0], "rsync")
        self.assertIn("-e", cmd)
        idx = cmd.index("-e")
        self.assertIn("StrictHostKeyChecking=accept-new", cmd[idx + 1])


@mock.patch("sesame.cli._resolve_ssh_user", return_value="me")
class TestPrePrompting(_SfMainTestBase):
    """Tests for pre-prompting missing credentials in the parent process."""

    @mock.patch("sesame.cli.getpass.getpass", return_value="prompted_pw")
    @mock.patch("sesame.cli.run_command", return_value=0)
    def test_prompts_for_missing_credential(self, mock_run, mock_gp, _res):
        """sf host (no stored pw) should prompt before launching SSH."""
        with mock.patch("sys.argv", ["sf", "192.168.1.92"]):
            with self.assertRaises(SystemExit):
                ssm_main()
        mock_gp.assert_called_once_with("me@192.168.1.92's password: ")
        creds = mock_run.call_args[1].get("credentials", {})
        self.assertEqual(creds.get("me@192.168.1.92"), "prompted_pw")

    @mock.patch("sesame.cli.getpass.getpass", return_value="prompted_pw")
    @mock.patch("sesame.cli.run_command", return_value=0)
    def test_saves_prompted_credential_on_success(self, mock_run, mock_gp, _res):
        """Prompted password should be saved to store after exit_code==0."""
        with mock.patch("sys.argv", ["sf", "192.168.1.92"]):
            with self.assertRaises(SystemExit):
                ssm_main()
        store = CredentialStore()
        self.assertEqual(store.lookup_by_key("me@192.168.1.92"), "prompted_pw")

    @mock.patch("sesame.cli.getpass.getpass", return_value="wrongpw")
    @mock.patch("sesame.cli.run_command", return_value=255)
    def test_does_not_save_on_failure(self, mock_run, mock_gp, _res):
        """Prompted password should NOT be saved if SSH fails."""
        with mock.patch("sys.argv", ["sf", "192.168.1.92"]):
            with self.assertRaises(SystemExit):
                ssm_main()
        store = CredentialStore()
        self.assertIsNone(store.lookup_by_key("me@192.168.1.92"))

    @mock.patch("sesame.cli.run_command", return_value=0)
    def test_no_prompt_when_credential_stored(self, mock_run, _res):
        """If a credential already exists, no prompt should appear."""
        store = CredentialStore()
        store.save("admin", "host", "saved_pw")
        with mock.patch("sesame.cli.getpass.getpass") as mock_gp:
            with mock.patch("sys.argv", ["sf", "admin@host"]):
                with self.assertRaises(SystemExit):
                    ssm_main()
        mock_gp.assert_not_called()

    @mock.patch("sesame.cli.run_command", return_value=0)
    def test_no_prompt_when_password_on_cmdline(self, mock_run, _res):
        """sf user:password@host should not trigger a prompt."""
        with mock.patch("sesame.cli.getpass.getpass") as mock_gp:
            with mock.patch("sys.argv", ["sf", "admin:secret@host"]):
                with self.assertRaises(SystemExit):
                    ssm_main()
        mock_gp.assert_not_called()

    @mock.patch("sesame.cli.getpass.getpass", return_value="")
    @mock.patch("sesame.cli.run_command", return_value=0)
    def test_empty_prompt_skips_credential(self, mock_run, mock_gp, _res):
        """If user enters empty password at prompt, don't save or pass it."""
        with mock.patch("sys.argv", ["sf", "192.168.1.92"]):
            with self.assertRaises(SystemExit):
                ssm_main()
        creds = mock_run.call_args[1].get("credentials", {})
        self.assertNotIn("me@192.168.1.92", creds)


class TestAliasStorage(unittest.TestCase):
    """Tests for alias load/save/resolve functions."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.aliases_file = Path(self.tmp_dir) / "aliases.json"
        self.patcher_aliases = mock.patch(
            "sesame.cli.ALIASES_FILE", self.aliases_file
        )
        self.patcher_dir = mock.patch(
            "sesame.cli.CONFIG_DIR", Path(self.tmp_dir)
        )
        self.patcher_aliases.start()
        self.patcher_dir.start()

    def tearDown(self):
        self.patcher_aliases.stop()
        self.patcher_dir.stop()
        import shutil
        shutil.rmtree(self.tmp_dir)

    def test_load_empty(self):
        """Loading when no file exists returns empty dict."""
        self.assertEqual(_load_aliases(), {})

    def test_save_and_load(self):
        """Saved aliases can be loaded back."""
        data = {"myserver": {"target": "admin@1.2.3.4", "args": []}}
        _save_aliases(data)
        self.assertEqual(_load_aliases(), data)

    def test_save_overwrites(self):
        """Saving replaces the entire alias file."""
        _save_aliases({"a": {"target": "h1", "args": []}})
        _save_aliases({"b": {"target": "h2", "args": []}})
        aliases = _load_aliases()
        self.assertNotIn("a", aliases)
        self.assertIn("b", aliases)

    def test_resolve_simple(self):
        """Resolve should return args + target."""
        _save_aliases({"srv": {"target": "admin@10.0.0.1", "args": []}})
        result = _resolve_alias("srv")
        self.assertEqual(result, ["admin@10.0.0.1"])

    def test_resolve_with_args(self):
        """Resolve should prepend stored args before target."""
        _save_aliases({
            "prod": {
                "target": "admin@10.0.0.5",
                "args": ["-J", "jump@gw", "-p", "2222"],
            }
        })
        result = _resolve_alias("prod")
        self.assertEqual(result, ["-J", "jump@gw", "-p", "2222", "admin@10.0.0.5"])

    def test_resolve_unknown(self):
        """Resolving an unknown alias returns None."""
        self.assertIsNone(_resolve_alias("nonexistent"))

    def test_resolve_no_target(self):
        """Alias with empty target should return just args."""
        _save_aliases({"x": {"target": "", "args": ["cp", "a", "b"]}})
        result = _resolve_alias("x")
        self.assertEqual(result, ["cp", "a", "b"])

    def test_load_corrupted_file(self):
        """Corrupted JSON should return empty dict."""
        self.aliases_file.write_text("not json{{{", encoding="utf-8")
        self.assertEqual(_load_aliases(), {})

    def test_file_permissions(self):
        """Alias file should be created with 0600 permissions."""
        _save_aliases({"test": {"target": "h", "args": []}})
        mode = self.aliases_file.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)


class TestAliasManagement(unittest.TestCase):
    """Tests for alias integration with --list, --forget, --forget-all."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.key_path = Path(self.tmp_dir) / "fake_key"
        self.key_path.write_bytes(b"fake-key-for-test")
        self.cred_file = Path(self.tmp_dir) / "credentials.enc"
        self.aliases_file = Path(self.tmp_dir) / "aliases.json"
        self.patcher_cred = mock.patch(
            "sesame.credentials.CRED_FILE", self.cred_file
        )
        self.patcher_dir = mock.patch(
            "sesame.credentials.CONFIG_DIR", Path(self.tmp_dir)
        )
        self.patcher_find = mock.patch(
            "sesame.credentials._find_ssh_key", return_value=self.key_path
        )
        self.patcher_aliases = mock.patch(
            "sesame.cli.ALIASES_FILE", self.aliases_file
        )
        self.patcher_cli_dir = mock.patch(
            "sesame.cli.CONFIG_DIR", Path(self.tmp_dir)
        )
        self.patcher_cred.start()
        self.patcher_dir.start()
        self.patcher_find.start()
        self.patcher_aliases.start()
        self.patcher_cli_dir.start()

    def tearDown(self):
        self.patcher_cred.stop()
        self.patcher_dir.stop()
        self.patcher_find.stop()
        self.patcher_aliases.stop()
        self.patcher_cli_dir.stop()
        import shutil
        shutil.rmtree(self.tmp_dir)

    def test_list_shows_aliases(self):
        """--list should display both credentials and aliases."""
        store = CredentialStore()
        store.save("admin", "host", "pw")
        _save_aliases({"myalias": {"target": "admin@host", "args": []}})
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            _handle_management(["--list"])
        output = out.getvalue()
        self.assertIn("admin@host", output)
        self.assertIn("myalias", output)
        self.assertIn("Aliases:", output)
        self.assertIn("Credentials:", output)

    def test_list_no_entries(self):
        """--list with no credentials or aliases shows appropriate message."""
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            _handle_management(["--list"])
        self.assertIn("No stored credentials or aliases", out.getvalue())

    def test_list_aliases_only(self):
        """--list with only aliases (no creds) should show aliases section."""
        _save_aliases({"srv": {"target": "h", "args": []}})
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            _handle_management(["--list"])
        output = out.getvalue()
        self.assertIn("Aliases:", output)
        self.assertIn("srv", output)

    def test_forget_alias(self):
        """--forget should remove an alias by name."""
        _save_aliases({"myalias": {"target": "h", "args": []}})
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            _handle_management(["--forget", "myalias"])
        self.assertIn("Removed alias", out.getvalue())
        self.assertEqual(_load_aliases(), {})

    def test_forget_multiple(self):
        """--forget should accept multiple targets."""
        store = CredentialStore()
        store.save("admin", "h1", "p1")
        store.save("admin", "h2", "p2")
        _save_aliases({"srv": {"target": "h3", "args": []}})
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            _handle_management(["--forget", "admin@h1", "admin@h2", "srv"])
        output = out.getvalue()
        self.assertIn("Removed credential: admin@h1", output)
        self.assertIn("Removed credential: admin@h2", output)
        self.assertIn("Removed alias: srv", output)
        self.assertEqual(store.list_all(), [])
        self.assertEqual(_load_aliases(), {})

    def test_forget_multiple_partial_miss(self):
        """--forget with mix of existing and missing targets."""
        store = CredentialStore()
        store.save("admin", "h1", "p1")
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            _handle_management(["--forget", "admin@h1", "nonexistent"])
        output = out.getvalue()
        self.assertIn("Removed credential: admin@h1", output)
        self.assertIn("Not found: nonexistent", output)

    def test_forget_credential_and_alias_same_name(self):
        """--forget should remove both credential and alias if name matches."""
        store = CredentialStore()
        store.save_by_key("myname", "pw")
        _save_aliases({"myname": {"target": "h", "args": []}})
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            _handle_management(["--forget", "myname"])
        output = out.getvalue()
        self.assertIn("Removed credential", output)
        self.assertIn("Removed alias", output)

    def test_forget_all_clears_aliases(self):
        """--forget-all should remove all aliases too."""
        _save_aliases({"a": {"target": "h1", "args": []}, "b": {"target": "h2", "args": []}})
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            _handle_management(["--forget-all"])
        self.assertIn("All credentials and aliases removed", out.getvalue())
        self.assertEqual(_load_aliases(), {})


class TestAliasInSfMain(_SfMainTestBase):
    """Tests for alias creation and resolution in ssm_main()."""

    def setUp(self):
        super().setUp()
        self.aliases_file = Path(self.tmp_dir) / "aliases.json"
        self.patcher_aliases = mock.patch(
            "sesame.cli.ALIASES_FILE", self.aliases_file
        )
        self.patcher_cli_dir = mock.patch(
            "sesame.cli.CONFIG_DIR", Path(self.tmp_dir)
        )
        self.patcher_aliases.start()
        self.patcher_cli_dir.start()

    def tearDown(self):
        self.patcher_aliases.stop()
        self.patcher_cli_dir.stop()
        super().tearDown()

    @mock.patch("sesame.cli._resolve_ssh_user", return_value="me")
    @mock.patch("sesame.cli.getpass.getpass", return_value="pw")
    @mock.patch("sesame.cli.run_command", return_value=0)
    def test_name_flag_saves_alias(self, mock_run, _gp, _res):
        """sf host --name myalias should save an alias after connecting."""
        with mock.patch("sys.argv", ["sf", "admin@1.2.3.4", "--name", "myalias"]):
            with self.assertRaises(SystemExit):
                ssm_main()
        aliases = _load_aliases()
        self.assertIn("myalias", aliases)
        self.assertEqual(aliases["myalias"]["target"], "admin@1.2.3.4")

    @mock.patch("sesame.cli._resolve_ssh_user", return_value="me")
    @mock.patch("sesame.cli.getpass.getpass", return_value="pw")
    @mock.patch("sesame.cli.run_command", return_value=0)
    def test_name_flag_with_options(self, mock_run, _gp, _res):
        """sf -p 2222 host --name myalias should store the -p option."""
        with mock.patch("sys.argv", ["sf", "-p", "2222", "admin@host", "--name", "srv"]):
            with self.assertRaises(SystemExit):
                ssm_main()
        aliases = _load_aliases()
        self.assertIn("srv", aliases)
        self.assertIn("-p", aliases["srv"]["args"])
        self.assertIn("2222", aliases["srv"]["args"])

    @mock.patch("sesame.cli._resolve_ssh_user", return_value="me")
    @mock.patch("sesame.cli.getpass.getpass", return_value="pw")
    @mock.patch("sesame.cli.run_command", return_value=0)
    def test_alias_resolves_on_connect(self, mock_run, _gp, _res):
        """sf myalias should expand to the stored target and connect."""
        _save_aliases({"myalias": {"target": "admin@1.2.3.4", "args": ["-p", "2222"]}})
        # Pre-store credential so no prompt needed
        store = CredentialStore()
        store.save("admin", "1.2.3.4", "saved_pw")
        with mock.patch("sys.argv", ["sf", "myalias"]):
            with self.assertRaises(SystemExit):
                ssm_main()
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[0], "ssh")
        self.assertIn("-p", cmd)
        self.assertIn("2222", cmd)
        self.assertIn("admin@1.2.3.4", cmd)

    @mock.patch("sesame.cli._resolve_ssh_user", return_value="me")
    @mock.patch("sesame.cli.getpass.getpass", return_value="pw")
    @mock.patch("sesame.cli.run_command", return_value=0)
    def test_alias_with_jump_host(self, mock_run, _gp, _res):
        """Alias with jump host args should expand correctly."""
        _save_aliases({
            "prod": {
                "target": "admin@10.0.0.5",
                "args": ["-J", "jump@gw"],
            }
        })
        store = CredentialStore()
        store.save("admin", "10.0.0.5", "pw1")
        store.save("jump", "gw", "pw2")
        with mock.patch("sys.argv", ["sf", "prod"]):
            with self.assertRaises(SystemExit):
                ssm_main()
        cmd = mock_run.call_args[0][0]
        self.assertIn("-J", cmd)
        self.assertIn("jump@gw", cmd)
        self.assertIn("admin@10.0.0.5", cmd)

    @mock.patch("sesame.cli._resolve_ssh_user", return_value="me")
    @mock.patch("sesame.cli.getpass.getpass", return_value="pw")
    @mock.patch("sesame.cli.run_command", return_value=0)
    def test_name_stripped_from_ssh_command(self, mock_run, _gp, _res):
        """--name and its value should not appear in the SSH command."""
        with mock.patch("sys.argv", ["sf", "admin@host", "--name", "foo"]):
            with self.assertRaises(SystemExit):
                ssm_main()
        cmd = mock_run.call_args[0][0]
        self.assertNotIn("--name", cmd)
        self.assertNotIn("foo", cmd)

    @mock.patch("sesame.cli._resolve_ssh_user", return_value="me")
    @mock.patch("sesame.cli.getpass.getpass", return_value="pw")
    @mock.patch("sesame.cli.run_command", return_value=255)
    def test_name_saved_even_on_failure(self, mock_run, _gp, _res):
        """Alias should be saved even if SSH connection fails."""
        with mock.patch("sys.argv", ["sf", "admin@host", "--name", "fail_alias"]):
            with self.assertRaises(SystemExit):
                ssm_main()
        aliases = _load_aliases()
        self.assertIn("fail_alias", aliases)

    @mock.patch("sesame.cli._resolve_ssh_user", return_value="me")
    @mock.patch("sesame.cli.getpass.getpass", return_value="pw")
    @mock.patch("sesame.cli.run_command", return_value=0)
    def test_subcommand_not_treated_as_alias(self, mock_run, _gp, _res):
        """Known subcommands (cp, ftp, sync) should not be resolved as aliases."""
        _save_aliases({"cp": {"target": "admin@host", "args": []}})
        with mock.patch("sys.argv", ["sf", "cp", "local.txt", "admin@host:/tmp/"]):
            with self.assertRaises(SystemExit):
                ssm_main()
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[0], "scp")


if __name__ == "__main__":
    unittest.main()
