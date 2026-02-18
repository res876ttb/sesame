"""Tests for sesame.parser."""

from __future__ import annotations

import unittest

from sesame.parser import (
    ParseResult,
    _parse_credential_full,
    _parse_jump_hosts,
    parse_args,
    parse_askpass_prompt,
)


class TestParseCredentialFull(unittest.TestCase):
    """Tests for _parse_credential_full()."""

    def test_basic_user_password_host(self):
        cleaned, creds = _parse_credential_full("admin:secret@192.168.1.10")
        self.assertEqual(cleaned, "admin@192.168.1.10")
        self.assertEqual(creds, {"admin@192.168.1.10": "secret"})

    def test_no_password(self):
        cleaned, creds = _parse_credential_full("admin@192.168.1.10")
        self.assertEqual(cleaned, "admin@192.168.1.10")
        self.assertEqual(creds, {})

    def test_no_at_sign(self):
        cleaned, creds = _parse_credential_full("localhost")
        self.assertEqual(cleaned, "localhost")
        self.assertEqual(creds, {})

    def test_password_with_at_sign(self):
        """Password contains @: split on LAST @."""
        cleaned, creds = _parse_credential_full("admin:p@ss@myhost")
        self.assertEqual(cleaned, "admin@myhost")
        self.assertEqual(creds, {"admin@myhost": "p@ss"})

    def test_password_with_colon(self):
        """Password contains :: split on FIRST :."""
        cleaned, creds = _parse_credential_full("admin:my:pass:word@myhost")
        self.assertEqual(cleaned, "admin@myhost")
        self.assertEqual(creds, {"admin@myhost": "my:pass:word"})

    def test_password_with_at_and_colon(self):
        cleaned, creds = _parse_credential_full("admin:p@ss:w0rd@myhost")
        self.assertEqual(cleaned, "admin@myhost")
        self.assertEqual(creds, {"admin@myhost": "p@ss:w0rd"})

    def test_empty_user(self):
        cleaned, creds = _parse_credential_full(":password@host")
        self.assertEqual(cleaned, ":password@host")
        self.assertEqual(creds, {})

    def test_empty_password(self):
        cleaned, creds = _parse_credential_full("admin:@host")
        self.assertEqual(cleaned, "admin:@host")
        self.assertEqual(creds, {})

    def test_empty_host(self):
        cleaned, creds = _parse_credential_full("admin:pw@")
        self.assertEqual(cleaned, "admin:pw@")
        self.assertEqual(creds, {})

    def test_scp_path_mode(self):
        """With allow_path=True, host:/path is preserved."""
        cleaned, creds = _parse_credential_full(
            "admin:pw@host:/remote/file", allow_path=True
        )
        self.assertEqual(cleaned, "admin@host:/remote/file")
        self.assertEqual(creds, {"admin@host": "pw"})

    def test_scp_path_no_password(self):
        cleaned, creds = _parse_credential_full(
            "admin@host:/remote/file", allow_path=True
        )
        self.assertEqual(cleaned, "admin@host:/remote/file")
        self.assertEqual(creds, {})

    def test_scp_local_path(self):
        """Local path without @ should pass through."""
        cleaned, creds = _parse_credential_full("./local/file", allow_path=True)
        self.assertEqual(cleaned, "./local/file")
        self.assertEqual(creds, {})


class TestParseJumpHosts(unittest.TestCase):
    """Tests for _parse_jump_hosts()."""

    def test_single_jump_host(self):
        cleaned, creds = _parse_jump_hosts("admin:pw@jump.example.com")
        self.assertEqual(cleaned, "admin@jump.example.com")
        self.assertEqual(creds, {"admin@jump.example.com": "pw"})

    def test_multiple_jump_hosts(self):
        cleaned, creds = _parse_jump_hosts("u1:pw1@j1,u2:pw2@j2")
        self.assertEqual(cleaned, "u1@j1,u2@j2")
        self.assertEqual(creds, {"u1@j1": "pw1", "u2@j2": "pw2"})

    def test_mixed_jump_hosts(self):
        """One with password, one without."""
        cleaned, creds = _parse_jump_hosts("u1:pw1@j1,u2@j2")
        self.assertEqual(cleaned, "u1@j1,u2@j2")
        self.assertEqual(creds, {"u1@j1": "pw1"})

    def test_no_password_jump_host(self):
        cleaned, creds = _parse_jump_hosts("admin@jump")
        self.assertEqual(cleaned, "admin@jump")
        self.assertEqual(creds, {})

    def test_three_jump_hosts(self):
        cleaned, creds = _parse_jump_hosts("a:p1@h1,b:p2@h2,c:p3@h3")
        self.assertEqual(cleaned, "a@h1,b@h2,c@h3")
        self.assertEqual(len(creds), 3)


class TestParseArgs(unittest.TestCase):
    """Tests for parse_args()."""

    # --- SSH mode ---

    def test_ssh_basic(self):
        r = parse_args(["admin:myP@ssw0rd@192.168.1.10"], mode="ssh")
        self.assertEqual(r.cleaned_args, ["admin@192.168.1.10"])
        self.assertEqual(r.credentials, {"admin@192.168.1.10": "myP@ssw0rd"})

    def test_ssh_no_password(self):
        r = parse_args(["admin@192.168.1.10"], mode="ssh")
        self.assertEqual(r.cleaned_args, ["admin@192.168.1.10"])
        self.assertEqual(r.credentials, {})

    def test_ssh_with_port(self):
        r = parse_args(["-p", "2222", "admin:pw@host"], mode="ssh")
        self.assertEqual(r.cleaned_args, ["-p", "2222", "admin@host"])
        self.assertEqual(r.credentials, {"admin@host": "pw"})

    def test_ssh_with_flags(self):
        r = parse_args(["-v", "-N", "admin:pw@host"], mode="ssh")
        self.assertEqual(r.cleaned_args, ["-v", "-N", "admin@host"])
        self.assertEqual(r.credentials, {"admin@host": "pw"})

    def test_ssh_with_remote_command(self):
        r = parse_args(["admin:pw@host", "ls", "-la", "/tmp"], mode="ssh")
        self.assertEqual(r.cleaned_args, ["admin@host", "ls", "-la", "/tmp"])
        self.assertEqual(r.credentials, {"admin@host": "pw"})

    def test_ssh_jump_host_separate(self):
        """'-J user:pw@jump target' form."""
        r = parse_args(
            ["-J", "admin:jumpPW@jump.com", "root:targetPW@10.0.0.5"], mode="ssh"
        )
        self.assertEqual(r.cleaned_args, ["-J", "admin@jump.com", "root@10.0.0.5"])
        self.assertEqual(
            r.credentials,
            {"admin@jump.com": "jumpPW", "root@10.0.0.5": "targetPW"},
        )

    def test_ssh_jump_host_attached(self):
        """'-Juser:pw@jump' form (no space)."""
        r = parse_args(["-Jadmin:pw@jump", "root@target"], mode="ssh")
        self.assertEqual(r.cleaned_args, ["-Jadmin@jump", "root@target"])
        self.assertEqual(r.credentials, {"admin@jump": "pw"})

    def test_ssh_multi_jump(self):
        r = parse_args(
            ["-J", "u1:pw1@j1,u2:pw2@j2", "admin:pw3@target"], mode="ssh"
        )
        self.assertEqual(r.cleaned_args, ["-J", "u1@j1,u2@j2", "admin@target"])
        self.assertEqual(len(r.credentials), 3)

    def test_ssh_proxy_jump_option(self):
        """-o ProxyJump= form."""
        r = parse_args(
            ["-o", "ProxyJump=admin:pw@jump", "root:pw2@target"], mode="ssh"
        )
        self.assertEqual(
            r.cleaned_args, ["-o", "ProxyJump=admin@jump", "root@target"]
        )
        self.assertEqual(
            r.credentials, {"admin@jump": "pw", "root@target": "pw2"}
        )

    def test_ssh_proxy_jump_combined(self):
        """-oProxyJump= form."""
        r = parse_args(["-oProxyJump=admin:pw@jump", "root@target"], mode="ssh")
        self.assertEqual(
            r.cleaned_args, ["-oProxyJump=admin@jump", "root@target"]
        )
        self.assertEqual(r.credentials, {"admin@jump": "pw"})

    def test_ssh_identity_file_preserved(self):
        r = parse_args(["-i", "~/.ssh/mykey", "admin:pw@host"], mode="ssh")
        self.assertEqual(r.cleaned_args, ["-i", "~/.ssh/mykey", "admin@host"])
        self.assertEqual(r.credentials, {"admin@host": "pw"})

    # --- SCP mode ---

    def test_scp_download(self):
        r = parse_args(
            ["admin:pw@host:/remote/file", "./local/"], mode="scp"
        )
        self.assertEqual(r.cleaned_args, ["admin@host:/remote/file", "./local/"])
        self.assertEqual(r.credentials, {"admin@host": "pw"})

    def test_scp_upload(self):
        r = parse_args(
            ["./local/file", "admin:pw@host:/remote/"], mode="scp"
        )
        self.assertEqual(r.cleaned_args, ["./local/file", "admin@host:/remote/"])
        self.assertEqual(r.credentials, {"admin@host": "pw"})

    def test_scp_no_password(self):
        r = parse_args(["admin@host:/remote/file", "./local/"], mode="scp")
        self.assertEqual(r.cleaned_args, ["admin@host:/remote/file", "./local/"])
        self.assertEqual(r.credentials, {})

    def test_scp_with_recursive(self):
        r = parse_args(
            ["-r", "admin:pw@host:/var/log/", "./logs/"], mode="scp"
        )
        self.assertEqual(
            r.cleaned_args, ["-r", "admin@host:/var/log/", "./logs/"]
        )
        self.assertEqual(r.credentials, {"admin@host": "pw"})

    # --- Rsync mode ---

    def test_rsync_download(self):
        r = parse_args(
            ["-avz", "admin:pw@host:/remote/", "./local/"], mode="rsync"
        )
        self.assertEqual(
            r.cleaned_args, ["-avz", "admin@host:/remote/", "./local/"]
        )
        self.assertEqual(r.credentials, {"admin@host": "pw"})

    def test_rsync_upload(self):
        r = parse_args(
            ["-avz", "./local/", "admin:pw@host:/remote/"], mode="rsync"
        )
        self.assertEqual(
            r.cleaned_args, ["-avz", "./local/", "admin@host:/remote/"]
        )
        self.assertEqual(r.credentials, {"admin@host": "pw"})

    # --- Edge cases ---

    def test_empty_args(self):
        r = parse_args([], mode="ssh")
        self.assertEqual(r.cleaned_args, [])
        self.assertEqual(r.credentials, {})

    def test_only_flags(self):
        r = parse_args(["-v", "-N"], mode="ssh")
        self.assertEqual(r.cleaned_args, ["-v", "-N"])
        self.assertEqual(r.credentials, {})

    def test_option_without_value_at_end(self):
        """Option that expects a value but is last arg."""
        r = parse_args(["-p"], mode="ssh")
        self.assertEqual(r.cleaned_args, ["-p"])


class TestParseAskpassPrompt(unittest.TestCase):
    """Tests for parse_askpass_prompt()."""

    def test_standard_prompt(self):
        result = parse_askpass_prompt("admin@192.168.1.10's password: ")
        self.assertEqual(result, "admin@192.168.1.10")

    def test_password_for_format(self):
        result = parse_askpass_prompt("Password for root@server:")
        self.assertEqual(result, "root@server")

    def test_paren_format(self):
        result = parse_askpass_prompt("(admin@host) Password: ")
        self.assertEqual(result, "admin@host")

    def test_hostname_with_dots(self):
        result = parse_askpass_prompt("user@my.server.example.com's password: ")
        self.assertEqual(result, "user@my.server.example.com")

    def test_no_user_host(self):
        result = parse_askpass_prompt("Enter passphrase: ")
        self.assertIsNone(result)

    def test_empty_prompt(self):
        result = parse_askpass_prompt("")
        self.assertIsNone(result)

    def test_hostname_with_dashes(self):
        result = parse_askpass_prompt("admin@my-server-01's password: ")
        self.assertEqual(result, "admin@my-server-01")


if __name__ == "__main__":
    unittest.main()
