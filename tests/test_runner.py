"""Tests for sesame.runner."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from sesame.runner import (
    _create_askpass_wrapper,
    _is_confirmation_prompt,
    _is_password_prompt,
    handle_askpass,
)


class TestCreateAskpassWrapper(unittest.TestCase):
    """Tests for _create_askpass_wrapper()."""

    def test_creates_executable_file(self):
        path = _create_askpass_wrapper()
        self.assertTrue(os.path.exists(path))
        self.assertTrue(os.access(path, os.X_OK))
        os.unlink(path)

    def test_wrapper_is_shell_script(self):
        path = _create_askpass_wrapper()
        with open(path) as f:
            content = f.read()
        self.assertTrue(content.startswith("#!/bin/sh"))
        self.assertIn("sesame", content)
        os.unlink(path)


class TestPromptClassification(unittest.TestCase):
    """Tests for prompt type detection."""

    def test_password_prompt_standard(self):
        self.assertTrue(_is_password_prompt("admin@host's password: "))

    def test_password_prompt_capitalized(self):
        self.assertTrue(_is_password_prompt("Password: "))

    def test_password_prompt_for_format(self):
        self.assertTrue(_is_password_prompt("Password for admin@host: "))

    def test_not_password_prompt(self):
        self.assertFalse(_is_password_prompt("Enter passphrase for key: "))
        self.assertFalse(
            _is_password_prompt(
                "Are you sure you want to continue connecting (yes/no)? "
            )
        )

    def test_confirmation_yes_no(self):
        self.assertTrue(
            _is_confirmation_prompt(
                "Are you sure you want to continue connecting (yes/no/[fingerprint])? "
            )
        )

    def test_confirmation_fingerprint(self):
        self.assertTrue(
            _is_confirmation_prompt(
                "Please type 'yes', 'no' or the fingerprint: "
            )
        )

    def test_confirmation_continue_connecting(self):
        self.assertTrue(
            _is_confirmation_prompt(
                "Are you sure you want to continue connecting? "
            )
        )

    def test_not_confirmation(self):
        self.assertFalse(_is_confirmation_prompt("admin@host's password: "))
        self.assertFalse(_is_confirmation_prompt("Password: "))


class TestHandleAskpass(unittest.TestCase):
    """Tests for handle_askpass() in ASKPASS mode."""

    def test_returns_password_from_env_creds(self):
        """When _SF_CREDS has the password, it should print it."""
        import json
        env = {
            "_SSM_ASKPASS": "1",
            "_SSM_CREDS": json.dumps({"admin@host": "secret123"}),
        }
        with mock.patch.dict(os.environ, env, clear=False):
            with mock.patch("sys.argv", ["ssm", "admin@host's password: "]):
                with mock.patch("builtins.print") as mock_print:
                    handle_askpass()
                    mock_print.assert_called_once_with("secret123")

    def test_returns_password_multiple_creds(self):
        """With multiple creds in JSON format."""
        import json
        env = {
            "_SSM_ASKPASS": "1",
            "_SSM_CREDS": json.dumps({"admin@host1": "pw1", "root@host2": "pw2"}),
        }
        with mock.patch.dict(os.environ, env, clear=False):
            with mock.patch("sys.argv", ["ssm", "root@host2's password: "]):
                with mock.patch("builtins.print") as mock_print:
                    handle_askpass()
                    mock_print.assert_called_once_with("pw2")

    def test_password_with_equals_in_value(self):
        """Password containing '=' should be handled correctly."""
        import json
        env = {
            "_SSM_ASKPASS": "1",
            "_SSM_CREDS": json.dumps({"admin@host": "pass=word=123"}),
        }
        with mock.patch.dict(os.environ, env, clear=False):
            with mock.patch("sys.argv", ["ssm", "admin@host's password: "]):
                with mock.patch("builtins.print") as mock_print:
                    handle_askpass()
                    mock_print.assert_called_once_with("pass=word=123")

    def test_password_with_newline(self):
        """Password containing newline should be handled correctly with JSON."""
        import json
        env = {
            "_SSM_ASKPASS": "1",
            "_SSM_CREDS": json.dumps({"admin@host": "line1\nline2"}),
        }
        with mock.patch.dict(os.environ, env, clear=False):
            with mock.patch("sys.argv", ["ssm", "admin@host's password: "]):
                with mock.patch("builtins.print") as mock_print:
                    handle_askpass()
                    mock_print.assert_called_once_with("line1\nline2")

    def test_host_key_verification_forwarded_to_user(self):
        """Host key prompt should be forwarded to user with echo."""
        prompt = "Are you sure you want to continue connecting (yes/no/[fingerprint])? "
        env = {"_SSM_ASKPASS": "1", "_SSM_CREDS": ""}
        with mock.patch.dict(os.environ, env, clear=False):
            with mock.patch("sys.argv", ["ssm", prompt]):
                with mock.patch(
                    "sesame.runner._prompt_user_visible", return_value="yes"
                ) as mock_visible:
                    with mock.patch("builtins.print") as mock_print:
                        handle_askpass()
                        mock_visible.assert_called_once_with(prompt)
                        mock_print.assert_called_once_with("yes")

    def test_passphrase_prompt_falls_through_to_user(self):
        """Non-password, non-confirmation prompts fall through to hidden input."""
        prompt = "Enter passphrase for key '/home/user/.ssh/id_rsa': "
        env = {"_SSM_ASKPASS": "1", "_SSM_CREDS": ""}
        with mock.patch.dict(os.environ, env, clear=False):
            with mock.patch("sys.argv", ["ssm", prompt]):
                with mock.patch(
                    "sesame.runner._prompt_user_hidden",
                    return_value="my-passphrase",
                ) as mock_hidden:
                    with mock.patch("builtins.print") as mock_print:
                        handle_askpass()
                        mock_hidden.assert_called_once_with(prompt)
                        mock_print.assert_called_once_with("my-passphrase")


if __name__ == "__main__":
    unittest.main()
