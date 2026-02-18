"""SSH_ASKPASS-based command runner.

Sets up SSH_ASKPASS to point to `ssm` itself, then executes ssh/scp/sftp/rsync
via subprocess.  The child process inherits the terminal for full interactive
support — no PTY emulation needed.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional


def _resolve_ssm_path() -> str:
    """Find the path to the `ssm` executable for SSH_ASKPASS.

    Tries shutil.which('ssm') first, then falls back to creating a temp wrapper
    that invokes `python -m sesame`.
    """
    ssm = shutil.which("ssm")
    if ssm:
        return ssm

    # Fallback: create a wrapper script
    return _create_askpass_wrapper()


def _create_askpass_wrapper() -> str:
    """Create a temporary executable script that calls ssm in ASKPASS mode."""
    python = sys.executable
    fd, path = tempfile.mkstemp(prefix="ssm-askpass-", suffix=".sh")
    with os.fdopen(fd, "w") as f:
        f.write(f'#!/bin/sh\nexec "{python}" -m sesame "$@"\n')
    os.chmod(path, stat.S_IRWXU)  # 0700
    return path


def run_command(
    cmd: List[str],
    credentials: Optional[Dict[str, str]] = None,
) -> int:
    """Execute a command with SSH_ASKPASS configured.

    Args:
        cmd: Full command to execute, e.g. ["ssh", "user@host"]
        credentials: Dict of {"user@host": "password"} for ASKPASS lookup

    Returns:
        Exit code from the child process
    """
    askpass_path = _resolve_ssm_path()
    # Track whether we created a temp wrapper so we can clean it up.
    # Use os.path.realpath to resolve symlinks for a reliable comparison.
    _tmp_prefix = os.path.realpath(tempfile.gettempdir()) + os.sep
    is_temp = os.path.realpath(askpass_path).startswith(_tmp_prefix)

    # Build environment
    env = os.environ.copy()
    env["SSH_ASKPASS"] = askpass_path
    env["SSH_ASKPASS_REQUIRE"] = "force"
    env["_SSM_ASKPASS"] = "1"

    # Pass credentials to the ASKPASS helper via env.
    # Use JSON for safe serialization — handles passwords containing
    # newlines, '=', or other special characters.
    if credentials:
        import json
        env["_SSM_CREDS"] = json.dumps(credentials)

    try:
        result = subprocess.run(cmd, env=env)
        return result.returncode
    finally:
        # Clean up temp wrapper if we created one
        if is_temp and os.path.exists(askpass_path):
            try:
                os.unlink(askpass_path)
            except OSError:
                pass


def _is_password_prompt(prompt: str) -> bool:
    """Check if a prompt is asking for a password (vs host key, passphrase, etc)."""
    lower = prompt.lower()
    return "password" in lower


def _is_confirmation_prompt(prompt: str) -> bool:
    """Check if a prompt expects a visible user response (yes/no, fingerprint, etc).

    These prompts must NOT have echo disabled — the user needs to see what
    they type.  Examples:
    - "Are you sure you want to continue connecting (yes/no/[fingerprint])?"
    - "Please type 'yes', 'no' or the fingerprint:"
    """
    lower = prompt.lower()
    return (
        "yes/no" in lower
        or "fingerprint" in lower
        or "continue connecting" in lower
        or "are you sure" in lower
    )


def _prompt_user_visible(prompt: str) -> str:
    """Prompt user via /dev/tty with echo ON (for yes/no answers)."""
    with open("/dev/tty", "r+") as tty:
        tty.write(prompt)
        tty.flush()
        response = tty.readline().rstrip("\n")
    return response


def _prompt_user_hidden(prompt: str) -> str:
    """Prompt user via /dev/tty with echo OFF (for passwords)."""
    import termios

    with open("/dev/tty", "r+") as tty:
        tty.write(prompt if prompt else "Password: ")
        tty.flush()
        old = termios.tcgetattr(tty)
        new = old[:]
        new[3] = new[3] & ~termios.ECHO
        try:
            termios.tcsetattr(tty, termios.TCSANOW, new)
            response = tty.readline().rstrip("\n")
        finally:
            termios.tcsetattr(tty, termios.TCSANOW, old)
            tty.write("\n")
    return response


def handle_askpass() -> None:
    """Handle ASKPASS mode — called by SSH when it needs a password.

    SSH passes the prompt as the first command-line argument.
    SSH_ASKPASS is called for ALL interactive prompts, not just passwords:
    - Host key verification ("Are you sure... yes/no")
    - Password prompts ("user@host's password:")
    - Key passphrase prompts ("Enter passphrase for key...")

    For non-password prompts, we forward them to the user via /dev/tty
    with echo enabled so they can type "yes"/"no"/fingerprint.

    NOTE: Many OpenSSH versions call setsid() in the ASKPASS child,
    which detaches from the controlling terminal.  /dev/tty may therefore
    fail.  The parent ``ssm`` process pre-prompts for missing passwords
    to avoid relying on /dev/tty here.
    """
    try:
        _handle_askpass_inner()
    except Exception as exc:
        # Surface any unexpected error so the user can report it.
        sys.stderr.write(f"ssm: ASKPASS error: {type(exc).__name__}: {exc}\n")
        sys.exit(1)


def _handle_askpass_inner() -> None:
    """Core ASKPASS logic, separated for clean error handling."""
    from .credentials import CredentialStore
    from .parser import parse_askpass_prompt

    prompt = sys.argv[1] if len(sys.argv) > 1 else ""

    # --- Confirmation prompts (host key, yes/no) → forward to user with echo ---
    if _is_confirmation_prompt(prompt):
        try:
            response = _prompt_user_visible(prompt)
            print(response)
        except OSError as exc:
            sys.stderr.write(
                f"ssm: cannot prompt for host key confirmation "
                f"(/dev/tty: {exc})\n"
            )
            sys.exit(1)
        return

    # --- Password prompts → auto-fill or ask ---
    if _is_password_prompt(prompt):
        cred_key = parse_askpass_prompt(prompt)

        # First, try in-memory credentials passed via env (JSON)
        env_creds = os.environ.get("_SSM_CREDS", "")
        memory_creds: Dict[str, str] = {}
        if env_creds:
            import json
            try:
                memory_creds = json.loads(env_creds)
            except (json.JSONDecodeError, ValueError):
                pass

        if cred_key and cred_key in memory_creds:
            print(memory_creds[cred_key])
            return

        # Second, try the persistent credential store
        if cred_key:
            try:
                store = CredentialStore()
                password = store.lookup_by_key(cred_key)
                if password:
                    print(password)
                    return
            except Exception:
                pass

    # --- Fallback: prompt user via /dev/tty (echo hidden) ---
    # This may fail if OpenSSH called setsid() (no controlling terminal).
    # The parent sf process should have already pre-prompted for missing
    # passwords, so reaching here is uncommon.

    # In completion mode (tab-completion), never prompt interactively —
    # just fail silently so the shell doesn't hang.
    if os.environ.get("_SSM_COMPLETION") == "1":
        sys.exit(1)

    try:
        password = _prompt_user_hidden(prompt)
        print(password)
    except (OSError, ImportError) as exc:
        sys.stderr.write(
            f"ssm: ASKPASS: no stored password and cannot prompt "
            f"(/dev/tty: {exc})\n"
            f"  Hint: provide the password on the command line:\n"
            f"    ssm user:password@host\n"
        )
        sys.exit(1)
