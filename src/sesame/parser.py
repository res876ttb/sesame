"""Parse user:password@host patterns from command-line arguments.

Supports:
- SSH:   user:password@host
- SCP:   user:password@host:/remote/path
- rsync: user:password@host:/remote/path
- -J:    user:password@jump1,user2:password2@jump2
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class ParseResult:
    """Result of parsing ssm arguments."""

    cleaned_args: List[str] = field(default_factory=list)
    credentials: Dict[str, str] = field(default_factory=dict)  # "user@host" -> password


def parse_credential(
    token: str, allow_path: bool = False
) -> Tuple[str, Optional[str], Optional[str]]:
    """Parse a single user:password@host token.

    Rules:
    - Split on the LAST '@' to get (left, host_part)
    - Split left on the FIRST ':' to get (user, password)
    - If allow_path and host_part contains ':', preserve the path portion

    Args:
        token: e.g. "admin:p@ss:word@myhost" or "admin:pw@host:/remote/path"
        allow_path: If True, host may contain ":path" (scp/rsync format)

    Returns:
        (cleaned_token, credential_key, password) where:
        - cleaned_token has password stripped: "user@host" or "user@host:/path"
        - credential_key is "user@host" if password was found, else None
        - password is the extracted password, or None if not found
    """
    at_idx = token.rfind("@")
    if at_idx == -1:
        return token, None, None

    left = token[:at_idx]
    host_part = token[at_idx + 1 :]

    colon_idx = left.find(":")
    if colon_idx == -1:
        return token, None, None

    user = left[:colon_idx]
    password = left[colon_idx + 1 :]

    if not user or not password or not host_part:
        return token, None, None

    # For scp/rsync, host_part may be "host:/path"
    if allow_path and ":" in host_part:
        host_name = host_part.split(":", 1)[0]
        cleaned = f"{user}@{host_part}"
        cred_key = f"{user}@{host_name}"
    else:
        cleaned = f"{user}@{host_part}"
        cred_key = f"{user}@{host_part}"

    return cleaned, cred_key, password


def _parse_credential_full(
    token: str, allow_path: bool = False
) -> Tuple[str, Dict[str, str]]:
    """Parse a token, returning cleaned token and any credentials found."""
    at_idx = token.rfind("@")
    if at_idx == -1:
        return token, {}

    left = token[:at_idx]
    host_part = token[at_idx + 1 :]

    colon_idx = left.find(":")
    if colon_idx == -1:
        return token, {}

    user = left[:colon_idx]
    password = left[colon_idx + 1 :]

    if not user or not password or not host_part:
        return token, {}

    if allow_path and ":" in host_part:
        host_name = host_part.split(":", 1)[0]
        cleaned = f"{user}@{host_part}"
        cred_key = f"{user}@{host_name}"
    else:
        cleaned = f"{user}@{host_part}"
        cred_key = f"{user}@{host_part}"

    return cleaned, {cred_key: password}


def _parse_jump_hosts(value: str) -> Tuple[str, Dict[str, str]]:
    """Parse -J value which may contain comma-separated jump hosts.

    e.g. "user1:pw1@jump1,user2:pw2@jump2"
    """
    parts = value.split(",")
    cleaned_parts = []
    creds: Dict[str, str] = {}

    for part in parts:
        cleaned, part_creds = _parse_credential_full(part, allow_path=False)
        cleaned_parts.append(cleaned)
        creds.update(part_creds)

    return ",".join(cleaned_parts), creds


def parse_args(args: List[str], mode: str = "ssh") -> ParseResult:
    """Parse ssm arguments, extract credentials, return cleaned args.

    Args:
        args: Raw arguments (excluding the program name and subcommand)
        mode: One of "ssh", "scp", "sftp", "rsync"

    Returns:
        ParseResult with cleaned args and extracted credentials
    """
    allow_path = mode in ("scp", "rsync")
    result = ParseResult()
    i = 0

    while i < len(args):
        arg = args[i]

        # Handle -J / -oProxyJump= for jump hosts
        if arg == "-J" and i + 1 < len(args):
            cleaned_jump, jump_creds = _parse_jump_hosts(args[i + 1])
            result.cleaned_args.append("-J")
            result.cleaned_args.append(cleaned_jump)
            result.credentials.update(jump_creds)
            i += 2
            continue

        if arg.startswith("-J") and len(arg) > 2:
            # -Juser:pw@host form (no space)
            cleaned_jump, jump_creds = _parse_jump_hosts(arg[2:])
            result.cleaned_args.append(f"-J{cleaned_jump}")
            result.credentials.update(jump_creds)
            i += 1
            continue

        if arg == "-o" and i + 1 < len(args) and args[i + 1].startswith("ProxyJump="):
            proxy_value = args[i + 1][len("ProxyJump=") :]
            cleaned_jump, jump_creds = _parse_jump_hosts(proxy_value)
            result.cleaned_args.append("-o")
            result.cleaned_args.append(f"ProxyJump={cleaned_jump}")
            result.credentials.update(jump_creds)
            i += 2
            continue

        if arg.startswith("-oProxyJump="):
            proxy_value = arg[len("-oProxyJump=") :]
            cleaned_jump, jump_creds = _parse_jump_hosts(proxy_value)
            result.cleaned_args.append(f"-oProxyJump={cleaned_jump}")
            result.credentials.update(jump_creds)
            i += 1
            continue

        # Skip known SSH options that take a value argument
        if arg in (
            "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-L",
            "-l", "-m", "-O", "-o", "-p", "-P", "-Q", "-R", "-S",
            "-W", "-w",
        ):
            result.cleaned_args.append(arg)
            if i + 1 < len(args):
                result.cleaned_args.append(args[i + 1])
                i += 2
            else:
                i += 1
            continue

        # Options that don't take values (flags)
        if arg.startswith("-"):
            result.cleaned_args.append(arg)
            i += 1
            continue

        # Positional argument — may contain user:password@host
        cleaned, token_creds = _parse_credential_full(arg, allow_path=allow_path)
        result.cleaned_args.append(cleaned)
        result.credentials.update(token_creds)
        i += 1

    return result


def parse_askpass_prompt(prompt: str) -> Optional[str]:
    """Extract user@host from an SSH password prompt.

    SSH prompts look like:
    - "user@host's password: "
    - "Password for user@host: "
    - "(user@host) Password: "

    Returns:
        "user@host" string if found, else None
    """
    # Pattern: something@something followed by 's password or similar
    m = re.search(r"(\S+@\S+?)(?:'s\s+password|(?:\)\s*)?[Pp]assword)", prompt)
    if m:
        candidate = m.group(1)
        # Remove leading/trailing parens that wrap the user@host.
        # The regex may capture "(user@host" (leading paren only, since
        # the closing ")" is consumed by the regex lookahead).
        if candidate.startswith("(") and candidate.endswith(")"):
            candidate = candidate[1:-1]
        elif candidate.startswith("("):
            candidate = candidate[1:]
        return candidate

    # Fallback: find any user@host pattern
    m = re.search(r"(\S+@[\w.\-]+)", prompt)
    if m:
        return m.group(1)

    return None
