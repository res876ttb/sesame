"""Encrypted credential store using HMAC-SHA256 CTR stream cipher.

Encryption uses only Python stdlib (hashlib, hmac, os).
The encryption key is derived from the raw bytes of the user's SSH private key.

Storage: ~/.config/sesame/credentials.enc
Format:  IV (16 bytes) | ciphertext | HMAC tag (32 bytes)
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import os
import stat
import sys
from pathlib import Path
from typing import Dict, List, Optional

SALT = b"sesame-v1"
CONFIG_DIR = Path.home() / ".config" / "sesame"
CRED_FILE = CONFIG_DIR / "credentials.enc"

# Export file constants
EXPORT_MAGIC = b"SESAME\x01\x01"  # 8 bytes: file identifier + version
PBKDF2_ITERATIONS = 600_000

SSH_KEY_SEARCH_ORDER = [
    Path.home() / ".ssh" / "id_rsa",
    Path.home() / ".ssh" / "id_ed25519",
    Path.home() / ".ssh" / "id_ecdsa",
]


class SSHKeyNotFoundError(Exception):
    """Raised when no SSH private key can be found for credential encryption."""


def _find_ssh_key() -> Path:
    """Find the SSH private key to use for encryption.

    Search order:
    1. SSM_SSH_KEY environment variable
    2. ~/.ssh/id_rsa
    3. ~/.ssh/id_ed25519
    4. ~/.ssh/id_ecdsa

    Raises SSHKeyNotFoundError if no key is found.
    """
    env_key = os.environ.get("SSM_SSH_KEY")
    if env_key:
        p = Path(env_key).expanduser()
        if p.is_file():
            return p
        print(f"ssm: warning: SSM_SSH_KEY={env_key} not found, searching defaults", file=sys.stderr)

    for key_path in SSH_KEY_SEARCH_ORDER:
        if key_path.is_file():
            return key_path

    raise SSHKeyNotFoundError(
        "No SSH private key found for credential encryption.\n"
        "  Searched: ~/.ssh/id_rsa, ~/.ssh/id_ed25519, ~/.ssh/id_ecdsa\n"
        "  Set SSM_SSH_KEY to specify a custom key path."
    )


def _derive_key(ssh_key_path: Optional[Path] = None) -> bytes:
    """Derive a 32-byte encryption key from SSH private key file bytes."""
    if ssh_key_path is None:
        ssh_key_path = _find_ssh_key()
    raw = ssh_key_path.read_bytes()
    return hashlib.sha256(raw + SALT).digest()


def _derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from a user-provided passphrase using PBKDF2."""
    return hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )


def _encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt using HMAC-SHA256 CTR stream cipher with integrity tag.

    Output: IV (16B) | ciphertext | HMAC tag (32B)
    """
    iv = os.urandom(16)

    # Generate keystream using HMAC-SHA256 in counter mode
    num_blocks = (len(plaintext) + 31) // 32
    keystream = b"".join(
        hmac_mod.new(key, iv + i.to_bytes(4, "big"), hashlib.sha256).digest()
        for i in range(num_blocks)
    )

    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))

    # Integrity tag over IV + ciphertext
    tag = hmac_mod.new(key, iv + ciphertext, hashlib.sha256).digest()

    return iv + ciphertext + tag


def _decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt and verify integrity.

    Raises ValueError if data is corrupted or wrong key.
    """
    if len(data) < 48:  # 16 (IV) + 0 (min ciphertext) + 32 (tag)
        raise ValueError("Credential file too short — corrupted or wrong format")

    iv = data[:16]
    ciphertext = data[16:-32]
    tag = data[-32:]

    # Verify integrity (timing-safe comparison)
    expected_tag = hmac_mod.new(key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac_mod.compare_digest(tag, expected_tag):
        raise ValueError(
            "Credential decryption failed — wrong SSH key or corrupted file.\n"
            "  If you changed your SSH key, use 'sf --forget-all' and re-add passwords."
        )

    # Decrypt
    num_blocks = (len(ciphertext) + 31) // 32
    keystream = b"".join(
        hmac_mod.new(key, iv + i.to_bytes(4, "big"), hashlib.sha256).digest()
        for i in range(num_blocks)
    )

    return bytes(c ^ k for c, k in zip(ciphertext, keystream))


def _ensure_dir() -> None:
    """Create config directory with proper permissions."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CONFIG_DIR, stat.S_IRWXU)  # 0700


def _check_permissions(path: Path) -> None:
    """Warn if file permissions are too open."""
    if not path.exists():
        return
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        print(
            f"sf: warning: {path} has overly permissive permissions "
            f"({oct(mode & 0o777)}). Recommended: 0600.",
            file=sys.stderr,
        )


class CredentialStore:
    """Encrypted credential storage backed by SSH private key."""

    def __init__(self, ssh_key_path: Optional[Path] = None) -> None:
        if ssh_key_path is None:
            ssh_key_path = _find_ssh_key()
        self._key = _derive_key(ssh_key_path)

    class DecryptionError(Exception):
        """Raised when the credential file cannot be decrypted."""

    def _load(self) -> Dict[str, str]:
        """Load and decrypt the credential store. Returns empty dict if not found.

        Raises DecryptionError if the file exists but cannot be decrypted
        (wrong key, corruption).  This prevents write operations from
        silently overwriting credentials they could not read.
        """
        if not CRED_FILE.exists():
            return {}
        _check_permissions(CRED_FILE)
        try:
            data = CRED_FILE.read_bytes()
            plaintext = _decrypt(data, self._key)
            return json.loads(plaintext.decode("utf-8"))
        except (ValueError, json.JSONDecodeError) as e:
            raise self.DecryptionError(str(e)) from e

    def _save(self, creds: Dict[str, str]) -> None:
        """Encrypt and save the credential store atomically."""
        import tempfile

        _ensure_dir()
        plaintext = json.dumps(creds, indent=2).encode("utf-8")
        data = _encrypt(plaintext, self._key)

        # Write atomically: create a unique temp file with restricted
        # permissions, write data, then rename over the target.
        fd = None
        tmp_path = None
        try:
            fd, tmp_name = tempfile.mkstemp(
                dir=str(CONFIG_DIR), prefix=".cred_", suffix=".tmp"
            )
            tmp_path = Path(tmp_name)
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)  # 0600 before writing
            os.write(fd, data)
            os.close(fd)
            fd = None  # mark as closed
            tmp_path.rename(CRED_FILE)
            tmp_path = None  # rename succeeded, no cleanup needed
        finally:
            if fd is not None:
                os.close(fd)
            if tmp_path is not None:
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    def _load_safe(self) -> Dict[str, str]:
        """Load credentials, printing an error and returning {} on failure.

        Use this for **read-only** operations (lookup, list) where a
        decryption failure should not crash the program.  Never use for
        operations that will subsequently _save — use _load() directly
        so DecryptionError propagates and prevents data loss.
        """
        try:
            return self._load()
        except self.DecryptionError as e:
            print(f"sf: error: {e}", file=sys.stderr)
            return {}

    def save(self, user: str, host: str, password: str) -> None:
        """Save or update a credential.

        Raises DecryptionError if the existing store cannot be read.
        """
        creds = self._load()
        creds[f"{user}@{host}"] = password
        self._save(creds)

    def save_by_key(self, key: str, password: str) -> None:
        """Save a credential by its full key (user@host)."""
        creds = self._load()
        creds[key] = password
        self._save(creds)

    def save_many(self, credentials: Dict[str, str]) -> None:
        """Save multiple credentials at once."""
        if not credentials:
            return
        creds = self._load()
        creds.update(credentials)
        self._save(creds)

    def lookup(self, user: str, host: str) -> Optional[str]:
        """Look up a password by user and host."""
        creds = self._load_safe()
        return creds.get(f"{user}@{host}")

    def lookup_by_key(self, key: str) -> Optional[str]:
        """Look up a password by full key (user@host)."""
        creds = self._load_safe()
        return creds.get(key)

    def remove(self, user: str, host: str) -> bool:
        """Remove a credential. Returns True if it existed."""
        creds = self._load()
        key = f"{user}@{host}"
        if key in creds:
            del creds[key]
            self._save(creds)
            return True
        return False

    def remove_by_key(self, key: str) -> bool:
        """Remove a credential by full key. Returns True if it existed."""
        creds = self._load()
        if key in creds:
            del creds[key]
            self._save(creds)
            return True
        return False

    def list_all(self) -> List[str]:
        """List all stored credential keys (user@host). No passwords."""
        creds = self._load_safe()
        return sorted(creds.keys())

    def clear_all(self) -> None:
        """Remove all credentials."""
        if CRED_FILE.exists():
            CRED_FILE.unlink()

    def export_to_file(self, path: Path, passphrase: str) -> int:
        """Export all credentials to a passphrase-encrypted portable file.

        File format:
            MAGIC       (8B)  b"SSHFUSN\\x01"
            PBKDF2_SALT (32B) random
            ITERATIONS  (4B)  big-endian uint32
            IV          (16B) random
            CIPHERTEXT  (var) HMAC-SHA256 CTR encrypted JSON
            HMAC_TAG    (32B) integrity check

        Args:
            path: Destination file path.
            passphrase: User-provided passphrase for encryption.

        Returns:
            Number of credentials exported.
        """
        creds = self._load()
        if not creds:
            return 0

        salt = os.urandom(32)
        key = _derive_key_from_passphrase(passphrase, salt)

        plaintext = json.dumps(creds, indent=2).encode("utf-8")
        encrypted = _encrypt(plaintext, key)  # IV + ciphertext + tag

        header = EXPORT_MAGIC + salt + PBKDF2_ITERATIONS.to_bytes(4, "big")

        # Atomic write: temp file → rename
        import tempfile as _tf

        parent = path.parent
        parent.mkdir(parents=True, exist_ok=True)
        fd = None
        tmp_path = None
        try:
            fd, tmp_name = _tf.mkstemp(dir=str(parent), prefix=".sfexport_")
            tmp_path = Path(tmp_name)
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)  # 0600
            os.write(fd, header + encrypted)
            os.close(fd)
            fd = None
            tmp_path.rename(path)
            tmp_path = None
        finally:
            if fd is not None:
                os.close(fd)
            if tmp_path is not None:
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
        return len(creds)

    def import_from_file(
        self, path: Path, passphrase: str, overwrite: bool = False
    ) -> tuple:
        """Import credentials from a passphrase-encrypted portable file.

        Args:
            path: Source file path.
            passphrase: User-provided passphrase for decryption.
            overwrite: If True, overwrite existing entries; otherwise skip them.

        Returns:
            (imported_count, skipped_count) tuple.

        Raises:
            ValueError: If the file is invalid or the passphrase is wrong.
        """
        data = path.read_bytes()

        # Validate magic
        if len(data) < 44 or data[:8] != EXPORT_MAGIC:
            raise ValueError(
                "Not a valid sesame export file (wrong magic header)."
            )

        # Parse header
        salt = data[8:40]
        iterations = int.from_bytes(data[40:44], "big")
        encrypted = data[44:]  # IV + ciphertext + tag

        # Derive key from passphrase
        key = hashlib.pbkdf2_hmac(
            "sha256", passphrase.encode("utf-8"), salt, iterations
        )

        # Decrypt
        try:
            plaintext = _decrypt(encrypted, key)
        except ValueError:
            raise ValueError(
                "Decryption failed — wrong passphrase or corrupted file."
            )

        try:
            incoming = json.loads(plaintext.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("Decrypted data is not valid JSON — corrupted file.")

        if not isinstance(incoming, dict):
            raise ValueError("Export file contains invalid credential format.")

        # Validate all keys and values are strings
        for k, v in incoming.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise ValueError(
                    "Export file contains non-string keys or values — "
                    "corrupted or tampered file."
                )

        # Merge into local store
        creds = self._load()
        imported = 0
        skipped = 0

        for key_name, password in incoming.items():
            if key_name in creds and not overwrite:
                skipped += 1
            else:
                creds[key_name] = password
                imported += 1

        if imported > 0:
            self._save(creds)

        return imported, skipped
