# sesame (`ssm`)

SSH wrapper that memorizes passwords — supports ssh, scp, sftp, and rsync.

**Zero external dependencies.** Pure Python stdlib only.

## Why?

- You have 100+ servers and don't want to `ssh-copy-id` for each
- You don't manage the servers, so you can't install SSH keys by default
- You want to type the password once and never again

## Install

**Quick (no pip needed):**

```bash
git clone https://github.com/res876ttb/sesame.git ~/.sesame
~/.sesame/install.sh
```

This creates a small `ssm` wrapper in `~/.local/bin/`. Make sure `~/.local/bin` is in your `PATH`.

**With pip/pipx:**

```bash
pipx install .     # recommended — isolated install
# or
pip install .      # system/venv install
```

## Usage

### SSH (default mode)

```bash
# First time — provide password (it gets encrypted & saved)
ssm admin:myP@ssw0rd@192.168.1.10

# Next time — password auto-filled
ssm admin@192.168.1.10

# Jump host
ssm -J admin:jumpPW@jump.example.com root:targetPW@10.0.0.5

# Remote command
ssm admin@192.168.1.10 ls -la /tmp

# With SSH options
ssm -p 2222 admin@192.168.1.10
```

### SCP (`ssm cp`)

```bash
ssm cp admin:pw@host:/remote/file ./local/
ssm cp ./local/file admin@host:/remote/
ssm cp -r admin@host:/var/log/ ./logs/
```

### SFTP (`ssm ftp`)

```bash
ssm ftp admin:pw@host
ssm ftp admin@host          # password already saved
```

### Rsync (`ssm sync`)

```bash
ssm sync -avz admin:pw@host:/remote/ ./local/
ssm sync -avz --delete ./dist/ admin@host:/var/www/html/
```

### Credential Management

```bash
ssm --list                  # List stored credentials and aliases
ssm --forget admin@host     # Remove one credential or alias
ssm --forget admin@h1 srv2  # Remove multiple at once
ssm --forget-all            # Remove all credentials and aliases
```

### Import & Export

Transfer credentials between machines using passphrase-encrypted files:

```bash
# Export — prompts for a passphrase (entered twice for confirmation)
ssm --export passwords.enc

# Import on another machine — prompts for the passphrase
ssm --import passwords.enc

# Import and overwrite any existing entries
ssm --import --overwrite passwords.enc
```

The export file is encrypted with PBKDF2 + HMAC-SHA256, independent of your SSH key.
You can safely transfer it across systems — only someone with the passphrase can read it.

### Aliases

Save frequently-used connections as short names:

```bash
# Save an alias after connecting
ssm admin@192.168.1.10 --name myserver

# With jump host and port
ssm -J jump@gateway -p 2222 admin@10.0.0.5 --name prod

# Now connect with just the alias
ssm myserver
ssm prod

# Aliases appear in --list and tab completion
ssm --list
ssm --forget myserver    # remove alias (and/or credential)
```

### Password Update

```bash
# Just provide the new password — it overwrites the old one
ssm admin:newPassword@192.168.1.10
```

### Shell Completion (Tab)

Supports **zsh** and **bash** only.

Add one line to your shell rc file:

```bash
# ~/.zshrc or ~/.bashrc
eval "$(ssm --init)"
```

Or specify the shell explicitly: `eval "$(ssm --init zsh)"` / `eval "$(ssm --init bash)"`

Remote file/directory completion — press Tab to browse files on the remote host:

```bash
ssm cp admin@server:/var/log/<TAB>
#  → auth.log  kern.log  syslog  nginx/

ssm cp admin@server:/etc/ngi<TAB>
#  → /etc/nginx/

ssm cp admin@server:<TAB>
#  → (lists home directory)
```

Also completes subcommands, options, and `--forget` credential keys.

## How It Works

1. `ssm` parses `user:password@host`, strips the password, saves it encrypted
2. Sets `SSH_ASKPASS` to point to itself, then runs `ssh`/`scp`/`sftp`/`rsync`
3. When SSH needs a password, it calls `ssm` in ASKPASS mode
4. ASKPASS mode looks up the password from the encrypted store and provides it
5. SSH handles all terminal interaction natively — no PTY emulation

## Security

### Encryption

Credentials are encrypted at rest using **HMAC-SHA256 CTR stream cipher**:

- Encryption key is derived from your SSH private key file (`sha256(key_bytes + salt)`)
- Each save uses a random 16-byte IV
- HMAC-SHA256 integrity tag prevents tampering
- File permissions enforced at `0600`

### What this means

- **Without your SSH private key, the credential file is unreadable**
- Credentials are NOT stored in plaintext
- The encryption key changes if you change your SSH key or its passphrase
  - If that happens, use `ssm --forget-all` and re-add your passwords

### SSH key auto-detection order

1. `$SSM_SSH_KEY` environment variable (if set)
2. `~/.ssh/id_rsa`
3. `~/.ssh/id_ed25519`
4. `~/.ssh/id_ecdsa`

### Limitations

- Passwords are passed to SSH via ASKPASS stdout (not command-line args, so `/proc/cmdline`-safe)
- Passwords are passed to the ASKPASS helper via environment variable within the same process tree
- Requires **OpenSSH 8.4+** for `SSH_ASKPASS_REQUIRE=force`
  - macOS 13+ and most modern Linux distros satisfy this

## Requirements

- Python >= 3.8
- OpenSSH >= 8.4
- An SSH private key in `~/.ssh/` (for credential encryption)

## License

MIT
