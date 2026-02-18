"""ssm — SSH wrapper that memorizes passwords.

Single entry point with dual mode:
1. ASKPASS helper mode (called by SSH via SSH_ASKPASS)
2. Main command mode (called by the user)

Subcommands:  cp (scp), ftp (sftp), sync (rsync)
Management:   --list, --forget, --forget-all, --export, --import
"""

from __future__ import annotations

import getpass
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .credentials import CONFIG_DIR, CredentialStore, SSHKeyNotFoundError
from .parser import parse_args
from .runner import handle_askpass, run_command

ALIASES_FILE = CONFIG_DIR / "aliases.json"

VERSION = "0.1.0"

# Maps subcommand to (underlying binary, mode)
SUBCOMMANDS = {
    "cp": ("scp", "scp"),
    "ftp": ("sftp", "sftp"),
    "sync": ("rsync", "rsync"),
}


def _load_aliases() -> Dict[str, Any]:
    """Load aliases from disk. Returns empty dict on any error."""
    try:
        if ALIASES_FILE.is_file():
            return json.loads(ALIASES_FILE.read_text("utf-8"))
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def _save_aliases(aliases: Dict[str, Any]) -> None:
    """Save aliases to disk atomically."""
    import tempfile

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    fd = None
    tmp_path = None
    try:
        fd, tmp_name = tempfile.mkstemp(
            dir=str(CONFIG_DIR), prefix=".alias_", suffix=".tmp"
        )
        tmp_path = Path(tmp_name)
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        os.write(fd, json.dumps(aliases, indent=2).encode("utf-8"))
        os.close(fd)
        fd = None
        tmp_path.rename(ALIASES_FILE)
        tmp_path = None
    finally:
        if fd is not None:
            os.close(fd)
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except OSError:
                pass


def _resolve_alias(name: str) -> Optional[List[str]]:
    """Resolve an alias name to its stored args list, or None."""
    aliases = _load_aliases()
    entry = aliases.get(name)
    if entry is None:
        return None
    if isinstance(entry, dict):
        args: List[str] = list(entry.get("args", []))
        target = entry.get("target", "")
        if target:
            args.append(target)
        return args
    return None


def _print_usage() -> None:
    """Print usage help."""
    print(
        f"ssm {VERSION} — SSH wrapper that memorizes passwords\n"
        "\n"
        "Usage:\n"
        "  ssm [SSH_OPTIONS] user[:password]@host [COMMAND]    SSH (default)\n"
        "  ssm cp [SCP_OPTIONS] [[user:]src] [[user:]dst]      SCP\n"
        "  ssm ftp [SFTP_OPTIONS] user[:password]@host          SFTP\n"
        "  ssm sync [RSYNC_OPTIONS] src dst                     Rsync\n"
        "\n"
        "Aliases:\n"
        "  ssm [OPTIONS] host --name NAME     Save connection as alias\n"
        "  ssm NAME                           Connect using saved alias\n"
        "\n"
        "Credential management:\n"
        "  ssm --list                         List stored credentials and aliases\n"
        "  ssm --forget NAME [NAME ...]       Remove credentials or aliases\n"
        "  ssm --forget-all                   Remove all credentials and aliases\n"
        "  ssm --export FILE                  Export credentials (passphrase-encrypted)\n"
        "  ssm --import FILE                  Import credentials (skip existing)\n"
        "  ssm --import --overwrite FILE      Import credentials (overwrite existing)\n"
        "\n"
        "Shell completion (zsh/bash only):\n"
        '  eval "$(ssm --init)"              Auto-detect shell\n'
        '  eval "$(ssm --init zsh)"          Zsh completion\n'
        '  eval "$(ssm --init bash)"         Bash completion\n'
        "\n"
        "Options:\n"
        "  --help, -h         Show this help\n"
        "  --version          Show version\n"
        "\n"
        "The first time you connect with user:password@host, the password\n"
        "is encrypted and saved. Next time, just use user@host.\n"
        "\n"
        "Environment variables:\n"
        "  SSM_SSH_KEY         Path to SSH private key for credential encryption\n"
        "                      (default: auto-detect ~/.ssh/id_*)\n"
    )


_COMPLETION_ZSH = r'''
typeset -g _ssm_rc_key=""
typeset -ga _ssm_rc_data=()
_ssm_complete_remote() {
    local target="${words[$CURRENT]}"
    [[ "$target" != *:* ]] && return 1
    local host_prefix="${target%%:*}:"
    local -a completions
    if [[ "$target" == "$_ssm_rc_key" ]]; then
        completions=("${_ssm_rc_data[@]}")
    else
        completions=("${(@f)$(ssm --_complete-remote "$target" 2>/dev/null)}")
        completions=("${(@)completions:#}")
        _ssm_rc_key="$target"
        _ssm_rc_data=("${completions[@]}")
    fi
    (( ! ${#completions} )) && return 1
    local -a dirs files
    local c p
    for c in "${completions[@]}"; do
        p="${c#"$host_prefix"}"
        if [[ "$p" == */ ]]; then
            dirs+=("$p")
        else
            files+=("$p")
        fi
    done
    (( ${#dirs} )) && compadd -U -Q -S '' -p "$host_prefix" -- "${dirs[@]}"
    (( ${#files} )) && compadd -U -Q -S ' ' -p "$host_prefix" -- "${files[@]}"
    return 0
}
_ssm_hosts_group() {
    local -a hosts
    hosts=("${(@f)$(ssm --_list-hosts 2>/dev/null)}")
    hosts=("${(@)hosts:#}")
    (( ${#hosts} )) && compadd -V hosts -S '' -- "${hosts[@]}"
}
_ssm() {
    local cur="${words[$CURRENT]}"
    if [[ "$cur" == *@*:* ]] || { [[ "$cur" == *:* ]] && [[ "$cur" != -* ]]; }; then
        _ssm_complete_remote && return
    fi
    if (( CURRENT == 2 )); then
        _ssm_hosts_group

        local -a _sc_items _sc_descs
        _sc_items=(cp ftp sync)
        _sc_descs=('cp  -- Copy files via SCP' 'ftp  -- Transfer files via SFTP' 'sync -- Synchronize via rsync')
        compadd -V subcommands -X '%F{yellow}-- subcommand --%f' -l -d _sc_descs -- "${_sc_items[@]}"

        local -a _op_items _op_descs
        _op_items=(--list --forget --forget-all --export --import --init --name --help --version)
        _op_descs=('--list       -- List stored credentials and aliases' '--forget     -- Remove a credential or alias' '--forget-all -- Remove all credentials and aliases' '--export     -- Export credentials to file' '--import     -- Import credentials from file' '--init       -- Output shell completion script' '--name       -- Save connection as alias' '--help       -- Show help' '--version    -- Show version')
        compadd -V options -X '%F{yellow}-- option --%f' -l -d _op_descs -- "${_op_items[@]}"
        return
    fi
    local subcmd="${words[2]}"
    case "$subcmd" in
        cp|sync)
            if [[ "$cur" == *:* ]]; then
                _ssm_complete_remote && return
            fi
            _ssm_hosts_group
            _files
            ;;
        ftp)
            _ssm_hosts_group
            _files
            ;;
        --forget)
            local -a hosts
            hosts=("${(@f)$(ssm --_list-hosts 2>/dev/null)}")
            hosts=("${(@)hosts:#}")
            (( ${#hosts} )) && compadd -- "${hosts[@]}"
            ;;
        --export|--import) _files ;;
        *)
            _ssm_hosts_group
            _files
            ;;
    esac
}
compdef _ssm ssm
'''

_COMPLETION_BASH = r'''
_ssm_rc_key=""
_ssm_rc_data=""
_ssm_remote() {
    local fullcur="$1"
    local host_prefix="${fullcur%%:*}:"
    local cached
    if [[ "$fullcur" == "$_ssm_rc_key" ]]; then
        cached="$_ssm_rc_data"
    else
        cached=$(ssm --_complete-remote "$fullcur" 2>/dev/null)
        _ssm_rc_key="$fullcur"
        _ssm_rc_data="$cached"
    fi
    COMPREPLY=()
    [[ -z "$cached" ]] && return
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local p="${line#"$host_prefix"}"
        if [[ "$p" == */ ]]; then
            COMPREPLY+=("$p")
        else
            COMPREPLY+=("$p ")
        fi
    done <<< "$cached"
}
_ssm_get_hosts() {
    local -a hosts=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && hosts+=("$line")
    done < <(ssm --_list-hosts 2>/dev/null)
    echo "${hosts[*]}"
}
_ssm() {
    local cur prev
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    local fullcur
    fullcur="${COMP_LINE:0:$COMP_POINT}"
    fullcur="${fullcur##* }"
    if [[ "$fullcur" == *@*:* ]] || { [[ "$fullcur" == *:* ]] && [[ "$fullcur" != -* ]]; }; then
        _ssm_remote "$fullcur"
        return
    fi
    if [[ $COMP_CWORD -eq 1 ]]; then
        local hosts=$(_ssm_get_hosts)
        COMPREPLY=( $(compgen -W "cp ftp sync --list --forget --forget-all --export --import --init --name --help --version $hosts" -- "$cur") )
        return
    fi
    local subcmd="${COMP_WORDS[1]}"
    case "$subcmd" in
        cp|sync)
            if [[ "$fullcur" == *:* ]]; then
                _ssm_remote "$fullcur"
            else
                local hosts=$(_ssm_get_hosts)
                COMPREPLY=( $(compgen -W "$hosts" -f -- "$cur") )
            fi
            ;;
        --forget)
            local hosts=$(_ssm_get_hosts)
            COMPREPLY=( $(compgen -W "$hosts" -- "$cur") )
            ;;
        --export|--import) COMPREPLY=( $(compgen -f -- "$cur") ) ;;
        *)
            local hosts=$(_ssm_get_hosts)
            COMPREPLY=( $(compgen -W "$hosts" -f -- "$cur") )
            ;;
    esac
}
complete -o nospace -o default -F _ssm ssm
'''


def _detect_shell() -> str:
    """Detect the current shell from $SHELL."""
    shell = os.path.basename(os.environ.get("SHELL", ""))
    if "zsh" in shell:
        return "zsh"
    if "bash" in shell:
        return "bash"
    return ""


def _print_completion_script(shell: str | None = None) -> None:
    """Print the shell completion script to stdout.

    Usage in ~/.zshrc:   eval "$(ssm --init zsh)"
    Usage in ~/.bashrc:  eval "$(ssm --init bash)"
    Auto-detect:         eval "$(ssm --init)"
    """
    if shell is None:
        shell = _detect_shell()

    if shell == "zsh":
        print(_COMPLETION_ZSH.strip())
    elif shell == "bash":
        print(_COMPLETION_BASH.strip())
    else:
        print(
            "ssm: error: cannot detect shell. Specify explicitly:\n"
            '  eval "$(ssm --init zsh)"\n'
            '  eval "$(ssm --init bash)"',
            file=sys.stderr,
        )
        sys.exit(1)


def _handle_management(args: List[str]) -> bool:
    """Handle management flags. Returns True if handled."""
    if not args:
        return False

    if args[0] in ("--help", "-h"):
        _print_usage()
        return True

    if args[0] == "--version":
        print(f"ssm {VERSION}")
        return True

    if args[0] == "--init":
        _print_completion_script(args[1] if len(args) >= 2 else None)
        return True

    if args[0] == "--list":
        store = CredentialStore()
        entries = store.list_all()
        aliases = _load_aliases()
        if entries:
            print("Credentials:")
            for entry in entries:
                print(f"  {entry}")
        if aliases:
            print("Aliases:")
            for name, info in sorted(aliases.items()):
                target = info.get("target", "") if isinstance(info, dict) else ""
                extra = info.get("args", []) if isinstance(info, dict) else []
                desc = " ".join(extra + [target]) if extra else target
                print(f"  {name} -> {desc}")
        if not entries and not aliases:
            print("No stored credentials or aliases.")
        return True

    if args[0] == "--forget":
        targets = args[1:]
        if not targets:
            print("ssm: error: --forget requires one or more USER@HOST or ALIAS arguments.", file=sys.stderr)
            sys.exit(1)
        store = None
        aliases = _load_aliases()
        aliases_changed = False
        for target in targets:
            removed = False
            # Try credential store
            try:
                if store is None:
                    store = CredentialStore()
                if store.remove_by_key(target):
                    print(f"Removed credential: {target}")
                    removed = True
            except (SSHKeyNotFoundError, CredentialStore.DecryptionError) as e:
                print(f"ssm: error: {e}", file=sys.stderr)
            # Try aliases
            if target in aliases:
                del aliases[target]
                aliases_changed = True
                print(f"Removed alias: {target}")
                removed = True
            if not removed:
                print(f"Not found: {target}")
        if aliases_changed:
            _save_aliases(aliases)
        return True

    if args[0] == "--forget-all":
        store = CredentialStore()
        store.clear_all()
        aliases = _load_aliases()
        if aliases:
            _save_aliases({})
        print("All credentials and aliases removed.")
        return True

    if args[0] == "--export" and len(args) >= 2:
        filepath = Path(args[1])
        store = CredentialStore()
        entries = store.list_all()
        if not entries:
            print("No credentials to export.")
            return True
        passphrase = getpass.getpass("Enter passphrase for export file: ")
        if not passphrase:
            print("ssm: error: passphrase cannot be empty.", file=sys.stderr)
            sys.exit(1)
        confirm = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirm:
            print("ssm: error: passphrases do not match.", file=sys.stderr)
            sys.exit(1)
        count = store.export_to_file(filepath, passphrase)
        print(f"Exported {count} credential(s) to {filepath}")
        return True

    if args[0] == "--import":
        overwrite = "--overwrite" in args
        remaining = [a for a in args[1:] if a != "--overwrite"]
        if not remaining:
            print("ssm: error: --import requires a file path.", file=sys.stderr)
            sys.exit(1)
        filepath = Path(remaining[0])
        if not filepath.is_file():
            print(f"ssm: error: file not found: {filepath}", file=sys.stderr)
            sys.exit(1)
        passphrase = getpass.getpass("Enter passphrase for import file: ")
        store = CredentialStore()
        try:
            imported, skipped = store.import_from_file(filepath, passphrase, overwrite=overwrite)
        except ValueError as e:
            print(f"ssm: error: {e}", file=sys.stderr)
            sys.exit(1)
        parts = [f"Imported {imported}"]
        if skipped:
            parts.append(f"skipped {skipped} (already exist, use --overwrite)")
        print(", ".join(parts) + ".")
        return True

    # --- Internal commands for shell completion (hidden from --help) ---

    if args[0] == "--_complete-remote":
        if len(args) >= 2:
            _complete_remote(args[1])
        return True

    if args[0] == "--_list-hosts":
        _list_hosts()
        return True

    return False


def _complete_remote(target: str) -> None:
    """List remote files/directories for shell tab-completion.

    Called by completion scripts via ``ssm --_complete-remote user@host:path``.
    Outputs one completion per line in ``host:path`` format.
    Designed to fail silently — any error produces no output.
    """
    import json
    import tempfile
    from .runner import _resolve_ssm_path

    if ":" not in target:
        return
    host_part, path_part = target.split(":", 1)
    if not host_part:
        return

    # Load credentials — fail silently for completion
    creds: Dict[str, str] = {}
    try:
        store = CredentialStore()
        for key in store.list_all():
            pw = store.lookup_by_key(key)
            if pw:
                creds[key] = pw
    except Exception:
        pass

    # Determine credential key for this host
    if "@" in host_part:
        cred_key = host_part
    else:
        try:
            cred_key = f"{_resolve_ssh_user(host_part)}@{host_part}"
        except Exception:
            cred_key = host_part

    relevant_creds: Dict[str, str] = {}
    if cred_key in creds:
        relevant_creds[cred_key] = creds[cred_key]

    # Shell-safe single-quote helper
    def _sq(s: str) -> str:
        return "'" + s.replace("'", "'\\''") + "'"

    # Build remote ls command
    if not path_part:
        # Empty path → list home directory contents
        remote_cmd = "ls -1p 2>/dev/null"
        path_prefix = ""
    elif path_part.endswith("/"):
        # Directory → list its contents
        remote_cmd = f"ls -1p {_sq(path_part)} 2>/dev/null"
        path_prefix = path_part
    else:
        # Partial name → glob match
        remote_cmd = f"ls -1dp {_sq(path_part)}* 2>/dev/null"
        path_prefix = ""

    # Set up ASKPASS so SSH can authenticate using stored credentials
    askpass_path = _resolve_ssm_path()
    _tmp_prefix = os.path.realpath(tempfile.gettempdir()) + os.sep
    is_temp = os.path.realpath(askpass_path).startswith(_tmp_prefix)

    env = os.environ.copy()
    env["SSH_ASKPASS"] = askpass_path
    env["SSH_ASKPASS_REQUIRE"] = "force"
    env["_SSM_ASKPASS"] = "1"
    env["_SSM_COMPLETION"] = "1"  # suppress /dev/tty fallback in ASKPASS
    if relevant_creds:
        env["_SSM_CREDS"] = json.dumps(relevant_creds)

    cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=5",
        "-o", "LogLevel=ERROR",
        host_part,
        remote_cmd,
    ]

    try:
        result = subprocess.run(
            cmd, env=env,
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.splitlines():
                name = line.strip()
                if name and name not in (".", "..", "./", "../"):
                    print(f"{host_part}:{path_prefix}{name}")
    except Exception:
        pass
    finally:
        if is_temp and os.path.exists(askpass_path):
            try:
                os.unlink(askpass_path)
            except OSError:
                pass


def _list_hosts() -> None:
    """Print known hosts for shell tab-completion.

    Sources (deduplicated, sorted):
    1. Stored credential keys (user@host) from the credential store.
    2. Host names from ~/.ssh/config (excluding wildcard patterns).
    3. Saved aliases.
    """
    hosts: set = set()

    # 1. Credential store — add both "user@host" and bare "host"
    try:
        store = CredentialStore()
        for key in store.list_all():
            hosts.add(key)
            if "@" in key:
                hosts.add(key.split("@", 1)[1])
    except Exception:
        pass

    # 2. ~/.ssh/config Host entries
    try:
        ssh_config = Path.home() / ".ssh" / "config"
        if ssh_config.is_file():
            with open(ssh_config, "r") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped.lower().startswith("host ") and not stripped.startswith("#"):
                        patterns = stripped.split()[1:]
                        for p in patterns:
                            if "*" not in p and "?" not in p and "!" not in p:
                                hosts.add(p)
    except Exception:
        pass

    # 3. Saved aliases
    try:
        aliases = _load_aliases()
        for name in aliases:
            hosts.add(name)
    except Exception:
        pass

    for h in sorted(hosts):
        print(h)


_SSH_VALUE_OPTS = frozenset(
    ["-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J",
     "-l", "-m", "-O", "-o", "-p", "-P", "-Q", "-R", "-S",
     "-W", "-w", "-L"]
)


def _resolve_ssh_user(host: str) -> str:
    """Resolve the effective SSH username for a host via ``ssh -G``.

    ``ssh -G`` prints the resolved configuration (after evaluating Host /
    Match blocks, Include directives, etc.) and exits without connecting.
    Available since OpenSSH 7.6.

    Falls back to the current OS user if ``ssh -G`` is unavailable or fails.
    """
    try:
        result = subprocess.run(
            ["ssh", "-G", host],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.lower().startswith("user "):
                    return line.split(None, 1)[1]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return getpass.getuser()


def _ssh_has_keys(host: str, cleaned_args: List[str]) -> bool:
    """Check if SSH key authentication is likely available for a host.

    When identity keys exist (via ``-i`` flag, ssh-agent, or identity files
    listed by ``ssh -G``), SSH should be allowed to try key auth before we
    prompt the user for a password.
    """
    # 1. Explicit -i identity file on the command line
    for idx, a in enumerate(cleaned_args):
        if a == "-i" and idx + 1 < len(cleaned_args):
            if Path(cleaned_args[idx + 1]).expanduser().is_file():
                return True
        elif a.startswith("-i") and len(a) > 2:
            if Path(a[2:]).expanduser().is_file():
                return True

    # 2. ssh-agent has keys loaded
    if os.environ.get("SSH_AUTH_SOCK"):
        try:
            result = subprocess.run(
                ["ssh-add", "-l"],
                capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    # 3. Identity files configured in SSH config (includes defaults)
    bare_host = host.split("@", 1)[1] if "@" in host else host
    try:
        result = subprocess.run(
            ["ssh", "-G", bare_host],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.lower().startswith("identityfile "):
                    key_path = Path(line.split(None, 1)[1]).expanduser()
                    if key_path.is_file():
                        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return False


def _extract_target_hosts(cleaned_args: List[str], mode: str) -> List[str]:
    """Identify user@host targets from cleaned args that may need credentials.

    OpenSSH's ASKPASS child process cannot reliably prompt the user (it runs
    after setsid(), losing the controlling terminal).  The parent ``ssm``
    process must therefore collect any missing passwords *before* launching
    SSH.  This helper extracts the target hosts so we know what to ask for.

    For bare hostnames (without ``user@``), the effective username is resolved
    from ``~/.ssh/config`` via ``ssh -G``, honouring Host/Match blocks.

    Returns:
        Deduplicated list of ``user@host`` strings.
    """
    hosts: List[str] = []

    # Check for explicit -l user option
    explicit_user: str | None = None
    for idx, a in enumerate(cleaned_args):
        if a == "-l" and idx + 1 < len(cleaned_args):
            explicit_user = cleaned_args[idx + 1]
            break

    def _add_host(token: str) -> None:
        if "@" in token:
            hosts.append(token)
        elif token:
            user = explicit_user or _resolve_ssh_user(token)
            hosts.append(f"{user}@{token}")

    i = 0
    found_target = False

    while i < len(cleaned_args):
        arg = cleaned_args[i]

        # -J / jump hosts
        if arg == "-J" and i + 1 < len(cleaned_args):
            for part in cleaned_args[i + 1].split(","):
                _add_host(part.strip())
            i += 2
            continue
        if arg.startswith("-J") and len(arg) > 2:
            for part in arg[2:].split(","):
                _add_host(part.strip())
            i += 1
            continue

        # -o ProxyJump=...
        if arg == "-o" and i + 1 < len(cleaned_args):
            nxt = cleaned_args[i + 1]
            if nxt.startswith("ProxyJump="):
                for part in nxt[len("ProxyJump="):].split(","):
                    _add_host(part.strip())
            i += 2
            continue
        if arg.startswith("-oProxyJump="):
            for part in arg[len("-oProxyJump="):].split(","):
                _add_host(part.strip())
            i += 1
            continue

        # Skip option + value pairs
        if arg in _SSH_VALUE_OPTS and i + 1 < len(cleaned_args):
            i += 2
            continue

        # Skip flags
        if arg.startswith("-"):
            i += 1
            continue

        # --- Positional argument ---
        if mode in ("ssh", "sftp"):
            if not found_target:
                _add_host(arg)
                found_target = True
            break  # remaining args are the remote command
        elif mode in ("scp", "rsync"):
            # Remote paths look like  user@host:/path  or  host:/path
            if ":" in arg and not arg.startswith("/") and not arg.startswith("."):
                remote_part = arg.split(":")[0]
                _add_host(remote_part)
        i += 1

    # Deduplicate preserving order
    seen: set[str] = set()
    unique: List[str] = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            unique.append(h)
    return unique


def ssm_main() -> None:
    """Main entry point for the `ssm` command."""
    # --- Mode 1: ASKPASS helper (called by SSH) ---
    if os.environ.get("_SSM_ASKPASS") == "1":
        handle_askpass()
        return

    # --- Mode 2: Main command ---
    args = sys.argv[1:]

    # Handle management and help flags
    if _handle_management(args):
        return

    if not args:
        _print_usage()
        return

    # --- Extract --name NAME (alias save) from args ---
    alias_name: Optional[str] = None
    filtered_args: List[str] = []
    i = 0
    while i < len(args):
        if args[i] == "--name" and i + 1 < len(args):
            alias_name = args[i + 1]
            i += 2
            continue
        if args[i].startswith("--name="):
            alias_name = args[i][len("--name="):]
            i += 1
            continue
        filtered_args.append(args[i])
        i += 1
    args = filtered_args

    # --- Resolve alias if the first positional arg matches a saved alias ---
    # Only when there's no subcommand and the first non-flag arg isn't a
    # known subcommand or management flag.
    if alias_name is None:  # Not creating an alias — try resolving one
        first_pos = None
        first_pos_idx = None
        for idx, a in enumerate(args):
            if not a.startswith("-"):
                first_pos = a
                first_pos_idx = idx
                break
        if first_pos and first_pos not in SUBCOMMANDS:
            expanded = _resolve_alias(first_pos)
            if expanded is not None:
                # Replace the alias name with expanded args
                args = args[:first_pos_idx] + expanded + args[first_pos_idx + 1:]

    # Determine subcommand
    subcmd = None
    subcmd_args = args

    # Check if first non-flag arg is a subcommand
    for i, arg in enumerate(args):
        if not arg.startswith("-"):
            if arg in SUBCOMMANDS:
                subcmd = arg
                subcmd_args = args[i + 1 :]
            break

    if subcmd:
        binary, mode = SUBCOMMANDS[subcmd]
    else:
        binary = "ssh"
        mode = "ssh"
        subcmd_args = args

    # Parse arguments: extract credentials, clean args
    result = parse_args(subcmd_args, mode=mode)

    # Save any new credentials provided on the command line
    if result.credentials:
        try:
            store = CredentialStore()
            store.save_many(result.credentials)
        except (SSHKeyNotFoundError, CredentialStore.DecryptionError) as e:
            print(f"ssm: error: {e}", file=sys.stderr)

    # Load stored credentials for ASKPASS to use
    all_creds: Dict[str, str] = dict(result.credentials)
    try:
        store = CredentialStore()
        for key in store.list_all():
            if key not in all_creds:
                password = store.lookup_by_key(key)
                if password:
                    all_creds[key] = password
    except (SSHKeyNotFoundError, CredentialStore.DecryptionError):
        pass

    # --- Pre-prompt for missing credentials ----------------------------------
    # The ASKPASS child process runs after setsid() and cannot access /dev/tty
    # to prompt the user interactively.  We therefore ask for any missing
    # passwords HERE (in the parent, which owns the terminal) before launching
    # SSH.  Prompted passwords are saved only after a successful connection.
    target_hosts = _extract_target_hosts(result.cleaned_args, mode)
    prompted_creds: Dict[str, str] = {}

    for host_key in target_hosts:
        if host_key not in all_creds:
            if _ssh_has_keys(host_key, result.cleaned_args):
                continue
            try:
                password = getpass.getpass(f"{host_key}'s password: ")
            except (EOFError, KeyboardInterrupt):
                print()
                sys.exit(130)
            if password:
                all_creds[host_key] = password
                prompted_creds[host_key] = password

    # Auto-accept new (never-seen) host keys so that SSH_ASKPASS mode works.
    # SSH's host key verification bypasses SSH_ASKPASS entirely (reads TTY
    # directly), which fails under SSH_ASKPASS_REQUIRE=force.
    # StrictHostKeyChecking=accept-new (OpenSSH 7.6+) auto-accepts new hosts
    # but still rejects CHANGED keys (MITM protection).
    # Check if the user explicitly set StrictHostKeyChecking via -o.
    # Match exact option forms to avoid false positives from hostnames
    # or other arguments that happen to contain the string.
    user_set_strict = False
    for idx, a in enumerate(result.cleaned_args):
        if a == "-o" and idx + 1 < len(result.cleaned_args):
            if result.cleaned_args[idx + 1].startswith("StrictHostKeyChecking"):
                user_set_strict = True
                break
        elif a.startswith("-oStrictHostKeyChecking"):
            user_set_strict = True
            break

    # Build command
    if mode == "rsync":
        if "-e" not in result.cleaned_args:
            ssh_e = (
                "ssh"
                if user_set_strict
                else "ssh -o StrictHostKeyChecking=accept-new"
            )
            cmd = [binary, "-e", ssh_e] + result.cleaned_args
        elif not user_set_strict:
            # User provided -e but didn't set StrictHostKeyChecking;
            # append our option to their -e value.
            patched_args = list(result.cleaned_args)
            for idx, a in enumerate(patched_args):
                if a == "-e" and idx + 1 < len(patched_args):
                    patched_args[idx + 1] += " -o StrictHostKeyChecking=accept-new"
                    break
            cmd = [binary] + patched_args
        else:
            cmd = [binary] + result.cleaned_args
    elif user_set_strict:
        cmd = [binary] + result.cleaned_args
    else:
        cmd = [binary, "-o", "StrictHostKeyChecking=accept-new"] + result.cleaned_args

    # Only pass relevant credentials to the ASKPASS child process
    # (target hosts + jump hosts), not the entire credential store.
    relevant_creds: Dict[str, str] = {}
    for host_key in target_hosts:
        if host_key in all_creds:
            relevant_creds[host_key] = all_creds[host_key]

    # Execute
    exit_code = run_command(cmd, credentials=relevant_creds)

    # Save prompted passwords only after a successful connection,
    # so typos don't get persisted.
    if exit_code == 0 and prompted_creds:
        try:
            store = CredentialStore()
            store.save_many(prompted_creds)
        except (SSHKeyNotFoundError, CredentialStore.DecryptionError) as e:
            print(f"ssm: error: cannot save credentials: {e}", file=sys.stderr)

    # Save alias after connection (regardless of exit code — the alias
    # records the user's *intent*, not whether the connection succeeded).
    if alias_name:
        # Reconstruct the original args (without --name) for storage.
        # Store the subcommand prefix (cp/ftp/sync) as part of args if present.
        alias_args_list: List[str] = []
        alias_target = ""
        stored_args = args  # args after --name removal and alias expansion

        if subcmd:
            # For subcommands, store: {"target": "", "args": ["cp", ...rest]}
            alias_args_list = [subcmd] + list(subcmd_args)
        else:
            # For plain SSH: separate target from other args.
            # Must skip option+value pairs (e.g. -p 2222) to find the
            # actual target hostname.
            skip_next = False
            for idx_a, a in enumerate(subcmd_args):
                if skip_next:
                    alias_args_list.append(a)
                    skip_next = False
                    continue
                if a in _SSH_VALUE_OPTS:
                    alias_args_list.append(a)
                    skip_next = True
                    continue
                if a.startswith("-"):
                    alias_args_list.append(a)
                    continue
                if not alias_target:
                    alias_target = a
                else:
                    alias_args_list.append(a)

        entry = {"target": alias_target, "args": alias_args_list}
        aliases = _load_aliases()
        aliases[alias_name] = entry
        _save_aliases(aliases)
        print(f"Alias saved: {alias_name} -> {' '.join(alias_args_list + [alias_target]).strip()}")

    sys.exit(exit_code)
