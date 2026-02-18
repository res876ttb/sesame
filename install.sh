#!/bin/sh
# sesame installer — zero dependencies, no pip needed.
# Creates a lightweight `ssm` wrapper in ~/.local/bin/

set -e

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
WRAPPER="${BIN_DIR}/ssm"

mkdir -p "$BIN_DIR"

# Use /usr/bin/env python3 so the wrapper resolves python3 at runtime,
# not at install time.  This avoids breakage when Python is upgraded.
cat > "$WRAPPER" <<EOF
#!/usr/bin/env python3
import sys
sys.path.insert(0, '${REPO_DIR}/src')
from sesame.cli import ssm_main
ssm_main()
EOF

chmod +x "$WRAPPER"

echo "Installed: ${WRAPPER}"

# Check if ~/.local/bin is in PATH
case ":${PATH}:" in
  *":${BIN_DIR}:"*) ;;
  *)
    echo ""
    echo "NOTE: ${BIN_DIR} is not in your PATH."
    echo "Add this to your shell rc file (~/.zshrc or ~/.bashrc):"
    echo ""
    echo "  export PATH=\"\${HOME}/.local/bin:\${PATH}\""
    ;;
esac

echo ""
echo "To enable tab completion, add to your shell rc file:"
echo ""
echo '  eval "$(ssm --init)"'
echo ""
