#!/usr/bin/env bash
# Sigil bootstrap — run on any machine to initialize its sigil
set -e

SIGIL_DIR="$HOME/.sigil"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Sigil — Machine Context Protocol"
echo "================================="
echo "Bootstrapping on: $(hostname)"
echo ""

# Create ~/.sigil/
mkdir -p "$SIGIL_DIR"
chmod 700 "$SIGIL_DIR"

# Copy sigil.py to ~/.sigil/ so it's self-contained on the machine
cp "$SCRIPT_DIR/sigil.py" "$SIGIL_DIR/sigil.py"
chmod 755 "$SIGIL_DIR/sigil.py"

# Check for cryptography package (optional, falls back to XOR obfuscation)
if python3 -c "from cryptography.fernet import Fernet" 2>/dev/null; then
    echo "[ok] cryptography package available (Fernet encryption)"
else
    echo "[warn] cryptography package not installed — using XOR obfuscation"
    echo "       Install for real encryption: pip install cryptography"
fi

# Key: prefer SIGIL_KEY env, else prompt
if [ -z "$SIGIL_KEY" ]; then
    echo ""
    read -rsp "Sigil passphrase (leave blank to use default): " SIGIL_KEY
    echo ""
    if [ -z "$SIGIL_KEY" ]; then
        echo "[warn] No key set. Using placeholder — run: sigil write --key YOUR_KEY to re-encrypt."
        SIGIL_KEY="change-me"
    fi
fi

echo ""
echo "Initializing sigil..."
python3 "$SIGIL_DIR/sigil.py" init --key "$SIGIL_KEY"

echo ""
echo "Done. Your sigil:"
echo ""
python3 "$SIGIL_DIR/sigil.py" read

echo ""
echo "Next steps:"
echo "  1. Edit ~/.sigil/context.pub to add machine-specific AGENT DIRECTIVES"
echo "  2. Run: python3 ~/.sigil/sigil.py write --file your_context.md"
echo "  3. Add to agent system prompts: 'Run cat ~/.sigil/context.pub before acting'"
