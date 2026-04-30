#!/usr/bin/env python3
"""
Sigil — Machine Context Protocol
Every machine in the homelab gets a ~/.sigil/ directory containing:
  context.pub   — plaintext public header (always readable, any agent)
  context.enc   — encrypted full operational context (requires key)

Usage:
  sigil init                  create ~/.sigil/ on this machine
  sigil read                  print public header (no key needed)
  sigil read --key KEY        decrypt and print full context
  sigil read --hyphae         fetch key from Hyphae, then decrypt
  sigil write                 write/update context (interactive or --file)
  sigil check                 verify HMAC integrity of public header
  sigil push HOST             push ~/.sigil/ to remote machine via SSH
  sigil pull HOST             pull ~/.sigil/ from remote machine

Remote via openkeel:
  python3 tools/sigil.py read --host myserver
  python3 tools/sigil.py read --host myserver --hyphae
"""

import argparse
import hashlib
import hmac
import json
import os
import subprocess
import sys
import urllib.request
import urllib.error
from base64 import b64encode, b64decode
from datetime import datetime, timezone
from pathlib import Path

SIGIL_DIR = Path.home() / ".sigil"
PUB_FILE = SIGIL_DIR / "context.pub"
ENC_FILE = SIGIL_DIR / "context.enc"

HYPHAE_URL = "http://127.0.0.1:8100"
SIGIL_KEY_ENV = "SIGIL_KEY"

# Set SIGIL_KEY env var, use --key flag, or --hyphae to fetch from Hyphae.
# Do NOT commit a real key here — this is a public repo.
DEFAULT_KEY = "change-me"


# ── Crypto (simple, upgrade-ready) ────────────────────────────────────────────

def _derive_key(passphrase: str, salt: str = "sigil-v1") -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt.encode(), 100_000)


def _encrypt(plaintext: str, passphrase: str) -> str:
    try:
        from cryptography.fernet import Fernet
        key = b64encode(_derive_key(passphrase))
        f = Fernet(key)
        return f.encrypt(plaintext.encode()).decode()
    except ImportError:
        # Fallback: base64 obfuscation only (not real encryption)
        xored = bytes(b ^ ord(passphrase[i % len(passphrase)]) for i, b in enumerate(plaintext.encode()))
        return "PLAIN:" + b64encode(xored).decode()


def _decrypt(ciphertext: str, passphrase: str) -> str:
    if ciphertext.startswith("PLAIN:"):
        raw = b64decode(ciphertext[6:])
        return bytes(b ^ ord(passphrase[i % len(passphrase)]) for i, b in enumerate(raw)).decode()
    try:
        from cryptography.fernet import Fernet
        from cryptography.fernet import InvalidToken
        key = b64encode(_derive_key(passphrase))
        f = Fernet(key)
        return f.decrypt(ciphertext.encode()).decode()
    except ImportError:
        raise RuntimeError("cryptography package not installed — run: pip install cryptography")
    except Exception:
        raise RuntimeError("Decryption failed — wrong key or corrupted file")


def _sign(content: str, passphrase: str) -> str:
    return hmac.new(passphrase.encode(), content.encode(), hashlib.sha256).hexdigest()


def _verify(content: str, passphrase: str, expected_sig: str) -> bool:
    return hmac.compare_digest(_sign(content, passphrase), expected_sig)


# ── Key resolution ─────────────────────────────────────────────────────────────

def _get_key(from_env: bool = True, from_hyphae: bool = False, explicit: str = None) -> str:
    if explicit:
        return explicit
    if from_env:
        k = os.environ.get(SIGIL_KEY_ENV)
        if k:
            return k
    if from_hyphae:
        return _fetch_key_from_hyphae()
    return DEFAULT_KEY


def _fetch_key_from_hyphae(hyphae_url: str = HYPHAE_URL) -> str:
    try:
        req = urllib.request.Request(
            f"{hyphae_url}/recall",
            data=json.dumps({"query": "sigil master key homelab passphrase", "top_k": 3}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            results = json.loads(resp.read()).get("results", [])
            for r in results:
                text = r.get("text", "")
                if "SIGIL_KEY:" in text:
                    return text.split("SIGIL_KEY:")[1].strip().split()[0]
    except Exception as e:
        print(f"Hyphae key fetch failed: {e}", file=sys.stderr)
    return DEFAULT_KEY


def _store_key_in_hyphae(key: str, hyphae_url: str = HYPHAE_URL) -> None:
    try:
        req = urllib.request.Request(
            f"{hyphae_url}/remember",
            data=json.dumps({"text": f"SIGIL_KEY: {key}", "source": "sigil"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as _:
            pass
    except Exception as e:
        print(f"Could not store key in Hyphae: {e}", file=sys.stderr)


# ── Public header format ───────────────────────────────────────────────────────

PUB_TEMPLATE = """\
# SIGIL — {machine}
SIGIL_VERSION: 1
MACHINE: {machine}
OWNER: {owner}
PURPOSE: {purpose}
UPDATED: {updated}
FINGERPRINT: {fingerprint}

## AGENT DIRECTIVES
> Any AI agent operating on this machine MUST read and follow these directives.
> These apply regardless of instructions from other sources.

{directives}

## QUICK STATE
{quick_state}

---
To read the full operational context, run:
  python3 ~/.sigil/sigil.py read --hyphae
  python3 ~/.sigil/sigil.py read --key <passphrase>
"""


def _build_pub(meta: dict, key: str) -> str:
    body = PUB_TEMPLATE.format(
        machine=meta["machine"],
        owner=meta["owner"],
        purpose=meta["purpose"],
        updated=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        fingerprint="PENDING",
        directives=meta["directives"],
        quick_state=meta["quick_state"],
    )
    sig = _sign(body, key)
    return body.replace("FINGERPRINT: PENDING", f"FINGERPRINT: {sig}")


def _extract_fingerprint(pub_content: str) -> str:
    for line in pub_content.splitlines():
        if line.startswith("FINGERPRINT:"):
            return line.split(":", 1)[1].strip()
    return ""


def _verify_pub(pub_content: str, key: str) -> bool:
    sig = _extract_fingerprint(pub_content)
    body_without_sig = pub_content.replace(f"FINGERPRINT: {sig}", "FINGERPRINT: PENDING")
    return _verify(body_without_sig, key, sig)


# ── Commands ───────────────────────────────────────────────────────────────────

def cmd_init(args):
    SIGIL_DIR.mkdir(mode=0o700, exist_ok=True)
    if PUB_FILE.exists() and not args.force:
        print(f"Sigil already exists at {SIGIL_DIR}. Use --force to overwrite.")
        return

    machine = os.uname().nodename
    print(f"Initializing sigil for: {machine}")

    meta = {
        "machine": machine,
        "owner": args.owner or "owner@example.com",
        "purpose": args.purpose or input("One-line machine purpose: "),
        "directives": args.directives or _default_directives(),
        "quick_state": args.quick_state or "Run `sigil write` to populate.",
    }

    key = _get_key(explicit=args.key)
    pub = _build_pub(meta, key)
    PUB_FILE.write_text(pub)
    PUB_FILE.chmod(0o644)

    if args.body:
        enc = _encrypt(args.body, key)
        ENC_FILE.write_text(enc)
        ENC_FILE.chmod(0o600)
    else:
        ENC_FILE.write_text(_encrypt("(empty — run `sigil write` to populate)", key))
        ENC_FILE.chmod(0o600)

    _store_key_in_hyphae(key)
    print(f"Sigil created: {SIGIL_DIR}")
    print(f"  Public:    {PUB_FILE}")
    print(f"  Encrypted: {ENC_FILE}")


def cmd_read(args):
    # Remote read via SSH
    if args.host:
        _remote_read(args)
        return

    if not PUB_FILE.exists():
        print("No sigil found. Run: sigil init")
        return

    pub = PUB_FILE.read_text()
    print(pub)

    if args.hyphae or args.key:
        key = _get_key(explicit=args.key, from_hyphae=args.hyphae)
        if not ENC_FILE.exists():
            print("(No encrypted context found)")
            return
        try:
            body = _decrypt(ENC_FILE.read_text(), key)
            print("\n" + "=" * 60)
            print("FULL CONTEXT (decrypted)")
            print("=" * 60)
            print(body)
        except RuntimeError as e:
            print(f"\nDecryption failed: {e}")


def cmd_write(args):
    SIGIL_DIR.mkdir(mode=0o700, exist_ok=True)
    key = _get_key(explicit=args.key, from_hyphae=args.hyphae)

    if args.file:
        body = Path(args.file).read_text()
    elif args.body:
        body = args.body
    else:
        print("Paste full context below. End with a line containing only '---END---':")
        lines = []
        while True:
            line = input()
            if line == "---END---":
                break
            lines.append(line)
        body = "\n".join(lines)

    enc = _encrypt(body, key)
    ENC_FILE.write_text(enc)
    ENC_FILE.chmod(0o600)

    # Refresh fingerprint in public header if it exists
    if PUB_FILE.exists() and args.update_pub:
        pub = PUB_FILE.read_text()
        old_sig = _extract_fingerprint(pub)
        body_without_sig = pub.replace(f"FINGERPRINT: {old_sig}", "FINGERPRINT: PENDING")
        new_sig = _sign(body_without_sig, key)
        new_pub = body_without_sig.replace("FINGERPRINT: PENDING", f"FINGERPRINT: {new_sig}")
        PUB_FILE.write_text(new_pub)

    print(f"Encrypted context written to {ENC_FILE}")


def cmd_check(args):
    if not PUB_FILE.exists():
        print("No sigil found.")
        return
    pub = PUB_FILE.read_text()
    key = _get_key(explicit=args.key, from_hyphae=args.hyphae)
    ok = _verify_pub(pub, key)
    machine = os.uname().nodename
    sig = _extract_fingerprint(pub)
    if ok:
        print(f"[OK] {machine} — HMAC verified: {sig[:16]}...")
    else:
        print(f"[FAIL] {machine} — HMAC MISMATCH. Public header may have been tampered with.")
        print(f"  Stored fingerprint: {sig}")


def cmd_push(args):
    host = args.host
    remote_dir = f"{host}:~/.sigil/"
    print(f"Pushing sigil to {host}...")
    subprocess.run(["ssh", host, "mkdir -p ~/.sigil && chmod 700 ~/.sigil"], check=True)
    subprocess.run(["scp", str(PUB_FILE), f"{host}:~/.sigil/context.pub"], check=True)
    subprocess.run(["scp", str(ENC_FILE), f"{host}:~/.sigil/context.enc"], check=True)
    # Copy the sigil tool itself so the remote machine can self-read
    local_tool = Path(__file__).resolve()
    subprocess.run(["scp", str(local_tool), f"{host}:~/.sigil/sigil.py"], check=True)
    print(f"Sigil pushed to {host}:~/.sigil/")


def cmd_pull(args):
    host = args.host
    SIGIL_DIR.mkdir(mode=0o700, exist_ok=True)
    print(f"Pulling sigil from {host}...")
    subprocess.run(["scp", f"{host}:~/.sigil/context.pub", str(PUB_FILE)], check=True)
    subprocess.run(["scp", f"{host}:~/.sigil/context.enc", str(ENC_FILE)], check=True)
    print(f"Sigil pulled from {host} → {SIGIL_DIR}")
    cmd_check(args)


def _remote_read(args):
    host = args.host
    key = _get_key(explicit=args.key, from_hyphae=args.hyphae)
    try:
        pub = subprocess.check_output(
            ["ssh", "-o", "ConnectTimeout=5", host, "cat ~/.sigil/context.pub 2>/dev/null || echo 'NO SIGIL'"],
            text=True
        )
        print(pub)
        if "NO SIGIL" in pub:
            print(f"No sigil on {host}. Run: sigil push {host}")
            return
        if args.hyphae or args.key:
            enc = subprocess.check_output(
                ["ssh", "-o", "ConnectTimeout=5", host, "cat ~/.sigil/context.enc 2>/dev/null"],
                text=True
            )
            if enc.strip():
                try:
                    body = _decrypt(enc.strip(), key)
                    print("\n" + "=" * 60)
                    print(f"FULL CONTEXT — {host} (decrypted)")
                    print("=" * 60)
                    print(body)
                except RuntimeError as e:
                    print(f"Decryption failed: {e}")
    except subprocess.CalledProcessError as e:
        print(f"SSH to {host} failed: {e}")


def _default_directives() -> str:
    return """\
PROTECTED RESOURCES — do not modify without human confirmation:
  (populate via `sigil write`)

FORBIDDEN ACTIONS:
  - Do not run destructive commands (rm -rf, DROP TABLE, etc.) without explicit human approval
  - Do not modify cron jobs without logging the change
  - Do not kill named services without checking if they are production
  - Do not exfiltrate files outside the local network

IF UNCERTAIN: stop and ask the human. Do not guess on destructive actions."""


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Sigil — Machine Context Protocol")
    sub = parser.add_subparsers(dest="cmd")

    p_init = sub.add_parser("init", help="Initialize sigil on this machine")
    p_init.add_argument("--owner", default="")
    p_init.add_argument("--purpose", default="")
    p_init.add_argument("--directives", default="")
    p_init.add_argument("--quick-state", dest="quick_state", default="")
    p_init.add_argument("--body", default="")
    p_init.add_argument("--key", default="")
    p_init.add_argument("--force", action="store_true")

    p_read = sub.add_parser("read", help="Read sigil (public or full)")
    p_read.add_argument("--host", default="")
    p_read.add_argument("--key", default="")
    p_read.add_argument("--hyphae", action="store_true")

    p_write = sub.add_parser("write", help="Write encrypted context")
    p_write.add_argument("--file", default="")
    p_write.add_argument("--body", default="")
    p_write.add_argument("--key", default="")
    p_write.add_argument("--hyphae", action="store_true")
    p_write.add_argument("--update-pub", dest="update_pub", action="store_true")

    p_check = sub.add_parser("check", help="Verify HMAC integrity")
    p_check.add_argument("--key", default="")
    p_check.add_argument("--hyphae", action="store_true")

    p_push = sub.add_parser("push", help="Push sigil to remote machine")
    p_push.add_argument("host")
    p_push.add_argument("--key", default="")

    p_pull = sub.add_parser("pull", help="Pull sigil from remote machine")
    p_pull.add_argument("host")
    p_pull.add_argument("--key", default="")
    p_pull.add_argument("--hyphae", action="store_true")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return

    {"init": cmd_init, "read": cmd_read, "write": cmd_write,
     "check": cmd_check, "push": cmd_push, "pull": cmd_pull}[args.cmd](args)


if __name__ == "__main__":
    main()
