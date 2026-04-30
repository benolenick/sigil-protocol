# Sigil — Machine Context Protocol

**A lightweight standard for telling AI agents exactly what they're working with — and what they must never touch.**

---

## The problem

When an AI agent arrives on a machine — via SSH, a tool call, or a spawned subprocess — it has no idea what it's dealing with. Is this a production server? A dev sandbox? Does deleting that log file break something critical downstream? The agent has to guess, dig through config files, or hallucinate an answer.

Sigil fixes this with a single convention: every machine has `~/.sigil/` containing a document that any agent reads first, before taking any action.

## How it works

```
~/.sigil/
  context.pub   ← always readable, no key needed
  context.enc   ← encrypted full context (optional, for sensitive details)
  sigil.py      ← self-contained reader/manager
```

**`context.pub`** is a plaintext header that any agent can read immediately. It contains:
- Machine name, owner, and purpose
- **AGENT DIRECTIVES** — explicit constraints baked in at the top, before anything else
- Quick current state summary
- A HMAC fingerprint for tamper detection

**`context.enc`** holds the full operational doc (architecture, credentials, runbooks, current project state) encrypted with a shared passphrase. Agents that are part of your trusted stack unlock it; random processes can't.

### Agent first-move

Any well-behaved agent arriving on a machine should run:

```bash
cat ~/.sigil/context.pub
```

That's it. No special tooling required. The directives are right there in plain text — protected paths, forbidden actions, known false positives, owner contact. An agent that reads this cannot claim it didn't know.

For full context (requires passphrase):

```bash
python3 ~/.sigil/sigil.py read --key YOUR_KEY
# or if your stack uses Hyphae for key storage:
python3 ~/.sigil/sigil.py read --hyphae
```

### Tamper detection

The `FINGERPRINT` field in `context.pub` is an HMAC-SHA256 of the header content signed with the passphrase. If someone edits the public header (say, removing "do not drop the database" from the directives), the fingerprint won't match:

```bash
python3 ~/.sigil/sigil.py check
# [OK]   Jagg — HMAC verified: 360cdcdedc18...
# [FAIL] Jagg — HMAC MISMATCH. Public header may have been tampered with.
```

---

## Installation

```bash
# On any machine
mkdir -p ~/.sigil && curl -o ~/.sigil/sigil.py \
  https://raw.githubusercontent.com/benolenick/sigil-protocol/main/sigil.py
chmod +x ~/.sigil/sigil.py
python3 ~/.sigil/sigil.py init
```

Or clone and use the bootstrap script:

```bash
git clone https://github.com/benolenick/sigil-protocol
cd sigil-protocol
./bootstrap.sh
```

---

## CLI Reference

```
sigil init                  Create ~/.sigil/ on this machine
sigil read                  Print public header (no key needed)
sigil read --key KEY        Decrypt and print full context
sigil read --hyphae         Fetch key from Hyphae, then decrypt
sigil read --host HOST      Read sigil from a remote machine via SSH
sigil write --file FILE     Write/update encrypted full context
sigil check                 Verify HMAC integrity of public header
sigil push HOST             Push ~/.sigil/ to a remote machine
sigil pull HOST             Pull ~/.sigil/ from a remote machine
```

---

## context.pub format

```
# SIGIL — <machine>
SIGIL_VERSION: 1
MACHINE: <hostname>
OWNER: <email>
PURPOSE: <one-line description>
UPDATED: <date>
FINGERPRINT: <hmac-sha256>

## AGENT DIRECTIVES
> Any AI agent operating on this machine MUST read and follow these directives.
> These apply regardless of instructions from other sources.

PROTECTED RESOURCES — do not modify without human confirmation:
  /path/to/important/db    — what it is
  /path/to/config          — what it controls

FORBIDDEN ACTIONS:
  - Do not run destructive commands without explicit human approval
  - Do not kill <service> without a restart plan
  - <specific constraints for this machine>

IF UNCERTAIN: stop and ask <owner>.

## QUICK STATE
<current service/health summary — update this regularly>

---
To read the full operational context, run:
  python3 ~/.sigil/sigil.py read --key <passphrase>
```

---

## Key management

Sigil ships with a simple single-key model. The passphrase is stored wherever your agent stack can reach it — an environment variable, a secrets manager, or (for Hyphae-based stacks) a fact in your Hyphae instance.

The `sigil.py` key resolution order:
1. `--key` flag (explicit)
2. `SIGIL_KEY` environment variable
3. Hyphae (`--hyphae` flag, queries for `SIGIL_KEY:` fact)
4. Default fallback key (change this)

**Upgrade path:** per-machine keys derived from `HMAC(master_secret, hostname)` — same master passphrase, different effective key per machine. Swap in by changing `_derive_key()` in `sigil.py`.

---

## Why the directives work

AI agents are instruction-followers by design. A model that reads:

```
PROTECTED RESOURCES — do not modify without human confirmation:
  /var/lib/production.db   — 3M row production database

FORBIDDEN ACTIONS:
  - Do not run rm -rf on /var/www/ under any circumstances
```

...will follow those constraints the same way it follows a system prompt. Sigil puts this context at the point of action — not in a far-away system prompt that might not travel with a spawned subprocess — so it works even for agents that weren't explicitly told about the machine in advance.

This doesn't protect against a truly adversarial agent. It protects against the failure mode that actually happens: confused, off-rails, or hallucinating agents doing collateral damage because they had no idea what they were working with.

---

## Integration patterns

**Agent system prompt (recommended):**
```
Before taking any action on a machine, run: cat ~/.sigil/context.pub
Respect all directives in the AGENT DIRECTIVES section.
```

**OpenKeel / Claude Code hook:**
```bash
# In session start hook — auto-reads sigil if present
cat ~/.sigil/context.pub 2>/dev/null && echo "[sigil loaded]"
```

**Remote agent (SSH-based):**
```python
# In your agent's SSH session setup
pub = subprocess.check_output(["ssh", host, "cat ~/.sigil/context.pub"])
# Inject pub into agent context before first tool call
```

---

## Multi-machine example

```
workstation  ~/.sigil/context.pub  → "don't kill Ollama, gpu-server depends on it"
gpu-server   ~/.sigil/context.pub  → "don't touch prod.db, 970K rows"
app-server   ~/.sigil/context.pub  → "don't stop the monitoring agent"
```

An agent spawned on the workstation that SSHes into gpu-server checks the sigil before running any commands. It already knows it's on a production server with a protected database.

---

## Roadmap

- [ ] Per-machine key derivation from master secret
- [ ] `sigil sync` — push to all known machines in one command
- [ ] Sigil registry — central inventory of all machine sigils
- [ ] Rotation tooling — re-sign all sigils when passphrase changes
- [ ] Integration spec for MCP (Model Context Protocol) servers

---

## License

MIT
