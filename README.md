# Agentic Shell Layer (`ash`)

[![Build & Test](https://img.shields.io/badge/tests-48%20passed-brightgreen.svg)]()
[![Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)]()
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)]()

> A semantic shell layer that runs inside any existing terminal emulator. It gives the terminal what it lacks: a structured model of commands, an open protocol for describing them, and a safety layer that makes both humans and AI agents safe to run with real privileges.

---

## Architecture

```
Emulator (Ghostty / WezTerm / kitty / iTerm2 / Windows Terminal / etc.)
  └─ ashd: PTY proxy + event bus + policy engine (per-session daemon)
       ├─ shell hook (zsh / bash / fish) → emits block events on private fd
       ├─ agent runner (`ash run <agent>`) → wraps agent CLIs under unified policy
       ├─ sandbox backend (Landlock + seccomp on Linux; Seatbelt on macOS)
       ├─ snapshot backend (git stash / file-level CoW / APFS clone)
       ├─ audit log (hash-chained JSONL with SHA-256 tamper-evidence)
       └─ a11y bridge → AT-SPI / UIA / NSAccessibility semantic landmarks
```

---

## Key Components

### 1. `ashd` (Daemon)
- **PTY Proxy & Sanitizer:** Intercepts output to sanitize in-band OSC 133 sequences from untrusted programs (spoofing prevention).
- **Block Protocol:** Tracks lifecycle of commands (`prompt` → `input` → `pending` → `running` → `done`).
- **Event Bus:** Emits JSON Lines over a Unix domain socket (`$XDG_RUNTIME_DIR/ash/<session>.sock`, permissions `0600`).
- **Policy Engine:** Evaluates declarative TOML rules with risk tiering (T0 Read-only, T1 Reversible write, T2 Irreversible local, T3 External side effects).
- **Snapshot Engine:** Automatic snapshots before reversible actions; supports instant `/undo`.
- **Audit Logger:** Hash-chained JSONL audit trail with automated secret redaction.

### 2. `ash` (CLI)
- `ash run <agent> [flags]`: Wraps any agent CLI (`claude`, `gemini`, `codex`) under unified policy.
- `ash undo [block-id]`: Reverts the last reversible command or a specific block.
- `ash diff [block-id]`: Shows what files changed in a block.
- `ash log`: Views the tamper-evident audit log with risk-tier badges.
- `ash verify`: Verifies the cryptographic integrity of the audit log hash chain.
- `ash approve <block-id>` / `ash deny <block-id>`: Human-in-the-loop gates for T2/T3 commands.
- `ash policy explain <command>`: Explains why a command receives a specific policy decision.
- `ash init [--trust]`: Initializes `.ash/policy.toml` in a project with trust-on-first-use controls.
- `ash hook <zsh|bash|fish>`: Emits the shell integration script.

### 3. Shell Hooks
- **Zsh:** `shell-hooks/ash.zsh`
- **Bash:** `shell-hooks/ash.bash`
- **Fish:** `shell-hooks/ash.fish`

Shell builtins: `/undo`, `/diff`, `/explain`, `/approve`, `/deny`.

---

## Building and Testing

```bash
# Build debug binaries
cargo build

# Run complete test suite (unit + integration tests)
cargo test

# Build optimized release binaries
cargo build --release
```

Binaries produced:
- `target/release/ashd`: Core daemon
- `target/release/ash`: CLI tool

---

## Quick Start

### 1. Shell Integration
Add to your `~/.zshrc` (or `~/.bashrc` / `~/.config/fish/config.fish`):
```bash
eval "$(ash hook zsh)"
```

### 2. Project Policy Setup
```bash
cd your-project
ash init --trust
```
This generates `.ash/policy.toml` configured to allow safe agent writes within the project while locking down external secrets and sensitive paths.

### 3. Running an Agent Safely
```bash
ash run claude-code --mode apply --scope ./src
```

### 4. Undoing Actions
```bash
# Revert last file modification
ash undo
# or using the shell builtin:
/undo
```

### 5. Audit & Compliance
```bash
# View recent commands and risk tiers
ash log

# Verify tamper-evident cryptographic hash chain
ash verify
```
