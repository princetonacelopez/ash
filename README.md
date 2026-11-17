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

## v0.2 (spec `Spec_v0.2.md`)

Implemented in this release:

| Spec § | Feature | Where |
|---|---|---|
| 3.1 | Peer-UID check, 0700 dir / 0600 socket, `$ASH_SOCKET`, 1 MiB line limit (`oversize`) | `ashd/src/socket.rs` |
| 3.2, 3.5 | Server-assigned `seq`, `ack`/`error` with client `id`, `subscribe`, `replay` (`replay.gap`), backpressure that never drops boundary/approval/policy events | `socket.rs` |
| 3.3, 3.6, 3.7 | New event types, error registry, `welcome` with `server`/`limits`, `agent`/`schema`/`remote`/`redaction` capabilities | `block.rs` |
| 4.1 | Full-screen (alt-screen) detection; no output events, raw bytes recorded only if opted in | `pty.rs` |
| 4.2 | Stream tagging (`tty`/`stdout`/`stderr`), opt-in `ash run --split-streams` | `pty.rs`, `cli run` |
| 4.3 | `ssh` / `docker exec` / `kubectl exec` → T3 `remote-opaque` | `policy/classifier.rs` |
| 4.4 | Redaction before persistence (`[redacted:<kind>]`, counts only) | `redact.rs`, `pty.rs` |
| 4.5 | Verbosity levels, announcement template, 80-char truncation, 2 s coalescing | `a11y.rs` |
| 5 | Agent runs, `agent.exec` idempotency, grants (narrow-only, never auto above T1), run-level undo | `agent.rs` |
| 6 | `--schema` discovery, sandboxed probe, trust model, `schema.violation`, secret masking | `schema.rs`, `ash schema` |
| 7.1-7.4, 7.6 | Specificity evaluation, locked org rules, enforcement report, content-hash project trust (`ash trust`) | `policy/` |
| 7.5 | Audit `seq`/`prev`, canonical JSON, rotation, anchor, `ash audit verify` | `audit.rs` |
| 8 | Conformance tests (`cargo test -p ashd --test conformance_test`) and `ash-conform` harness | `ashd/tests`, `cli/src/conform.rs` |

Known gaps (honest status): remote `ashd` socket forwarding (§4.3) is classification-only;
the proxy network allowlist (§7.3) is modeled in the enforcement report but no proxy is
shipped; CORE-03 foreign-UID rejection is implemented but only the owner path is testable
single-user; A11Y-03 (screen reader protocol) and the freeze criteria in §8.4 need humans
and second implementations.
