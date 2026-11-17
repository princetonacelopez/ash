# Agentic Shell Layer: Product Spec v0.1

**Working title:** `ash` (placeholder) **Status:** Draft 0.1. Scope: Block Protocol and Policy Engine in depth; other components outlined. **Author:** Princeton Ace Lopez (PAL)

## 1. Summary

`ash` is a semantic shell layer that runs inside any existing terminal emulator. It gives the terminal what it lacks: a structured model of commands, an open protocol for describing them, and a safety layer that makes both humans and AI agents safe to run with real privileges. It does not replace the emulator, the shell, or the agent CLIs. It sits between them.

### 1.1 Problems addressed

1. The terminal sees a grid of cells, not commands, exit codes, or errors (no semantics).
2. Control data and content share one channel (in-band signaling), so output can spoof structure.
3. Screen readers get a flat, redrawing grid with no landmarks or live-region behavior.
4. Every process runs with the full ambient authority of the user, with no undo.
5. Agent CLIs each invent their own permission model, usually all-or-nothing.

### 1.2 Goals

- G1. Backward compatible: plain POSIX shells and unmodified binaries keep working. Everything else is progressive enhancement.
- G2. Emulator-neutral: works in Ghostty, kitty, WezTerm, iTerm2, Windows Terminal with graceful degradation.
- G3. One command surface for humans and agents, with identical policy applied to both.
- G4. Accessibility is a first-class output, not a retrofit.
- G5. Risk-tiered friction: read-only is instant, reversible is undoable, irreversible is gated.

### 1.3 Non-goals

- Building a terminal emulator or GPU renderer.
- Replacing POSIX or requiring tools to be rewritten.
- Being an AI model provider or a proprietary agent.
- Defeating a determined local attacker who already has root (see Threat Model).

## 2. Architecture

```
Emulator (any)
  └─ ashd  PTY proxy + event bus + policy engine (per-session daemon)
       ├─ shell hook (zsh/bash/fish) → emits block events on a private fd
       ├─ agent runner → wraps claude / gemini / codex etc. as native commands
       ├─ sandbox backend (Landlock+seccomp / Seatbelt / later: Windows job objects)
       ├─ snapshot backend (git / APFS clone / btrfs / ZFS / file-level CoW fallback)
       └─ a11y bridge → AT-SPI / UIA / NSAccessibility
```

**Key decision:** `ashd` owns the PTY and sits between the emulator and the shell. This lets it (a) sanitize untrusted in-band sequences from program output, (b) record output with stable offsets, and (c) enforce policy outside the shell process.

## 3. Block Protocol

A **block** is the unit of terminal semantics: one command invocation with its input, output, and outcome.

### 3.1 Design principles

- **Superset of OSC 133.** Existing shell integrations (prompt start, command start, command end) remain valid. Emulators that only understand OSC 133 still get prompt navigation.
- **Out-of-band authority, in-band hints.** The authoritative event stream travels over a Unix domain socket (named pipe on Windows). In-band sequences are emitted only as compatibility hints, and `ashd` strips any in-band structural sequence that did not originate from the shell hook.
- **Plain-text fallback.** If nothing understands the protocol, the user sees an ordinary terminal.
- **Versioned and negotiable.** Every capability is opt-in via handshake.

### 3.2 Spoofing resistance

Problem: any program can print `\e]133;D;0\a` and fake a successful block.

Solution:

1. The shell hook writes block events to a private file descriptor opened with `CLOEXEC` and not inherited by children.
2. `ashd` treats that fd as the only authority for block boundaries and status.
3. The PTY proxy removes or escapes OSC 133 and `ash` OSC sequences that appear in program output (configurable: strip, escape, or pass-through with a visible marker).
4. When forwarding hints to the emulator, `ashd` re-emits them itself, so the emulator only ever sees sequences `ashd` vouches for.

### 3.3 Block lifecycle

```
prompt_start → input → exec_start → [output…] → exec_end → (next prompt_start)
                  └─ policy_pending → approved | denied (may precede exec_start)
```

| State | Meaning |
| --- | --- |
| `prompt` | Shell is waiting for input |
| `input` | User or agent is composing a command |
| `pending` | Policy engine requires approval or preview |
| `running` | Process group is executing |
| `done` | Exited, signaled, denied, or aborted |

### 3.4 Block record

```json
{
  "v": 1,
  "id": "01JD5Z8K7Q3M2X9T4R6W1B0HNE",
  "session": "01JD5Z7YV0A8C3F5G2H4J6K9PQ",
  "parent": null,
  "actor": { "kind": "agent", "name": "claude-code", "run": "01JD5Z8A..." },
  "command": "npm run build",
  "argv": ["npm", "run", "build"],
  "cwd": "/home/ace/projects/site",
  "started_at": "2026-11-17T09:14:02.113Z",
  "ended_at": "2026-11-17T09:14:09.870Z",
  "status": { "kind": "exit", "code": 1 },
  "risk": { "tier": "T1", "basis": "static+schema" },
  "policy": { "decision": "allow_snapshot", "rule": "project-write", "approval": null },
  "snapshot": "snap_01JD5Z8K...",
  "output": { "offset": 48211, "length": 3920, "streams": ["stdout", "stderr"] },
  "labels": { "error_summary": "2 type errors" }
}
```

Field notes:

- `id` and `session` are ULIDs (sortable, collision-safe).
- `parent` links nested or agent-spawned commands to the block that caused them, forming a tree.
- `actor.kind` is `human`, `agent`, or `script`. Policy applies per actor.
- `status.kind` is `exit`, `signal`, `denied`, `aborted`, or `detached`.
- `output` references offsets into a session-wide append-only recording rather than inlining bytes. This makes blocks cheap to list, collapse, share, and re-render.
- `labels` is optional free-form, tool-provided metadata (for example, from a `--schema` contract).

### 3.5 Event stream

JSON Lines over the socket. Each event carries `v`, `type`, `ts`, `session`, and `block`.

| Event | Emitted when | Key payload |
| --- | --- | --- |
| `session.start` | PTY opened | shell, tty size, capabilities |
| `block.prompt` | Prompt rendered | cwd, git state (optional) |
| `block.input` | Input committed | command text, actor |
| `block.pending` | Policy needs a decision | risk, preview ref |
| `block.start` | Process group spawned | pid, pgid, effective policy |
| `block.output` | Output chunk recorded | offset, length, stream |
| `block.end` | Process finished | status, duration |
| `block.snapshot` | Snapshot taken or restored | ref, backend |
| `session.end` | PTY closed | reason |

Consumers (emulators, a11y bridge, loggers, agents) subscribe with a filter. Output events are opt-in because they are high volume.

### 3.6 Capability handshake

Replaces reliance on `$TERM` and terminfo for new features.

Client sends:

```json
{ "type": "hello", "v": 1, "client": "ghostty/1.3", "wants": ["blocks", "a11y-tree", "hyperlinks", "images:kitty"] }
```

Server replies:

```json
{ "type": "welcome", "v": 1, "granted": ["blocks", "a11y-tree", "hyperlinks"], "denied": [{"cap": "images:kitty", "reason": "not-supported"}] }
```

Rules: unknown capabilities are ignored, never fatal. Versions are negotiated down. If the handshake times out (200 ms), `ashd` assumes a legacy emulator and uses OSC 133 hints only.

### 3.7 In-band compatibility sequences

For emulators without socket integration:

- `OSC 133 ; A` prompt start, `B` input start, `C` command start, `D ; <exit>` command end (standard).
- Extension parameters as `key=value` pairs after the standard fields, for example `OSC 133 ; D ; 1 ; id=<ulid> ; dur=7757`. Legacy emulators ignore unknown parameters.
- Dedicated OSC code for `ash` extensions: **TBD**, to be requested through the emulator maintainers' shared registry. Do not squat a number without coordination.

### 3.8 Accessibility mapping

The protocol exists in part so assistive tech gets structure. Mapping:

| Terminal concept | Accessibility role | Behavior |
| --- | --- | --- |
| Session | `application` / `document` | Named by shell and cwd |
| Block | `region` (landmark) | Labelled with command text and status |
| Command text | `heading` (level 2) | Navigable via heading shortcuts |
| Output | `log` / text content | Browsable line by line, not re-announced wholesale |
| Exit status | Live region (`polite` on success, `assertive` on failure) | One concise announcement: "build failed, exit 1, 7.8 seconds" |
| Pending approval | `alertdialog`-like region, non-modal | Focus moves predictably, Escape denies |
| Prompt | Text input control | Real input semantics, cursor and selection exposed |

Requirements:

- Announcements are summaries, not output dumps. Full output is read on demand.
- Verbosity is user-configurable: silent, status-only, status+summary, full.
- Redraws (progress bars, spinners) are coalesced into a single updatable status node to avoid screen reader spam.
- Meets WCAG 2.1 AA for any UI `ash` ships (approval prompts, block navigation). Do not rely on color alone for status.
- Platform bridges: AT-SPI (Linux), UI Automation (Windows), NSAccessibility (macOS). Until emulators adopt the protocol, ship a **companion bridge** that renders the block tree for assistive tech.

### 3.9 Open questions (protocol)

1. Stream separation: can stdout and stderr be tagged without breaking programs that expect a merged PTY? Likely requires an opt-in wrapper mode.
2. Full-screen apps (vim, htop): treat alternate-screen sessions as a single opaque block with start and end semantics only.
3. Remote sessions: does `ashd` run remotely, locally, or both? Proposal: remote `ashd` over SSH with the same socket protocol forwarded.
4. Output recording size caps and redaction (secrets) before persistence.

## 4. Policy Engine

The policy engine decides whether, how, and with what privileges a command runs. It applies identical logic to humans, agents, and scripts, with different default policies per actor.

### 4.1 Principles

- **Enforce at the OS boundary, not by string matching.** Shell parsing is undecidable in practice (`eval`, `$(...)`, aliases, scripts). Classification informs UX. Sandboxing enforces.
- **Risk-tiered friction.** Match friction to consequence (NN/g: error prevention, user control and freedom, visibility of system status).
- **Fail conservative on unknowns.** Unclassifiable commands are treated as T2.
- **Explain every decision.** Each allow, gate, or deny cites a rule and a reason.
- **Policy is data.** Declarative, diffable, reviewable, and shareable.

### 4.2 Risk tiers

| Tier | Definition | Default behavior (human) | Default behavior (agent) |
| --- | --- | --- | --- |
| **T0** Read-only | No writes, no network side effects (`ls`, `cat`, `git status`) | Run instantly | Run instantly within read scope |
| **T1** Reversible write | Writes that can be undone via snapshot (edit files in project, `git commit`) | Run, auto-snapshot, `/undo` available | Run in scoped sandbox, auto-snapshot |
| **T2** Irreversible local | Destroys data not covered by snapshots (`rm -rf` outside snapshot scope, `dd`, `mkfs`) | Preview and confirm | Preview and require human approval |
| **T3** External side effects | Network writes, publishing, payments, sending messages (`git push`, `npm publish`, `curl -X POST`, cloud CLIs) | Confirm with destination shown | Require human approval every time unless a scoped grant exists |

Tiers are ordered. When signals disagree, the highest tier wins.

### 4.3 Classification pipeline

1. **Parse.** Tokenize the command line, resolve aliases and functions, expand globs (read-only), and identify pipelines and redirections. Redirections (`>`, `>>`) promote at least to T1.
2. **Schema lookup.** If the binary publishes a `--schema` contract (see section 6), use its declared side effects per subcommand and flag.
3. **Registry lookup.** Fall back to a curated, versioned rule set for common tools (coreutils, git, package managers, cloud CLIs).
4. **Heuristics.** Detect dangerous patterns (recursive delete, device writes, `sudo`, `curl | sh`, force flags).
5. **Unknown handling.** If still unclassified, assign T2 and mark `basis: unknown` so the UI can say why.
6. **Dry-run probe (optional).** For tools that support `--dry-run`, `--check`, or `--what-if`, run the probe inside the sandbox to produce a preview.

The result is stored in the block record as `risk.tier` and `risk.basis`.

### 4.4 Policy language

Declarative TOML. Evaluation order: **deny rules first, then most specific allow, then tier defaults.** No implicit allow for T2 or T3 for agents.

```toml
version = 1

[defaults.human]
T0 = "allow"
T1 = "allow_snapshot"
T2 = "confirm_preview"
T3 = "confirm"

[defaults.agent]
T0 = "allow"
T1 = "allow_snapshot"
T2 = "require_approval"
T3 = "require_approval"

[[rule]]
id = "never-touch-ssh"
actor = "any"
match.path_write = ["~/.ssh/**", "~/.gnupg/**"]
decision = "deny"
reason = "Key material is off limits"

[[rule]]
id = "project-write"
actor = "agent:*"
match.cwd_within = "${PROJECT_ROOT}"
match.path_write = ["${PROJECT_ROOT}/**"]
capabilities.fs_write = ["${PROJECT_ROOT}"]
capabilities.network = []
decision = "allow_snapshot"

[[rule]]
id = "registry-installs"
actor = "agent:*"
match.command = ["npm install", "pnpm add"]
capabilities.network = ["registry.npmjs.org"]
decision = "allow_snapshot"
expires = "session"
```

**Decisions:**

| Decision | Effect |
| --- | --- |
| `allow` | Run immediately |
| `allow_snapshot` | Snapshot affected scope, then run |
| `confirm` | Human confirmation required |
| `confirm_preview` | Show preview (diff or file list), then confirm |
| `require_approval` | Agent-initiated: pause the agent, request human approval |
| `deny` | Block with reason, return structured error to the actor |

**Scopes of a grant:** once, this block tree, this session, this project (persisted, visible, revocable).

### 4.5 Capability model

Each command runs with an explicit capability set derived from the matched rule:

| Capability | Examples |
| --- | --- |
| `fs_read` | Allowed read roots |
| `fs_write` | Allowed write roots |
| `network` | Allowed hosts or ports, or none |
| `exec` | Allowed binaries |
| `env` | Which environment variables and secrets are visible |
| `proc` | Spawn limits, signal permissions |

Defaults for agents: read within project plus system libraries, write within project only, no network, a scrubbed environment (no ambient secrets). Anything broader needs a rule or an approval.

### 4.6 Enforcement backends

| Platform | Mechanism | Notes |
| --- | --- | --- |
| Linux | Landlock (fs), seccomp-bpf (syscalls), network namespaces or eBPF for host allowlists | Landlock needs a recent kernel; fall back to bubblewrap |
| macOS | Seatbelt profiles | Tooling is deprecated-but-functional; track Apple changes |
| Windows | AppContainer, job objects | Later milestone |
| Fallback | Run unsandboxed with visible `unenforced` badge and the strictest confirm policy | Never silently degrade |

Honest limitation: where the OS cannot enforce a capability, the engine says so in the block record (`enforcement: partial`) and escalates to confirmation.

### 4.7 Snapshots and undo

Backends in order of preference:

1. Filesystem snapshots (APFS clones, btrfs, ZFS) for the declared write scope.
2. Git-aware snapshot (stash or ephemeral ref plus untracked file capture) when the scope is a repository.
3. File-level copy-on-write of only the files a command is predicted or observed to touch.

Undo semantics:

- `/undo` reverts the last reversible block. `/undo <block-id>` reverts a specific block and warns if later blocks depend on it.
- Snapshots are retained for a configurable window (default: 24 hours or 2 GB).
- Undo covers local filesystem state only. T3 actions are explicitly **not undoable**, and the UI says so before they run.

### 4.8 Previews and approval UX

Grounded in NN/g heuristics:

- **Visibility of system status:** every pending block shows what will run, as which actor, under which rule, and with which capabilities.
- **Error prevention:** previews show effects in domain terms, such as "deletes 214 files (48 MB) under ./dist" or "pushes 3 commits to origin/main", instead of raw flags.
- **User control and freedom:** every gate offers approve, deny, edit command, and approve-with-narrower-scope. Escape always denies.
- **Recognition over recall:** a rule name and a one-click "why?" explain the gate.
- **Minimize fatigue:** batched approvals ("approve these 6 reads and 2 writes in ./src") and scoped session grants. Never prompt for T0.
- **Accessibility:** approvals are non-modal regions in the block tree, announced once, operable by keyboard alone, with state conveyed by text and icon, not color only.

**Creative middle ground:** power users can enable *flow mode*, which executes T1 immediately with undo and queues T2/T3 approvals as non-blocking badges so typing is never interrupted, while irreversible actions still cannot run unattended.

### 4.9 Credentials

- Agents never receive long-lived secrets by default.
- A credential broker issues short-lived, scoped tokens per block or session (for example, a push-only token for one repo, expiring in 10 minutes). Backends are pluggable (OS keychain, 1Password CLI, cloud STS).
- Secrets are redacted from recorded output using pattern and exact-value matching before persistence.

### 4.10 Audit log

Append-only, hash-chained JSONL. Each entry includes: block id, actor, command, cwd, risk tier and basis, matched rule, decision, approver identity and timestamp, capabilities granted, enforcement status, snapshot ref, exit status. Tamper-evidence comes from `hash = H(prev_hash || canonical_entry)`. Export formats: JSONL, and a human-readable report for compliance reviews. Log content respects redaction rules.

### 4.11 Policy distribution

- Layers: built-in defaults, user (`~/.config/ash/policy.toml`), project (`.ash/policy.toml`, checked in), organization (managed).
- Lower layers can only **tighten** what a higher-precedence organizational layer sets. A project file cannot loosen a user deny.
- Project policies from untrusted repos are inert until the user explicitly trusts them (prevents a malicious repo from granting itself privileges).

### 4.12 Open questions (policy)

1. How aggressively to predict file effects before execution versus observe-and-snapshot lazily (cost versus safety).
2. Handling of long-running agent loops that issue hundreds of T1 commands: aggregate into a single reviewable "run" with a combined diff.
3. Network allowlisting granularity without a proxy: per-host enforcement may require a local transparent proxy.
4. Interaction with containers and remote execution (`docker exec`, `ssh`): treat as T3 by default, or recurse policy into the remote end where `ashd` is present.

## 5. Agent Integration (outline)

- `ash run <agent> [flags]` wraps any agent CLI. Unmodified agents get a sandboxed shell tool whose commands pass through the policy engine.
- Agents that opt in speak the event protocol directly: they emit intent and plan, receive structured allow, deny, and error results, and can request scoped grants with a stated reason.
- Inline prompts (for example `@agent explain this failure`) are shell syntax handled by the hook, routed to the configured model with the previous block as context.
- Flags: `--model`, `--mode plan|apply`, `--budget`, `--scope`. Slash commands (`/undo`, `/diff`, `/explain`, `/approve`) are shell builtins.
- Agent identity is bound to a run id so the audit log and policy can attribute every block.

## 6. CLI Schema Contract (outline)

A `--schema` flag (or `.schema` sidecar file) returns machine-readable JSON describing subcommands, flags, argument types, output shape, and declared side effects (`reads`, `writes`, `network`, `destructive`). Consumers: autocomplete, inline documentation, validation, policy classification, and agent tool-calling. Adapters are provided for tools that have no native schema, derived from `--help` parsing and a curated registry. Full spec in v0.2.

## 7. Threat Model (summary)

| Threat | Mitigation |
| --- | --- |
| Program output spoofs block boundaries or success status | Out-of-band authority, PTY proxy sanitization |
| Malicious escape sequences (title injection, clipboard writes, hyperlink abuse) | Allowlist sequences by capability, strip the rest, require opt-in for clipboard and hyperlink schemes |
| Prompt injection causes an agent to run harmful commands | Policy applies regardless of the agent's reasoning, scrubbed env, scoped capabilities, approval for T2 and T3 |
| Malicious repo ships a permissive project policy | Trust-on-first-use prompt, tighten-only layering |
| `ashd` compromise | Minimal privileges, no network listener, socket permissions `0600`, signed releases, fuzzed parsers |
| Policy bypass via shell indirection (`eval`, scripts) | OS-level enforcement as the source of truth, conservative classification |
| Secret leakage via recorded output | Redaction before persistence, configurable retention |
| Approval fatigue leads to rubber-stamping | Tiered defaults, batching, scoped grants, metrics on approval rates |

Out of scope: local root attackers, kernel exploits, hardware attacks.

## 8. Milestones

| Milestone | Scope | Exit criteria |
| --- | --- | --- |
| **M0 Prototype** | zsh/fish hook, `ashd` PTY proxy, block events over socket, OSC 133 compat hints | Block list renders correctly in Ghostty and WezTerm; spoofing test suite passes |
| **M1 Policy v1** | Tiering, TOML rules, Landlock and Seatbelt enforcement, git and APFS snapshots, `/undo` | Agent run in a repo is sandboxed to the project, undo restores state in all test cases |
| **M2 Accessibility bridge** | Block tree to AT-SPI and NSAccessibility, verbosity modes | Task completion verified with NVDA, VoiceOver, and Orca users, with no wholesale re-announcement of output |
| **M3 Agent integration** | `ash run`, scoped grants, credential broker, audit log | Third-party agent CLI runs unmodified under policy |
| **M4 Protocol 1.0** | Published spec, conformance tests, emulator outreach | At least one emulator ships native support |

## 9. Success Metrics

- **Safety:** zero unrecoverable data-loss incidents in agent runs under default policy (benchmarked against a fault-injection suite).
- **Friction:** under 5% of commands interrupted by a prompt in typical dev sessions, median approval time under 3 seconds.
- **Accessibility:** screen reader users complete a standard task set (run build, find failing test, rerun) with measurably fewer keystrokes and no loss of orientation versus a baseline terminal.
- **Adoption:** protocol implemented by at least two independent emulators or shells within 12 months of 1.0.
- **Overhead:** under 5 ms added latency per keystroke, under 50 MB resident for `ashd`.

## 10. Next Steps

1. Validate the spoofing-resistance design with a prototype and adversarial output tests.
2. User-test the approval UX and accessibility mapping (screen reader users first, then agent-heavy developers).
3. Write section 6 (CLI schema) and the full conformance suite spec for v0.2.
4. Decide license and governance (proposal: protocol under a permissive license with an open spec repo, core daemon open-source, team and compliance features commercial).
