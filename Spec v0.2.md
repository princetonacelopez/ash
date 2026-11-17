# Agentic Shell Layer: Spec v0.2

**Status:** Draft 0.2, supersedes v0.1 (first tab). **Scope:** normative wire protocol, agent event protocol, CLI schema contract, policy rule format, conformance suite. The wire version stays `v: 1`.

## 1. What changes in v0.2

M0 to M4 are implemented, so v0.2 turns the v0.1 design into a contract that an independent implementation can be built and tested against.

1. MUST, SHOULD and MAY (RFC 2119) now mark wire behavior. Everything else stays informative.
2. The three outlines in v0.1 (agent integration, CLI schema, conformance) become full sections 5, 6 and 8.
3. Every open question in v0.1 gets a decision (section 9), marked as a proposal until implementation data confirms it.

This draft was written without the implementation findings. Section 11 lists what to confirm from the M0 to M4 builds before v0.3.

## 2. Conventions and versioning

- Integer `v` is the protocol major version. New behavior ships as a new capability, never as a new required field. A breaking change bumps `v`.
- Receivers MUST ignore unknown fields and unknown event types, and SHOULD count them. Clients MUST NOT request unknown capabilities.
- Vendor extensions use the prefix `x-<vendor>.` on field and event names.
- Timestamps are RFC 3339 UTC with milliseconds. IDs are ULIDs. Output offsets are unsigned 64-bit byte offsets into the session recording.
- Drafts below 1.0 may break between versions. The freeze criteria are in section 8.4.

## 3. Wire protocol

### 3.1 Transport and authentication

- Transport is a Unix domain socket (Windows named pipes stay informative). The path is `$ASH_SOCKET` if set, else `$XDG_RUNTIME_DIR/ash/<session>.sock` (macOS: `$TMPDIR/ash/<session>.sock`). The directory is mode 0700 and the socket 0600.
- The server MUST check the peer UID (SO\_PEERCRED or LOCAL\_PEERCRED) against the session owner and reject any other.
- Sandboxed command processes MUST NOT have access to the control socket.
- Framing is JSON Lines, UTF-8, one object per newline. The maximum line is 1 MiB. Larger payloads travel as a `ref` into the recording. Receivers MUST drop and report an oversize line instead of buffering it.

### 3.2 Envelope

```json
{ "v": 1, "type": "block.end", "seq": 1042, "ts": "2026-11-17T09:14:09.870Z", "session": "01JD5Z7Y...", "block": "01JD5Z8K...", "data": { "status": { "kind": "exit", "code": 1 } } }
```

- `seq` is a per-session, strictly increasing integer assigned by the server. Client messages carry a client-chosen `id` and receive an `ack` or `error` with the same `id`.
- The server MUST emit a session's events in `seq` order. `block.start` MUST precede any `block.output` or `block.end` for the same block.

### 3.3 Message types

| Direction | Types |
| --- | --- |
| Server to client | `session.start`, `block.prompt`, `block.input`, `block.pending`, `block.start`, `block.output`, `block.end`, `block.snapshot`, `session.end` (unchanged from v0.1), plus new `policy.decision`, `approval.requested`, `approval.resolved`, `run.start`, `run.end`, `warn`, `error` |
| Client to server | `hello`, `subscribe`, `replay`, `approve`, `deny`, `undo`, `grant.revoke`, `ping`, and the agent messages in section 5 |

### 3.4 Who may assert what

| Source | May assert | May not assert |
| --- | --- | --- |
| Shell hook (private fd) | Prompt, input, exec boundaries, exit status | Policy decisions, snapshots |
| Server (`ashd`) | Pending state, policy decisions, snapshots, output offsets, run grouping | Anything the hook never reported |
| Clients | Requests only (approve, deny, undo, subscribe) | Block boundaries or status |
| Program output | Nothing. In-band OSC 133 and `ash` sequences are stripped or escaped | Everything |

### 3.5 Subscriptions, replay and backpressure

- `subscribe` takes a filter: `types`, `blocks`, `actors`, and `output` (default false).
- `replay` takes `from_seq`. The server returns the retained events or a `warn` with `code: "replay.gap"` and the oldest available `seq`.
- Each subscriber has a bounded queue (default 4096 events). When it fills, the server drops `block.output` first and emits `warn` with the dropped counts. It MUST NOT drop block boundaries, `approval.*` or `policy.decision`. If critical events would overflow, it closes the connection with `error` code `slow_consumer`, and the client reconnects and replays.

### 3.6 Errors

An `error` carries `code`, `message`, `retryable` and an optional `doc` URL. The registry: `bad_request`, `unauthorized`, `unsupported_version`, `unsupported_capability`, `oversize`, `slow_consumer`, `not_found`, `conflict`, `policy_denied`, `approval_timeout`, `sandbox_violation`, `internal`.

### 3.7 Capability negotiation

`hello` and `welcome` work as in v0.1. `welcome` also returns `server`, `session` and `limits` (`max_line`, `queue`). Registered capabilities: `blocks`, `output`, `a11y-tree`, `hyperlinks`, `agent`, `schema`, `remote`, `redaction`. A handshake that does not complete in 200 ms falls back to OSC 133 hints.

## 4. Block protocol changes

**4.1 Full-screen programs.** The PTY proxy detects alternate-screen entry (DECSET 1049, 1047, 47) and sets `kind: "fullscreen"` on the block. No `block.output` events are emitted, and raw bytes are recorded only if `record_fullscreen` is true (default false). Assistive tech sees one region named with the command and "full-screen application", with no inner structure.

**4.2 Stream tagging.** Interactive blocks keep one merged PTY stream (`streams: ["tty"]`). Non-interactive commands can opt in to split mode (`ash run --split-streams` or a policy flag) and get separate pipes, so output events carry `stream: "stdout"` or `"stderr"`. Split mode is never automatic, because programs change behavior when stdout is not a TTY.

**4.3 Remote sessions.** A local `ashd` forwards its socket over the SSH channel to a remote `ashd` and tags blocks with `origin: {host, session}`. Policy is evaluated where the command runs. Without a remote `ashd`, `ssh` and `docker exec` are T3 with `risk.basis: "remote-opaque"` and appear as one opaque block.

**4.4 Recording and redaction.** The recording is append-only per session. Redaction runs before bytes are persisted or sent to a subscriber with the `output` capability. Sources: exact values the credential broker or environment scrubber knows, a versioned token-pattern set, and policy-defined patterns. A redacted span becomes `[redacted:<kind>]`; the record keeps the count and kind, never the value or a hash of it. Redaction is best effort and the spec says so to users, because encoded secrets can slip through.

**4.5 Accessibility mapping.** The v0.1 mapping stands. v0.2 adds: verbosity levels `silent`, `status`, `summary`, `full` as a named setting; a normative announcement template of command summary, outcome, duration; command text announced up to 80 characters followed by the remaining count; carriage-return redraws within a block coalesced into one updatable status node, announced at most once per two seconds. The limits are tunable and need confirmation from the M2 tests.

## 5. Agent event protocol

### 5.1 Modes

- **Adapter mode (default).** `ash run <agent>` starts an unmodified agent CLI. Its shell executions pass through the PTY proxy and policy engine, and `ashd` attributes blocks by run ID. No agent cooperation is needed.
- **Native mode.** The agent connects to the socket with the `agent` capability and uses the messages below.

### 5.2 Run lifecycle

`run.start` carries `run`, `agent {name, version}`, optional `parent_run` (subagents) and `task`. `run.end` carries `status` (`completed`, `failed`, `cancelled`, `denied`), `diff_ref` (combined snapshot diff) and an optional `summary`. Blocks reference their run in `actor.run`.

### 5.3 Native messages

| Message | Purpose |
| --- | --- |
| `agent.intent` | Informational plan with optional steps. The server MAY reply with `agent.preview` showing likely decisions per step |
| `agent.exec` | Request to run a command (`command` or `argv`, `cwd`, optional `split_streams`). The server answers with `policy.decision`, then `block.*` events, then `agent.result` |
| `agent.request_grant` | Ask for capabilities with a `reason`, `scope` (`run` or `session`) and `ttl`. Answered by `grant.decision` |
| `agent.cancel` | Best-effort cancel: SIGTERM, then SIGKILL after a grace period |

```json
{ "v": 1, "type": "agent.exec", "id": "req-17", "data": { "run": "01JD5Z8A...", "argv": ["git", "push", "origin", "main"], "cwd": "/home/ace/site" } }
{ "v": 1, "type": "agent.result", "id": "req-17", "data": { "status": "denied", "error": { "code": "policy_denied", "rule": "approval-required", "reason": "git push is T3 and needs human approval", "retryable": true } } }
```

Rules:

- An `id` repeated within a session returns the original result and MUST NOT re-execute the command.
- A grant MUST be shown to the human with the agent's reason, MUST be narrowable, and is never auto-approved above T1.
- A denial returns the matched rule and reason only, never the contents of other rules.
- Policy decisions MUST NOT depend on agent-supplied text such as `reason` or `plan`. Those are displayed, never evaluated.

### 5.4 Run-level behavior

T1 blocks inside a run execute with snapshots. T2 and T3 blocks still need approval one by one unless the human granted `scope: run`. `undo` with a run ID reverts the run's T1 blocks in reverse order and stops at the first conflict.

## 6. CLI schema contract

### 6.1 Discovery order

1. `<binary> --schema`, which MUST print one JSON document to stdout, exit 0 within 2 seconds, and have no side effects.
2. A sidecar `<binary>.schema.json` beside the binary or in `~/.config/ash/schemas/`.
3. The curated registry.
4. A heuristic adapter that parses `--help`, lowest confidence.

`ashd` MUST NOT execute `--schema` on a binary unless policy already allows that binary to run. It runs the probe in a sandbox with no network, a read-only filesystem and a scrubbed environment. Probing is off by default outside system directories and the project root.

### 6.2 Document shape

```json
{
  "schema_version": 1,
  "name": "deploytool",
  "version": "2.4.0",
  "commands": [{
    "name": "publish",
    "summary": "Publish a build to a registry",
    "args": [{ "name": "path", "type": "path", "required": true }],
    "flags": [{ "name": "--token", "type": "string", "secret": true, "env": "DEPLOY_TOKEN" }],
    "effects": { "reads": ["{path}"], "writes": [], "network": ["registry.example.com"], "destructive": false, "reversible": false },
    "outputs": { "formats": ["text", "json"], "select_flag": "--json" },
    "exit_codes": { "0": "published", "2": "auth failed" }
  }]
}
```

Flag types: `bool`, `string`, `int`, `float`, `path`, `enum`, `duration`, `url`. Path selectors in `effects` may reference arguments (`{path}`), `cwd` and home-relative paths. `secret: true` fields are masked in history and logs.

### 6.3 Trust model

| Source | Trust | May lower a tier? |
| --- | --- | --- |
| Signed publisher schema | Highest | Yes |
| Curated registry | High | Yes |
| Declared by the binary or sidecar | Low | No, only raise |
| Inferred from `--help` | Lowest | No, only raise |

The highest tier from all sources wins. If observed behavior contradicts a declared effect (a sandbox violation or an unexpected write), `ashd` emits `schema.violation`, treats that source as untrusted for the rest of the session, and logs it.

### 6.4 Consumers

Autocomplete, pre-exec validation shown as block warnings, policy classification, agent tool definitions generated from the schema, and inline docs. Typed pipelines that use the declared `outputs.formats` are deferred beyond v0.2.

## 7. Policy engine changes

### 7.1 Evaluation algorithm

1. Collect rules from all layers (built-in, user, project, organization).
2. Keep rules whose `actor` and `match` constraints fit the block.
3. If any kept rule says `deny`, the result is `deny`.
4. Otherwise pick the most specific rule. Specificity order: `command` match, then `path_write`, then `cwd_within`, then actor wildcard. A tie resolves to the stricter decision.
5. With no rule, use the tier default for the actor.

Strictness order: `deny`, `require_approval`, `confirm_preview`, `confirm`, `allow_snapshot`, `allow`. Organization rules marked `locked = true` cannot be loosened by any lower layer.

The result is a decision object: `decision`, `rule_id`, `layer`, `tier`, `basis`, `capabilities`, `enforcement`, and an `explain` string for display.

### 7.2 Enforcement report

Each decision records enforcement levels per capability: filesystem (`os`, `partial`, `none`), network (`os`, `proxy`, `none`) and exec. A required capability at `none` escalates the decision to at least `confirm` and shows an unenforced badge.

### 7.3 Network allowlisting

`os` means kernel-enforced where the platform supports it. `proxy` means `ashd` runs a local proxy with a host allowlist, matched on the CONNECT host or SNI, without inspecting TLS contents. Rules declare `network.min_enforcement`, and the decision escalates if the platform cannot meet it. Granularity is per host; path-level rules are out of scope for v0.2.

### 7.4 Approvals

`approval.requested` carries `approval`, `block`, optional `run`, `preview_ref`, `rule` and `expires`. A human replies with `approve` (optionally narrowed, with a scope of once, run, session or project) or `deny`. An unanswered approval expires into a denial and the agent receives `approval_timeout`. The approval UI is rendered only from server data (actor, command, rule, capabilities). It never displays agent-written text as part of the prompt itself.

### 7.5 Audit log

Entries are JSON Lines. Each has `seq`, `prev` and `hash`, where `hash` is SHA-256 over the entry in RFC 8785 canonical JSON including `prev`. `ash audit verify` checks the chain. A rotated file starts with the final hash of the previous one. Anchoring the latest hash in an external store is optional and detects truncation.

### 7.6 Project policy trust

A project policy is inert until the user trusts it. Trust is keyed to the file's content hash, so any change prompts again.

## 8. Conformance suite

### 8.1 Levels and roles

| Level | Covers |
| --- | --- |
| Core | Wire protocol, authority rules, spoofing resistance |
| Policy | Tiers, rule evaluation, enforcement report, snapshots and undo, audit log |
| Agent | Run lifecycle, exec, grants, idempotency |
| Schema | Discovery, probing safety, trust rules |
| A11y | Block-tree mapping (automated structure checks plus a manual screen reader protocol) |

Roles are daemon, shell hook, and client (emulator or accessibility bridge). An implementation claims levels per role.

### 8.2 Representative tests

| ID | Test | Passes when |
| --- | --- | --- |
| CORE-01 | A program prints a forged OSC 133 end-of-command | No `block.end` is created and the sequence is stripped from the forwarded stream |
| CORE-02 | A 2 MiB line is sent | It is dropped with `oversize` and the connection survives |
| CORE-03 | A second user connects to the socket | The connection is rejected |
| CORE-04 | Unknown fields and event types arrive | They are ignored and counted |
| CORE-05 | A client reconnects after missed events | Replay returns contiguous `seq` or a `replay.gap` warning |
| CORE-06 | A subscriber stalls during heavy output | Boundary and approval events are never dropped |
| POL-01 | A T0 command runs | No prompt appears |
| POL-02 | An agent writes outside the project through `sh -c`, `eval` or a script file | The write is blocked by enforcement, not only by classification |
| POL-03 | `rm -rf` outside snapshot scope | It is gated as T2 |
| POL-04 | A T1 block is undone | The tree is byte-identical to the snapshot |
| POL-05 | A project policy tries to loosen an organization deny | The deny still applies |
| POL-06 | An untrusted project policy is present | It has no effect until trusted |
| POL-07 | Any audit entry is altered | `ash audit verify` fails |
| POL-08 | A sandboxed process tries to open the control socket | The attempt fails |
| AGT-01 | The same `agent.exec` id is sent twice | The command runs once |
| AGT-02 | A grant is narrowed by the human | Only the narrowed capabilities apply |
| AGT-03 | A command is denied | The error names the matched rule only |
| SCH-01 | A declared schema claims a command is read-only | The tier is not lowered; a curated schema can lower it |
| SCH-02 | A `--schema` probe tries a network call | It fails inside the probe sandbox |
| SCH-03 | A command violates its declared effects | `schema.violation` is emitted and the source is untrusted |
| A11Y-01 | Any finished block | It yields a region, a heading and a status node |
| A11Y-02 | A progress bar redraws many times | Announcements are coalesced |
| A11Y-03 | Manual task script (run build, find failing test, rerun) | Completed with NVDA, VoiceOver and Orca without losing orientation |
| PERF-01 | Typing through the PTY proxy | Added latency stays under 5 ms and resident memory under 50 MB |

### 8.3 Harness

`ash-conform` drives a target daemon over the socket with a test shell and writes a JSON report: implementation, version, roles, levels, per-test results and environment. Sandbox tests run in a disposable VM or container. The suite ships a fuzz corpus for the OSC parser, JSONL framing and schema documents.

### 8.4 Criteria to freeze 1.0

- Core passes on at least two independent shell hook implementations and two independent client implementations.
- At least one daemon passes every automated level.
- A11Y-03 passes with all three screen readers.
- No open spoofing or sandbox-bypass findings at the time of the freeze.

## 9. Decisions on v0.1 open questions

| Question | Proposed decision | Section |
| --- | --- | --- |
| Stream tagging without breaking TTY behavior | Opt-in split mode for non-interactive commands | 4.2 |
| Full-screen apps | One opaque block, no output events | 4.1 |
| Remote sessions | Remote `ashd` with forwarded socket; opaque T3 otherwise | 4.3 |
| Secrets in recordings | Redact before persistence, best effort | 4.4 |
| Predict versus observe file effects | Snapshot the rule's declared write roots up front; writes outside them are blocked by enforcement, so no lazy snapshots. Prediction is for previews only | 7.1 |
| Long agent loops | Group into runs with a combined diff and run-level undo | 5.4 |
| Per-host network control | Three enforcement levels with escalation | 7.3 |
| Containers and remote execution | Policy applies where the command runs; opaque T3 otherwise | 4.3 |

## 10. Threat model additions

| Threat | Mitigation |
| --- | --- |
| Schema poisoning: a binary claims it is harmless | Declared schemas can only raise tiers; violations mark the source untrusted |
| Sandboxed process reaches the control socket | Socket not exposed in the sandbox; POL-08 |
| Agent text imitates the approval UI | Approval prompts render from server data only |
| Forged or replayed events | Authority table; server-assigned `seq`; hook events only on the private fd |
| Redaction bypass through encoding | Documented as best effort; broker values matched exactly |
| Remote forwarding abuse | Peer UID check on each hop; policy evaluated at the executing end |
| Audit log truncation | Hash chain plus optional external anchor |

## 11. To confirm from the M0 to M4 implementation (before v0.3)

- [ ] Where the implementation diverged from v0.1 (field names, events, lifecycle), and which side should move
- [ ] Measured keystroke latency and resident memory against the PERF-01 targets
- [ ] Spoofing suite results and any bypass found
- [ ] Per-OS sandbox gaps: which capabilities report `partial` or `none`
- [ ] Approval rate in real sessions against the 5% interruption target
- [ ] Screen reader findings from M2, and any change they force in section 4.5
- [ ] Which agent CLIs ran unmodified in adapter mode and which needed native mode
- [ ] Whether a second implementation can be built from this text alone

## 12. Next steps

1. Fold the section 11 findings into v0.3 and correct every place the implementation disagrees with this draft.
2. Publish the conformance suite and fuzz corpus in a public repo.
3. Recruit the second hook and client implementations the freeze criteria need.
4. Freeze 1.0 once section 8.4 is met.
