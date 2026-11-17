//! # ASH Block Protocol
//!
//! A **block** is the unit of terminal semantics: one command invocation with
//! its input, output, and outcome. This module defines all types in the
//! Block Protocol spec §3.
//!
//! v0.2 additions:
//! - `seq` (server-assigned strictly increasing integer) on Event (§3.2)
//! - `id` on client messages; `ack`/`error` responses (§3.2)
//! - New event kinds: `policy.decision`, `approval.requested`, `approval.resolved`,
//!   `run.start`, `run.end`, `warn`, `error`, plus client-side `subscribe`,
//!   `replay`, `grant.revoke`, `ping`, and agent messages (§3.3, §5)
//! - `BlockKind`: interactive | fullscreen (§4.1)
//! - `BlockOrigin`: remote session tagging (§4.3)
//! - `ApprovalScope::Run` added (§7.4)
//! - `EnforcementReport` per capability (§7.2)
//! - Registered capabilities: `agent`, `schema`, `remote`, `redaction` (§3.7)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use ulid::Ulid;

/// Protocol major version. Breaking changes bump this.
pub const PROTOCOL_VERSION: u8 = 1;

/// A ULID is used as the canonical ID type for sessions and blocks.
/// ULIDs are sortable and collision-safe (spec §3.4).
pub type Id = String;

/// Generate a new ULID string.
pub fn new_id() -> Id {
    Ulid::new().to_string()
}

// ─────────────────────────── Actor ──────────────────────────────────────────

/// Who initiated this block: a human, an agent, or a script.
/// Policy is applied per actor (spec §3.4, §4.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Actor {
    Human,
    Agent {
        /// Registered agent name, e.g. "claude-code", "gemini"
        name: String,
        /// Unique run identifier within the agent's session (spec §5.2)
        run: Id,
    },
    Script {
        /// Script path or name
        name: String,
    },
}

impl Actor {
    pub fn kind_str(&self) -> &'static str {
        match self {
            Actor::Human => "human",
            Actor::Agent { .. } => "agent",
            Actor::Script { .. } => "script",
        }
    }
}

// ─────────────────────────── Risk ───────────────────────────────────────────

/// Risk tier as defined in spec §4.2.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskTier {
    /// T0 Read-only: ls, cat, git status
    T0,
    /// T1 Reversible write: edit files, git commit
    T1,
    /// T2 Irreversible local: rm -rf, dd, mkfs
    T2,
    /// T3 External side effects: git push, npm publish, curl POST
    T3,
}

impl std::fmt::Display for RiskTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskTier::T0 => write!(f, "T0"),
            RiskTier::T1 => write!(f, "T1"),
            RiskTier::T2 => write!(f, "T2"),
            RiskTier::T3 => write!(f, "T3"),
        }
    }
}

/// How the risk tier was determined (spec §4.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskBasis {
    /// Determined from --schema contract
    Schema,
    /// Determined from curated registry
    Registry,
    /// Determined by heuristics
    Heuristic,
    /// Static analysis only
    Static,
    /// Combined static analysis and schema
    StaticPlusSchema,
    /// Remote execution without a remote ashd (§4.3)
    RemoteOpaque,
    /// Could not classify; defaulted to T2
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Risk {
    pub tier: RiskTier,
    pub basis: RiskBasis,
    /// Optional human-readable explanation
    pub reason: Option<String>,
}

// ─────────────────────────── Policy ─────────────────────────────────────────

/// The policy decision taken for a block (spec §4.4, §7.1).
/// Strictness order (ascending): allow < allow_snapshot < confirm < confirm_preview
///                                < require_approval < deny
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Run immediately
    Allow,
    /// Snapshot affected scope, then run
    AllowSnapshot,
    /// Human confirmation required
    Confirm,
    /// Show preview (diff or file list), then confirm
    ConfirmPreview,
    /// Agent-initiated: pause the agent, request human approval
    RequireApproval,
    /// Block with reason
    Deny,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Decision::Allow => "allow",
            Decision::AllowSnapshot => "allow_snapshot",
            Decision::Confirm => "confirm",
            Decision::ConfirmPreview => "confirm_preview",
            Decision::RequireApproval => "require_approval",
            Decision::Deny => "deny",
        };
        write!(f, "{}", s)
    }
}

/// Per-capability enforcement levels (spec §7.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementLevel {
    /// Kernel-enforced (seccomp, landlock, pledge, etc.)
    Os,
    /// ashd-managed proxy (network proxy, path filter)
    Partial,
    /// Not enforced at the OS level
    None,
}

/// Enforcement report emitted with every policy.decision (spec §7.2).
/// A required capability at `None` escalates the decision to at least `confirm`
/// and shows an unenforced badge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementReport {
    pub filesystem: EnforcementLevel,
    pub network: EnforcementLevel,
    pub exec: EnforcementLevel,
}

impl EnforcementReport {
    pub fn full() -> Self {
        Self {
            filesystem: EnforcementLevel::Os,
            network: EnforcementLevel::Os,
            exec: EnforcementLevel::Os,
        }
    }

    pub fn none() -> Self {
        Self {
            filesystem: EnforcementLevel::None,
            network: EnforcementLevel::None,
            exec: EnforcementLevel::None,
        }
    }
}

/// Legacy compatibility alias (single-field enforcement flag).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementStatus {
    Full,
    Partial,
    Unenforced,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    pub decision: Decision,
    /// The rule id that produced this decision
    pub rule: Option<String>,
    /// Layer that matched: "builtin" | "user" | "project" | "org"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<String>,
    /// Approver identity (populated after a human approves)
    pub approval: Option<ApprovalRecord>,
    /// Whether OS-level enforcement is active or degraded
    pub enforcement: EnforcementStatus,
    /// Per-capability enforcement report (v0.2 §7.2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement_report: Option<EnforcementReport>,
    /// Human-readable explanation string (v0.2 §7.1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub approver: String,
    pub at: DateTime<Utc>,
    pub scope: ApprovalScope,
}

/// How long an approval grant is valid (spec §7.4).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    /// Valid for one block only
    Once,
    /// Valid for the whole agent run
    Run,
    /// Valid for the entire session
    Session,
    /// Valid until the project policy is changed
    Project,
}

// ─────────────────────────── Status ─────────────────────────────────────────

/// Final status of a completed block (spec §3.4).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum BlockStatus {
    Exit { code: i32 },
    Signal { signal: i32, name: Option<String> },
    Denied { reason: String },
    Aborted { reason: String },
    Detached,
}

// ─────────────────────────── Block kind (v0.2 §4.1) ─────────────────────────

/// Whether the block is interactive or full-screen (§4.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum BlockKind {
    /// Normal interactive block; output events are emitted.
    #[default]
    Interactive,
    /// Full-screen application (vim, htop, etc.); no output events.
    Fullscreen,
}

// ─────────────────────────── Remote origin (v0.2 §4.3) ──────────────────────

/// Tag on blocks that ran on a remote host (§4.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockOrigin {
    pub host: String,
    pub session: Id,
}

// ─────────────────────────── Block lifecycle state ──────────────────────────

/// The state machine for a block (spec §3.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum BlockState {
    /// Shell is waiting for input
    #[default]
    Prompt,
    /// User or agent is composing a command
    Input,
    /// Policy engine requires approval or preview
    Pending,
    /// Process group is executing
    Running,
    /// Exited, signaled, denied, or aborted
    Done,
}

// ─────────────────────────── Output reference ───────────────────────────────

/// Reference into the session-wide append-only output recording (spec §3.4).
/// Blocks reference output by offset rather than inlining bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputRef {
    pub offset: u64,
    pub length: u64,
    pub streams: Vec<Stream>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Stream {
    /// Merged PTY stream (interactive blocks); also "tty"
    Tty,
    Stdout,
    Stderr,
}

// ─────────────────────────── Block record ────────────────────────────────────

/// The canonical block record (spec §3.4).
/// One per command invocation; stored in the session database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Protocol version
    pub v: u8,
    /// Unique ULID for this block
    pub id: Id,
    /// Session this block belongs to
    pub session: Id,
    /// Parent block (agent-spawned commands form a tree)
    pub parent: Option<Id>,
    /// Who ran this command
    pub actor: Actor,
    /// Raw command text as entered/received
    pub command: String,
    /// Tokenized arguments
    pub argv: Vec<String>,
    /// Working directory at time of invocation
    pub cwd: String,
    /// Interactive or full-screen (v0.2 §4.1)
    #[serde(default)]
    pub kind: BlockKind,
    /// Remote origin, if any (v0.2 §4.3)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<BlockOrigin>,
    /// Whether stream split mode is active (v0.2 §4.2)
    #[serde(default)]
    pub split_streams: bool,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub status: Option<BlockStatus>,
    pub risk: Option<Risk>,
    pub policy: Option<PolicyResult>,
    /// Reference to filesystem snapshot taken before execution
    pub snapshot: Option<String>,
    /// Reference to the output recording
    pub output: Option<OutputRef>,
    /// Optional free-form metadata (from --schema or tools)
    pub labels: HashMap<String, serde_json::Value>,
    /// Current lifecycle state (not persisted in final record)
    #[serde(skip)]
    pub state: BlockState,
}

impl Block {
    pub fn new(session: Id, actor: Actor, command: String, cwd: String) -> Self {
        let argv = shlex::split(&command).unwrap_or_else(|| vec![command.clone()]);
        Self {
            v: PROTOCOL_VERSION,
            id: new_id(),
            session,
            parent: None,
            actor,
            command,
            argv,
            cwd,
            kind: BlockKind::Interactive,
            origin: None,
            split_streams: false,
            started_at: None,
            ended_at: None,
            status: None,
            risk: None,
            policy: None,
            snapshot: None,
            output: None,
            labels: HashMap::new(),
            state: BlockState::Input,
        }
    }

    pub fn duration_ms(&self) -> Option<u64> {
        match (self.started_at, self.ended_at) {
            (Some(s), Some(e)) => {
                Some((e - s).num_milliseconds().unsigned_abs())
            }
            _ => None,
        }
    }
}

// ─────────────────────────── Session ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub v: u8,
    pub id: Id,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub shell: String,
    pub tty_rows: u16,
    pub tty_cols: u16,
    /// Capabilities granted by the emulator handshake
    pub capabilities: Vec<String>,
    /// Total bytes written to the output recording
    pub recording_bytes: u64,
}

impl Session {
    pub fn new(shell: String, rows: u16, cols: u16) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id: new_id(),
            started_at: Utc::now(),
            ended_at: None,
            shell,
            tty_rows: rows,
            tty_cols: cols,
            capabilities: Vec::new(),
            recording_bytes: 0,
        }
    }
}

// ─────────────────────────── Event stream ────────────────────────────────────

/// All events that flow over the Unix domain socket (spec §3.3, §3.5).
/// JSON Lines, one event per line.
/// v0.2: `seq` is server-assigned, strictly increasing per session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub v: u8,
    #[serde(rename = "type")]
    pub kind: EventKind,
    /// Server-assigned monotonically increasing sequence number (§3.2).
    /// Client messages carry a client-chosen `id` instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    pub ts: DateTime<Utc>,
    pub session: Id,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: Option<Id>,
    /// For agent run events (§5.2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run: Option<Id>,
    /// Client message ID echoed in ack/error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub data: serde_json::Value,
}

impl Event {
    pub fn server(session: Id, block: Option<Id>, kind: EventKind, data: serde_json::Value) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind,
            seq: None, // assigned by socket server
            ts: Utc::now(),
            session,
            block,
            run: None,
            id: None,
            data,
        }
    }

    /// Legacy constructor — kept for backwards compat with v0.1 tests.
    pub fn new(session: Id, block: Option<Id>, kind: EventKind, payload: EventPayload) -> Self {
        let data = serde_json::to_value(&payload).unwrap_or(serde_json::Value::Null);
        Self {
            v: PROTOCOL_VERSION,
            kind,
            seq: None,
            ts: Utc::now(),
            session,
            block,
            run: None,
            id: None,
            data,
        }
    }
}

// ─────────────────────────── Event kinds ─────────────────────────────────────

/// All event type names (server→client and client→server) per §3.3.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    // ── Server → client (unchanged from v0.1) ──────────────────────────────
    SessionStart,
    BlockPrompt,
    BlockInput,
    BlockPending,
    BlockStart,
    BlockOutput,
    BlockEnd,
    BlockSnapshot,
    SessionEnd,
    // ── Server → client (new in v0.2, §3.3) ───────────────────────────────
    PolicyDecision,
    ApprovalRequested,
    ApprovalResolved,
    RunStart,
    RunEnd,
    Warn,
    Error,
    SchemaViolation,
    Ack,
    // ── Client → server (unchanged) ────────────────────────────────────────
    Hello,
    Welcome,
    // ── Client → server (new in v0.2) ─────────────────────────────────────
    Subscribe,
    Replay,
    Approve,
    Deny,
    Undo,
    GrantRevoke,
    Ping,
    // ── Agent → server (§5.3) ─────────────────────────────────────────────
    AgentIntent,
    AgentExec,
    AgentRequestGrant,
    AgentCancel,
    AgentResult,
    AgentPreview,
    GrantDecision,
}

// ─────────────────────────── Payload types ───────────────────────────────────

/// Legacy payload enum — kept for v0.1 test compat.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventPayload {
    SessionStart(SessionStartPayload),
    BlockPrompt(BlockPromptPayload),
    BlockInput(BlockInputPayload),
    BlockPending(BlockPendingPayload),
    BlockStart(BlockStartPayload),
    BlockOutput(BlockOutputPayload),
    BlockEnd(BlockEndPayload),
    BlockSnapshot(BlockSnapshotPayload),
    SessionEnd(SessionEndPayload),
    Hello(HelloPayload),
    Welcome(WelcomePayload),
    Empty(serde_json::Value),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStartPayload {
    pub shell: String,
    pub tty_rows: u16,
    pub tty_cols: u16,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockPromptPayload {
    pub cwd: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_dirty: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInputPayload {
    pub command: String,
    pub actor: Actor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockPendingPayload {
    pub risk: Risk,
    pub preview_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockStartPayload {
    pub pid: u32,
    pub pgid: u32,
    pub policy: PolicyResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockOutputPayload {
    pub offset: u64,
    pub length: u64,
    pub stream: Stream,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEndPayload {
    pub status: BlockStatus,
    pub duration_ms: u64,
    pub snapshot: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSnapshotPayload {
    pub r#ref: String,
    pub backend: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEndPayload {
    pub reason: String,
}

/// Capability handshake - client hello (spec §3.7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloPayload {
    pub client: String,
    pub wants: Vec<String>,
}

/// Capability handshake - server welcome (spec §3.7).
/// v0.2 adds `server`, `session`, and `limits`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomePayload {
    pub granted: Vec<String>,
    pub denied: Vec<DeniedCapability>,
    /// Server implementation info (v0.2 §3.7)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<ServerInfo>,
    /// Session ULID for this connection (v0.2 §3.7)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Protocol limits (v0.2 §3.7)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<ProtocolLimits>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

/// Wire protocol limits advertised in `welcome` (§3.7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolLimits {
    /// Maximum line size in bytes (spec: 1 MiB)
    pub max_line: u64,
    /// Per-subscriber event queue depth
    pub queue: u64,
}

impl ProtocolLimits {
    pub fn default_limits() -> Self {
        Self {
            max_line: 1024 * 1024,
            queue: 4096,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeniedCapability {
    pub cap: String,
    pub reason: String,
}

// ─────────────────────────── Warn / Error wire types ─────────────────────────

/// Wire error codes (§3.6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    UnsupportedVersion,
    UnsupportedCapability,
    Oversize,
    SlowConsumer,
    NotFound,
    Conflict,
    PolicyDenied,
    ApprovalTimeout,
    SandboxViolation,
    Internal,
    ReplayGap,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireError {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
    /// Rule id that caused a policy_denied error (§5.3)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

// ─────────────────────────── Approval wire types ─────────────────────────────

/// `approval.requested` payload (§7.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequestedPayload {
    pub approval: Id,
    pub block: Id,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run: Option<Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_ref: Option<String>,
    pub rule: Option<String>,
    /// RFC 3339 UTC expiry time
    pub expires: DateTime<Utc>,
}

/// `approval.resolved` payload (§7.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResolvedPayload {
    pub approval: Id,
    pub resolution: ApprovalResolution,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<ApprovalScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalResolution {
    Approved,
    Denied,
    TimedOut,
}

// ─────────────────────────── Run lifecycle (§5.2) ────────────────────────────

/// `run.start` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunStartPayload {
    pub run: Id,
    pub agent: AgentInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_run: Option<Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
}

/// `run.end` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunEndPayload {
    pub run: Id,
    pub status: RunStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Completed,
    Failed,
    Cancelled,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub name: String,
    pub version: String,
}

// ─────────────────────────── Capabilities ────────────────────────────────────

/// All capabilities `ashd` supports (spec §3.7).
pub mod capabilities {
    pub const BLOCKS: &str = "blocks";
    pub const OUTPUT: &str = "output";
    pub const A11Y_TREE: &str = "a11y-tree";
    pub const HYPERLINKS: &str = "hyperlinks";
    // v0.1 aliases kept for backwards compat
    pub const IMAGES_KITTY: &str = "images:kitty";
    pub const IMAGES_SIXEL: &str = "images:sixel";
    pub const OUTPUT_STREAM: &str = "output-stream";
    // v0.2 new capabilities (§3.7)
    pub const AGENT: &str = "agent";
    pub const SCHEMA: &str = "schema";
    pub const REMOTE: &str = "remote";
    pub const REDACTION: &str = "redaction";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_new_parses_argv() {
        let b = Block::new(
            new_id(),
            Actor::Human,
            "npm run build".to_string(),
            "/tmp".to_string(),
        );
        assert_eq!(b.argv, vec!["npm", "run", "build"]);
    }

    #[test]
    fn risk_tier_ordering() {
        assert!(RiskTier::T0 < RiskTier::T1);
        assert!(RiskTier::T1 < RiskTier::T2);
        assert!(RiskTier::T2 < RiskTier::T3);
    }

    #[test]
    fn decision_strictness_ordering() {
        // spec §7.1 strictness order
        assert!(Decision::Allow < Decision::AllowSnapshot);
        assert!(Decision::AllowSnapshot < Decision::Confirm);
        assert!(Decision::Confirm < Decision::ConfirmPreview);
        assert!(Decision::ConfirmPreview < Decision::RequireApproval);
        assert!(Decision::RequireApproval < Decision::Deny);
    }

    #[test]
    fn event_serializes_to_json() {
        let e = Event::new(
            new_id(),
            None,
            EventKind::SessionStart,
            EventPayload::SessionStart(SessionStartPayload {
                shell: "zsh".to_string(),
                tty_rows: 24,
                tty_cols: 80,
                capabilities: vec![],
            }),
        );
        let j = serde_json::to_string(&e).unwrap();
        assert!(j.contains("\"type\":\"session_start\""));
    }

    #[test]
    fn block_kind_defaults_interactive() {
        let b = Block::new(new_id(), Actor::Human, "ls".to_string(), "/".to_string());
        assert_eq!(b.kind, BlockKind::Interactive);
    }

    #[test]
    fn approval_scope_run_serializes() {
        let scope = ApprovalScope::Run;
        let j = serde_json::to_string(&scope).unwrap();
        assert_eq!(j, "\"run\"");
    }

    #[test]
    fn enforcement_report_full() {
        let r = EnforcementReport::full();
        assert_eq!(r.filesystem, EnforcementLevel::Os);
        assert_eq!(r.network, EnforcementLevel::Os);
        assert_eq!(r.exec, EnforcementLevel::Os);
    }

    #[test]
    fn error_code_serializes() {
        let e = ErrorCode::SlowConsumer;
        let j = serde_json::to_string(&e).unwrap();
        assert_eq!(j, "\"slow_consumer\"");
    }

    #[test]
    fn protocol_limits_defaults() {
        let l = ProtocolLimits::default_limits();
        assert_eq!(l.max_line, 1024 * 1024);
        assert_eq!(l.queue, 4096);
    }
}
