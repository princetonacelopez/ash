//! # ASH Block Protocol
//!
//! A **block** is the unit of terminal semantics: one command invocation with
//! its input, output, and outcome. This module defines all types in the
//! Block Protocol spec §3.
//!
//! Design principles (spec §3.1):
//! - Superset of OSC 133: existing shell integrations remain valid
//! - Out-of-band authority, in-band hints
//! - Plain-text fallback if nothing understands the protocol
//! - Versioned and negotiable via capability handshake

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use ulid::Ulid;

/// Protocol version. All events carry this.
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
        /// Unique run identifier within the agent's session
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

/// The policy decision taken for a block (spec §4.4).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    pub decision: Decision,
    /// The rule id that produced this decision
    pub rule: Option<String>,
    /// Approver identity (populated after a human approves)
    pub approval: Option<ApprovalRecord>,
    /// Whether OS-level enforcement is active or degraded
    pub enforcement: EnforcementStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementStatus {
    Full,
    Partial,
    Unenforced,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub approver: String,
    pub at: DateTime<Utc>,
    pub scope: ApprovalScope,
}

/// How long an approval grant is valid (spec §4.4).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    Once,
    BlockTree,
    Session,
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

/// All events that flow over the Unix domain socket (spec §3.5).
/// JSON Lines, one event per line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub v: u8,
    #[serde(rename = "type")]
    pub kind: EventKind,
    pub ts: DateTime<Utc>,
    pub session: Id,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: Option<Id>,
    pub payload: EventPayload,
}

impl Event {
    pub fn new(session: Id, block: Option<Id>, kind: EventKind, payload: EventPayload) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            kind,
            ts: Utc::now(),
            session,
            block,
            payload,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    SessionStart,
    BlockPrompt,
    BlockInput,
    BlockPending,
    BlockStart,
    BlockOutput,
    BlockEnd,
    BlockSnapshot,
    SessionEnd,
    // Capability handshake
    Hello,
    Welcome,
}

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

/// Capability handshake - client hello (spec §3.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloPayload {
    pub client: String,
    pub wants: Vec<String>,
}

/// Capability handshake - server welcome (spec §3.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomePayload {
    pub granted: Vec<String>,
    pub denied: Vec<DeniedCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeniedCapability {
    pub cap: String,
    pub reason: String,
}

// ─────────────────────────── Capabilities ────────────────────────────────────

/// All capabilities `ashd` supports (spec §3.6, §4.5).
pub mod capabilities {
    pub const BLOCKS: &str = "blocks";
    pub const A11Y_TREE: &str = "a11y-tree";
    pub const HYPERLINKS: &str = "hyperlinks";
    pub const IMAGES_KITTY: &str = "images:kitty";
    pub const IMAGES_SIXEL: &str = "images:sixel";
    pub const OUTPUT_STREAM: &str = "output-stream";
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
}
