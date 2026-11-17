//! # Accessibility mapping (spec v0.2 §4.5)
//!
//! Verbosity levels, the normative announcement template (command summary,
//! outcome, duration), 80-char command truncation, and coalescing of
//! carriage-return redraws into one updatable status node announced at most
//! once per two seconds.

use crate::block::{Block, BlockKind, BlockStatus};
use serde::{Deserialize, Serialize};

pub const COMMAND_ANNOUNCE_LIMIT: usize = 80;
pub const COALESCE_WINDOW_MS: u64 = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verbosity {
    Silent,
    Status,
    Summary,
    Full,
}

impl std::str::FromStr for Verbosity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "silent" => Ok(Self::Silent),
            "status" => Ok(Self::Status),
            "summary" => Ok(Self::Summary),
            "full" => Ok(Self::Full),
            o => Err(format!("unknown verbosity '{}'", o)),
        }
    }
}

/// Command text up to 80 chars followed by the remaining count.
pub fn truncate_command(cmd: &str) -> String {
    let n = cmd.chars().count();
    if n <= COMMAND_ANNOUNCE_LIMIT {
        return cmd.to_string();
    }
    let head: String = cmd.chars().take(COMMAND_ANNOUNCE_LIMIT).collect();
    format!("{} (+{} more characters)", head, n - COMMAND_ANNOUNCE_LIMIT)
}

fn outcome(status: &Option<BlockStatus>) -> String {
    match status {
        Some(BlockStatus::Exit { code: 0 }) => "succeeded".into(),
        Some(BlockStatus::Exit { code }) => format!("failed with exit code {}", code),
        Some(BlockStatus::Signal { signal, .. }) => format!("killed by signal {}", signal),
        Some(BlockStatus::Denied { reason }) => format!("denied: {}", reason),
        Some(BlockStatus::Aborted { reason }) => format!("aborted: {}", reason),
        Some(BlockStatus::Detached) => "detached".into(),
        None => "running".into(),
    }
}

/// Announcement for a finished block at the given verbosity; `None` when silent.
pub fn announce(block: &Block, v: Verbosity) -> Option<String> {
    let dur = block
        .duration_ms()
        .map(|ms| format!("{:.1} seconds", ms as f64 / 1000.0))
        .unwrap_or_else(|| "unknown duration".into());
    let out = outcome(&block.status);
    match v {
        Verbosity::Silent => None,
        Verbosity::Status => Some(out),
        Verbosity::Summary | Verbosity::Full => Some(format!(
            "{}: {}, {}",
            truncate_command(&block.command),
            out,
            dur
        )),
    }
}

/// Accessibility tree for one block: region, heading, status (A11Y-01).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockTree {
    pub region: String,
    pub heading: String,
    pub status: String,
    /// Full-screen apps expose one opaque region with no inner structure (§4.1).
    pub opaque: bool,
}

pub fn block_tree(block: &Block) -> BlockTree {
    let cmd = truncate_command(&block.command);
    if block.kind == BlockKind::Fullscreen {
        return BlockTree {
            region: format!("{}, full-screen application", cmd),
            heading: cmd,
            status: outcome(&block.status),
            opaque: true,
        };
    }
    BlockTree {
        region: format!("Command {}", cmd),
        heading: cmd,
        status: outcome(&block.status),
        opaque: false,
    }
}

/// Coalesces carriage-return redraws into one status node; time is injected for testing.
#[derive(Debug, Default)]
pub struct Coalescer {
    latest: Option<String>,
    last_announced_ms: Option<u64>,
    pub announcements: u64,
}

impl Coalescer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed raw output; returns the text to announce now, if the window allows.
    pub fn feed(&mut self, bytes: &str, now_ms: u64) -> Option<String> {
        // The last segment after the final carriage return is the current line state.
        let state = bytes
            .rsplit('\r')
            .find(|s| !s.trim_end_matches('\n').is_empty())
            .map(|s| s.trim_end_matches('\n').to_string());
        if let Some(s) = state {
            self.latest = Some(s);
        }
        let due = match self.last_announced_ms {
            None => true,
            Some(t) => now_ms.saturating_sub(t) >= COALESCE_WINDOW_MS,
        };
        if due && self.latest.is_some() {
            self.last_announced_ms = Some(now_ms);
            self.announcements += 1;
            return self.latest.clone();
        }
        None
    }

    /// The current content of the updatable status node.
    pub fn status_node(&self) -> Option<&str> {
        self.latest.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{new_id, Actor};

    fn done(cmd: &str, code: i32) -> Block {
        let mut b = Block::new(new_id(), Actor::Human, cmd.into(), "/".into());
        b.started_at = Some(chrono::Utc::now());
        b.ended_at = Some(b.started_at.unwrap() + chrono::Duration::milliseconds(1500));
        b.status = Some(BlockStatus::Exit { code });
        b
    }

    #[test]
    fn finished_block_has_region_heading_status() {
        let t = block_tree(&done("make", 0));
        assert!(!t.region.is_empty() && !t.heading.is_empty() && !t.status.is_empty());
    }

    #[test]
    fn command_truncated_at_80() {
        let long = "x".repeat(100);
        assert!(truncate_command(&long).ends_with("(+20 more characters)"));
        assert_eq!(truncate_command("ls"), "ls");
    }

    #[test]
    fn verbosity_levels() {
        let b = done("make", 1);
        assert_eq!(announce(&b, Verbosity::Silent), None);
        assert_eq!(announce(&b, Verbosity::Status).unwrap(), "failed with exit code 1");
        assert_eq!(announce(&b, Verbosity::Summary).unwrap(), "make: failed with exit code 1, 1.5 seconds");
    }

    #[test]
    fn progress_redraws_coalesced() {
        let mut c = Coalescer::new();
        let mut spoken = 0;
        for i in 0..100u64 {
            if c.feed(&format!("\rprogress {}%", i), i * 50).is_some() {
                spoken += 1;
            }
        }
        // 100 redraws over 5 s -> at most 3 announcements (t=0,2000,4000)
        assert!(spoken <= 3, "spoken={}", spoken);
        assert_eq!(c.status_node(), Some("progress 99%"));
    }

    #[test]
    fn fullscreen_is_opaque() {
        let mut b = done("vim a.txt", 0);
        b.kind = BlockKind::Fullscreen;
        let t = block_tree(&b);
        assert!(t.opaque && t.region.contains("full-screen application"));
    }
}
