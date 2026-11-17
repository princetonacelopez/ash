//! # Audit Log (spec §4.10)
//!
//! Append-only, hash-chained JSONL audit log.
//!
//! Each entry includes: block id, actor, command, cwd, risk tier and basis,
//! matched rule, decision, approver identity and timestamp, capabilities
//! granted, enforcement status, snapshot ref, exit status.
//!
//! Tamper-evidence: `hash = H(prev_hash || canonical_entry)` using SHA-256.
//! Log content respects redaction rules (secrets stripped before writing).

use crate::block::{Block, BlockStatus};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

/// One entry in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub block_id: String,
    pub session_id: String,
    /// "human", "agent:name", "script:name"
    pub actor: String,
    pub command: String,
    pub cwd: String,
    pub risk_tier: String,
    pub risk_basis: String,
    pub matched_rule: Option<String>,
    pub decision: String,
    pub approver: Option<String>,
    pub approved_at: Option<DateTime<Utc>>,
    pub capabilities_granted: Vec<String>,
    pub enforcement_status: String,
    pub snapshot_ref: Option<String>,
    pub exit_status: Option<i32>,
    pub signal: Option<i32>,
    pub denied: bool,
    pub at: DateTime<Utc>,
    /// SHA-256 of (prev_hash || canonical JSON of this entry)
    pub hash: String,
}

impl AuditEntry {
    /// Compute the chain hash for this entry given the previous hash.
    fn compute_hash(prev_hash: &str, entry_json: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(entry_json.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Builds an `AuditEntry` from a completed `Block`.
pub fn entry_from_block(block: &Block, prev_hash: &str) -> AuditEntry {
    let actor_str = match &block.actor {
        crate::block::Actor::Human => "human".to_string(),
        crate::block::Actor::Agent { name, .. } => format!("agent:{}", name),
        crate::block::Actor::Script { name } => format!("script:{}", name),
    };

    let (risk_tier, risk_basis) = block
        .risk
        .as_ref()
        .map(|r| (r.tier.to_string(), format!("{:?}", r.basis)))
        .unwrap_or_else(|| ("?".to_string(), "unknown".to_string()));

    let (decision, matched_rule, approver, approved_at, enforcement, capabilities) =
        if let Some(ref p) = block.policy {
            let caps = if let Some(ref _cap) = p.approval {
                vec![] // grants from approval (simplified)
            } else {
                vec![]
            };
            (
                p.decision.to_string(),
                p.rule.clone(),
                p.approval.as_ref().map(|a| a.approver.clone()),
                p.approval.as_ref().map(|a| a.at),
                format!("{:?}", p.enforcement),
                caps,
            )
        } else {
            ("unknown".to_string(), None, None, None, "unknown".to_string(), vec![])
        };

    let (exit_status, signal, denied) = match block.status.as_ref() {
        Some(BlockStatus::Exit { code }) => (Some(*code), None, false),
        Some(BlockStatus::Signal { signal, .. }) => (None, Some(*signal), false),
        Some(BlockStatus::Denied { .. }) => (None, None, true),
        Some(BlockStatus::Aborted { .. }) => (None, None, false),
        Some(BlockStatus::Detached) | None => (None, None, false),
    };

    // Build the entry without hash first, then compute hash
    let mut entry = AuditEntry {
        block_id: block.id.clone(),
        session_id: block.session.clone(),
        actor: actor_str,
        command: redact_secrets(&block.command),
        cwd: block.cwd.clone(),
        risk_tier,
        risk_basis,
        matched_rule,
        decision,
        approver,
        approved_at,
        capabilities_granted: capabilities,
        enforcement_status: enforcement,
        snapshot_ref: block.snapshot.clone(),
        exit_status,
        signal,
        denied,
        at: Utc::now(),
        hash: String::new(),
    };

    // Serialize without hash, then compute hash
    let canonical = serde_json::to_string(&entry).unwrap_or_default();
    entry.hash = AuditEntry::compute_hash(prev_hash, &canonical);

    entry
}

/// Simple secret redaction: strip common secret patterns.
fn redact_secrets(command: &str) -> String {
    // Redact tokens, passwords, and secrets from command strings.
    // Patterns: --token=..., --password=..., GITHUB_TOKEN=..., etc.
    let mut out = command.to_string();

    // Environment variable assignments with common secret names
    let secret_patterns = [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "KEY",
        "APIKEY",
        "API_KEY",
        "PRIVATE",
    ];

    for pat in &secret_patterns {
        // Match PATTERN=value
        let mut result = String::new();
        let bytes = out.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            // Look for pattern
            let upper = out[i..].to_uppercase();
            if upper.starts_with(pat) {
                let rest = &out[i + pat.len()..];
                if rest.starts_with('=') {
                    // Find end of value (space or end)
                    let end = rest[1..].find(|c: char| c.is_whitespace()).map_or(rest.len() - 1, |e| e + 1);
                    result.push_str(pat);
                    result.push_str("=[REDACTED]");
                    i += pat.len() + 1 + end;
                    continue;
                }
            }
            result.push(out[i..].chars().next().unwrap_or(' '));
            i += out[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
        }
        out = result;
    }

    out
}

/// The audit log writer. Appends hash-chained JSONL to disk.
pub struct AuditLog {
    path: PathBuf,
    prev_hash: String,
}

/// Genesis hash for the first entry.
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

impl AuditLog {
    /// Open or create the audit log at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        // Create parent directories
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating audit log directory {:?}", parent))?;
        }

        // Find the last hash in the existing log (for chain continuity)
        let prev_hash = if path.exists() {
            read_last_hash(path).unwrap_or_else(|_| GENESIS_HASH.to_string())
        } else {
            GENESIS_HASH.to_string()
        };

        Ok(Self {
            path: path.to_path_buf(),
            prev_hash,
        })
    }

    /// Append a completed block to the audit log.
    pub fn record(&mut self, block: &Block) -> Result<()> {
        let entry = entry_from_block(block, &self.prev_hash);
        self.prev_hash = entry.hash.clone();

        let mut line = serde_json::to_string(&entry).context("serializing audit entry")?;
        line.push('\n');

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("opening audit log {:?}", self.path))?;

        file.write_all(line.as_bytes())
            .context("writing audit log entry")?;

        Ok(())
    }

    /// Verify the integrity of the entire audit log chain.
    /// Returns Ok(count) or Err with the first broken entry.
    pub fn verify_chain(path: &Path) -> Result<usize> {
        let content = std::fs::read_to_string(path).context("reading audit log")?;
        let mut prev_hash = GENESIS_HASH.to_string();
        let mut count = 0;

        for (line_no, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let mut entry: AuditEntry =
                serde_json::from_str(line).with_context(|| {
                    format!("parsing audit log line {}", line_no + 1)
                })?;

            let claimed_hash = entry.hash.clone();
            entry.hash = String::new();
            let canonical = serde_json::to_string(&entry)?;
            let expected_hash = AuditEntry::compute_hash(&prev_hash, &canonical);

            if claimed_hash != expected_hash {
                anyhow::bail!(
                    "Audit log integrity violation at line {}: expected hash {}, got {}",
                    line_no + 1,
                    expected_hash,
                    claimed_hash
                );
            }

            prev_hash = claimed_hash;
            count += 1;
        }

        Ok(count)
    }
}

fn read_last_hash(path: &Path) -> Result<String> {
    // Read the last non-empty line
    let content = std::fs::read_to_string(path)?;
    let last_line = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .last()
        .ok_or_else(|| anyhow::anyhow!("empty file"))?;
    let entry: AuditEntry = serde_json::from_str(last_line)?;
    Ok(entry.hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::*;
    use tempfile::tempdir;

    fn make_complete_block(session: Id) -> Block {
        let mut b = Block::new(session.clone(), Actor::Human, "ls -la".to_string(), "/tmp".to_string());
        b.started_at = Some(Utc::now());
        b.ended_at = Some(Utc::now());
        b.status = Some(BlockStatus::Exit { code: 0 });
        b.risk = Some(Risk {
            tier: RiskTier::T0,
            basis: RiskBasis::Registry,
            reason: None,
        });
        b.policy = Some(PolicyResult {
            decision: Decision::Allow,
            rule: None,
            approval: None,
            enforcement: EnforcementStatus::Full,
        });
        b
    }

    #[test]
    fn audit_log_writes_and_verifies() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let mut log = AuditLog::open(&log_path).unwrap();

        let session = new_id();
        let block = make_complete_block(session);
        log.record(&block).unwrap();

        // Verify chain
        let count = AuditLog::verify_chain(&log_path).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn audit_log_multiple_entries_chain() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let mut log = AuditLog::open(&log_path).unwrap();

        let session = new_id();
        for _ in 0..5 {
            let block = make_complete_block(session.clone());
            log.record(&block).unwrap();
        }

        let count = AuditLog::verify_chain(&log_path).unwrap();
        assert_eq!(count, 5);
    }

    #[test]
    fn redact_secrets_works() {
        let cmd = "curl -H TOKEN=mysecrettoken123 https://api.example.com";
        let redacted = redact_secrets(cmd);
        assert!(!redacted.contains("mysecrettoken123"));
        assert!(redacted.contains("[REDACTED]"));
    }
}
