//! # Policy Engine - Orchestrator (spec §4)
//!
//! Combines classification, policy lookup, and sandbox enforcement into a
//! single decision point for each command invocation.

use crate::block::{
    ApprovalRecord, Block, Decision, EnforcementStatus, PolicyResult,
};
use crate::policy::classifier::classify;
use crate::policy::config::{CapabilityGrant, CompiledPolicy};
use anyhow::Result;
use std::path::{Path, PathBuf};

/// The policy engine owns the compiled policy and orchestrates decisions.
pub struct PolicyEngine {
    policy: CompiledPolicy,
}

impl PolicyEngine {
    pub fn new(project_root: Option<&Path>) -> Result<Self> {
        let policy = CompiledPolicy::load(project_root)?;
        Ok(Self { policy })
    }

    /// Evaluate a block before execution.
    /// Returns a PolicyResult with the final decision.
    pub fn evaluate(&self, block: &mut Block) -> PolicyResult {
        // Classify the command
        let classification = classify(&block.command, &block.cwd);

        // Update block risk
        block.risk = Some(classification.risk.clone());

        // Determine write paths for rule matching
        let write_paths: Vec<PathBuf> = classification.predicted_writes.clone();

        // Look up policy
        let eval = self.policy.evaluate(
            &block.actor,
            &block.command,
            &block.cwd,
            classification.risk.tier,
            &write_paths,
        );

        PolicyResult {
            decision: eval.decision,
            rule: eval.rule_id,
            approval: None,
            enforcement: EnforcementStatus::Full, // set by sandbox
        }
    }

    /// Mark a pending block as approved by a human.
    pub fn approve(
        &self,
        block: &mut Block,
        approver: String,
        scope: crate::block::ApprovalScope,
    ) {
        if let Some(ref mut policy) = block.policy {
            policy.approval = Some(ApprovalRecord {
                approver,
                at: chrono::Utc::now(),
                scope,
            });
            // Promote to allow_snapshot after approval
            if matches!(
                policy.decision,
                Decision::RequireApproval | Decision::Confirm | Decision::ConfirmPreview
            ) {
                policy.decision = Decision::AllowSnapshot;
            }
        }
    }

    /// Generate a human-readable preview description for the block.
    pub fn preview_text(&self, block: &Block) -> String {
        let risk = block
            .risk
            .as_ref()
            .map(|r| r.tier.to_string())
            .unwrap_or_else(|| "?".to_string());
        let actor = block.actor.kind_str();
        let decision = block
            .policy
            .as_ref()
            .map(|p| p.decision.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let rule = block
            .policy
            .as_ref()
            .and_then(|p| p.rule.as_deref())
            .unwrap_or("tier-default");

        format!(
            "Command: {}\nActor: {}\nRisk: {}\nDecision: {} (rule: {})\nCwd: {}",
            block.command, actor, risk, decision, rule, block.cwd
        )
    }
}

/// Per-command capability set derived from the matched rule (spec §4.5).
#[derive(Debug, Clone)]
pub struct Capabilities {
    pub fs_read: Vec<String>,
    pub fs_write: Vec<String>,
    pub network: Vec<String>,
    pub exec: Vec<String>,
    pub env: Vec<String>,
}

impl Capabilities {
    /// Default agent capabilities: read/write within project, no network.
    pub fn agent_default(project_root: &str) -> Self {
        Self {
            fs_read: vec![project_root.to_string(), "/usr/lib/**".to_string()],
            fs_write: vec![project_root.to_string()],
            network: vec![],
            exec: vec![],
            env: vec![],
        }
    }

    pub fn from_grant(grant: &CapabilityGrant) -> Self {
        Self {
            fs_read: grant.fs_read.clone(),
            fs_write: grant.fs_write.clone(),
            network: grant.network.clone(),
            exec: grant.exec.clone(),
            env: grant.env.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{new_id, Actor, Block};

    #[test]
    fn engine_evaluates_ls_as_allow() {
        let engine = PolicyEngine::new(None).unwrap();
        let mut block = Block::new(new_id(), Actor::Human, "ls -la".to_string(), "/tmp".to_string());
        let result = engine.evaluate(&mut block);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn engine_evaluates_agent_rm_rf_as_require_approval() {
        let engine = PolicyEngine::new(None).unwrap();
        let mut block = Block::new(
            new_id(),
            Actor::Agent {
                name: "claude-code".to_string(),
                run: "run-1".to_string(),
            },
            "rm -rf ./dist".to_string(),
            "/home/user/project".to_string(),
        );
        let result = engine.evaluate(&mut block);
        assert_eq!(result.decision, Decision::RequireApproval);
    }

    #[test]
    fn engine_evaluates_git_push_as_confirm() {
        let engine = PolicyEngine::new(None).unwrap();
        let mut block = Block::new(
            new_id(),
            Actor::Human,
            "git push origin main".to_string(),
            "/repo".to_string(),
        );
        let result = engine.evaluate(&mut block);
        assert_eq!(result.decision, Decision::Confirm);
    }
}
