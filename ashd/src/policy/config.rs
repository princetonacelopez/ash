//! # Policy Configuration (TOML)
//!
//! Declarative policy in TOML format (spec §4.4).
//!
//! Evaluation order: **deny rules first, then most specific allow, then tier defaults.**
//! No implicit allow for T2 or T3 for agents.
//!
//! Policy layers (spec §4.11):
//! - Built-in defaults
//! - User: ~/.config/ash/policy.toml
//! - Project: .ash/policy.toml
//! - Organization: managed (future)
//!
//! Lower layers can only **tighten** what a higher-precedence layer sets.

use crate::block::{Actor, Decision, RiskTier};
use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Top-level policy file structure.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyFile {
    pub version: u32,
    #[serde(default)]
    pub defaults: DefaultPolicies,
    #[serde(default, rename = "rule")]
    pub rules: Vec<PolicyRule>,
}

impl Default for PolicyFile {
    fn default() -> Self {
        Self {
            version: 1,
            defaults: DefaultPolicies::default(),
            rules: Vec::new(),
        }
    }
}

/// Default decision per actor kind and risk tier (spec §4.4).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DefaultPolicies {
    #[serde(default)]
    pub human: TierDefaults,
    #[serde(default)]
    pub agent: TierDefaults,
}

impl Default for DefaultPolicies {
    fn default() -> Self {
        Self {
            human: TierDefaults {
                t0: Decision::Allow,
                t1: Decision::AllowSnapshot,
                t2: Decision::ConfirmPreview,
                t3: Decision::Confirm,
            },
            agent: TierDefaults {
                t0: Decision::Allow,
                t1: Decision::AllowSnapshot,
                t2: Decision::RequireApproval,
                t3: Decision::RequireApproval,
            },
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TierDefaults {
    #[serde(rename = "T0")]
    pub t0: Decision,
    #[serde(rename = "T1")]
    pub t1: Decision,
    #[serde(rename = "T2")]
    pub t2: Decision,
    #[serde(rename = "T3")]
    pub t3: Decision,
}

impl Default for TierDefaults {
    fn default() -> Self {
        Self {
            t0: Decision::Allow,
            t1: Decision::AllowSnapshot,
            t2: Decision::ConfirmPreview,
            t3: Decision::Confirm,
        }
    }
}

impl TierDefaults {
    pub fn for_tier(&self, tier: RiskTier) -> &Decision {
        match tier {
            RiskTier::T0 => &self.t0,
            RiskTier::T1 => &self.t1,
            RiskTier::T2 => &self.t2,
            RiskTier::T3 => &self.t3,
        }
    }
}

/// A single named policy rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyRule {
    pub id: String,
    /// "any", "human", "agent:*", "agent:claude-code", "script"
    pub actor: String,
    #[serde(default)]
    pub r#match: MatchConditions,
    #[serde(default)]
    pub capabilities: CapabilityGrant,
    pub decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Scope of the grant: "once", "block_tree", "session", "project"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

/// Conditions that must all match for a rule to apply.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct MatchConditions {
    /// The command line must start with one of these prefixes
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    /// The working directory must be under this path (env var expansion supported)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd_within: Option<String>,
    /// Any file write must be to these glob patterns
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_write: Vec<String>,
    /// Any file read must be to these glob patterns
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_read: Vec<String>,
    /// Risk tier filter
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<RiskTier>,
}

/// Capability grant for the matched command (spec §4.5).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CapabilityGrant {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fs_read: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fs_write: Vec<String>,
    /// Allowed network hosts; empty means no network
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,
    /// Allowed binaries to exec
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exec: Vec<String>,
    /// Environment variables visible to the process
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
}

/// Built-in default policy TOML embedded in the binary.
pub const BUILTIN_POLICY: &str = r#"
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
id = "never-touch-ash-daemon"
actor = "any"
match.path_write = ["~/.local/share/ash/**"]
decision = "deny"
reason = "ASH daemon state is off limits to commands"
"#;

/// Loaded and validated policy (all layers merged).
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    /// Rules in evaluation order (deny-first, most-specific-first)
    pub rules: Vec<CompiledRule>,
    pub defaults: DefaultPolicies,
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: String,
    pub actor_pattern: ActorPattern,
    pub conditions: MatchConditions,
    pub capabilities: CapabilityGrant,
    pub decision: Decision,
    pub reason: Option<String>,
    pub expires: Option<String>,
    /// Pre-compiled globsets for path matching
    pub write_globs: Option<GlobSet>,
    pub read_globs: Option<GlobSet>,
}

#[derive(Debug, Clone)]
pub enum ActorPattern {
    Any,
    Human,
    AnyAgent,
    SpecificAgent(String),
    Script,
}

impl ActorPattern {
    pub fn parse(s: &str) -> Self {
        match s {
            "any" => ActorPattern::Any,
            "human" => ActorPattern::Human,
            "script" => ActorPattern::Script,
            s if s == "agent:*" => ActorPattern::AnyAgent,
            s if s.starts_with("agent:") => {
                ActorPattern::SpecificAgent(s.trim_start_matches("agent:").to_string())
            }
            _ => ActorPattern::Any,
        }
    }

    pub fn matches(&self, actor: &Actor) -> bool {
        match (self, actor) {
            (ActorPattern::Any, _) => true,
            (ActorPattern::Human, Actor::Human) => true,
            (ActorPattern::AnyAgent, Actor::Agent { .. }) => true,
            (ActorPattern::SpecificAgent(n), Actor::Agent { name, .. }) => n == name,
            (ActorPattern::Script, Actor::Script { .. }) => true,
            _ => false,
        }
    }
}

impl CompiledPolicy {
    /// Load and merge policy layers.
    /// Layers: built-in → user → project (each can only tighten).
    pub fn load(project_root: Option<&Path>) -> Result<Self> {
        let mut file = parse_policy(BUILTIN_POLICY).context("failed to parse built-in policy")?;

        // User layer: ~/.config/ash/policy.toml
        if let Some(config_dir) = dirs::config_dir() {
            let user_path = config_dir.join("ash").join("policy.toml");
            if user_path.exists() {
                let user_layer = load_policy_file(&user_path)
                    .with_context(|| format!("failed to load user policy at {:?}", user_path))?;
                merge_policy(&mut file, user_layer);
            }
        }

        // Project layer: .ash/policy.toml (must be explicitly trusted)
        if let Some(root) = project_root {
            let proj_path = root.join(".ash").join("policy.toml");
            if proj_path.exists() && is_trusted_project(root) {
                let proj_layer = load_policy_file(&proj_path)
                    .with_context(|| format!("failed to load project policy at {:?}", proj_path))?;
                merge_policy(&mut file, proj_layer);
            }
        }

        compile_policy(file)
    }

    /// Find the first matching rule for a command evaluation context.
    pub fn evaluate(
        &self,
        actor: &Actor,
        command: &str,
        cwd: &str,
        tier: RiskTier,
        write_paths: &[PathBuf],
    ) -> PolicyEvaluation {
        // Deny rules first
        for rule in self.rules.iter().filter(|r| r.decision == Decision::Deny) {
            if self.rule_matches(rule, actor, command, cwd, tier, write_paths) {
                return PolicyEvaluation {
                    decision: Decision::Deny,
                    rule_id: Some(rule.id.clone()),
                    reason: rule.reason.clone(),
                    capabilities: None,
                };
            }
        }

        // Then most specific allow rules
        for rule in self.rules.iter().filter(|r| r.decision != Decision::Deny) {
            if self.rule_matches(rule, actor, command, cwd, tier, write_paths) {
                return PolicyEvaluation {
                    decision: rule.decision.clone(),
                    rule_id: Some(rule.id.clone()),
                    reason: rule.reason.clone(),
                    capabilities: Some(rule.capabilities.clone()),
                };
            }
        }

        // Fall back to tier defaults
        let tier_decision = match actor {
            Actor::Human => self.defaults.human.for_tier(tier).clone(),
            Actor::Agent { .. } => self.defaults.agent.for_tier(tier).clone(),
            Actor::Script { .. } => self.defaults.agent.for_tier(tier).clone(),
        };

        PolicyEvaluation {
            decision: tier_decision,
            rule_id: None,
            reason: None,
            capabilities: None,
        }
    }

    fn rule_matches(
        &self,
        rule: &CompiledRule,
        actor: &Actor,
        command: &str,
        cwd: &str,
        tier: RiskTier,
        write_paths: &[PathBuf],
    ) -> bool {
        // Actor must match
        if !rule.actor_pattern.matches(actor) {
            return false;
        }

        // Tier filter
        if let Some(rule_tier) = rule.conditions.tier {
            if tier != rule_tier {
                return false;
            }
        }

        // CWD check
        if let Some(ref cwd_within) = rule.conditions.cwd_within {
            let expanded = expand_env(cwd_within);
            if !cwd.starts_with(&expanded) {
                return false;
            }
        }

        // Command prefix check
        if !rule.conditions.command.is_empty() {
            if !rule
                .conditions
                .command
                .iter()
                .any(|c| command.starts_with(c.as_str()))
            {
                return false;
            }
        }

        // Write path check
        if let Some(ref gs) = rule.write_globs {
            if write_paths.is_empty() {
                return false;
            }
            if !write_paths.iter().any(|p| gs.is_match(p)) {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone)]
pub struct PolicyEvaluation {
    pub decision: Decision,
    pub rule_id: Option<String>,
    pub reason: Option<String>,
    pub capabilities: Option<CapabilityGrant>,
}

// ─────────────────────────── Helpers ─────────────────────────────────────────

fn parse_policy(s: &str) -> Result<PolicyFile> {
    toml::from_str(s).context("TOML parse error")
}

fn load_policy_file(path: &Path) -> Result<PolicyFile> {
    let content = std::fs::read_to_string(path)?;
    parse_policy(&content)
}

/// Merge `layer` into `base`, appending rules.
/// Per spec §4.11: lower layers can only tighten, not loosen.
fn merge_policy(base: &mut PolicyFile, layer: PolicyFile) {
    // Rules are appended (evaluated in order, so later = less precedence)
    // Deny rules will still win due to deny-first evaluation
    base.rules.extend(layer.rules);
}

fn compile_policy(file: PolicyFile) -> Result<CompiledPolicy> {
    let mut compiled_rules = Vec::new();

    for rule in file.rules {
        let write_globs = build_glob_set(&rule.r#match.path_write)?;
        let read_globs = build_glob_set(&rule.r#match.path_read)?;
        compiled_rules.push(CompiledRule {
            actor_pattern: ActorPattern::parse(&rule.actor),
            conditions: rule.r#match,
            capabilities: rule.capabilities,
            decision: rule.decision,
            reason: rule.reason,
            expires: rule.expires,
            write_globs,
            read_globs,
            id: rule.id,
        });
    }

    // Sort: deny rules first, then preserve insertion order
    compiled_rules.sort_by_key(|r| if r.decision == Decision::Deny { 0u8 } else { 1u8 });

    Ok(CompiledPolicy {
        rules: compiled_rules,
        defaults: file.defaults,
    })
}

fn build_glob_set(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        let expanded = expand_env(p);
        // Handle ~ expansion
        let expanded = expanded.replace('~', &dirs::home_dir().map(|h| h.to_string_lossy().into_owned()).unwrap_or_default());
        builder.add(Glob::new(&expanded)?);
    }
    Ok(Some(builder.build()?))
}

fn expand_env(s: &str) -> String {
    // Simple ${VAR} expansion
    let mut result = s.to_string();
    for (key, value) in std::env::vars() {
        result = result.replace(&format!("${{{}}}", key), &value);
    }
    result
}

/// Check if a project directory is trusted for policy loading.
/// Returns true if ~/.local/share/ash/trusted_projects contains this path.
fn is_trusted_project(root: &Path) -> bool {
    let trusted_file = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("~/.local/share"))
        .join("ash")
        .join("trusted_projects");

    if let Ok(content) = std::fs::read_to_string(&trusted_file) {
        let abs = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        content.lines().any(|l| l.trim() == abs.to_string_lossy())
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Actor;

    #[test]
    fn builtin_policy_parses() {
        let p = parse_policy(BUILTIN_POLICY).unwrap();
        assert_eq!(p.version, 1);
        assert!(!p.rules.is_empty());
    }

    #[test]
    fn deny_ssh_rule_fires() {
        let policy = CompiledPolicy::load(None).unwrap();
        // .ssh write path should be denied
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"));
        let ssh_key = home.join(".ssh").join("id_rsa");
        let result = policy.evaluate(
            &Actor::Human,
            "echo key > ~/.ssh/id_rsa",
            "/tmp",
            RiskTier::T1,
            &[ssh_key],
        );
        assert_eq!(result.decision, Decision::Deny);
    }

    #[test]
    fn human_t0_defaults_to_allow() {
        let policy = CompiledPolicy::load(None).unwrap();
        let result = policy.evaluate(&Actor::Human, "ls -la", "/tmp", RiskTier::T0, &[]);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn agent_t2_defaults_to_require_approval() {
        let policy = CompiledPolicy::load(None).unwrap();
        let result = policy.evaluate(
            &Actor::Agent {
                name: "test-agent".to_string(),
                run: "run-1".to_string(),
            },
            "rm -rf ./dist",
            "/home/user/project",
            RiskTier::T2,
            &[],
        );
        assert_eq!(result.decision, Decision::RequireApproval);
    }
}
