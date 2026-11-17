//! # Command Classifier (spec §4.3)
//!
//! Implements the classification pipeline:
//! 1. Parse - tokenize the command line, identify redirections
//! 2. Schema lookup - --schema contract (stub for v0.1)
//! 3. Registry lookup - curated rules for common tools
//! 4. Heuristics - dangerous patterns
//! 5. Unknown handling - default to T2
//!
//! Tiers are ordered; when signals disagree, the highest tier wins.

use crate::block::{Risk, RiskBasis, RiskTier};
use crate::policy::registry::REGISTRY;
use std::path::PathBuf;

/// Result of classifying a command line.
#[derive(Debug, Clone)]
pub struct Classification {
    pub risk: Risk,
    /// Predicted write paths (best effort, not exhaustive)
    pub predicted_writes: Vec<PathBuf>,
    /// Predicted read paths (best effort)
    pub predicted_reads: Vec<PathBuf>,
    /// Whether the command accesses the network
    pub network_access: bool,
}

/// Classify a command string.
pub fn classify(command: &str, cwd: &str) -> Classification {
    let argv = match shlex::split(command) {
        Some(v) if !v.is_empty() => v,
        _ => {
            return Classification {
                risk: Risk {
                    tier: RiskTier::T2,
                    basis: RiskBasis::Unknown,
                    reason: Some("Could not tokenize command".to_string()),
                },
                predicted_writes: vec![],
                predicted_reads: vec![],
                network_access: false,
            };
        }
    };

    let mut tier = RiskTier::T0;
    let mut basis = RiskBasis::Unknown;
    let mut predicted_writes = vec![];
    let mut network_access = false;
    let mut reason = None;

    // ── Step 1: Parse redirections ───────────────────────────────────────────
    if has_write_redirection(&argv) {
        tier = tier.max(RiskTier::T1);
        basis = RiskBasis::Static;
        reason = Some("Write redirection detected".to_string());
    }

    // ── Step 2: Collect redirect target paths ────────────────────────────────
    for path in extract_redirect_paths(&argv, cwd) {
        predicted_writes.push(path);
    }

    // ── Step 3: Registry lookup ──────────────────────────────────────────────
    let binary = argv[0].as_str();
    let subcommand = argv.get(1).map(|s| s.as_str());
    let flags: Vec<&str> = argv[1..].iter().map(|s| s.as_str()).collect();

    if let Some(reg_tier) = REGISTRY.classify(binary, subcommand, &flags) {
        if reg_tier > tier {
            tier = reg_tier;
            basis = RiskBasis::Registry;
            reason = None;
        } else if basis == RiskBasis::Unknown {
            basis = RiskBasis::Registry;
        }
    }

    // ── Step 4: Heuristics ───────────────────────────────────────────────────
    let (heuristic_tier, heuristic_reason, heuristic_network) =
        apply_heuristics(command, &argv, &flags);
    if heuristic_tier > tier {
        tier = heuristic_tier;
        basis = RiskBasis::Heuristic;
        reason = heuristic_reason;
    }
    if heuristic_network {
        network_access = true;
        tier = tier.max(RiskTier::T3);
        basis = RiskBasis::Heuristic;
    }

    // ── Step 5: Unknown handling ─────────────────────────────────────────────
    if basis == RiskBasis::Unknown {
        // Unclassifiable → T2 (spec §4.1 "fail conservative")
        tier = tier.max(RiskTier::T2);
        reason = Some(format!(
            "Command '{}' not in registry; classified T2 as unknown",
            binary
        ));
    }

    Classification {
        risk: Risk { tier, basis, reason },
        predicted_writes,
        predicted_reads: vec![],
        network_access,
    }
}

/// True if the argv contains a write redirection (>, >>).
fn has_write_redirection(argv: &[String]) -> bool {
    argv.iter().any(|a| a == ">" || a == ">>" || a.starts_with('>'))
}

/// Extract paths that are targets of write redirections.
fn extract_redirect_paths(argv: &[String], cwd: &str) -> Vec<PathBuf> {
    let mut paths = vec![];
    let mut i = 0;
    while i < argv.len() {
        if argv[i] == ">" || argv[i] == ">>" {
            if let Some(target) = argv.get(i + 1) {
                paths.push(resolve_path(target, cwd));
                i += 2;
                continue;
            }
        } else if argv[i].starts_with('>') {
            let target = argv[i].trim_start_matches('>');
            if !target.is_empty() {
                paths.push(resolve_path(target, cwd));
            }
        }
        i += 1;
    }
    paths
}

fn resolve_path(p: &str, cwd: &str) -> PathBuf {
    let expanded = p.replacen('~', &dirs::home_dir().map(|h| h.to_string_lossy().into_owned()).unwrap_or_default(), 1);
    let path = PathBuf::from(&expanded);
    if path.is_absolute() {
        path
    } else {
        PathBuf::from(cwd).join(path)
    }
}

/// Apply heuristic rules for dangerous patterns (spec §4.3 step 4).
fn apply_heuristics(
    command: &str,
    argv: &[String],
    flags: &[&str],
) -> (RiskTier, Option<String>, bool) {
    let mut tier = RiskTier::T0;
    let mut reason = None;
    let mut network = false;

    // sudo escalation
    if argv.first().map(|s| s.as_str()) == Some("sudo") {
        tier = tier.max(RiskTier::T2);
        reason = Some("sudo invocation".to_string());
    }

    // curl | sh pipe pattern
    if command.contains("| sh") || command.contains("| bash") || command.contains("| zsh") {
        tier = tier.max(RiskTier::T3);
        reason = Some("Shell pipe execution (curl | sh pattern)".to_string());
        network = true;
    }

    // Recursive delete
    if (argv.first().map(|s| s.as_str()) == Some("rm"))
        && flags.contains(&"-r")
        || flags.contains(&"-rf")
        || flags.contains(&"-fr")
        || flags.contains(&"--recursive")
    {
        tier = tier.max(RiskTier::T2);
        reason = Some("Recursive delete".to_string());
    }

    // Force flags with rm
    if argv.first().map(|s| s.as_str()) == Some("rm") && flags.contains(&"-f") {
        tier = tier.max(RiskTier::T2);
        reason = Some("Force delete".to_string());
    }

    // Device writes (dd)
    if argv.first().map(|s| s.as_str()) == Some("dd") {
        // Check for of= pointing to a device
        for flag in flags {
            if flag.starts_with("of=/dev/") {
                tier = tier.max(RiskTier::T2);
                reason = Some("Device write (dd)".to_string());
                break;
            }
        }
    }

    // mkfs, fdisk, parted
    if matches!(
        argv.first().map(|s| s.as_str()),
        Some("mkfs") | Some("fdisk") | Some("parted") | Some("mkfs.ext4") | Some("mkfs.vfat")
    ) {
        tier = tier.max(RiskTier::T2);
        reason = Some("Disk formatting command".to_string());
    }

    // Network write operations
    if let Some(binary) = argv.first() {
        match binary.as_str() {
            "curl" | "wget" => {
                let write_flags = ["-X", "--request"];
                let post_methods = ["POST", "PUT", "PATCH", "DELETE"];
                for (i, flag) in flags.iter().enumerate() {
                    if write_flags.contains(flag) {
                        if let Some(method) = flags.get(i + 1) {
                            if post_methods.contains(&method.to_uppercase().as_str()) {
                                tier = tier.max(RiskTier::T3);
                                network = true;
                                reason = Some(format!(
                                    "Network write via {} {}",
                                    binary, method
                                ));
                            }
                        }
                    }
                }
                // curl / wget themselves are T3 for network access
                if network {
                    // already set
                } else {
                    // Read-only network: still T3 for safety (external side effect)
                    tier = tier.max(RiskTier::T1); // downloading is T1 (reversible)
                    network = true;
                }
            }
            _ => {}
        }
    }

    // eval / source
    if argv.first().map(|s| s.as_str()) == Some("eval")
        || argv.first().map(|s| s.as_str()) == Some("source")
        || argv.first().map(|s| s.as_str()) == Some(".")
    {
        tier = tier.max(RiskTier::T2);
        reason = Some("Dynamic code execution (eval/source)".to_string());
    }

    (tier, reason, network)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ls_is_t0() {
        let c = classify("ls -la", "/tmp");
        assert_eq!(c.risk.tier, RiskTier::T0);
    }

    #[test]
    fn rm_rf_is_t2() {
        let c = classify("rm -rf ./dist", "/home/user/project");
        assert!(c.risk.tier >= RiskTier::T2);
    }

    #[test]
    fn git_push_is_t3() {
        let c = classify("git push origin main", "/repo");
        assert_eq!(c.risk.tier, RiskTier::T3);
    }

    #[test]
    fn npm_install_is_t1() {
        let c = classify("npm install", "/project");
        assert!(c.risk.tier >= RiskTier::T1);
    }

    #[test]
    fn curl_post_is_t3() {
        let c = classify("curl -X POST https://api.example.com/data", "/tmp");
        assert_eq!(c.risk.tier, RiskTier::T3);
    }

    #[test]
    fn write_redirect_is_at_least_t1() {
        let c = classify("echo hello > output.txt", "/tmp");
        assert!(c.risk.tier >= RiskTier::T1);
    }

    #[test]
    fn curl_sh_is_t3() {
        let c = classify("curl https://install.sh | sh", "/tmp");
        assert_eq!(c.risk.tier, RiskTier::T3);
    }
}
