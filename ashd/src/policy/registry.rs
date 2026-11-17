//! # Curated Tool Registry (spec §4.3 step 3)
//!
//! Versioned, curated rules for common tools: coreutils, git, package managers,
//! cloud CLIs. This supplements heuristics and schema lookup.
//!
//! Each entry maps `(binary, subcommand)` to a risk tier.
//! Flags can further promote the tier (e.g., --force).

use crate::block::RiskTier;
use std::collections::HashMap;

/// A registry entry describing a command's side effects.
#[derive(Debug, Clone)]
pub struct RegistryEntry {
    /// Base tier for this subcommand (flags may promote it)
    pub base_tier: RiskTier,
    /// Flags that promote the tier
    pub flag_promotions: Vec<FlagPromotion>,
}

#[derive(Debug, Clone)]
pub struct FlagPromotion {
    pub flag: &'static str,
    pub promotes_to: RiskTier,
}

pub struct Registry {
    // (binary, Option<subcommand>) → entry
    entries: HashMap<(&'static str, Option<&'static str>), RegistryEntry>,
}

impl Registry {
    fn new() -> Self {
        let mut entries: HashMap<(&'static str, Option<&'static str>), RegistryEntry> =
            HashMap::new();

        macro_rules! reg {
            ($bin:expr, $sub:expr, $tier:expr) => {
                entries.insert(
                    ($bin, $sub),
                    RegistryEntry {
                        base_tier: $tier,
                        flag_promotions: vec![],
                    },
                );
            };
            ($bin:expr, $sub:expr, $tier:expr, $($flag:expr => $ptier:expr),*) => {
                entries.insert(
                    ($bin, $sub),
                    RegistryEntry {
                        base_tier: $tier,
                        flag_promotions: vec![
                            $(FlagPromotion { flag: $flag, promotes_to: $ptier }),*
                        ],
                    },
                );
            };
        }

        // ── coreutils ────────────────────────────────────────────────────────
        reg!("ls", None, RiskTier::T0);
        reg!("cat", None, RiskTier::T0);
        reg!("less", None, RiskTier::T0);
        reg!("more", None, RiskTier::T0);
        reg!("head", None, RiskTier::T0);
        reg!("tail", None, RiskTier::T0);
        reg!("grep", None, RiskTier::T0);
        reg!("find", None, RiskTier::T0);
        reg!("wc", None, RiskTier::T0);
        reg!("echo", None, RiskTier::T0);
        reg!("printf", None, RiskTier::T0);
        reg!("pwd", None, RiskTier::T0);
        reg!("which", None, RiskTier::T0);
        reg!("type", None, RiskTier::T0);
        reg!("file", None, RiskTier::T0);
        reg!("stat", None, RiskTier::T0);
        reg!("du", None, RiskTier::T0);
        reg!("df", None, RiskTier::T0);
        reg!("ps", None, RiskTier::T0);
        reg!("top", None, RiskTier::T0);
        reg!("htop", None, RiskTier::T0);
        reg!("env", None, RiskTier::T0);
        reg!("printenv", None, RiskTier::T0);
        reg!("date", None, RiskTier::T0);
        reg!("uname", None, RiskTier::T0);
        reg!("hostname", None, RiskTier::T0);
        reg!("id", None, RiskTier::T0);
        reg!("whoami", None, RiskTier::T0);
        reg!("history", None, RiskTier::T0);
        reg!("man", None, RiskTier::T0);
        reg!("help", None, RiskTier::T0);

        // Write operations
        reg!("cp", None, RiskTier::T1, "--force" => RiskTier::T1, "-f" => RiskTier::T1);
        reg!("mv", None, RiskTier::T1);
        reg!("mkdir", None, RiskTier::T1);
        reg!("touch", None, RiskTier::T1);
        reg!("ln", None, RiskTier::T1);
        reg!("chmod", None, RiskTier::T1);
        reg!("chown", None, RiskTier::T1);
        reg!("tee", None, RiskTier::T1);
        reg!("install", None, RiskTier::T1);

        // rm is T1 by default, heuristics promote -rf to T2
        reg!("rm", None, RiskTier::T1, "-rf" => RiskTier::T2, "--recursive" => RiskTier::T2, "-fr" => RiskTier::T2);
        reg!("rmdir", None, RiskTier::T1);
        reg!("shred", None, RiskTier::T2);
        reg!("dd", None, RiskTier::T1, "of=/dev" => RiskTier::T2);
        reg!("mkfs", None, RiskTier::T2);

        // ── git ──────────────────────────────────────────────────────────────
        reg!("git", Some("status"), RiskTier::T0);
        reg!("git", Some("log"), RiskTier::T0);
        reg!("git", Some("diff"), RiskTier::T0);
        reg!("git", Some("show"), RiskTier::T0);
        reg!("git", Some("branch"), RiskTier::T0);
        reg!("git", Some("remote"), RiskTier::T0);
        reg!("git", Some("tag"), RiskTier::T0);
        reg!("git", Some("stash"), RiskTier::T1);
        reg!("git", Some("add"), RiskTier::T1);
        reg!("git", Some("commit"), RiskTier::T1);
        reg!("git", Some("checkout"), RiskTier::T1);
        reg!("git", Some("switch"), RiskTier::T1);
        reg!("git", Some("restore"), RiskTier::T1);
        reg!("git", Some("reset"), RiskTier::T1, "--hard" => RiskTier::T2);
        reg!("git", Some("clean"), RiskTier::T2);
        reg!("git", Some("push"), RiskTier::T3);
        reg!("git", Some("pull"), RiskTier::T3);
        reg!("git", Some("fetch"), RiskTier::T3);
        reg!("git", Some("clone"), RiskTier::T3);
        reg!("git", Some("submodule"), RiskTier::T1);
        reg!("git", Some("merge"), RiskTier::T1);
        reg!("git", Some("rebase"), RiskTier::T1);
        reg!("git", Some("cherry-pick"), RiskTier::T1);
        reg!("git", None, RiskTier::T1); // unknown git subcommand → T1

        // ── npm / pnpm / yarn / bun ──────────────────────────────────────────
        reg!("npm", Some("run"), RiskTier::T1);
        reg!("npm", Some("install"), RiskTier::T1);
        reg!("npm", Some("ci"), RiskTier::T1);
        reg!("npm", Some("build"), RiskTier::T1);
        reg!("npm", Some("test"), RiskTier::T0);
        reg!("npm", Some("audit"), RiskTier::T0);
        reg!("npm", Some("ls"), RiskTier::T0);
        reg!("npm", Some("outdated"), RiskTier::T0);
        reg!("npm", Some("publish"), RiskTier::T3);
        reg!("npm", Some("unpublish"), RiskTier::T3);
        reg!("npm", Some("deprecate"), RiskTier::T3);
        reg!("npm", None, RiskTier::T1);

        reg!("pnpm", Some("run"), RiskTier::T1);
        reg!("pnpm", Some("add"), RiskTier::T1);
        reg!("pnpm", Some("install"), RiskTier::T1);
        reg!("pnpm", Some("build"), RiskTier::T1);
        reg!("pnpm", Some("test"), RiskTier::T0);
        reg!("pnpm", Some("publish"), RiskTier::T3);
        reg!("pnpm", None, RiskTier::T1);

        reg!("yarn", Some("install"), RiskTier::T1);
        reg!("yarn", Some("add"), RiskTier::T1);
        reg!("yarn", Some("build"), RiskTier::T1);
        reg!("yarn", Some("test"), RiskTier::T0);
        reg!("yarn", Some("publish"), RiskTier::T3);
        reg!("yarn", None, RiskTier::T1);

        reg!("bun", Some("install"), RiskTier::T1);
        reg!("bun", Some("add"), RiskTier::T1);
        reg!("bun", Some("run"), RiskTier::T1);
        reg!("bun", Some("build"), RiskTier::T1);
        reg!("bun", Some("test"), RiskTier::T0);
        reg!("bun", Some("publish"), RiskTier::T3);
        reg!("bun", None, RiskTier::T1);

        // ── Python / pip / uv ───────────────────────────────────────────────
        reg!("python", None, RiskTier::T1);
        reg!("python3", None, RiskTier::T1);
        reg!("pip", Some("install"), RiskTier::T1);
        reg!("pip", Some("uninstall"), RiskTier::T1);
        reg!("pip", Some("list"), RiskTier::T0);
        reg!("pip", Some("show"), RiskTier::T0);
        reg!("pip3", Some("install"), RiskTier::T1);
        reg!("pip3", None, RiskTier::T1);
        reg!("uv", Some("sync"), RiskTier::T1);
        reg!("uv", Some("add"), RiskTier::T1);
        reg!("uv", Some("run"), RiskTier::T1);
        reg!("uv", Some("publish"), RiskTier::T3);
        reg!("uv", None, RiskTier::T1);

        // ── Rust / cargo ─────────────────────────────────────────────────────
        reg!("cargo", Some("build"), RiskTier::T1);
        reg!("cargo", Some("run"), RiskTier::T1);
        reg!("cargo", Some("test"), RiskTier::T0);
        reg!("cargo", Some("check"), RiskTier::T0);
        reg!("cargo", Some("clippy"), RiskTier::T0);
        reg!("cargo", Some("fmt"), RiskTier::T1);
        reg!("cargo", Some("add"), RiskTier::T1);
        reg!("cargo", Some("install"), RiskTier::T1);
        reg!("cargo", Some("publish"), RiskTier::T3);
        reg!("cargo", None, RiskTier::T1);
        reg!("rustc", None, RiskTier::T1);
        reg!("rustup", None, RiskTier::T1);

        // ── make / cmake / ninja ─────────────────────────────────────────────
        reg!("make", None, RiskTier::T1);
        reg!("cmake", None, RiskTier::T1);
        reg!("ninja", None, RiskTier::T1);

        // ── docker ───────────────────────────────────────────────────────────
        reg!("docker", Some("build"), RiskTier::T1);
        reg!("docker", Some("run"), RiskTier::T1);
        reg!("docker", Some("ps"), RiskTier::T0);
        reg!("docker", Some("images"), RiskTier::T0);
        reg!("docker", Some("pull"), RiskTier::T3);
        reg!("docker", Some("push"), RiskTier::T3);
        reg!("docker", Some("exec"), RiskTier::T3);
        reg!("docker", Some("rm"), RiskTier::T2);
        reg!("docker", Some("rmi"), RiskTier::T2);
        reg!("docker", Some("stop"), RiskTier::T1);
        reg!("docker", Some("start"), RiskTier::T1);
        reg!("docker", None, RiskTier::T1);

        // ── ssh / scp / rsync ────────────────────────────────────────────────
        reg!("ssh", None, RiskTier::T3);
        reg!("scp", None, RiskTier::T3);
        reg!("rsync", None, RiskTier::T3);
        reg!("sftp", None, RiskTier::T3);

        // ── cloud CLIs ───────────────────────────────────────────────────────
        reg!("aws", None, RiskTier::T3);
        reg!("gcloud", None, RiskTier::T3);
        reg!("az", None, RiskTier::T3);
        reg!("kubectl", None, RiskTier::T3);
        reg!("terraform", Some("plan"), RiskTier::T0);
        reg!("terraform", Some("apply"), RiskTier::T3);
        reg!("terraform", Some("destroy"), RiskTier::T3);
        reg!("terraform", None, RiskTier::T2);
        reg!("pulumi", Some("preview"), RiskTier::T0);
        reg!("pulumi", Some("up"), RiskTier::T3);
        reg!("pulumi", Some("destroy"), RiskTier::T3);
        reg!("pulumi", None, RiskTier::T2);

        // ── text editors (non-interactive invocation) ─────────────────────────
        reg!("sed", None, RiskTier::T1);
        reg!("awk", None, RiskTier::T0); // reading unless redirected
        reg!("sort", None, RiskTier::T0);
        reg!("uniq", None, RiskTier::T0);
        reg!("cut", None, RiskTier::T0);
        reg!("tr", None, RiskTier::T0);
        reg!("xargs", None, RiskTier::T1);
        reg!("patch", None, RiskTier::T1);

        // ── system management ────────────────────────────────────────────────
        reg!("systemctl", Some("start"), RiskTier::T2);
        reg!("systemctl", Some("stop"), RiskTier::T2);
        reg!("systemctl", Some("restart"), RiskTier::T2);
        reg!("systemctl", Some("enable"), RiskTier::T2);
        reg!("systemctl", Some("disable"), RiskTier::T2);
        reg!("systemctl", Some("status"), RiskTier::T0);
        reg!("systemctl", Some("list-units"), RiskTier::T0);
        reg!("systemctl", None, RiskTier::T2);
        reg!("service", None, RiskTier::T2);
        reg!("shutdown", None, RiskTier::T2);
        reg!("reboot", None, RiskTier::T2);

        // ── package managers ─────────────────────────────────────────────────
        reg!("apt", Some("install"), RiskTier::T2);
        reg!("apt", Some("remove"), RiskTier::T2);
        reg!("apt", Some("update"), RiskTier::T1);
        reg!("apt", Some("upgrade"), RiskTier::T2);
        reg!("apt", None, RiskTier::T1);
        reg!("apt-get", Some("install"), RiskTier::T2);
        reg!("apt-get", None, RiskTier::T1);
        reg!("dnf", Some("install"), RiskTier::T2);
        reg!("dnf", None, RiskTier::T1);
        reg!("yum", Some("install"), RiskTier::T2);
        reg!("yum", None, RiskTier::T1);
        reg!("brew", Some("install"), RiskTier::T1);
        reg!("brew", Some("uninstall"), RiskTier::T1);
        reg!("brew", Some("update"), RiskTier::T1);
        reg!("brew", None, RiskTier::T1);

        Self { entries }
    }

    /// Look up a command in the registry.
    /// Returns the risk tier if found, or None for unknown commands.
    pub fn classify(&self, binary: &str, subcommand: Option<&str>, flags: &[&str]) -> Option<RiskTier> {
        // First try exact (binary, subcommand) match
        let key = (binary, subcommand);
        let entry = self.entries.get(&key).or_else(|| {
            // Fall back to (binary, None) for unknown subcommands
            self.entries.get(&(binary, None))
        })?;

        let mut tier = entry.base_tier;

        // Apply flag promotions
        for promo in &entry.flag_promotions {
            if flags.contains(&promo.flag) {
                tier = tier.max(promo.promotes_to);
            }
        }

        Some(tier)
    }
}

/// Global singleton registry.
pub static REGISTRY: once_cell::sync::Lazy<Registry> =
    once_cell::sync::Lazy::new(Registry::new);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ls_is_t0() {
        assert_eq!(REGISTRY.classify("ls", None, &[]), Some(RiskTier::T0));
    }

    #[test]
    fn git_push_is_t3() {
        assert_eq!(
            REGISTRY.classify("git", Some("push"), &[]),
            Some(RiskTier::T3)
        );
    }

    #[test]
    fn git_status_is_t0() {
        assert_eq!(
            REGISTRY.classify("git", Some("status"), &[]),
            Some(RiskTier::T0)
        );
    }

    #[test]
    fn npm_publish_is_t3() {
        assert_eq!(
            REGISTRY.classify("npm", Some("publish"), &[]),
            Some(RiskTier::T3)
        );
    }

    #[test]
    fn unknown_binary_returns_none() {
        assert_eq!(REGISTRY.classify("my-custom-tool", None, &[]), None);
    }

    #[test]
    fn rm_rf_promotes_to_t2() {
        assert_eq!(
            REGISTRY.classify("rm", None, &["-rf"]),
            Some(RiskTier::T2)
        );
    }
}
