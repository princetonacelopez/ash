//! `ash init` - initialize ash in the current project (spec §4.11)

use anyhow::{Context, Result};
use clap::Args;
use std::path::{Path, PathBuf};

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Trust and load the generated project policy immediately
    #[arg(long)]
    pub trust: bool,
}

pub async fn execute(args: InitArgs) -> Result<()> {
    let cwd = std::env::current_dir().context("getting current directory")?;

    println!("🔷 Initializing ash in {}", cwd.display());

    // Create .ash directory
    let ash_dir = cwd.join(".ash");
    std::fs::create_dir_all(&ash_dir)
        .with_context(|| format!("creating {:?}", ash_dir))?;

    // Write default project policy
    let policy_path = ash_dir.join("policy.toml");
    if !policy_path.exists() {
        std::fs::write(&policy_path, default_project_policy(&cwd))
            .with_context(|| format!("writing {:?}", policy_path))?;
        println!("  Created: .ash/policy.toml");
    } else {
        println!("  Exists:  .ash/policy.toml (not overwritten)");
    }

    // Write .ash/.gitignore (don't commit session data, only the policy)
    let gitignore_path = ash_dir.join(".gitignore");
    if !gitignore_path.exists() {
        std::fs::write(&gitignore_path, "# ash session data - do not commit\nsessions/\nsnapshots/\n")
            .context("writing .ash/.gitignore")?;
        println!("  Created: .ash/.gitignore");
    }

    // If --trust, add this project to the trusted list
    if args.trust {
        trust_project(&cwd)?;
        println!("  Trusted: {} added to trusted projects", cwd.display());
    } else {
        println!("\n💡 Project policy created but NOT trusted yet.");
        println!("   Run 'ash init --trust' or manually trust this project to load its policy.");
        println!("   This prevents malicious repos from granting themselves privileges (spec §4.11).");
    }

    println!("\n✅ ash initialized. Add .ash/policy.toml to git for team sharing.");
    println!("   The .ash/sessions/ and .ash/snapshots/ directories are gitignored.");

    // Shell integration hint
    println!("\n📌 To use ash in this shell, add to your .zshrc / .bashrc:");
    println!("   source ~/.config/ash/ash.zsh   # (or ash.bash / ash.fish)");
    println!("   Or run: ash hook zsh >> ~/.zshrc");

    Ok(())
}

fn default_project_policy(project_root: &Path) -> String {
    let project_root_str = project_root.to_string_lossy();
    format!(r#"# ash project policy
# This file is checked in with the project. It can only *tighten* the user's
# policy, never loosen it (spec §4.11). To take effect, users must trust this
# project: 'ash init --trust' or 'ash trust'.
version = 1

# Allow agents to read and write within this project root
[[rule]]
id = "project-write"
actor = "agent:*"
match.cwd_within = "{project_root}"
match.path_write = ["{project_root}/**"]
capabilities.fs_write = ["{project_root}"]
capabilities.network = []
decision = "allow_snapshot"

# Allow npm/pnpm install (needs registry access)
[[rule]]
id = "registry-installs"
actor = "agent:*"
match.command = ["npm install", "pnpm add", "pnpm install", "yarn install", "bun install"]
capabilities.network = ["registry.npmjs.org"]
decision = "allow_snapshot"
expires = "session"

# Never allow key material to be touched (belt-and-suspenders)
[[rule]]
id = "protect-secrets"
actor = "any"
match.path_write = ["~/.ssh/**", "~/.gnupg/**", "~/.config/ash/**"]
decision = "deny"
reason = "Secret and config files are protected"
"#,
        project_root = project_root_str
    )
}

fn trust_project(root: &Path) -> Result<()> {
    let trusted_file = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("~/.local/share"))
        .join("ash")
        .join("trusted_projects");

    std::fs::create_dir_all(trusted_file.parent().unwrap())?;

    let abs = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let abs_str = abs.to_string_lossy();

    // Don't duplicate
    if let Ok(content) = std::fs::read_to_string(&trusted_file) {
        if content.lines().any(|l| l.trim() == abs_str) {
            return Ok(());
        }
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&trusted_file)?;
    std::io::Write::write_all(&mut file, format!("{}\n", abs_str).as_bytes())?;
    Ok(())
}
