//! `ash policy` - manage policy files

use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommands,
}

#[derive(Subcommand, Debug)]
pub enum PolicyCommands {
    /// Show the current effective policy (all layers merged)
    Show,
    /// Validate a policy file for syntax errors
    Validate {
        #[arg(default_value = ".ash/policy.toml")]
        path: PathBuf,
    },
    /// Show why a command would receive a specific decision
    Explain {
        /// The command to explain
        command: String,
        /// Actor: human (default), agent, agent:<name>
        #[arg(long, default_value = "human")]
        actor: String,
        /// Working directory
        #[arg(long, default_value = ".")]
        cwd: String,
    },
    /// Trust a project to load its .ash/policy.toml
    Trust {
        /// Project directory (default: current dir)
        path: Option<PathBuf>,
    },
    /// Untrust a project
    Untrust {
        path: Option<PathBuf>,
    },
}

pub async fn execute(args: PolicyArgs) -> Result<()> {
    match args.command {
        PolicyCommands::Show => show_policy().await,
        PolicyCommands::Validate { path } => validate_policy(&path).await,
        PolicyCommands::Explain { command, actor, cwd } => explain_command(&command, &actor, &cwd).await,
        PolicyCommands::Trust { path } => trust_project(path).await,
        PolicyCommands::Untrust { path } => untrust_project(path).await,
    }
}

async fn show_policy() -> Result<()> {
    println!("📋 Effective ash policy (all layers)\n");

    // Show layer paths
    println!("Layers (highest precedence first):");
    println!("  1. Built-in defaults");

    if let Some(config_dir) = dirs::config_dir() {
        let user_path = config_dir.join("ash").join("policy.toml");
        if user_path.exists() {
            println!("  2. User: {} ✓", user_path.display());
        } else {
            println!("  2. User: {} (not found)", user_path.display());
        }
    }

    let cwd = std::env::current_dir()?;
    let proj_path = cwd.join(".ash").join("policy.toml");
    if proj_path.exists() {
        println!("  3. Project: {} ✓", proj_path.display());
    } else {
        println!("  3. Project: {} (not found)", proj_path.display());
    }

    println!("\nDefault decisions:");
    println!("  Human: T0=allow  T1=allow_snapshot  T2=confirm_preview  T3=confirm");
    println!("  Agent: T0=allow  T1=allow_snapshot  T2=require_approval  T3=require_approval");

    Ok(())
}

async fn validate_policy(path: &PathBuf) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("Policy file not found: {}", path.display());
    }

    let content = std::fs::read_to_string(path)?;
    match toml::from_str::<toml::Value>(&content) {
        Ok(_) => println!("✅ Policy file is valid TOML: {}", path.display()),
        Err(e) => {
            eprintln!("✗ Policy file has errors: {}", e);
            std::process::exit(1);
        }
    }
    Ok(())
}

async fn explain_command(command: &str, actor_str: &str, cwd: &str) -> Result<()> {
    println!("🔍 Explaining: '{}'", command);
    println!("   Actor: {}", actor_str);
    println!("   CWD: {}", cwd);
    println!();

    // Classify the command
    let argv: Vec<String> = shlex::split(command).unwrap_or_else(|| vec![command.to_string()]);
    let binary = argv.first().map(|s| s.as_str()).unwrap_or("");
    let subcommand = argv.get(1).map(|s| s.as_str());
    let flags: Vec<&str> = argv[1..].iter().map(|s| s.as_str()).collect();

    // Simple classification output
    println!("Classification:");
    println!("  Binary: {}", binary);
    if let Some(sub) = subcommand {
        println!("  Subcommand: {}", sub);
    }

    // Check for redirections
    if argv.iter().any(|a| a == ">" || a == ">>") {
        println!("  ⚠️  Write redirection detected → at least T1");
    }

    // Check registry
    let tier_str = match binary {
        "ls" | "cat" | "echo" | "grep" | "find" | "stat" | "du" | "df" => "T0 (registry: read-only)",
        "git" if matches!(subcommand, Some("status") | Some("log") | Some("diff") | Some("branch") | Some("show")) => "T0 (registry: read-only)",
        "cp" | "mv" | "mkdir" | "touch" | "sed" => "T1 (registry: reversible write)",
        "rm" if flags.contains(&"-rf") || flags.contains(&"-r") => "T2 (heuristic: recursive delete)",
        "git" if subcommand == Some("push") || subcommand == Some("pull") => "T3 (registry: external side effect)",
        "git" if subcommand == Some("commit") || subcommand == Some("add") => "T1 (registry: reversible)",
        "npm" if subcommand == Some("publish") => "T3 (registry: external side effect)",
        "npm" if subcommand == Some("install") || subcommand == Some("run") => "T1 (registry: reversible write)",
        _ => "T2 (unknown: conservative default)",
    };

    println!("  Risk tier: {}", tier_str);

    // Decision based on actor
    let decision = if actor_str == "human" {
        match tier_str.split_once(' ').map(|(t, _)| t).unwrap_or("T2") {
            "T0" => "allow",
            "T1" => "allow_snapshot",
            "T2" => "confirm_preview",
            "T3" => "confirm",
            _ => "confirm_preview",
        }
    } else {
        // agent
        match tier_str.split_once(' ').map(|(t, _)| t).unwrap_or("T2") {
            "T0" => "allow",
            "T1" => "allow_snapshot",
            _ => "require_approval",
        }
    };

    println!();
    println!("Policy decision ({}): {}", actor_str, decision);
    println!("Rule: tier-default");

    Ok(())
}

async fn trust_project(path: Option<PathBuf>) -> Result<()> {
    let root = path.unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let abs = root.canonicalize().unwrap_or(root.clone());

    let trusted_file = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("ash")
        .join("trusted_projects");

    std::fs::create_dir_all(trusted_file.parent().unwrap())?;

    let abs_str = abs.to_string_lossy();
    if let Ok(content) = std::fs::read_to_string(&trusted_file) {
        if content.lines().any(|l| l.trim() == abs_str) {
            println!("Already trusted: {}", abs.display());
            return Ok(());
        }
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&trusted_file)?;
    std::io::Write::write_all(&mut file, format!("{}\n", abs_str).as_bytes())?;
    println!("✅ Trusted: {}", abs.display());
    Ok(())
}

async fn untrust_project(path: Option<PathBuf>) -> Result<()> {
    let root = path.unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let abs = root.canonicalize().unwrap_or(root.clone());
    let abs_str = abs.to_string_lossy();

    let trusted_file = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("ash")
        .join("trusted_projects");

    if !trusted_file.exists() {
        println!("Not trusted: {}", abs.display());
        return Ok(());
    }

    let content = std::fs::read_to_string(&trusted_file)?;
    let new_content: String = content
        .lines()
        .filter(|l| l.trim() != abs_str)
        .map(|l| format!("{}\n", l))
        .collect();
    std::fs::write(&trusted_file, new_content)?;
    println!("✅ Untrusted: {}", abs.display());
    Ok(())
}
