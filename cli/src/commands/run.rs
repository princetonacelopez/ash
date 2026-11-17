//! `ash run <agent>` - wrap an agent CLI under ash policy (spec §5)
//!
//! Unmodified agents get a sandboxed shell tool whose commands pass through
//! the policy engine. Flags: --model, --mode plan|apply, --budget, --scope

use anyhow::Result;
use clap::Args;
use std::process::Command;

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Agent CLI to run (e.g. claude, gemini, codex)
    pub agent: String,

    /// Additional arguments to pass to the agent
    #[arg(trailing_var_arg = true)]
    pub agent_args: Vec<String>,

    /// Model to use
    #[arg(long)]
    pub model: Option<String>,

    /// Execution mode: plan or apply
    #[arg(long, value_parser = ["plan", "apply"], default_value = "apply")]
    pub mode: String,

    /// Maximum cost budget (in tokens or USD)
    #[arg(long)]
    pub budget: Option<String>,

    /// Scope: path(s) the agent is allowed to operate on
    #[arg(long)]
    pub scope: Option<String>,
}

pub async fn execute(args: RunArgs, session_id: Option<String>) -> Result<()> {
    let session = session_id
        .or_else(|| std::env::var("ASH_SESSION_ID").ok())
        .unwrap_or_else(|| {
            eprintln!("Warning: no ASH_SESSION_ID; running without ashd policy enforcement");
            String::new()
        });

    println!("🤖 ash run: launching {} under ash policy", args.agent);
    if !session.is_empty() {
        println!("   Session: {}", session);
    }
    println!("   Mode: {}", args.mode);
    if let Some(ref scope) = args.scope {
        println!("   Scope: {}", scope);
    }

    // Set environment variables for the agent subprocess
    // The agent's shell tool calls will be intercepted by the shell hook
    let mut cmd = Command::new(&args.agent);
    cmd.args(&args.agent_args);

    // Inject ash context into agent environment
    if !session.is_empty() {
        cmd.env("ASH_SESSION_ID", &session);
    }
    cmd.env("ASH_MODE", &args.mode);
    if let Some(ref scope) = args.scope {
        cmd.env("ASH_SCOPE", scope);
    }
    if let Some(ref model) = args.model {
        cmd.env("ASH_MODEL", model);
    }

    // Actor identification for policy attribution
    cmd.env("ASH_ACTOR_KIND", "agent");
    cmd.env("ASH_ACTOR_NAME", &args.agent);

    println!("\nStarting agent... (Ctrl+C to stop, all commands run under ash policy)\n");

    let status = cmd.status();

    match status {
        Ok(s) => {
            if s.success() {
                println!("\n✅ Agent completed successfully");
            } else {
                let code = s.code().unwrap_or(-1);
                eprintln!("\n⚠️  Agent exited with code {}", code);
                std::process::exit(code);
            }
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::bail!("Agent '{}' not found in PATH. Is it installed?", args.agent);
            }
            return Err(e.into());
        }
    }

    Ok(())
}
