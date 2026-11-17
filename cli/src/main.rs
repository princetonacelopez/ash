//! # ash CLI
//!
//! The user-facing `ash` command. Provides:
//! - `ash run <agent>` - wrap an agent CLI under policy
//! - `ash undo [block-id]` - revert the last reversible block
//! - `ash diff [block-id]` - show diff for a block
//! - `ash log` - view the audit log
//! - `ash approve <block-id>` - approve a pending block
//! - `ash deny <block-id>` - deny a pending block
//! - `ash status` - show session status
//! - `ash init` - initialize ash in the current project
//! - `ash policy` - manage policy files
//! - `ash verify` - verify audit log chain integrity

pub mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// ash - Agentic Shell Layer
#[derive(Parser, Debug)]
#[command(
    name = "ash",
    version,
    about = "Semantic shell layer: structured blocks, risk-tiered policy, and undo for humans and agents",
    long_about = r#"ash is a semantic shell layer that runs inside any existing terminal emulator.

It gives the terminal what it lacks: a structured model of commands, an open
protocol for describing them, and a safety layer that makes both humans and
AI agents safe to run with real privileges.

ash does not replace the emulator, the shell, or the agent CLIs.
It sits between them.
"#
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Session ID to connect to (defaults to $ASH_SESSION_ID)
    #[arg(long, global = true, env = "ASH_SESSION_ID")]
    session: Option<String>,

    /// Output format: human (default), json
    #[arg(long, global = true, default_value = "human")]
    format: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run an agent CLI under ash policy
    Run(commands::run::RunArgs),

    /// Revert the last reversible block (or a specific block by ID)
    Undo(commands::undo::UndoArgs),

    /// Show the diff for a block (what changed)
    Diff(commands::diff::DiffArgs),

    /// View the audit log
    Log(commands::log::LogArgs),

    /// Approve a pending block
    Approve(commands::approve::ApproveArgs),

    /// Deny a pending block
    Deny(commands::deny::DenyArgs),

    /// Show session and block status
    Status(commands::status::StatusArgs),

    /// Initialize ash in the current project (.ash/ directory)
    Init(commands::init::InitArgs),

    /// Output shell integration script (zsh, bash, fish)
    Hook(commands::hook::HookArgs),

    /// Emit an event to the ashd daemon socket (internal hook helper)
    #[command(hide = true)]
    Emit(commands::emit::EmitArgs),

    /// Manage policy files
    Policy(commands::policy::PolicyArgs),

    /// Verify the audit log chain integrity
    Verify(commands::verify::VerifyArgs),

    /// Show block details
    Show(commands::show::ShowArgs),

    /// Audit log operations (`ash audit verify`)
    Audit(commands::audit::AuditArgs),

    /// Trust this project's policy file (bound to its content hash)
    Trust(commands::trust::TrustArgs),

    /// Discover and show a CLI schema for a binary
    Schema(commands::schema::SchemaArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing to stderr
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let format = cli.format.as_str();
    let session_id = cli.session;

    match cli.command {
        Commands::Run(args) => commands::run::execute(args, session_id).await,
        Commands::Undo(args) => commands::undo::execute(args, session_id).await,
        Commands::Diff(args) => commands::diff::execute(args, session_id).await,
        Commands::Log(args) => commands::log::execute(args, format).await,
        Commands::Approve(args) => commands::approve::execute(args, session_id).await,
        Commands::Deny(args) => commands::deny::execute(args, session_id).await,
        Commands::Status(args) => commands::status::execute(args, session_id).await,
        Commands::Init(args) => commands::init::execute(args).await,
        Commands::Hook(args) => commands::hook::execute(args).await,
        Commands::Emit(args) => commands::emit::execute(args, session_id).await,
        Commands::Policy(args) => commands::policy::execute(args).await,
        Commands::Verify(args) => commands::verify::execute(args).await,
        Commands::Show(args) => commands::show::execute(args, session_id).await,
        Commands::Audit(args) => commands::audit::execute(args).await,
        Commands::Trust(args) => commands::trust::execute(args).await,
        Commands::Schema(args) => commands::schema::execute(args).await,
    }
}
