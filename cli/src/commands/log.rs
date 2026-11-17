//! `ash log` - view the audit log (spec §4.10)

use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct LogArgs {
    /// Number of entries to show (default: 20)
    #[arg(short = 'n', long, default_value_t = 20)]
    pub count: usize,

    /// Filter by actor: human, agent, or agent:<name>
    #[arg(long)]
    pub actor: Option<String>,

    /// Filter by risk tier: T0, T1, T2, T3
    #[arg(long)]
    pub tier: Option<String>,

    /// Show only denied commands
    #[arg(long)]
    pub denied: bool,

    /// Show only approved commands
    #[arg(long)]
    pub approved: bool,

    /// Show raw JSON
    #[arg(long)]
    pub json: bool,

    /// Session ID to filter by
    #[arg(long)]
    pub session: Option<String>,
}

pub async fn execute(args: LogArgs, format: &str) -> Result<()> {
    let log_path = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("ash")
        .join("audit.jsonl");

    if !log_path.exists() {
        println!("No audit log found at {:?}", log_path);
        println!("Run some commands under ash to populate the log.");
        return Ok(());
    }

    let content = std::fs::read_to_string(&log_path)?;
    let mut entries: Vec<serde_json::Value> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    // Apply filters
    if let Some(ref actor) = args.actor {
        entries.retain(|e| {
            e["actor"].as_str().map(|a| a.starts_with(actor.as_str())).unwrap_or(false)
        });
    }

    if let Some(ref tier) = args.tier {
        entries.retain(|e| {
            e["risk_tier"].as_str().map(|t| t == tier.as_str()).unwrap_or(false)
        });
    }

    if args.denied {
        entries.retain(|e| e["denied"].as_bool().unwrap_or(false));
    }

    if args.approved {
        entries.retain(|e| e["approver"].is_string());
    }

    if let Some(ref session) = args.session {
        entries.retain(|e| {
            e["session_id"].as_str().map(|s| s == session.as_str()).unwrap_or(false)
        });
    }

    // Show last N
    let entries: Vec<_> = entries.iter().rev().take(args.count).rev().collect();

    if entries.is_empty() {
        println!("No log entries match the filter.");
        return Ok(());
    }

    if args.json || format == "json" {
        for entry in entries {
            println!("{}", serde_json::to_string(entry)?);
        }
    } else {
        // Human-readable table
        println!("\n{:<24} {:<8} {:<10} {:<12} {:<40}", "BLOCK ID", "TIER", "DECISION", "ACTOR", "COMMAND");
        println!("{}", "─".repeat(96));
        for entry in entries {
            let block_id = entry["block_id"].as_str().unwrap_or("?");
            let tier = entry["risk_tier"].as_str().unwrap_or("?");
            let decision = entry["decision"].as_str().unwrap_or("?");
            let actor = entry["actor"].as_str().unwrap_or("?");
            let command = entry["command"].as_str().unwrap_or("?");
            let denied = entry["denied"].as_bool().unwrap_or(false);
            let approved = entry["approver"].is_string();

            let status_icon = if denied { "✗" } else if approved { "✓A" } else { "✓" };
            let tier_icon = match tier {
                "T0" => "🔵",
                "T1" => "🟡",
                "T2" => "🟠",
                "T3" => "🔴",
                _ => "⚪",
            };

            println!(
                "{:<24} {} {:<8} {:<10} {:<12} {:<40} {}",
                &block_id[..block_id.len().min(22)],
                tier_icon,
                tier,
                decision,
                &actor[..actor.len().min(10)],
                &command[..command.len().min(38)],
                status_icon
            );
        }
        println!();
    }

    Ok(())
}
