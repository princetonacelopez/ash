//! `ash show <block-id>` - show block details

use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct ShowArgs {
    /// Block ID to show
    pub block_id: String,

    /// Show raw JSON
    #[arg(long)]
    pub json: bool,
}

pub async fn execute(args: ShowArgs, _session_id: Option<String>) -> Result<()> {
    let log_path = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("ash")
        .join("audit.jsonl");

    if !log_path.exists() {
        anyhow::bail!("No audit log found");
    }

    let content = std::fs::read_to_string(&log_path)?;
    let entry = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|e| e["block_id"].as_str().map(|id| id.starts_with(&args.block_id)).unwrap_or(false))
        .ok_or_else(|| anyhow::anyhow!("Block '{}' not found in audit log", args.block_id))?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&entry)?);
        return Ok(());
    }

    // Human-readable
    let bid = entry["block_id"].as_str().unwrap_or("?");
    let session = entry["session_id"].as_str().unwrap_or("?");
    let actor = entry["actor"].as_str().unwrap_or("?");
    let command = entry["command"].as_str().unwrap_or("?");
    let cwd = entry["cwd"].as_str().unwrap_or("?");
    let tier = entry["risk_tier"].as_str().unwrap_or("?");
    let basis = entry["risk_basis"].as_str().unwrap_or("?");
    let decision = entry["decision"].as_str().unwrap_or("?");
    let rule = entry["matched_rule"].as_str().unwrap_or("tier-default");
    let enforcement = entry["enforcement_status"].as_str().unwrap_or("?");
    let snap = entry["snapshot_ref"].as_str();
    let exit = entry["exit_status"].as_i64();
    let denied = entry["denied"].as_bool().unwrap_or(false);
    let approver = entry["approver"].as_str();
    let at = entry["at"].as_str().unwrap_or("?");

    let tier_icon = match tier {
        "T0" => "🔵",
        "T1" => "🟡",
        "T2" => "🟠",
        "T3" => "🔴",
        _ => "⚪",
    };

    println!("┌─ Block {}", bid);
    println!("│  Session:    {}", session);
    println!("│  Actor:      {}", actor);
    println!("│  Command:    {}", command);
    println!("│  CWD:        {}", cwd);
    println!("│  Timestamp:  {}", at);
    println!("├─ Risk");
    println!("│  Tier:       {} {}", tier_icon, tier);
    println!("│  Basis:      {}", basis);
    println!("├─ Policy");
    println!("│  Decision:   {}", decision);
    println!("│  Rule:       {}", rule);
    println!("│  Enforcement:{}", enforcement);
    if let Some(a) = approver {
        println!("│  Approved by:{}", a);
    }
    println!("├─ Outcome");
    if denied {
        println!("│  Status:     ✗ DENIED");
    } else if let Some(code) = exit {
        let icon = if code == 0 { "✓" } else { "✗" };
        println!("│  Exit code:  {} {}", icon, code);
    }
    if let Some(s) = snap {
        println!("│  Snapshot:   {} (use 'ash undo {}' to revert)", s, bid);
    }
    println!("└─────────────────────────────────────────");

    Ok(())
}
