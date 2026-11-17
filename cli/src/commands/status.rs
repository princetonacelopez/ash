//! `ash status` - show session and block status

use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Show all blocks, not just recent ones
    #[arg(long)]
    pub all: bool,
}

pub async fn execute(args: StatusArgs, session_id: Option<String>) -> Result<()> {
    let session = session_id.or_else(|| std::env::var("ASH_SESSION_ID").ok());

    println!("🔷 ash status\n");

    if let Some(ref sid) = session {
        println!("Session: {}", sid);
        // Check if ashd is running
        let socket_path = resolve_socket_path(sid)?;
        if socket_path.exists() {
            println!("Daemon:  running ({})", socket_path.display());
        } else {
            println!("Daemon:  not running");
        }
    } else {
        println!("Session: (not in an ash session)");
        println!("         Run 'eval $(ashd --print-env)' to start a session");
    }

    // Show recent audit log entries
    let log_path = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("ash")
        .join("audit.jsonl");

    if log_path.exists() {
        let content = std::fs::read_to_string(&log_path)?;
        let entries: Vec<serde_json::Value> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();

        let recent: Vec<_> = if args.all {
            entries.iter().collect()
        } else {
            entries.iter().rev().take(5).rev().collect()
        };

        if !recent.is_empty() {
            println!("\nRecent blocks:");
            for entry in recent {
                let bid = entry["block_id"].as_str().unwrap_or("?");
                let cmd = entry["command"].as_str().unwrap_or("?");
                let tier = entry["risk_tier"].as_str().unwrap_or("?");
                let _decision = entry["decision"].as_str().unwrap_or("?");
                let denied = entry["denied"].as_bool().unwrap_or(false);

                let icon = if denied { "✗" } else { "✓" };
                let tier_icon = match tier {
                    "T0" => "🔵",
                    "T1" => "🟡",
                    "T2" => "🟠",
                    "T3" => "🔴",
                    _ => "⚪",
                };

                println!(
                    "  {} {} {:4} {:18} {}",
                    icon,
                    tier_icon,
                    tier,
                    &bid[..bid.len().min(16)],
                    &cmd[..cmd.len().min(60)]
                );
            }

            let total = entries.len();
            let denied = entries.iter().filter(|e| e["denied"].as_bool().unwrap_or(false)).count();
            let approved = entries.iter().filter(|e| e["approver"].is_string()).count();

            println!("\nTotal blocks: {} | Denied: {} | Approved: {}", total, denied, approved);
        }

        // Snapshot count
        let snap_index = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("ash")
            .join("snapshots")
            .join("index.jsonl");

        if snap_index.exists() {
            if let Ok(content) = std::fs::read_to_string(&snap_index) {
                let count = content.lines().filter(|l| !l.trim().is_empty()).count();
                println!("Snapshots available: {} (use 'ash undo' to revert)", count);
            }
        }
    } else {
        println!("\nNo audit log yet. Run commands under ash to populate.");
    }

    Ok(())
}

fn resolve_socket_path(session_id: &str) -> anyhow::Result<PathBuf> {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let uid = unsafe { libc::getuid() };
            PathBuf::from(format!("/tmp/ash-{}", uid))
        });
    Ok(runtime_dir.join("ash").join(format!("{}.sock", session_id)))
}
