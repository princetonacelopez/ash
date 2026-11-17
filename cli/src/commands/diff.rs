//! `ash diff [block-id]` - show diff for a block

use anyhow::Result;
use clap::Args;

#[derive(Args, Debug)]
pub struct DiffArgs {
    /// Block ID to show diff for (defaults to last block)
    pub block_id: Option<String>,
}

pub async fn execute(args: DiffArgs, _session_id: Option<String>) -> Result<()> {
    // For git-based snapshots, show git diff since the snapshot was taken
    println!("📊 ash diff");

    if let Some(ref bid) = args.block_id {
        println!("Block: {}", bid);
    } else {
        println!("(last block)");
    }

    // Try git diff as the primary diff mechanism
    let output = std::process::Command::new("git")
        .args(&["diff", "--stat", "HEAD"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.trim().is_empty() {
                println!("No changes detected.");
            } else {
                println!("\n{}", stdout);
            }
        }
        _ => {
            println!("No git repository or no changes to show.");
        }
    }

    Ok(())
}
