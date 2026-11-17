//! `ash undo [block-id]` - revert the last reversible block (spec §4.7)

use anyhow::{Context, Result};
use clap::Args;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct UndoArgs {
    /// Block ID to undo (defaults to the last reversible block)
    pub block_id: Option<String>,

    /// Dry run: show what would be undone without actually doing it
    #[arg(long)]
    pub dry_run: bool,
}

pub async fn execute(args: UndoArgs, _session_id: Option<String>) -> Result<()> {
    let snapshot_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("ash")
        .join("snapshots");

    let block_id = match args.block_id {
        Some(id) => id,
        None => {
            // Find the last reversible block from the session
            find_last_undoable_block(&snapshot_dir)?
        }
    };

    if args.dry_run {
        println!("Would undo block: {}", block_id);
        println!("(dry run - no changes made)");
        return Ok(());
    }

    // Send undo event to ashd via the session socket
    // For now, perform the undo directly
    let snap_id = format!("snap_{}", block_id);

    let index_path = snapshot_dir.join("index.jsonl");
    if !index_path.exists() {
        anyhow::bail!("No snapshots found. Nothing to undo.");
    }

    // Load the snapshot ref
    let snap_ref = load_snapshot_ref(&snap_id, &snapshot_dir)
        .with_context(|| format!("No snapshot found for block {}", block_id))?;

    println!("🔄 Undoing block {} (snapshot: {}, backend: {:?})", block_id, snap_ref.id, snap_ref.backend);

    if args.dry_run {
        println!("(dry run - no changes made)");
        return Ok(());
    }

    restore_snapshot(&snap_ref).await?;

    println!("✅ Undone. Block {} reverted.", block_id);

    Ok(())
}

fn find_last_undoable_block(snapshot_dir: &PathBuf) -> Result<String> {
    let index_path = snapshot_dir.join("index.jsonl");
    if !index_path.exists() {
        anyhow::bail!("No snapshots found. Nothing to undo.");
    }

    let content = std::fs::read_to_string(&index_path)?;
    let last = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .last()
        .ok_or_else(|| anyhow::anyhow!("No snapshots in index"))?;

    let snap: serde_json::Value = serde_json::from_str(last)?;
    let snap_id = snap["id"].as_str().unwrap_or("");
    let block_id = snap_id.trim_start_matches("snap_");
    Ok(block_id.to_string())
}

#[derive(Debug, serde::Deserialize)]
struct SnapshotRef {
    id: String,
    backend: String,
    metadata: serde_json::Value,
}

fn load_snapshot_ref(snap_id: &str, snapshot_dir: &PathBuf) -> Result<SnapshotRef> {
    let index_path = snapshot_dir.join("index.jsonl");
    let content = std::fs::read_to_string(&index_path)?;

    for line in content.lines() {
        if let Ok(snap) = serde_json::from_str::<SnapshotRef>(line) {
            if snap.id == snap_id {
                return Ok(snap);
            }
        }
    }
    anyhow::bail!("snapshot '{}' not found", snap_id)
}

async fn restore_snapshot(snap: &SnapshotRef) -> Result<()> {
    match snap.backend.as_str() {
        "git" => {
            let git_root = snap.metadata["git_root"].as_str().unwrap_or(".");
            let no_changes = snap.metadata["no_changes"].as_bool().unwrap_or(false);

            if no_changes {
                println!("No changes were made; nothing to restore.");
                return Ok(());
            }

            let output = std::process::Command::new("git")
                .args(&["-C", git_root, "stash", "pop"])
                .output()?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("git stash pop failed: {}", stderr);
            }
            println!("Git state restored from stash.");
        }
        "file-cow" => {
            let copied: Vec<String> = snap.metadata["copied_files"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();

            let snap_dir = dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join("ash")
                .join("snapshots")
                .join(&snap.id);

            for original_path in &copied {
                let rel = original_path.trim_start_matches('/');
                let backup = snap_dir.join(rel);
                if backup.exists() {
                    std::fs::copy(&backup, original_path)
                        .with_context(|| format!("restoring {}", original_path))?;
                    println!("  Restored: {}", original_path);
                }
            }
        }
        other => {
            anyhow::bail!("Restore not implemented for backend '{}'", other);
        }
    }
    Ok(())
}
