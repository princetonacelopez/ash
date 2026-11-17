//! # Snapshot Backends (spec §4.7)
//!
//! Snapshot backends in order of preference:
//! 1. Git-aware snapshot (stash/ephemeral ref + untracked file capture)
//! 2. File-level copy-on-write of predicted write paths
//! 3. Filesystem snapshots (APFS, btrfs, ZFS) — future
//!
//! Undo semantics:
//! - `/undo` reverts the last reversible block
//! - `/undo <block-id>` reverts a specific block
//! - Snapshots retained for configurable window (default: 24h or 2GB)
//! - Undo covers local filesystem state only; T3 actions are NOT undoable

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A snapshot reference stored with a block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRef {
    pub id: String,
    pub backend: SnapshotBackend,
    pub created_at: DateTime<Utc>,
    pub scope: Vec<PathBuf>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotBackend {
    Git,
    FileCow,
    Btrfs,
    Zfs,
    ApfsClone,
}

impl std::fmt::Display for SnapshotBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SnapshotBackend::Git => "git",
            SnapshotBackend::FileCow => "file-cow",
            SnapshotBackend::Btrfs => "btrfs",
            SnapshotBackend::Zfs => "zfs",
            SnapshotBackend::ApfsClone => "apfs-clone",
        };
        write!(f, "{}", s)
    }
}

/// Take a snapshot of the given paths before execution.
/// Returns the snapshot ref ID, or None if no snapshot backend is available.
pub async fn take_snapshot(
    block_id: &str,
    cwd: &Path,
    predicted_write_paths: &[PathBuf],
    snapshot_dir: &Path,
) -> Result<Option<SnapshotRef>> {
    // Try git snapshot first
    if let Ok(snap) = try_git_snapshot(block_id, cwd, snapshot_dir).await {
        return Ok(Some(snap));
    }

    // Fall back to file-level CoW
    if !predicted_write_paths.is_empty() {
        let snap = file_cow_snapshot(block_id, predicted_write_paths, snapshot_dir).await?;
        return Ok(Some(snap));
    }

    Ok(None)
}

/// Git-based snapshot: create an ephemeral stash or ref capturing the current state.
async fn try_git_snapshot(
    block_id: &str,
    cwd: &Path,
    snapshot_dir: &Path,
) -> Result<SnapshotRef> {
    // Check if this is a git repo
    let git_root = find_git_root(cwd)?;
    let snap_id = format!("snap_{}", block_id);

    // Create ash namespace ref: refs/ash/snaps/<block-id>
    // This captures the current HEAD + index + untracked files via git stash
    let stash_msg = format!("ash-snap:{}", block_id);

    let output = Command::new("git")
        .args(&[
            "-C",
            git_root.to_str().unwrap_or("."),
            "stash",
            "push",
            "--include-untracked",
            "--message",
            &stash_msg,
        ])
        .output()
        .context("running git stash")?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // If nothing to stash, that's fine
    let no_changes = stdout.contains("No local changes");

    // Store the stash SHA for reference
    let stash_sha = if !no_changes {
        get_git_stash_sha(&git_root, 0).unwrap_or_default()
    } else {
        get_git_head_sha(&git_root).unwrap_or_default()
    };

    // Also record the git root path in snapshot metadata
    let metadata = serde_json::json!({
        "git_root": git_root.to_string_lossy(),
        "stash_sha": stash_sha,
        "no_changes": no_changes,
        "stash_message": stash_msg,
    });

    // Persist snapshot index entry
    let snap = SnapshotRef {
        id: snap_id.clone(),
        backend: SnapshotBackend::Git,
        created_at: Utc::now(),
        scope: vec![git_root.clone()],
        metadata,
    };

    persist_snapshot_ref(&snap, snapshot_dir)?;

    Ok(snap)
}

/// File-level copy-on-write: copy predicted write paths before execution.
async fn file_cow_snapshot(
    block_id: &str,
    paths: &[PathBuf],
    snapshot_dir: &Path,
) -> Result<SnapshotRef> {
    let snap_id = format!("snap_{}", block_id);
    let snap_dir = snapshot_dir.join(&snap_id);
    std::fs::create_dir_all(&snap_dir)?;

    let mut copied = vec![];
    for path in paths {
        if path.exists() && path.is_file() {
            // Preserve directory structure within the snapshot dir
            let rel = path.strip_prefix("/").unwrap_or(path);
            let dest = snap_dir.join(rel);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(path, &dest)
                .with_context(|| format!("copying {:?} to snapshot", path))?;
            copied.push(path.to_string_lossy().to_string());
        }
    }

    let metadata = serde_json::json!({ "copied_files": copied });
    let snap = SnapshotRef {
        id: snap_id,
        backend: SnapshotBackend::FileCow,
        created_at: Utc::now(),
        scope: paths.to_vec(),
        metadata,
    };

    persist_snapshot_ref(&snap, snapshot_dir)?;

    Ok(snap)
}

/// Restore a snapshot (undo).
pub async fn restore_snapshot(snap_ref: &SnapshotRef) -> Result<()> {
    match snap_ref.backend {
        SnapshotBackend::Git => restore_git_snapshot(snap_ref).await,
        SnapshotBackend::FileCow => restore_file_cow_snapshot(snap_ref).await,
        _ => anyhow::bail!("Restore not implemented for backend {}", snap_ref.backend),
    }
}

async fn restore_git_snapshot(snap_ref: &SnapshotRef) -> Result<()> {
    let git_root = snap_ref
        .metadata
        .get("git_root")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing git_root in snapshot metadata"))?;

    let no_changes = snap_ref
        .metadata
        .get("no_changes")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if no_changes {
        // Nothing was stashed; just ensure we're at the right state
        tracing::info!("Snapshot had no changes; nothing to restore");
        return Ok(());
    }

    // Apply the stash
    let output = Command::new("git")
        .args(&["-C", git_root, "stash", "pop"])
        .output()
        .context("running git stash pop")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git stash pop failed: {}", stderr);
    }

    tracing::info!(git_root, snap_id = %snap_ref.id, "Git snapshot restored");
    Ok(())
}

async fn restore_file_cow_snapshot(snap_ref: &SnapshotRef) -> Result<()> {
    // Find the snapshot directory
    let snap_dir_name = &snap_ref.id;
    let copied: Vec<String> = snap_ref
        .metadata
        .get("copied_files")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Restore each file from the snapshot directory
    if let Some(data_dir) = dirs::data_local_dir() {
        let snapshot_dir = data_dir.join("ash").join("snapshots");
        let snap_dir = snapshot_dir.join(snap_dir_name);

        for original_path in &copied {
            let rel = original_path.trim_start_matches('/');
            let backup = snap_dir.join(rel);
            if backup.exists() {
                std::fs::copy(&backup, original_path)
                    .with_context(|| format!("restoring {:?}", original_path))?;
            }
        }
    }

    tracing::info!(snap_id = %snap_ref.id, "File CoW snapshot restored");
    Ok(())
}

fn find_git_root(start: &Path) -> Result<PathBuf> {
    let output = Command::new("git")
        .args(&["-C", start.to_str().unwrap_or("."), "rev-parse", "--show-toplevel"])
        .output()
        .context("running git rev-parse")?;

    if !output.status.success() {
        anyhow::bail!("not a git repository: {:?}", start);
    }

    let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(PathBuf::from(root))
}

fn get_git_stash_sha(git_root: &Path, index: usize) -> Result<String> {
    let output = Command::new("git")
        .args(&[
            "-C",
            git_root.to_str().unwrap_or("."),
            "rev-parse",
            &format!("stash@{{{}}}", index),
        ])
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn get_git_head_sha(git_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(&["-C", git_root.to_str().unwrap_or("."), "rev-parse", "HEAD"])
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn persist_snapshot_ref(snap: &SnapshotRef, snapshot_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(snapshot_dir)?;
    let index_path = snapshot_dir.join("index.jsonl");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&index_path)?;
    let line = serde_json::to_string(snap)? + "\n";
    std::io::Write::write_all(&mut file, line.as_bytes())?;
    Ok(())
}

/// Load a snapshot ref by ID from the snapshot index.
pub fn load_snapshot_ref(snap_id: &str, snapshot_dir: &Path) -> Result<SnapshotRef> {
    let index_path = snapshot_dir.join("index.jsonl");
    let content = std::fs::read_to_string(&index_path)
        .with_context(|| format!("reading snapshot index {:?}", index_path))?;

    for line in content.lines() {
        if let Ok(snap) = serde_json::from_str::<SnapshotRef>(line) {
            if snap.id == snap_id {
                return Ok(snap);
            }
        }
    }

    anyhow::bail!("snapshot '{}' not found", snap_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn file_cow_snapshot_copies_files() {
        let dir = tempdir().unwrap();
        let test_file = dir.path().join("test.txt");
        std::fs::write(&test_file, "original content").unwrap();

        let snap_dir = tempdir().unwrap();

        let snap = tokio::runtime::Runtime::new().unwrap().block_on(
            file_cow_snapshot("test-block-id", &[test_file.clone()], snap_dir.path())
        ).unwrap();

        assert_eq!(snap.backend, SnapshotBackend::FileCow);
        assert!(snap.metadata["copied_files"].as_array().unwrap().len() > 0);
    }
}
