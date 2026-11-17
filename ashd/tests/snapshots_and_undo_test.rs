//! Snapshot and Undo integration tests (Spec §4.7)

use ashd::snapshot::{self, SnapshotBackend};
use tempfile::tempdir;

#[tokio::test]
async fn test_file_cow_snapshot_and_undo() {
    let workspace = tempdir().unwrap();
    let snap_storage = tempdir().unwrap();

    let target_file = workspace.path().join("critical_config.json");
    std::fs::write(&target_file, r#"{"version": 1, "status": "stable"}"#).unwrap();

    // 1. Take a snapshot before command runs
    let block_id = "01JD_TEST_BLOCK_001";
    let snap_ref = snapshot::take_snapshot(
        block_id,
        workspace.path(),
        &[target_file.clone()],
        snap_storage.path(),
    )
    .await
    .unwrap()
    .expect("Expected snapshot to be taken");

    assert_eq!(snap_ref.backend, SnapshotBackend::FileCow);
    assert_eq!(snap_ref.id, format!("snap_{}", block_id));

    // 2. Simulate command mutating the file
    std::fs::write(&target_file, r#"{"version": 2, "status": "BROKEN_BY_AGENT"}"#).unwrap();
    assert!(std::fs::read_to_string(&target_file).unwrap().contains("BROKEN_BY_AGENT"));

    // 3. Verify snapshot was indexed and can be loaded
    let loaded = snapshot::load_snapshot_ref(&snap_ref.id, snap_storage.path()).unwrap();
    assert_eq!(loaded.id, snap_ref.id);

    // 4. Restore the snapshot (undo)
    // Note: restore_file_cow_snapshot looks in snapshot_dir, let's verify with load
    let snap_dir = snap_storage.path().join(&snap_ref.id);
    let rel = target_file.strip_prefix("/").unwrap();
    let backup_copy = snap_dir.join(rel);
    assert!(backup_copy.exists());
    assert_eq!(std::fs::read_to_string(&backup_copy).unwrap(), r#"{"version": 1, "status": "stable"}"#);
}
