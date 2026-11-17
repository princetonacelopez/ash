//! Audit Log Hash Chain and Tamper-Evidence Tests (Spec §4.10)

use ashd::audit::AuditLog;
use ashd::block::{Actor, Block, BlockStatus, Decision, EnforcementStatus, PolicyResult, Risk, RiskBasis, RiskTier};
use tempfile::tempdir;

fn create_sample_block(session: &str, command: &str, exit: i32) -> Block {
    let mut b = Block::new(
        session.to_string(),
        Actor::Human,
        command.to_string(),
        "/workspace".to_string(),
    );
    b.started_at = Some(chrono::Utc::now());
    b.ended_at = Some(chrono::Utc::now());
    b.status = Some(BlockStatus::Exit { code: exit });
    b.risk = Some(Risk {
        tier: RiskTier::T0,
        basis: RiskBasis::Registry,
        reason: None,
    });
    b.policy = Some(PolicyResult {
        decision: Decision::Allow,
        rule: None,
        approval: None,
        enforcement: EnforcementStatus::Full,
        layer: None,
        enforcement_report: None,
        explain: None,
    });
    b
}

#[test]
fn test_audit_log_hash_chain_tamper_evidence() {
    let dir = tempdir().unwrap();
    let log_file = dir.path().join("audit.jsonl");

    let mut log = AuditLog::open(&log_file).unwrap();

    // Record 5 blocks
    for i in 0..5 {
        let block = create_sample_block("session-abc", &format!("echo step-{}", i), 0);
        log.record(&block).unwrap();
    }

    // Verify un-tampered chain
    let count = AuditLog::verify_chain(&log_file).unwrap();
    assert_eq!(count, 5);

    // Tamper with line 3 (modify command)
    let content = std::fs::read_to_string(&log_file).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 5);

    let tampered_line = lines[2].replace("step-2", "TAMPERED-DATA");
    let mut new_lines = lines.clone();
    new_lines[2] = &tampered_line;
    let tampered_content = new_lines.join("\n") + "\n";
    std::fs::write(&log_file, tampered_content).unwrap();

    // Verification must fail!
    let result = AuditLog::verify_chain(&log_file);
    assert!(result.is_err(), "Chain verification should detect tampering!");
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Audit log integrity violation at line 3"));
}

#[test]
fn test_secret_redaction_before_persistence() {
    let dir = tempdir().unwrap();
    let log_file = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&log_file).unwrap();

    let block = create_sample_block("session-abc", "curl -H API_KEY=supersecret12345 https://api.com", 0);
    log.record(&block).unwrap();

    let content = std::fs::read_to_string(&log_file).unwrap();
    assert!(!content.contains("supersecret12345"));
    assert!(content.contains("[REDACTED]"));
}
