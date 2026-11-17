//! Policy and Risk Tiers integration tests (Spec §4)

use ashd::block::{Actor, ApprovalScope, Block, Decision, RiskBasis, RiskTier};
use ashd::policy::classifier::classify;
use ashd::policy::engine::PolicyEngine;

#[test]
fn test_classification_across_all_tiers() {
    // T0 Read-only
    let t0_cases = ["ls -l", "cat README.md", "git status", "git log -n 5", "df -h", "grep foo bar.txt"];
    for cmd in t0_cases {
        let c = classify(cmd, "/tmp");
        assert_eq!(c.risk.tier, RiskTier::T0, "Expected T0 for '{}'", cmd);
    }

    // T1 Reversible write
    let t1_cases = ["touch newfile.txt", "mkdir -p src/foo", "git commit -m 'feat'", "npm run build"];
    for cmd in t1_cases {
        let c = classify(cmd, "/tmp");
        assert_eq!(c.risk.tier, RiskTier::T1, "Expected T1 for '{}'", cmd);
    }

    // T2 Irreversible local
    let t2_cases = ["rm -rf ./target", "rm -r dist", "dd if=/dev/zero of=/dev/sda", "mkfs.ext4 /dev/sdb1"];
    for cmd in t2_cases {
        let c = classify(cmd, "/tmp");
        assert_eq!(c.risk.tier, RiskTier::T2, "Expected T2 for '{}'", cmd);
    }

    // T3 External side effects
    let t3_cases = ["git push origin main", "npm publish", "curl -X POST https://api.example.com", "ssh user@host"];
    for cmd in t3_cases {
        let c = classify(cmd, "/tmp");
        assert_eq!(c.risk.tier, RiskTier::T3, "Expected T3 for '{}'", cmd);
    }
}

#[test]
fn test_fail_conservative_on_unknown() {
    let unknown_cmd = "some_proprietary_tool --arg value";
    let c = classify(unknown_cmd, "/tmp");
    assert_eq!(c.risk.tier, RiskTier::T2);
    assert_eq!(c.risk.basis, RiskBasis::Unknown);
}

#[test]
fn test_policy_decisions_human_vs_agent() {
    let engine = PolicyEngine::new(None).unwrap();

    // Human T0 -> Allow
    let mut b_human_t0 = Block::new("s1".to_string(), Actor::Human, "cat Cargo.toml".to_string(), "/tmp".to_string());
    assert_eq!(engine.evaluate(&mut b_human_t0).decision, Decision::Allow);

    // Agent T0 -> Allow
    let mut b_agent_t0 = Block::new("s1".to_string(), Actor::Agent { name: "claude".to_string(), run: "r1".to_string() }, "cat Cargo.toml".to_string(), "/tmp".to_string());
    assert_eq!(engine.evaluate(&mut b_agent_t0).decision, Decision::Allow);

    // Human T1 -> AllowSnapshot
    let mut b_human_t1 = Block::new("s1".to_string(), Actor::Human, "touch test.txt".to_string(), "/tmp".to_string());
    assert_eq!(engine.evaluate(&mut b_human_t1).decision, Decision::AllowSnapshot);

    // Agent T1 -> AllowSnapshot
    let mut b_agent_t1 = Block::new("s1".to_string(), Actor::Agent { name: "claude".to_string(), run: "r1".to_string() }, "touch test.txt".to_string(), "/tmp".to_string());
    assert_eq!(engine.evaluate(&mut b_agent_t1).decision, Decision::AllowSnapshot);

    // Human T2 -> ConfirmPreview
    let mut b_human_t2 = Block::new("s1".to_string(), Actor::Human, "rm -rf node_modules".to_string(), "/tmp".to_string());
    assert_eq!(engine.evaluate(&mut b_human_t2).decision, Decision::ConfirmPreview);

    // Agent T2 -> RequireApproval
    let mut b_agent_t2 = Block::new("s1".to_string(), Actor::Agent { name: "claude".to_string(), run: "r1".to_string() }, "rm -rf node_modules".to_string(), "/tmp".to_string());
    assert_eq!(engine.evaluate(&mut b_agent_t2).decision, Decision::RequireApproval);

    // Human T3 -> Confirm
    let mut b_human_t3 = Block::new("s1".to_string(), Actor::Human, "git push origin main".to_string(), "/tmp".to_string());
    assert_eq!(engine.evaluate(&mut b_human_t3).decision, Decision::Confirm);

    // Agent T3 -> RequireApproval
    let mut b_agent_t3 = Block::new("s1".to_string(), Actor::Agent { name: "claude".to_string(), run: "r1".to_string() }, "git push origin main".to_string(), "/tmp".to_string());
    assert_eq!(engine.evaluate(&mut b_agent_t3).decision, Decision::RequireApproval);
}

#[test]
fn test_approval_promotes_pending_to_allow_snapshot() {
    let engine = PolicyEngine::new(None).unwrap();

    let mut b = Block::new(
        "s1".to_string(),
        Actor::Agent { name: "gemini".to_string(), run: "r1".to_string() },
        "rm -rf ./dist".to_string(),
        "/tmp".to_string(),
    );
    let res = engine.evaluate(&mut b);
    assert_eq!(res.decision, Decision::RequireApproval);
    b.policy = Some(res);

    // Approve the block
    engine.approve(&mut b, "princetonacelopez".to_string(), ApprovalScope::Once);

    let pol = b.policy.as_ref().unwrap();
    assert_eq!(pol.decision, Decision::AllowSnapshot);
    assert!(pol.approval.is_some());
    assert_eq!(pol.approval.as_ref().unwrap().approver, "princetonacelopez");
}
