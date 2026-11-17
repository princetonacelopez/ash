//! Conformance suite (spec v0.2 §8.2): CORE, POL, AGT (see unit tests in
//! `ashd::agent`), SCH (see `ashd::schema`), A11Y (see `ashd::a11y`).
//! This file holds the daemon-level CORE and POL tests.

use ashd::audit::AuditLog;
use ashd::block::{new_id, Actor, Block, BlockStatus, Decision, PolicyResult, EnforcementStatus, Event, EventKind, EventPayload, SessionEndPayload};
use ashd::policy::config::{CompiledPolicy, PolicyFile};
use ashd::policy::engine::PolicyEngine;
use ashd::policy::sandbox::{bwrap_usable, sandboxed_command, SandboxSpec};
use ashd::pty::PtyProxy;
use ashd::socket::SocketServer;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::time::{sleep, timeout, Duration};

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

async fn start() -> (Arc<SocketServer>, std::path::PathBuf, tokio::task::JoinHandle<()>) {
    let dir = tempfile::tempdir().unwrap().keep();
    let path = dir.join("ash").join("s.sock");
    let server = {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("ASH_SOCKET", &path);
        let s = Arc::new(SocketServer::new(format!("conf-{}", new_id())).unwrap());
        std::env::remove_var("ASH_SOCKET");
        s
    };
    let h = tokio::spawn({
        let s = Arc::clone(&server);
        async move { let _ = s.run().await; }
    });
    sleep(Duration::from_millis(80)).await;
    (server, path, h)
}

async fn hello(stream: UnixStream, wants: &[&str]) -> (BufReader<tokio::net::unix::OwnedReadHalf>, tokio::net::unix::OwnedWriteHalf, serde_json::Value) {
    let (r, mut w) = stream.into_split();
    let msg = serde_json::json!({"v":1,"type":"hello","client":"conf","wants":wants});
    w.write_all(format!("{}\n", msg).as_bytes()).await.unwrap();
    let mut r = BufReader::new(r);
    let mut l = String::new();
    r.read_line(&mut l).await.unwrap();
    (r, w, serde_json::from_str(l.trim()).unwrap())
}

fn session_end(_server: &SocketServer, n: u32) -> Event {
    Event::new(
        format!("conf"),
        None,
        EventKind::SessionEnd,
        EventPayload::SessionEnd(SessionEndPayload { reason: format!("e{}", n) }),
    )
}

/// CORE-01
#[tokio::test]
async fn core_01_forged_osc133_end_is_stripped() {
    let p = PtyProxy::new("s".into(), tempfile::tempdir().unwrap().keep().join("r.bin"), tokio::sync::broadcast::channel(16).0).unwrap();
    let out = p.process_output(b"a\x1b]133;D;0\x07b", Some("blk")).await.unwrap();
    assert_eq!(out.bytes, b"ab");
}

/// CORE-02
#[tokio::test]
async fn core_02_oversize_line_dropped_connection_survives() {
    let (_s, path, h) = start().await;
    let stream = UnixStream::connect(&path).await.unwrap();
    let (mut r, mut w, welcome) = hello(stream, &["blocks"]).await;
    assert_eq!(welcome["limits"]["max_line"], 1048576);
    let big = vec![b'a'; 2 * 1024 * 1024];
    w.write_all(&big).await.unwrap();
    w.write_all(b"\n").await.unwrap();
    let mut l = String::new();
    timeout(Duration::from_secs(5), r.read_line(&mut l)).await.unwrap().unwrap();
    let v: serde_json::Value = serde_json::from_str(l.trim()).unwrap();
    assert_eq!(v["type"], "error");
    assert_eq!(v["data"]["code"], "oversize");
    // connection survives
    w.write_all(b"{\"type\":\"ping\",\"id\":\"p1\"}\n").await.unwrap();
    l.clear();
    timeout(Duration::from_secs(5), r.read_line(&mut l)).await.unwrap().unwrap();
    let v: serde_json::Value = serde_json::from_str(l.trim()).unwrap();
    assert_eq!(v["type"], "ack");
    assert_eq!(v["id"], "p1");
    h.abort();
}

/// CORE-03: a connection whose peer UID differs is rejected. We can only run as
/// one uid here, so verify the owner IS accepted and the check function path is live.
#[tokio::test]
async fn core_03_owner_accepted_socket_modes() {
    use std::os::unix::fs::PermissionsExt;
    let (_s, path, h) = start().await;
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let dmode = std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777;
    assert_eq!(dmode, 0o700);
    let stream = UnixStream::connect(&path).await.unwrap();
    let (_r, _w, welcome) = hello(stream, &["blocks"]).await;
    assert_eq!(welcome["type"], "welcome");
    h.abort();
}

/// CORE-04
#[tokio::test]
async fn core_04_unknown_types_ignored_and_counted() {
    let (s, path, h) = start().await;
    let stream = UnixStream::connect(&path).await.unwrap();
    let (mut r, mut w, _) = hello(stream, &["blocks"]).await;
    w.write_all(b"{\"type\":\"x-vendor.thing\",\"extra\":1}\n{\"type\":\"ping\",\"id\":\"z\",\"unknown_field\":true}\n").await.unwrap();
    let mut l = String::new();
    timeout(Duration::from_secs(5), r.read_line(&mut l)).await.unwrap().unwrap();
    let v: serde_json::Value = serde_json::from_str(l.trim()).unwrap();
    assert_eq!(v["type"], "ack");
    assert_eq!(s.ignored.load(std::sync::atomic::Ordering::Relaxed), 1);
    h.abort();
}

/// CORE-05
#[tokio::test]
async fn core_05_replay_contiguous_seq_or_gap() {
    let (s, path, h) = start().await;
    for i in 0..5 { s.publish_event(&session_end(&s, i)).unwrap(); }
    let stream = UnixStream::connect(&path).await.unwrap();
    let (mut r, mut w, _) = hello(stream, &["blocks"]).await;
    w.write_all(b"{\"type\":\"replay\",\"id\":\"r\",\"from_seq\":2}\n").await.unwrap();
    let mut seqs = vec![];
    for _ in 0..3 {
        let mut l = String::new();
        timeout(Duration::from_secs(5), r.read_line(&mut l)).await.unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(l.trim()).unwrap();
        seqs.push(v["seq"].as_u64().unwrap());
    }
    assert_eq!(seqs, vec![3, 4, 5]);
    h.abort();
}

/// CORE-06: boundary events survive a stalled subscriber flooded with output.
#[tokio::test]
async fn core_06_boundaries_not_dropped_for_slow_subscriber() {
    let (s, path, h) = start().await;
    let stream = UnixStream::connect(&path).await.unwrap();
    let (r, mut w, _) = hello(stream, &["blocks", "output"]).await;
    let _ = &mut w;
    // flood output without reading, then publish a boundary
    for i in 0..20000u64 {
        let e = Event::server("conf".into(), Some("b".into()), EventKind::BlockOutput,
            serde_json::json!({"offset": i, "length": 1, "stream": "tty"}));
        s.publish_event(&e).unwrap();
    }
    let end = Event::server("conf".into(), Some("b".into()), EventKind::BlockEnd,
        serde_json::json!({"status": {"kind": "exit", "code": 0}}));
    s.publish_event(&end).unwrap();
    // now read everything: the block_end must be present
    let mut r = r;
    let mut found = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        let mut l = String::new();
        match timeout(Duration::from_secs(2), r.read_line(&mut l)).await {
            Ok(Ok(n)) if n > 0 => {
                if l.contains("\"block_end\"") { found = true; break; }
            }
            _ => break,
        }
    }
    assert!(found, "block_end was dropped");
    h.abort();
}

/// POL-01
#[test]
fn pol_01_t0_runs_without_prompt() {
    let e = PolicyEngine::new(None).unwrap();
    let mut b = Block::new("s".into(), Actor::Human, "ls -la".into(), "/tmp".into());
    assert_eq!(e.evaluate(&mut b).decision, Decision::Allow);
}

/// POL-02: writes outside the project are blocked by enforcement (not classification).
#[test]
fn pol_02_sandbox_blocks_writes_outside_project() {
    if !bwrap_usable() { eprintln!("skip: bwrap unusable"); return; }
    let project = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let spec = SandboxSpec { fs_read: vec![], fs_write: vec![project.path().to_string_lossy().into()], network_allowed_hosts: vec![], allow_network: false };
    let target = outside.path().join("pwn.txt");
    for script in [
        format!("echo x > {}", target.display()),
        format!("eval 'echo x > {}'", target.display()),
        { let sp = project.path().join("s.sh"); std::fs::write(&sp, format!("echo x > {}\n", target.display())).unwrap(); format!("sh {}", sp.display()) },
    ] {
        let st = sandboxed_command(&spec, &script, project.path().to_str().unwrap(), &[]).output().unwrap();
        assert!(!target.exists(), "write escaped via: {}", script);
        let _ = st;
    }
    // inside the project writes still work
    let ok = project.path().join("ok.txt");
    let st = sandboxed_command(&spec, &format!("echo x > {}", ok.display()), project.path().to_str().unwrap(), &[]).status().unwrap();
    assert!(st.success() && ok.exists());
}

/// POL-03
#[test]
fn pol_03_rm_rf_is_t2_gated() {
    let e = PolicyEngine::new(None).unwrap();
    let mut b = Block::new("s".into(), Actor::Human, "rm -rf /var/data".into(), "/tmp".into());
    let r = e.evaluate(&mut b);
    assert!(b.risk.unwrap().tier >= ashd::block::RiskTier::T2);
    assert_ne!(r.decision, Decision::Allow);
}

/// POL-04 lives in snapshots_and_undo_test (byte-identical restore).

fn layer(toml: &str) -> PolicyFile { toml::from_str(toml).unwrap() }

/// POL-05
#[test]
fn pol_05_project_cannot_loosen_org_deny() {
    let org = layer(r#"version=1
[[rule]]
id="org-no-curl"
actor="any"
match.command=["curl"]
decision="deny"
locked=true"#);
    let proj = layer(r#"version=1
[[rule]]
id="proj-allow-curl"
actor="any"
match.command=["curl"]
decision="allow""#);
    let p = CompiledPolicy::from_layers(vec![
        ("builtin".into(), layer("version=1")),
        ("project".into(), proj),
        ("org".into(), org),
    ]).unwrap();
    let r = p.evaluate(&Actor::Human, "curl https://x", "/tmp", ashd::block::RiskTier::T3, &[]);
    assert_eq!(r.decision, Decision::Deny);
    assert_eq!(r.rule_id.as_deref(), Some("org-no-curl"));
    assert_eq!(r.layer.as_deref(), Some("org"));
}

#[test]
fn pol_05b_locked_org_confirm_cannot_be_loosened_by_specific_allow() {
    let org = layer(r#"version=1
[[rule]]
id="org-gate-push"
actor="any"
decision="require_approval"
locked=true
match.command=["git push"]"#);
    let user = layer(r#"version=1
[[rule]]
id="user-allow-push"
actor="any"
decision="allow"
match.command=["git push origin"]
match.cwd_within="/repo""#);
    let p = CompiledPolicy::from_layers(vec![("builtin".into(), layer("version=1")), ("user".into(), user), ("org".into(), org)]).unwrap();
    let r = p.evaluate(&Actor::Human, "git push origin main", "/repo", ashd::block::RiskTier::T3, &[]);
    assert_eq!(r.decision, Decision::RequireApproval);
}

/// POL-06: project policy inert until trusted; trust is keyed to content hash.
#[test]
fn pol_06_untrusted_project_policy_inert_and_hash_bound() {
    let home = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    std::env::set_var("ASH_TRUST_FILE", home.path().join("trusted"));
    std::fs::create_dir_all(proj.path().join(".ash")).unwrap();
    let pol = proj.path().join(".ash/policy.toml");
    std::fs::write(&pol, "version=1\n[[rule]]\nid=\"p\"\nactor=\"any\"\ndecision=\"deny\"\nmatch.command=[\"zzz\"]\n").unwrap();
    let eval = |root: &std::path::Path| CompiledPolicy::load(Some(root)).unwrap().rules.iter().any(|r| r.id == "p");
    assert!(!eval(proj.path()), "untrusted policy must have no effect");
    ashd::policy::config::trust_project(proj.path()).unwrap();
    assert!(eval(proj.path()), "trusted policy applies");
    std::fs::write(&pol, "version=1\n[[rule]]\nid=\"p\"\nactor=\"any\"\ndecision=\"allow\"\nmatch.command=[\"zzz\"]\n").unwrap();
    assert!(!eval(proj.path()), "changed content must require trust again");
    std::env::remove_var("ASH_TRUST_FILE");
}

fn done_block(cmd: &str) -> Block {
    let mut b = Block::new("s".into(), Actor::Human, cmd.into(), "/".into());
    b.status = Some(BlockStatus::Exit { code: 0 });
    b.policy = Some(PolicyResult { decision: Decision::Allow, rule: None, layer: None, approval: None, enforcement: EnforcementStatus::Full, enforcement_report: None, explain: None });
    b
}

/// POL-07 + rotation + anchor
#[test]
fn pol_07_audit_tamper_detected_rotation_and_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&path).unwrap();
    for i in 0..4 { log.record(&done_block(&format!("echo {}", i))).unwrap(); }
    assert_eq!(AuditLog::verify_chain(&path).unwrap(), 4);
    let anchor = log.head_hash().to_string();
    assert_eq!(AuditLog::verify_with_anchor(&path, &anchor).unwrap(), 4);

    // rotation continues the chain
    let rotated = log.rotate().unwrap();
    log.record(&done_block("echo after")).unwrap();
    let final_prev = std::fs::read_to_string(&rotated).unwrap().lines().last().map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["hash"].as_str().unwrap().to_string()).unwrap();
    assert_eq!(AuditLog::verify_rotated(&path, &final_prev).unwrap(), 1);

    // truncation detected via anchor
    let content = std::fs::read_to_string(&rotated).unwrap();
    let truncated: Vec<&str> = content.lines().take(2).collect();
    std::fs::write(&rotated, truncated.join("\n") + "\n").unwrap();
    assert!(AuditLog::verify_with_anchor(&rotated, &anchor).is_err());

    // alteration detected
    let tampered = content.replacen("echo 1", "echo X", 1);
    std::fs::write(&rotated, tampered).unwrap();
    assert!(AuditLog::verify_chain(&rotated).is_err());
}

/// POL-08: a sandboxed process cannot open the control socket.
#[tokio::test]
async fn pol_08_sandbox_cannot_reach_control_socket() {
    if !bwrap_usable() { eprintln!("skip: bwrap unusable"); return; }
    let (_s, path, h) = start().await;
    let dir = path.parent().unwrap().to_path_buf();
    let project = tempfile::tempdir().unwrap();
    let spec = SandboxSpec { fs_read: vec![], fs_write: vec![project.path().to_string_lossy().into()], network_allowed_hosts: vec![], allow_network: false };
    // python3 connects to the unix socket; exit 0 if connected
    let script = format!("python3 -c \"import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect('{}')\"", path.display());
    // control: unsandboxed succeeds
    let ctrl = std::process::Command::new("sh").arg("-c").arg(&script).status().unwrap();
    assert!(ctrl.success(), "control connect should work outside sandbox");
    let st = sandboxed_command(&spec, &script, project.path().to_str().unwrap(), &[dir]).status().unwrap();
    assert!(!st.success(), "sandboxed process reached the control socket");
    h.abort();
}

/// PERF-01 (informal): processing a keystroke-sized chunk adds well under 5 ms.
#[tokio::test]
async fn perf_01_proxy_latency() {
    let p = PtyProxy::new("s".into(), tempfile::tempdir().unwrap().keep().join("r.bin"), tokio::sync::broadcast::channel(16).0).unwrap();
    let start = std::time::Instant::now();
    for _ in 0..1000 { p.process_output(b"a", Some("b")).await.unwrap(); }
    let per = start.elapsed().as_secs_f64() * 1000.0 / 1000.0;
    assert!(per < 5.0, "per-chunk {:.3} ms", per);
    let _ = AsyncReadExt::read(&mut tokio::io::empty(), &mut [0u8; 1]).await;
}
