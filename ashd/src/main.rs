//! # ashd - Agentic Shell Layer Daemon
//!
//! The core per-session daemon. It:
//! 1. Opens the PTY and sits between the emulator and the shell
//! 2. Receives block events from the shell hook over a private fd
//! 3. Applies the policy engine to each command
//! 4. Manages snapshots and audit logging
//! 5. Serves the event stream to consumers over a Unix domain socket
//!
//! Entry point for the `ashd` binary.

use ashd::{audit, block, policy, pty, snapshot, socket};

use anyhow::{Context, Result};
use block::{Actor, Block, BlockState, BlockStatus, Decision, Session};
use chrono::Utc;
use clap::Parser;
use policy::engine::PolicyEngine;
use socket::SocketServer;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

/// ashd - Agentic Shell Layer Daemon
#[derive(Parser, Debug)]
#[command(name = "ashd", version, about)]
struct Args {
    /// Shell to launch (default: $SHELL or zsh)
    #[arg(short, long, env = "SHELL")]
    shell: Option<String>,

    /// Working directory for the session
    #[arg(short = 'C', long, default_value = ".")]
    cwd: PathBuf,

    /// Session ID (auto-generated if not provided)
    #[arg(long)]
    session_id: Option<String>,

    /// Project root for policy loading
    #[arg(long)]
    project_root: Option<PathBuf>,

    /// Emit OSC 133 compatibility hints even without an emulator connection
    #[arg(long, default_value_t = true)]
    osc133: bool,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&args.log_level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    info!("ashd starting");

    // Session setup
    let _session_id = args
        .session_id
        .unwrap_or_else(|| block::new_id());
    let shell = args
        .shell
        .or_else(|| std::env::var("SHELL").ok())
        .unwrap_or_else(|| "zsh".to_string());
    let cwd = args.cwd.canonicalize().unwrap_or(args.cwd);

    let session = Session::new(shell.clone(), 24, 80);

    info!(
        session_id = %session.id,
        shell = %shell,
        cwd = ?cwd,
        "Session created"
    );

    // Policy engine
    let policy_engine = PolicyEngine::new(args.project_root.as_deref())
        .context("failed to initialize policy engine")?;
    let policy_engine = Arc::new(policy_engine);

    // Data directories
    let data_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("ash");
    let session_dir = data_dir.join("sessions").join(&session.id);
    std::fs::create_dir_all(&session_dir)?;

    // Audit log
    let audit_path = data_dir.join("audit.jsonl");
    let audit_log = Arc::new(Mutex::new(
        audit::AuditLog::open(&audit_path)
            .context("failed to open audit log")?,
    ));

    // Snapshot directory
    let snapshot_dir = data_dir.join("snapshots");
    std::fs::create_dir_all(&snapshot_dir)?;

    // Event broadcast channel
    let (event_tx, _) = broadcast::channel::<String>(4096);

    // PTY recording
    let recording_path = session_dir.join("recording.bin");
    let _pty_proxy = pty::PtyProxy::new(
        session.id.clone(),
        recording_path,
        event_tx.clone(),
    )
    .context("failed to create PTY proxy")?;

    // Socket server
    let socket_server = Arc::new(
        SocketServer::new(session.id.clone())
            .context("failed to create socket server")?,
    );
    let socket_server_clone = Arc::clone(&socket_server);

    // Start socket server in background
    tokio::spawn(async move {
        if let Err(e) = socket_server_clone.run().await {
            error!("Socket server error: {}", e);
        }
    });

    // Publish session.start event
    let start_event = block::Event::new(
        session.id.clone(),
        None,
        block::EventKind::SessionStart,
        block::EventPayload::SessionStart(block::SessionStartPayload {
            shell: shell.clone(),
            tty_rows: session.tty_rows,
            tty_cols: session.tty_cols,
            capabilities: vec![],
        }),
    );
    socket_server.publish_event(&start_event)?;

    info!(
        socket = ?socket_server.socket_path(),
        session_id = %session.id,
        "ashd ready - socket listening"
    );

    // Print the socket path and session ID for the shell hook to pick up
    println!("ASH_SESSION_ID={}", session.id);
    println!("ASH_SOCKET={}", socket_server.socket_path().display());

    // Main event loop: read block events from stdin (shell hook protocol)
    // The shell hook sends JSON events on stdout, which ashd reads here.
    // In production, this would be a private fd; for this implementation
    // we use stdin as the hook channel.
    run_hook_listener(
        session.id.clone(),
        policy_engine,
        audit_log,
        snapshot_dir,
        socket_server,
        event_tx,
    )
    .await
}

/// Listen for block events from the shell hook.
/// Events arrive as JSON Lines on stdin.
async fn run_hook_listener(
    session_id: String,
    policy_engine: Arc<PolicyEngine>,
    audit_log: Arc<Mutex<audit::AuditLog>>,
    snapshot_dir: PathBuf,
    socket_server: Arc<SocketServer>,
    _event_tx: broadcast::Sender<String>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    // Block registry: active blocks indexed by block ID
    let blocks: Arc<Mutex<std::collections::HashMap<String, Block>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));

    info!("Listening for shell hook events on stdin");

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                info!("Shell hook EOF; shutting down");
                break;
            }
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                match serde_json::from_str::<serde_json::Value>(trimmed) {
                    Ok(event) => {
                        if let Err(e) = handle_hook_event(
                            &event,
                            &session_id,
                            &policy_engine,
                            &audit_log,
                            &snapshot_dir,
                            &socket_server,
                            &blocks,
                        )
                        .await
                        {
                            error!("Error handling hook event: {}", e);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse hook event: {} - {}", e, trimmed);
                    }
                }
            }
            Err(e) => {
                error!("Error reading from stdin: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Process a single event from the shell hook.
async fn handle_hook_event(
    event: &serde_json::Value,
    session_id: &str,
    policy_engine: &Arc<PolicyEngine>,
    audit_log: &Arc<Mutex<audit::AuditLog>>,
    snapshot_dir: &PathBuf,
    socket_server: &Arc<SocketServer>,
    blocks: &Arc<Mutex<std::collections::HashMap<String, Block>>>,
) -> Result<()> {
    let event_type = event["type"].as_str().unwrap_or("");

    match event_type {
        // Shell prompt rendered
        "block.prompt" => {
            let cwd = event["cwd"].as_str().unwrap_or(".").to_string();
            let git_branch = event["git_branch"].as_str().map(|s| s.to_string());
            let git_dirty = event["git_dirty"].as_bool();

            let ev = block::Event::new(
                session_id.to_string(),
                None,
                block::EventKind::BlockPrompt,
                block::EventPayload::BlockPrompt(block::BlockPromptPayload {
                    cwd,
                    git_branch,
                    git_dirty,
                }),
            );
            socket_server.publish_event(&ev)?;
            info!("Prompt rendered");
        }

        // User submitted a command (agent or human)
        "block.input" => {
            let command = event["command"].as_str().unwrap_or("").to_string();
            let cwd = event["cwd"].as_str().unwrap_or(".").to_string();
            let actor = parse_actor(event);

            let mut block = Block::new(session_id.to_string(), actor.clone(), command.clone(), cwd);

            // Apply policy
            let policy_result = policy_engine.evaluate(&mut block);
            block.policy = Some(policy_result.clone());

            info!(
                block_id = %block.id,
                command = %command,
                decision = %policy_result.decision,
                tier = ?block.risk.as_ref().map(|r| r.tier),
                "Block input evaluated"
            );

            // Publish block.input event
            let ev = block::Event::new(
                session_id.to_string(),
                Some(block.id.clone()),
                block::EventKind::BlockInput,
                block::EventPayload::BlockInput(block::BlockInputPayload {
                    command: block.command.clone(),
                    actor: actor.clone(),
                }),
            );
            socket_server.publish_event(&ev)?;

            // If policy requires approval or confirmation, emit pending event
            if matches!(
                policy_result.decision,
                Decision::RequireApproval | Decision::Confirm | Decision::ConfirmPreview
            ) {
                block.state = BlockState::Pending;
                let ev = block::Event::new(
                    session_id.to_string(),
                    Some(block.id.clone()),
                    block::EventKind::BlockPending,
                    block::EventPayload::BlockPending(block::BlockPendingPayload {
                        risk: block.risk.clone().unwrap(),
                        preview_ref: None,
                    }),
                );
                socket_server.publish_event(&ev)?;

                // Write the pending block ID to stdout so the shell hook can pause
                println!("ASH_PENDING={}", block.id);
                println!("ASH_DECISION={}", policy_result.decision);
                println!("ASH_RISK_TIER={}", block.risk.as_ref().map(|r| r.tier.to_string()).unwrap_or_default());
                if let Some(ref reason) = policy_result.rule {
                    println!("ASH_RULE={}", reason);
                }
            } else if policy_result.decision == Decision::Deny {
                block.state = BlockState::Done;
                block.status = Some(BlockStatus::Denied {
                    reason: policy_result
                        .rule
                        .clone()
                        .unwrap_or_else(|| "policy deny".to_string()),
                });
                // Audit and return
                let mut log = audit_log.lock().await;
                log.record(&block)?;
                println!("ASH_DENIED=1");
                println!("ASH_DENY_REASON={}", block.status.as_ref().map(|s| {
                    if let BlockStatus::Denied { reason } = s { reason.clone() } else { String::new() }
                }).unwrap_or_default());
            }

            // Store block for later exec/end events
            let block_id = block.id.clone();
            let mut b = blocks.lock().await;
            b.insert(block_id, block);
        }

        // Process group spawned
        "block.start" => {
            let block_id = event["block"].as_str().unwrap_or("").to_string();
            let pid = event["pid"].as_u64().unwrap_or(0) as u32;
            let pgid = event["pgid"].as_u64().unwrap_or(0) as u32;

            let mut b = blocks.lock().await;
            if let Some(block) = b.get_mut(&block_id) {
                block.started_at = Some(Utc::now());
                block.state = BlockState::Running;

                // Take a snapshot if policy requires it
                if matches!(
                    block.policy.as_ref().map(|p| &p.decision),
                    Some(Decision::AllowSnapshot)
                ) {
                    let predicted_writes = block
                        .risk
                        .as_ref()
                        .map(|_| vec![]) // We'd compute from classification
                        .unwrap_or_default();
                    let cwd = PathBuf::from(&block.cwd);
                    let snap = snapshot::take_snapshot(
                        &block.id,
                        &cwd,
                        &predicted_writes,
                        snapshot_dir,
                    )
                    .await?;

                    if let Some(snap_ref) = snap {
                        block.snapshot = Some(snap_ref.id.clone());
                        let ev = block::Event::new(
                            session_id.to_string(),
                            Some(block_id.clone()),
                            block::EventKind::BlockSnapshot,
                            block::EventPayload::BlockSnapshot(block::BlockSnapshotPayload {
                                r#ref: snap_ref.id,
                                backend: snap_ref.backend.to_string(),
                            }),
                        );
                        socket_server.publish_event(&ev)?;
                    }
                }

                let policy = block.policy.clone().unwrap_or_else(|| block::PolicyResult {
                    decision: Decision::Allow,
                    rule: None,
                    approval: None,
                    enforcement: block::EnforcementStatus::Unenforced,
                });

                let ev = block::Event::new(
                    session_id.to_string(),
                    Some(block_id.clone()),
                    block::EventKind::BlockStart,
                    block::EventPayload::BlockStart(block::BlockStartPayload {
                        pid,
                        pgid,
                        policy,
                    }),
                );
                socket_server.publish_event(&ev)?;
                info!(block_id = %block_id, pid = pid, "Block started");
            }
        }

        // Process finished
        "block.end" => {
            let block_id = event["block"].as_str().unwrap_or("").to_string();
            let exit_code = event["exit_code"].as_i64().map(|c| c as i32);
            let signal = event["signal"].as_i64().map(|s| s as i32);

            let mut b = blocks.lock().await;
            if let Some(block) = b.get_mut(&block_id) {
                block.ended_at = Some(Utc::now());
                block.state = BlockState::Done;
                block.status = Some(match (exit_code, signal) {
                    (Some(code), _) => BlockStatus::Exit { code },
                    (_, Some(sig)) => BlockStatus::Signal {
                        signal: sig,
                        name: signal_name(sig).map(|s| s.to_string()),
                    },
                    _ => BlockStatus::Detached,
                });

                let duration_ms = block.duration_ms().unwrap_or(0);

                let ev = block::Event::new(
                    session_id.to_string(),
                    Some(block_id.clone()),
                    block::EventKind::BlockEnd,
                    block::EventPayload::BlockEnd(block::BlockEndPayload {
                        status: block.status.clone().unwrap(),
                        duration_ms,
                        snapshot: block.snapshot.clone(),
                    }),
                );
                socket_server.publish_event(&ev)?;

                // Write audit log entry
                let mut log = audit_log.lock().await;
                log.record(block)?;

                info!(
                    block_id = %block_id,
                    duration_ms = duration_ms,
                    status = ?block.status,
                    "Block ended"
                );
            }

            // Remove from active blocks
            b.remove(&block_id);
        }

        // Approval from the human operator
        "block.approve" => {
            let block_id = event["block"].as_str().unwrap_or("").to_string();
            let approver = event["approver"].as_str().unwrap_or("human").to_string();
            let scope_str = event["scope"].as_str().unwrap_or("once");
            let scope = parse_approval_scope(scope_str);

            let mut b = blocks.lock().await;
            if let Some(block) = b.get_mut(&block_id) {
                policy_engine.approve(block, approver.clone(), scope);
                block.state = BlockState::Running;
                info!(block_id = %block_id, approver = %approver, "Block approved");
                println!("ASH_APPROVED={}", block_id);
            }
        }

        // Denial from the human operator
        "block.deny" => {
            let block_id = event["block"].as_str().unwrap_or("").to_string();
            let reason = event["reason"].as_str().unwrap_or("user denied").to_string();

            let mut b = blocks.lock().await;
            if let Some(block) = b.get_mut(&block_id) {
                block.state = BlockState::Done;
                block.status = Some(BlockStatus::Denied { reason: reason.clone() });
                let mut log = audit_log.lock().await;
                log.record(block)?;
                info!(block_id = %block_id, reason = %reason, "Block denied by user");
                println!("ASH_DENIED=1");
                println!("ASH_DENY_REASON={}", reason);
            }
            b.remove(&block_id);
        }

        // Undo request
        "undo" => {
            let block_id = event["block"].as_str();
            info!(block_id = ?block_id, "Undo requested");

            if let Some(bid) = block_id {
                // Load snapshot for the specified block from index
                let snap_path = dirs::data_local_dir()
                    .unwrap_or_else(|| PathBuf::from("/tmp"))
                    .join("ash")
                    .join("snapshots");
                let snap_id = format!("snap_{}", bid);
                match snapshot::load_snapshot_ref(&snap_id, &snap_path) {
                    Ok(snap_ref) => {
                        snapshot::restore_snapshot(&snap_ref).await?;
                        println!("ASH_UNDONE={}", bid);
                        info!(block_id = %bid, "Snapshot restored (undo)");
                    }
                    Err(e) => {
                        warn!("Cannot undo {}: {}", bid, e);
                        println!("ASH_UNDO_ERROR={}", e);
                    }
                }
            }
        }

        unknown => {
            warn!("Unknown hook event type: {}", unknown);
        }
    }

    Ok(())
}

fn parse_actor(event: &serde_json::Value) -> Actor {
    match event["actor"]["kind"].as_str() {
        Some("human") => Actor::Human,
        Some("agent") => Actor::Agent {
            name: event["actor"]["name"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
            run: event["actor"]["run"]
                .as_str()
                .unwrap_or(&block::new_id())
                .to_string(),
        },
        Some("script") => Actor::Script {
            name: event["actor"]["name"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
        },
        _ => Actor::Human, // Default to human if unspecified
    }
}

fn parse_approval_scope(s: &str) -> block::ApprovalScope {
    match s {
        "block_tree" => block::ApprovalScope::BlockTree,
        "session" => block::ApprovalScope::Session,
        "project" => block::ApprovalScope::Project,
        _ => block::ApprovalScope::Once,
    }
}

fn signal_name(sig: i32) -> Option<&'static str> {
    match sig {
        1 => Some("SIGHUP"),
        2 => Some("SIGINT"),
        3 => Some("SIGQUIT"),
        6 => Some("SIGABRT"),
        9 => Some("SIGKILL"),
        11 => Some("SIGSEGV"),
        13 => Some("SIGPIPE"),
        15 => Some("SIGTERM"),
        _ => None,
    }
}
