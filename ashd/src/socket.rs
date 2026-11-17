//! # Unix Domain Socket Server (spec v0.2 §3.1-§3.7)
//!
//! JSON Lines over a Unix socket. v0.2 behaviour:
//! - peer UID check (§3.1), 1 MiB line limit with `oversize` error (§3.1)
//! - server-assigned strictly increasing `seq`, bounded replay buffer (§3.2, §3.5)
//! - `subscribe` filters, `replay`, `ping`/`ack`, unknown messages ignored and counted
//! - backpressure: output dropped first; boundary/approval/policy events re-sent on lag
//! - `welcome` returns server, session and limits (§3.7)

use crate::block::{
    capabilities, ErrorCode, Event, EventKind, ProtocolLimits, ServerInfo, PROTOCOL_VERSION,
};
use anyhow::{Context, Result};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

/// All capabilities `ashd` can grant (§3.7).
const ALL_CAPABILITIES: &[&str] = &[
    capabilities::BLOCKS,
    capabilities::OUTPUT,
    capabilities::A11Y_TREE,
    capabilities::HYPERLINKS,
    capabilities::OUTPUT_STREAM,
    capabilities::AGENT,
    capabilities::SCHEMA,
    capabilities::REMOTE,
    capabilities::REDACTION,
];

pub const MAX_LINE: usize = 1024 * 1024;
const REPLAY_CAP: usize = 8192;

/// Events that must never be dropped for a slow subscriber (§3.5).
fn is_critical(json: &str) -> bool {
    !json.contains("\"type\":\"block_output\"")
}

#[derive(Default)]
struct Retained {
    events: VecDeque<(u64, String)>,
}

pub struct SocketServer {
    socket_path: PathBuf,
    session_id: String,
    event_tx: broadcast::Sender<String>,
    seq: AtomicU64,
    retained: StdMutex<Retained>,
    /// Count of unknown/ignored client messages (CORE-04).
    pub ignored: AtomicU64,
    /// Count of oversize lines dropped (CORE-02).
    pub oversize_dropped: AtomicU64,
}

impl SocketServer {
    pub fn new(session_id: String) -> Result<Self> {
        let socket_path = resolve_socket_path(&session_id)?;
        let (event_tx, _) = broadcast::channel(4096);
        Ok(Self {
            socket_path,
            session_id,
            event_tx,
            seq: AtomicU64::new(0),
            retained: StdMutex::new(Retained::default()),
            ignored: AtomicU64::new(0),
            oversize_dropped: AtomicU64::new(0),
        })
    }

    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    pub fn event_sender(&self) -> broadcast::Sender<String> {
        self.event_tx.clone()
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }
        if let Some(parent) = self.socket_path.parent() {
            let existed = parent.exists();
            std::fs::create_dir_all(parent)?;
            // §3.1: socket directory is 0700. Only tighten directories we own by
            // construction (newly created, or the dedicated `ash` directory).
            if !existed || parent.file_name().map(|n| n == "ash").unwrap_or(false) {
                set_dir_permissions(parent)?;
            }
        }
        let listener = UnixListener::bind(&self.socket_path)
            .with_context(|| format!("binding socket {:?}", self.socket_path))?;
        set_socket_permissions(&self.socket_path)?;
        info!(path = ?self.socket_path, session = %self.session_id, "ASH socket listening");

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    // §3.1: reject any peer whose UID differs from the owner.
                    if !peer_is_owner(&stream) {
                        warn!("rejecting connection from foreign UID");
                        let _ = reject(stream).await;
                        continue;
                    }
                    let server = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_client(stream).await {
                            debug!("client handler ended: {}", e);
                        }
                    });
                }
                Err(e) => {
                    warn!("accept error: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }

    fn envelope(&self, kind: EventKind, id: Option<String>, data: serde_json::Value) -> String {
        let mut ev = Event::server(self.session_id.clone(), None, kind, data);
        ev.id = id;
        serde_json::to_string(&ev).unwrap_or_default()
    }

    fn error_line(&self, code: ErrorCode, msg: &str, retryable: bool, id: Option<String>) -> String {
        self.envelope(
            EventKind::Error,
            id,
            serde_json::json!({"code": code, "message": msg, "retryable": retryable}),
        )
    }

    /// Events retained with seq > from_seq.
    fn retained_after(&self, from_seq: u64, critical_only: bool) -> (Vec<String>, Option<u64>) {
        let r = self.retained.lock().unwrap();
        let oldest = r.events.front().map(|(s, _)| *s);
        let out = r
            .events
            .iter()
            .filter(|(s, j)| *s > from_seq && (!critical_only || is_critical(j)))
            .map(|(_, j)| j.clone())
            .collect();
        (out, oldest)
    }

    async fn handle_client(&self, stream: UnixStream) -> Result<()> {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);

        // ── Handshake (200 ms) ────────────────────────────────────────────
        let first = timeout(Duration::from_millis(200), read_line_limited(&mut reader)).await;
        let mut pending: Option<serde_json::Value> = None;
        let (client_name, granted) = match first {
            Ok(Ok(Line::Text(l))) => match serde_json::from_str::<serde_json::Value>(l.trim()) {
                Ok(val) if val["type"] == "hello" => {
                    let name = val["client"].as_str().unwrap_or("unknown").to_string();
                    let wants: Vec<String> = val["wants"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    let (granted, denied) = negotiate_capabilities(&wants);
                    let welcome = serde_json::json!({
                        "v": PROTOCOL_VERSION,
                        "type": "welcome",
                        "ts": chrono::Utc::now(),
                        "session": self.session_id,
                        "granted": granted,
                        "denied": denied,
                        "server": ServerInfo { name: "ashd".into(), version: env!("CARGO_PKG_VERSION").into() },
                        "limits": ProtocolLimits::default_limits(),
                    });
                    let mut s = welcome.to_string();
                    s.push('\n');
                    writer.write_all(s.as_bytes()).await?;
                    (name, granted)
                }
                Ok(val) => {
                    pending = Some(val);
                    ("legacy".to_string(), vec![capabilities::BLOCKS.to_string()])
                }
                Err(_) => ("legacy".to_string(), vec![capabilities::BLOCKS.to_string()]),
            },
            Ok(Ok(Line::Oversize)) => {
                self.oversize_dropped.fetch_add(1, Ordering::Relaxed);
                let l = self.error_line(ErrorCode::Oversize, "line exceeds 1 MiB", false, None);
                writer.write_all(format!("{}\n", l).as_bytes()).await?;
                ("legacy".to_string(), vec![])
            }
            Ok(Ok(Line::Eof)) | Ok(Err(_)) => return Ok(()),
            // Timeout: fall back to legacy (OSC 133 hints) with block events only.
            Err(_) => ("legacy".to_string(), vec![capabilities::BLOCKS.to_string()]),
        };
        debug!(client = %client_name, caps = ?granted, "client connected");

        let mut filter = Filter::default();
        let mut last_seq: u64 = self.seq.load(Ordering::SeqCst);
        let mut rx = self.event_tx.subscribe();

        if let Some(v) = pending.take() {
            if let Some(out) = self.handle_message(&v, &mut filter) {
                for l in out {
                    writer.write_all(format!("{}\n", l).as_bytes()).await?;
                }
            }
        }

        loop {
            tokio::select! {
                line = read_line_limited(&mut reader) => {
                    match line? {
                        Line::Eof => break,
                        Line::Oversize => {
                            self.oversize_dropped.fetch_add(1, Ordering::Relaxed);
                            let l = self.error_line(ErrorCode::Oversize, "line exceeds 1 MiB", false, None);
                            writer.write_all(format!("{}\n", l).as_bytes()).await?;
                        }
                        Line::Text(t) => {
                            let t = t.trim();
                            if t.is_empty() { continue; }
                            match serde_json::from_str::<serde_json::Value>(t) {
                                Ok(v) => {
                                    for l in self.handle_message(&v, &mut filter).unwrap_or_default() {
                                        writer.write_all(format!("{}\n", l).as_bytes()).await?;
                                    }
                                }
                                Err(_) => {
                                    let l = self.error_line(ErrorCode::BadRequest, "invalid JSON", false, None);
                                    writer.write_all(format!("{}\n", l).as_bytes()).await?;
                                }
                            }
                        }
                    }
                }
                ev = rx.recv() => {
                    match ev {
                        Ok(json) => {
                            if let Some(s) = seq_of(&json) { last_seq = s; }
                            if should_send_event(&json, &granted) && filter.allows(&json) {
                                writer.write_all(format!("{}\n", json).as_bytes()).await?;
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            // Drop output first; never drop critical events (§3.5).
                            let w = self.envelope(EventKind::Warn, None,
                                serde_json::json!({"code": "output.dropped", "dropped": n}));
                            writer.write_all(format!("{}\n", w).as_bytes()).await?;
                            let (crit, _) = self.retained_after(last_seq, true);
                            for j in crit {
                                if let Some(s) = seq_of(&j) { last_seq = last_seq.max(s); }
                                if filter.allows(&j) {
                                    writer.write_all(format!("{}\n", j).as_bytes()).await?;
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Process one client message; returns lines to send back.
    fn handle_message(&self, v: &serde_json::Value, filter: &mut Filter) -> Option<Vec<String>> {
        let id = v["id"].as_str().map(String::from);
        match v["type"].as_str()? {
            "ping" => Some(vec![self.envelope(EventKind::Ack, id, serde_json::json!({"pong": true}))]),
            "subscribe" => {
                let f = &v["filter"];
                *filter = Filter::from_json(if f.is_null() { v } else { f });
                Some(vec![self.envelope(EventKind::Ack, id, serde_json::json!({"subscribed": true}))])
            }
            "replay" => {
                let from = v["from_seq"].as_u64().unwrap_or(0);
                let (events, oldest) = self.retained_after(from, false);
                let mut out = vec![];
                if let Some(o) = oldest {
                    if from + 1 < o && from > 0 || (from == 0 && o > 1) {
                        out.push(self.envelope(EventKind::Warn, id.clone(),
                            serde_json::json!({"code": "replay.gap", "oldest_seq": o})));
                    }
                }
                out.extend(events.into_iter().filter(|j| filter.allows(j)));
                Some(out)
            }
            // Known message types handled elsewhere (approve/deny/agent.*) are acked.
            "approve" | "deny" | "undo" | "grant.revoke" | "grant_revoke" | "hello" => {
                Some(vec![self.envelope(EventKind::Ack, id, serde_json::json!({}))])
            }
            _ => {
                // CORE-04: unknown types are ignored and counted.
                self.ignored.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Publish an event: assigns `seq`, retains it for replay, fans out.
    pub fn publish_event(&self, event: &Event) -> Result<()> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let mut ev = event.clone();
        ev.seq = Some(seq);
        let json = serde_json::to_string(&ev)?;
        {
            let mut r = self.retained.lock().unwrap();
            r.events.push_back((seq, json.clone()));
            while r.events.len() > REPLAY_CAP {
                r.events.pop_front();
            }
        }
        let _ = self.event_tx.send(json);
        Ok(())
    }
}

#[derive(Default)]
struct Filter {
    types: Option<Vec<String>>,
    blocks: Option<Vec<String>>,
}

impl Filter {
    fn from_json(v: &serde_json::Value) -> Self {
        let list = |k: &str| {
            v[k].as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        };
        Self { types: list("types"), blocks: list("blocks") }
    }
    fn allows(&self, json: &str) -> bool {
        if self.types.is_none() && self.blocks.is_none() {
            return true;
        }
        let v: serde_json::Value = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(_) => return true,
        };
        if let Some(t) = &self.types {
            if !v["type"].as_str().map(|s| t.iter().any(|x| x == s)).unwrap_or(false) {
                return false;
            }
        }
        if let Some(b) = &self.blocks {
            if !v["block"].as_str().map(|s| b.iter().any(|x| x == s)).unwrap_or(false) {
                return false;
            }
        }
        true
    }
}

fn seq_of(json: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(json).ok()?["seq"].as_u64()
}

enum Line {
    Text(String),
    Oversize,
    Eof,
}

/// Read one line, never buffering more than MAX_LINE; oversize lines are drained and dropped.
async fn read_line_limited<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R) -> std::io::Result<Line> {
    let mut buf = Vec::new();
    let n = (&mut *r).take(MAX_LINE as u64 + 1).read_until(b'\n', &mut buf).await?;
    if n == 0 {
        return Ok(Line::Eof);
    }
    if buf.last() == Some(&b'\n') {
        return Ok(Line::Text(String::from_utf8_lossy(&buf).into_owned()));
    }
    if buf.len() > MAX_LINE {
        // drain the rest of the line without buffering it
        loop {
            let chunk = r.fill_buf().await?;
            if chunk.is_empty() {
                break;
            }
            if let Some(p) = chunk.iter().position(|b| *b == b'\n') {
                r.consume(p + 1);
                break;
            }
            let l = chunk.len();
            r.consume(l);
        }
        return Ok(Line::Oversize);
    }
    // EOF without trailing newline
    Ok(Line::Text(String::from_utf8_lossy(&buf).into_owned()))
}

async fn reject(mut stream: UnixStream) -> std::io::Result<()> {
    let l = r#"{"v":1,"type":"error","data":{"code":"unauthorized","message":"peer uid mismatch","retryable":false}}"#;
    stream.write_all(format!("{}\n", l).as_bytes()).await?;
    stream.shutdown().await
}

fn peer_is_owner(stream: &UnixStream) -> bool {
    match stream.peer_cred() {
        Ok(c) => c.uid() == get_uid(),
        Err(_) => false,
    }
}

fn set_dir_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Negotiate capabilities: returns (granted, denied).
fn negotiate_capabilities(wants: &[String]) -> (Vec<String>, Vec<serde_json::Value>) {
    let mut granted = vec![];
    let mut denied = vec![];

    for want in wants {
        let supported: Vec<&str> = ALL_CAPABILITIES.to_vec();
        if supported.contains(&want.as_str()) {
            granted.push(want.clone());
        } else {
            denied.push(serde_json::json!({
                "cap": want,
                "reason": "not-supported"
            }));
        }
    }

    (granted, denied)
}

/// Should this event be sent to a client with these capabilities?
fn should_send_event(event_json: &str, capabilities: &[String]) -> bool {
    // Output events are opt-in (high volume) - only send if client has OUTPUT_STREAM cap
    if event_json.contains("\"block_output\"") || event_json.contains("\"block.output\"") {
        return capabilities.contains(&capabilities::OUTPUT_STREAM.to_string());
    }
    // All other events go to any connected client
    true
}

/// Resolve the socket path for a session.
/// $XDG_RUNTIME_DIR/ash/<session-id>.sock
pub fn resolve_socket_path(session_id: &str) -> Result<PathBuf> {
    // §3.1: $ASH_SOCKET wins when set.
    if let Ok(p) = std::env::var("ASH_SOCKET") {
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .or_else(|_| {
            // Fallback: /tmp/ash-<uid>
            let uid = get_uid();
            Ok::<PathBuf, anyhow::Error>(PathBuf::from(format!("/tmp/ash-{}", uid)))
        })?;

    Ok(runtime_dir.join("ash").join(format!("{}.sock", session_id)))
}

fn get_uid() -> u32 {
    #[cfg(unix)]
    {
        unsafe { libc::getuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn set_socket_permissions(path: &PathBuf) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Connect to `ashd` as a client and return a stream.
/// Used by the shell hook and CLI tools.
pub async fn connect(session_id: &str) -> Result<UnixStream> {
    let socket_path = resolve_socket_path(session_id)?;
    UnixStream::connect(&socket_path)
        .await
        .with_context(|| format!("connecting to ashd socket {:?}", socket_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_known_capabilities() {
        let (granted, denied) = negotiate_capabilities(&[
            "blocks".to_string(),
            "a11y-tree".to_string(),
            "images:kitty".to_string(), // not supported
        ]);
        assert!(granted.contains(&"blocks".to_string()));
        assert!(granted.contains(&"a11y-tree".to_string()));
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0]["cap"], "images:kitty");
    }

    #[test]
    fn output_events_filtered_without_cap() {
        assert!(!should_send_event(
            r#"{"type":"block_output","data":"..."}"#,
            &[]
        ));
        assert!(should_send_event(
            r#"{"type":"block_output","data":"..."}"#,
            &["output-stream".to_string()]
        ));
    }

    #[test]
    fn all_other_events_pass_through() {
        assert!(should_send_event(
            r#"{"type":"block_end","data":"..."}"#,
            &[]
        ));
    }
}
