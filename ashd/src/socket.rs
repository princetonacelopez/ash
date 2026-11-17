//! # Unix Domain Socket Server (spec §3.2, §3.5)
//!
//! Provides the out-of-band event channel between:
//! - The shell hook (emitting block events)
//! - Consumers (emulators, a11y bridge, loggers, agents)
//!
//! Protocol: JSON Lines over a Unix domain socket.
//! Socket path: $XDG_RUNTIME_DIR/ash/<session-id>.sock
//! Permissions: 0600 (spec §7, ashd compromise mitigation)
//!
//! Capability handshake (spec §3.6):
//! - Client sends `hello` with `wants` list
//! - Server replies `welcome` with `granted` and `denied`
//! - Handshake timeout: 200ms; on timeout, assume legacy emulator

use crate::block::{capabilities, Event};
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, Mutex};
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn};

/// All capabilities `ashd` can grant.
const ALL_CAPABILITIES: &[&str] = &[
    capabilities::BLOCKS,
    capabilities::A11Y_TREE,
    capabilities::HYPERLINKS,
    capabilities::OUTPUT_STREAM,
];

/// A connected client with its granted capabilities.
#[derive(Debug)]
pub struct Client {
    pub id: String,
    pub capabilities: Vec<String>,
    pub client_name: String,
}

/// The socket server: accepts connections and fans out events.
pub struct SocketServer {
    socket_path: PathBuf,
    session_id: String,
    /// Broadcast channel for events (all connected clients receive all events)
    event_tx: broadcast::Sender<String>,
    _clients: Arc<Mutex<Vec<Arc<Mutex<Client>>>>>,
}

impl SocketServer {
    pub fn new(session_id: String) -> Result<Self> {
        let socket_path = resolve_socket_path(&session_id)?;
        let (event_tx, _) = broadcast::channel(4096);

        Ok(Self {
            socket_path,
            session_id,
            event_tx,
            _clients: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    /// Get a sender handle to broadcast events to all clients.
    pub fn event_sender(&self) -> broadcast::Sender<String> {
        self.event_tx.clone()
    }

    /// Start listening for client connections.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        // Remove stale socket if present
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        // Ensure parent directory exists
        if let Some(parent) = self.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&self.socket_path)
            .with_context(|| format!("binding socket {:?}", self.socket_path))?;

        // Set permissions to 0600 (spec §7)
        set_socket_permissions(&self.socket_path)?;

        info!(path = ?self.socket_path, session = %self.session_id, "ASH socket server listening");

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let server = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_client(stream).await {
                            error!("Client handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_client(&self, stream: UnixStream) -> Result<()> {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        // ── Capability handshake ──────────────────────────────────────────────
        // Wait up to 200ms for a hello message (spec §3.6)
        let handshake_result = timeout(Duration::from_millis(200), async {
            reader.read_line(&mut line).await?;
            Ok::<(), std::io::Error>(())
        })
        .await;

        let (client_name, granted) = match handshake_result {
            Ok(Ok(())) if !line.trim().is_empty() => {
                // Try to parse as a hello event
                match serde_json::from_str::<serde_json::Value>(line.trim()) {
                    Ok(val) if val["type"] == "hello" => {
                        let client_name = val["client"]
                            .as_str()
                            .unwrap_or("unknown")
                            .to_string();
                        let wants: Vec<String> = val["wants"]
                            .as_array()
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();

                        let (granted, denied) = negotiate_capabilities(&wants);

                        // Send welcome
                        let welcome = serde_json::json!({
                            "type": "welcome",
                            "v": 1,
                            "granted": granted,
                            "denied": denied
                        });
                        let mut welcome_str = serde_json::to_string(&welcome)?;
                        welcome_str.push('\n');
                        writer.write_all(welcome_str.as_bytes()).await?;

                        (client_name, granted)
                    }
                    _ => {
                        // Not a hello; treat as legacy (OSC 133 only)
                        warn!("Client sent non-hello first message; treating as legacy");
                        ("legacy".to_string(), vec![])
                    }
                }
            }
            _ => {
                // Timeout or error: assume legacy emulator
                debug!("Handshake timed out; assuming legacy emulator");
                ("legacy".to_string(), vec![])
            }
        };

        let client_id = crate::block::new_id();
        let capabilities = granted.clone();

        info!(
            client_id = %client_id,
            client_name = %client_name,
            capabilities = ?capabilities,
            "Client connected"
        );

        // Subscribe to the event broadcast channel
        let mut rx = self.event_tx.subscribe();

        // Forward events to this client based on its capabilities
        loop {
            match rx.recv().await {
                Ok(event_json) => {
                    // Filter events based on client capabilities
                    if should_send_event(&event_json, &capabilities) {
                        let mut payload = event_json;
                        payload.push('\n');
                        if writer.write_all(payload.as_bytes()).await.is_err() {
                            debug!(client_id = %client_id, "Client disconnected");
                            break;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(client_id = %client_id, skipped = n, "Client lagged; events dropped");
                }
            }
        }

        info!(client_id = %client_id, "Client disconnected");
        Ok(())
    }

    /// Publish an event to all connected clients.
    pub fn publish_event(&self, event: &Event) -> Result<()> {
        let json = serde_json::to_string(event)?;
        // Ignore errors when no receivers (channel is empty)
        let _ = self.event_tx.send(json);
        Ok(())
    }
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
