//! `ash emit <event_json>` - emit an event to the ashd socket

use anyhow::Result;
use clap::Args;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

#[derive(Args, Debug)]
pub struct EmitArgs {
    /// The event JSON string to send
    pub event: String,

    /// Socket path override
    #[arg(long)]
    pub socket: Option<std::path::PathBuf>,
}

pub async fn execute(args: EmitArgs, session_id: Option<String>) -> Result<()> {
    let socket_path = match args.socket {
        Some(p) => p,
        None => {
            let session = session_id
                .or_else(|| std::env::var("ASH_SESSION_ID").ok())
                .unwrap_or_default();
            if session.is_empty() {
                return Ok(()); // silently exit if no active session
            }
            resolve_socket_path(&session)?
        }
    };

    if !socket_path.exists() {
        return Ok(());
    }

    if let Ok(mut stream) = UnixStream::connect(&socket_path).await {
        let mut payload = args.event;
        payload.push('\n');
        let _ = stream.write_all(payload.as_bytes()).await;
    }

    Ok(())
}

fn resolve_socket_path(session_id: &str) -> Result<std::path::PathBuf> {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let uid = unsafe { libc::getuid() };
            std::path::PathBuf::from(format!("/tmp/ash-{}", uid))
        });
    Ok(runtime_dir.join("ash").join(format!("{}.sock", session_id)))
}
