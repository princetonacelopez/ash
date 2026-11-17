//! `ash deny <block-id>` - deny a pending block

use anyhow::Result;
use clap::Args;

#[derive(Args, Debug)]
pub struct DenyArgs {
    /// Block ID to deny
    pub block_id: String,

    /// Reason for denial
    #[arg(long, default_value = "user denied")]
    pub reason: String,
}

pub async fn execute(args: DenyArgs, session_id: Option<String>) -> Result<()> {
    let session = session_id
        .or_else(|| std::env::var("ASH_SESSION_ID").ok())
        .ok_or_else(|| anyhow::anyhow!("No session ID. Set ASH_SESSION_ID or use --session."))?;

    send_to_ashd(&session, serde_json::json!({
        "type": "block.deny",
        "block": args.block_id,
        "reason": args.reason
    })).await?;

    println!("🚫 Denied block {} (reason: {})", args.block_id, args.reason);
    Ok(())
}

async fn send_to_ashd(session_id: &str, event: serde_json::Value) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let uid = unsafe { libc::getuid() };
            std::path::PathBuf::from(format!("/tmp/ash-{}", uid))
        });
    let socket_path = runtime_dir.join("ash").join(format!("{}.sock", session_id));

    let mut stream = UnixStream::connect(&socket_path).await
        .map_err(|e| anyhow::anyhow!("Cannot connect to ashd at {:?}: {}", socket_path, e))?;

    let mut payload = serde_json::to_string(&event)?;
    payload.push('\n');
    stream.write_all(payload.as_bytes()).await?;
    Ok(())
}
