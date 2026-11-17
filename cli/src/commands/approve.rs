//! `ash approve <block-id>` - approve a pending block

use anyhow::Result;
use clap::Args;

#[derive(Args, Debug)]
pub struct ApproveArgs {
    /// Block ID to approve
    pub block_id: String,

    /// Approval scope: once (default), session, project
    #[arg(long, value_parser = ["once", "session", "project"], default_value = "once")]
    pub scope: String,
}

pub async fn execute(args: ApproveArgs, session_id: Option<String>) -> Result<()> {
    let session = session_id
        .or_else(|| std::env::var("ASH_SESSION_ID").ok())
        .ok_or_else(|| anyhow::anyhow!("No session ID. Set ASH_SESSION_ID or use --session."))?;

    // Send approval event to ashd
    send_to_ashd(&session, serde_json::json!({
        "type": "block.approve",
        "block": args.block_id,
        "approver": get_user_identity(),
        "scope": args.scope
    })).await?;

    println!("✅ Approved block {} (scope: {})", args.block_id, args.scope);
    Ok(())
}

async fn send_to_ashd(session_id: &str, event: serde_json::Value) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

    let socket_path = resolve_socket_path(session_id)?;
    let mut stream = UnixStream::connect(&socket_path).await
        .map_err(|e| anyhow::anyhow!("Cannot connect to ashd at {:?}: {}", socket_path, e))?;

    let mut payload = serde_json::to_string(&event)?;
    payload.push('\n');
    stream.write_all(payload.as_bytes()).await?;
    Ok(())
}

fn resolve_socket_path(session_id: &str) -> anyhow::Result<std::path::PathBuf> {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let uid = unsafe { libc::getuid() };
            std::path::PathBuf::from(format!("/tmp/ash-{}", uid))
        });
    Ok(runtime_dir.join("ash").join(format!("{}.sock", session_id)))
}

fn get_user_identity() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}
