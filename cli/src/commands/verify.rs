//! `ash verify` / `ash audit verify` - verify audit log chain integrity (spec v0.2 §7.5)

use anyhow::Result;
use ashd::audit::AuditLog;
use clap::Args;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Path to audit log (default: ~/.local/share/ash/audit.jsonl)
    #[arg(long)]
    pub path: Option<PathBuf>,
    /// External anchor: the expected head hash (detects truncation)
    #[arg(long)]
    pub anchor: Option<String>,
    /// For a rotated continuation file: final hash of the previous file
    #[arg(long)]
    pub after: Option<String>,
}

pub async fn execute(args: VerifyArgs) -> Result<()> {
    let log_path = args.path.unwrap_or_else(|| {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("ash")
            .join("audit.jsonl")
    });
    if !log_path.exists() {
        println!("No audit log found at {}", log_path.display());
        return Ok(());
    }
    println!("Verifying audit log: {}", log_path.display());
    let res = match (&args.after, &args.anchor) {
        (Some(prev), _) => AuditLog::verify_rotated(&log_path, prev),
        (None, Some(a)) => AuditLog::verify_with_anchor(&log_path, a),
        (None, None) => AuditLog::verify_chain(&log_path),
    };
    match res {
        Ok(n) => {
            println!("OK: {} entries, chain intact", n);
            Ok(())
        }
        Err(e) => {
            eprintln!("FAILED: {}", e);
            std::process::exit(1);
        }
    }
}
