//! `ash verify` - verify audit log chain integrity (spec §4.10)

use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Path to audit log (default: ~/.local/share/ash/audit.jsonl)
    #[arg(long)]
    pub path: Option<PathBuf>,
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

    println!("🔍 Verifying audit log: {}", log_path.display());

    let content = std::fs::read_to_string(&log_path)?;
    let genesis_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let mut prev_hash = genesis_hash.to_string();
    let mut count = 0;
    let mut errors = 0;

    for (line_no, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let mut entry: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  ✗ Line {}: JSON parse error: {}", line_no + 1, e);
                errors += 1;
                continue;
            }
        };

        let claimed_hash = entry["hash"].as_str().unwrap_or("").to_string();

        // Recompute hash without the hash field
        entry["hash"] = serde_json::Value::String(String::new());
        let canonical = serde_json::to_string(&entry)?;

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(canonical.as_bytes());
        let expected_hash = hex::encode(hasher.finalize());

        if claimed_hash != expected_hash {
            eprintln!(
                "  ✗ Line {}: Hash mismatch (expected {}, got {})",
                line_no + 1,
                &expected_hash[..16],
                &claimed_hash[..claimed_hash.len().min(16)]
            );
            errors += 1;
        }

        prev_hash = claimed_hash;
        count += 1;
    }

    if errors == 0 {
        println!("✅ Audit log verified: {} entries, chain intact", count);
    } else {
        eprintln!("⚠️  {} integrity violation(s) found in {} entries", errors, count);
        std::process::exit(1);
    }

    Ok(())
}
