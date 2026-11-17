//! `ash schema <binary>` - discover and show a CLI schema (spec v0.2 §6)

use anyhow::Result;
use ashd::schema::{heuristic_from_help, load_sidecar, probe, ProbeError, SchemaSource};
use clap::Args;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct SchemaArgs {
    /// Binary to inspect
    pub binary: PathBuf,
    /// Allow executing `<binary> --schema` in the probe sandbox (off by default)
    #[arg(long)]
    pub probe: bool,
}

pub async fn execute(args: SchemaArgs) -> Result<()> {
    let bin = which(&args.binary).unwrap_or(args.binary.clone());
    let cfg = dirs::config_dir().map(|d| d.join("ash"));

    // 1. --schema (only when explicitly allowed; sandboxed)
    if args.probe {
        let in_scope = bin.starts_with("/usr") || bin.starts_with("/bin") || bin.starts_with(std::env::current_dir()?);
        match probe(&bin, true, in_scope) {
            Ok(r) => {
                println!("{}", serde_json::to_string_pretty(&r.doc)?);
                eprintln!("source: declared (--schema), network isolation: {}", r.network_isolation);
                return Ok(());
            }
            Err(ProbeError::OutsideProbeScope) => eprintln!("probe skipped: binary is outside system dirs and project root"),
            Err(e) => eprintln!("probe failed: {:?}", e),
        }
    }
    // 2. sidecar
    if let Some(doc) = load_sidecar(&bin, cfg.as_deref()) {
        println!("{}", serde_json::to_string_pretty(&doc)?);
        eprintln!("source: {:?} (sidecar; may only raise tiers)", SchemaSource::Declared);
        return Ok(());
    }
    // 4. heuristic --help (lowest confidence)
    let out = std::process::Command::new(&bin).arg("--help").env_clear().env("PATH", "/usr/bin:/bin").output();
    if let Ok(o) = out {
        let help = String::from_utf8_lossy(&o.stdout);
        let doc = heuristic_from_help(&bin.file_name().unwrap_or_default().to_string_lossy(), &help);
        println!("{}", serde_json::to_string_pretty(&doc)?);
        eprintln!("source: {:?} (lowest confidence; may only raise tiers)", SchemaSource::Heuristic);
        return Ok(());
    }
    anyhow::bail!("no schema found for {}", bin.display())
}

fn which(p: &PathBuf) -> Option<PathBuf> {
    if p.components().count() > 1 {
        return Some(p.clone());
    }
    std::env::var("PATH").ok()?.split(':').map(|d| PathBuf::from(d).join(p)).find(|c| c.is_file())
}
