//! `ash trust` - trust the current project's policy by content hash (spec v0.2 §7.6)

use anyhow::Result;
use clap::Args;

#[derive(Args, Debug)]
pub struct TrustArgs {}

pub async fn execute(_args: TrustArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    ashd::policy::config::trust_project(&cwd)?;
    println!("Trusted .ash/policy.toml in {} (bound to its current content hash)", cwd.display());
    println!("Any change to the file requires running `ash trust` again.");
    Ok(())
}
