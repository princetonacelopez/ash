//! `ash audit verify` (spec v0.2 §7.5)

use anyhow::Result;
use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub action: AuditAction,
}

#[derive(Subcommand, Debug)]
pub enum AuditAction {
    /// Check the hash chain
    Verify(super::verify::VerifyArgs),
}

pub async fn execute(args: AuditArgs) -> Result<()> {
    match args.action {
        AuditAction::Verify(v) => super::verify::execute(v).await,
    }
}
