//! `ash hook <shell>` - generate shell integration script

use anyhow::Result;
use clap::Args;

const ZSH_HOOK: &str = include_str!("../../../shell-hooks/ash.zsh");
const BASH_HOOK: &str = include_str!("../../../shell-hooks/ash.bash");
const FISH_HOOK: &str = include_str!("../../../shell-hooks/ash.fish");

#[derive(Args, Debug)]
pub struct HookArgs {
    /// Shell type: zsh, bash, fish
    #[arg(value_parser = ["zsh", "bash", "fish"])]
    pub shell: String,
}

pub async fn execute(args: HookArgs) -> Result<()> {
    match args.shell.as_str() {
        "zsh" => print!("{}", ZSH_HOOK),
        "bash" => print!("{}", BASH_HOOK),
        "fish" => print!("{}", FISH_HOOK),
        _ => anyhow::bail!("Unsupported shell: {}", args.shell),
    }
    Ok(())
}
