mod binary;
mod cli;
mod elf;
mod macho;
mod output;
mod symbol_finder;
mod debuginfod;

use anyhow::Result;
use cli::Args;
use clap::Parser;

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Disable colors if not a TTY or JSON output
    if !atty::is(atty::Stream::Stdout) || args.json {
        colored::control::set_override(false);
    }
    
    // Run the scanner
    cli::run(args)?;
    
    Ok(())
}

