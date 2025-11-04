use clap::Parser;
use std::path::PathBuf;
use anyhow::Result;
use walkdir::WalkDir;
use colored::*;
use std::fs;
use std::time::Instant;

use crate::binary::{BinaryInfo, scan_binary};
use crate::output::{OutputFormatter, HumanFormatter, JsonFormatter};

#[derive(Parser, Debug)]
#[command(
    name = "symwalker",
    version,
    about = "Advanced ELF/Mach-O binary scanner with intelligent debug symbol detection",
    long_about = "Recursively scans directories for ELF and Mach-O binaries, analyzing debug symbols,\n\
                  build IDs, dSYM bundles, and providing intelligent heuristics for symbol discovery."
)]
pub struct Args {
    /// Directory to scan for binaries
    #[arg(value_name = "DIRECTORY")]
    pub directory: PathBuf,

    /// Show detailed information about each binary
    #[arg(short, long)]
    pub verbose: bool,

    /// Only show binaries with local debug symbols
    #[arg(long)]
    pub local_only: bool,

    /// Only show binaries with remote symbols available (via debuginfod)
    #[arg(long)]
    pub remote_only: bool,

    /// Check if remote symbols exist via debuginfod
    #[arg(long)]
    pub check_remote: bool,

    /// Output directory for copying binaries and debug symbols
    #[arg(short, long, value_name = "DIR")]
    pub output: Option<PathBuf>,

    /// Copy binaries in addition to debug symbols (requires --output)
    #[arg(long, requires = "output")]
    pub copy_binaries: bool,

    /// Download remote debug symbols (requires --output and --check-remote)
    #[arg(long, requires = "output")]
    pub download_remote: bool,

    /// Overwrite existing files in output directory
    #[arg(short, long)]
    pub force: bool,

    /// Output results as JSON
    #[arg(long)]
    pub json: bool,

    /// Maximum recursion depth
    #[arg(long, value_name = "N")]
    pub max_depth: Option<usize>,

    /// Follow symbolic links
    #[arg(long)]
    pub follow_symlinks: bool,

    /// Show stripped binaries (binaries without debug info)
    #[arg(long)]
    pub show_stripped: bool,

    /// Custom debuginfod server URLs (comma-separated)
    #[arg(long, value_name = "URLS", value_delimiter = ',')]
    pub debuginfod_urls: Vec<String>,

    /// Check for dSYM bundles in standard macOS locations
    #[arg(long)]
    pub check_dsym: bool,

    /// Analyze binary security features (NX, PIE, RELRO, etc.)
    #[arg(long)]
    pub security: bool,
}

pub fn run(args: Args) -> Result<()> {
    let start = Instant::now();
    
    if !args.directory.exists() {
        anyhow::bail!("Directory does not exist: {}", args.directory.display());
    }

    if !args.directory.is_dir() {
        anyhow::bail!("Path is not a directory: {}", args.directory.display());
    }

    // Create output directory if specified
    if let Some(ref output) = args.output {
        fs::create_dir_all(output)?;
    }

    // Print header for human output
    if !args.json {
        println!("{}", "Symbol Walker - ELF/Mach-O Binary Scanner".bright_cyan().bold());
        println!("{}", "=".repeat(50).bright_black());
        println!("Scanning directory: {}", args.directory.display().to_string().bright_white());
        println!();
    }

    // Collect all binaries
    let mut binaries = Vec::new();
    let mut walker = WalkDir::new(&args.directory);
    
    if let Some(depth) = args.max_depth {
        walker = walker.max_depth(depth);
    }
    
    if !args.follow_symlinks {
        walker = walker.follow_links(false);
    }

    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        
        // Skip directories
        if !path.is_file() {
            continue;
        }

        // Try to scan the binary
        if let Ok(info) = scan_binary(path, &args) {
            // Apply filters
            if args.local_only && !info.has_local_debug_symbols() {
                continue;
            }
            
            if args.remote_only && !info.has_remote_debug_symbols() {
                continue;
            }
            
            // Skip stripped binaries unless explicitly requested
            if !args.show_stripped && info.is_stripped && !info.has_local_debug_symbols() {
                continue;
            }
            
            binaries.push(info);
        }
    }

    let elapsed = start.elapsed();

    // Output results
    if args.json {
        let formatter = JsonFormatter;
        formatter.format(&binaries)?;
    } else {
        let formatter = HumanFormatter::new(args.verbose);
        formatter.format(&binaries)?;
        
        // Print summary
        print_summary(&binaries, elapsed);
    }

    // Handle output operations
    if args.output.is_some() {
        handle_output(&args, &binaries)?;
    }

    Ok(())
}

fn print_summary(binaries: &[BinaryInfo], elapsed: std::time::Duration) {
    println!();
    println!("{}", "─".repeat(60).bright_black());
    println!("{}", "Summary".bright_cyan().bold());
    println!();
    
    let total = binaries.len();
    let with_debug = binaries.iter().filter(|b| b.has_debug_info).count();
    let with_local = binaries.iter().filter(|b| b.has_local_debug_symbols()).count();
    let with_remote = binaries.iter().filter(|b| b.has_remote_debug_symbols()).count();
    let stripped = binaries.iter().filter(|b| b.is_stripped).count();
    let elf_count = binaries.iter().filter(|b| b.binary_type == "ELF").count();
    let macho_count = binaries.iter().filter(|b| b.binary_type == "Mach-O").count();
    
    println!("   Total binaries: {}", total.to_string().bright_white());
    println!("   ELF binaries: {}", elf_count.to_string().bright_white());
    println!("   Mach-O binaries: {}", macho_count.to_string().bright_white());
    println!("   With embedded debug: {}", with_debug.to_string().bright_green());
    println!("   With local symbols: {}", with_local.to_string().bright_green());
    println!("   Stripped: {}", stripped.to_string().bright_red());
    
    if with_remote > 0 {
        println!("   Remote available: {}", with_remote.to_string().bright_blue());
    }
    
    println!();
    println!("   Scan time: {:.2}s", elapsed.as_secs_f64());
}

fn handle_output(args: &Args, binaries: &[BinaryInfo]) -> Result<()> {
    let output_dir = args.output.as_ref().unwrap();
    let mut manifest = Vec::new();

    for binary in binaries {
        let mut entry = serde_json::json!({
            "binary": binary.file_path.display().to_string(),
            "binary_copied": null,
            "symbols_copied": null,
            "symbols_downloaded": null,
        });

        // Copy binary if requested
        if args.copy_binaries {
            let filename = binary.file_path.file_name().unwrap();
            let dest = output_dir.join(filename);
            
            if !dest.exists() || args.force {
                fs::copy(&binary.file_path, &dest)?;
                entry["binary_copied"] = serde_json::json!(dest.display().to_string());
            }
        }

        // Copy local debug symbols
        if let Some(ref debug_path) = binary.debug_file_path {
            let filename = debug_path.file_name().unwrap();
            let dest = output_dir.join(filename);
            
            if !dest.exists() || args.force {
                if debug_path.is_file() {
                    fs::copy(debug_path, &dest)?;
                    entry["symbols_copied"] = serde_json::json!(dest.display().to_string());
                } else if debug_path.is_dir() {
                    // Handle dSYM bundles
                    copy_dir_recursive(debug_path, &dest)?;
                    entry["symbols_copied"] = serde_json::json!(dest.display().to_string());
                }
            }
        }

        manifest.push(entry);
    }

    // Write manifest
    let manifest_path = output_dir.join("manifest.json");
    let manifest_json = serde_json::json!({
        "files": manifest,
        "count": binaries.len(),
    });
    
    fs::write(manifest_path, serde_json::to_string_pretty(&manifest_json)?)?;

    Ok(())
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let dest = dst.join(entry.file_name());
        
        if path.is_dir() {
            copy_dir_recursive(&path, &dest)?;
        } else {
            fs::copy(&path, &dest)?;
        }
    }
    
    Ok(())
}

