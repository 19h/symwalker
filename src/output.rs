use anyhow::Result;
use colored::*;
use crate::binary::BinaryInfo;

pub trait OutputFormatter {
    fn format(&self, binaries: &[BinaryInfo]) -> Result<()>;
}

pub struct HumanFormatter {
    verbose: bool,
}

impl HumanFormatter {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }
    
    fn format_size(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;
        
        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} B", bytes)
        }
    }
}

impl OutputFormatter for HumanFormatter {
    fn format(&self, binaries: &[BinaryInfo]) -> Result<()> {
        if binaries.is_empty() {
            println!("{}", "No binaries found.".yellow());
            return Ok(());
        }
        
        println!("Found {} binar{}", 
            binaries.len().to_string().bright_white().bold(),
            if binaries.len() == 1 { "y" } else { "ies" }
        );
        println!();
        
        for (idx, binary) in binaries.iter().enumerate() {
            self.format_binary(idx + 1, binary)?;
        }
        
        Ok(())
    }
}

impl HumanFormatter {
    fn format_binary(&self, index: usize, binary: &BinaryInfo) -> Result<()> {
        // Header
        let type_label = if binary.is_executable {
            "EXE"
        } else if binary.is_library {
            "LIB"
        } else {
            "BIN"
        };
        
        println!("{} Binary #{} ({})", 
            "●".bright_cyan(),
            index.to_string().bright_white(),
            type_label.bright_yellow()
        );
        
        // Basic info
        println!("   {}: {}", 
            "Path".bright_black(),
            binary.file_path.display().to_string().white()
        );
        println!("   {}: {}", 
            "Size".bright_black(),
            Self::format_size(binary.file_size).white()
        );
        println!("   {}: {} {}", 
            "Architecture".bright_black(),
            binary.architecture.white(),
            if binary.is_64bit { "(64-bit)" } else { "(32-bit)" }.bright_black()
        );
        println!("   {}: {}", 
            "Type".bright_black(),
            binary.binary_type.white()
        );
        println!("   {}: {}", 
            "Modified".bright_black(),
            binary.file_modified.format("%Y-%m-%d %H:%M:%S UTC").to_string().white()
        );
        
        // Verbose mode
        if self.verbose {
            if let Some(ref entry) = binary.entry_point {
                println!("   {}: {}", "Entry Point".bright_black(), entry.white());
            }
            
            if let Some(ref interp) = binary.interpreter {
                println!("   {}: {}", "Interpreter".bright_black(), interp.white());
            }
            
            // Security features
            println!();
            println!("   {}", "Security Features:".bright_cyan());
            println!("      PIE: {}", if binary.is_pie { "✓".green() } else { "✗".red() });
            println!("      NX: {}", if binary.has_nx { "✓".green() } else { "✗".red() });
            println!("      Canary: {}", if binary.has_canary { "✓".green() } else { "✗".red() });
            
            if binary.binary_type == "ELF" {
                println!("      RELRO: {}", if binary.has_relro { "✓".green() } else { "✗".red() });
                println!("      Fortify: {}", if binary.has_fortify { "✓".green() } else { "✗".red() });
            }
        }
        
        println!();
        
        // Debug info status
        if binary.is_stripped {
            println!("   {}: {}", 
                "Symbols".bright_black(),
                "Stripped".red()
            );
        } else {
            println!("   {}: {}", 
                "Symbols".bright_black(),
                "Present".green()
            );
        }
        
        if binary.has_debug_info {
            println!("   {}: {} {}", 
                "Debug Info".bright_black(),
                "✓".green(),
                "Embedded".bright_black()
            );
        }
        
        // ELF-specific
        if binary.binary_type == "ELF" {
            if let Some(ref build_id) = binary.build_id {
                println!("   {}: {}", 
                    "Build ID".bright_black(),
                    build_id.bright_white()
                );
            }
            
            if let Some(ref debuglink) = binary.gnu_debuglink {
                println!("   {}: {}", 
                    "GNU Debuglink".bright_black(),
                    debuglink.white()
                );
            }
            
            if !binary.debug_sections.is_empty() && self.verbose {
                println!("   {}: {}", 
                    "Debug Sections".bright_black(),
                    binary.debug_sections.join(", ").white()
                );
            }
        }
        
        // Mach-O specific
        if binary.binary_type == "Mach-O" {
            if let Some(ref uuid) = binary.uuid {
                println!("   {}: {}", 
                    "UUID".bright_black(),
                    uuid.bright_white()
                );
            }
            
            if let Some(ref dsym) = binary.dsym_bundle {
                println!();
                println!("   {}: {} {}", 
                    "dSYM Bundle".bright_black(),
                    "✓".green(),
                    "Found".bright_black()
                );
                println!("      {}: {}", 
                    "Path".bright_black(),
                    dsym.display().to_string().white()
                );
            } else {
                println!();
                println!("   {}: {} {}", 
                    "dSYM Bundle".bright_black(),
                    "✗".red(),
                    "Not found".bright_black()
                );
            }
        }
        
        // Local debug file
        if let Some(ref debug_path) = binary.debug_file_path {
            if binary.binary_type == "ELF" {
                println!();
                println!("   {}: {} {}", 
                    "Local Debug".bright_black(),
                    "✓".green(),
                    "Found".bright_black()
                );
                println!("      {}: {}", 
                    "Path".bright_black(),
                    debug_path.display().to_string().white()
                );
            }
        } else if binary.binary_type == "ELF" && !binary.has_debug_info {
            println!();
            println!("   {}: {} {}", 
                "Local Debug".bright_black(),
                "✗".red(),
                "Not found".bright_black()
            );
        }
        
        // Remote availability (debuginfod)
        if let Some(available) = binary.debuginfod_available {
            println!();
            if available {
                println!("   {}: {} {}", 
                    "Remote Debug".bright_black(),
                    "✓".green(),
                    "Available".bright_black()
                );
                if let Some(ref url) = binary.debuginfod_url {
                    if self.verbose {
                        println!("      {}: {}", 
                            "URL".bright_black(),
                            url.white()
                        );
                    }
                }
            } else {
                println!("   {}: {} {}", 
                    "Remote Debug".bright_black(),
                    "✗".red(),
                    "Not available".bright_black()
                );
            }
        }
        
        println!();
        println!("{}", "─".repeat(60).bright_black());
        
        Ok(())
    }
}

pub struct JsonFormatter;

impl OutputFormatter for JsonFormatter {
    fn format(&self, binaries: &[BinaryInfo]) -> Result<()> {
        let json = serde_json::to_string_pretty(&binaries)?;
        println!("{}", json);
        Ok(())
    }
}

