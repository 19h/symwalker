use std::path::{Path, PathBuf};
use std::fs;
use anyhow::Result;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

use crate::cli::Args;
use crate::elf::ElfAnalyzer;
use crate::macho::MachoAnalyzer;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub file_path: PathBuf,
    pub file_size: u64,
    pub file_modified: DateTime<Utc>,
    pub binary_type: String,  // "ELF" or "Mach-O"
    pub architecture: String,
    pub is_64bit: bool,
    pub is_stripped: bool,
    pub has_debug_info: bool,
    
    // ELF specific
    pub build_id: Option<String>,
    pub gnu_debuglink: Option<String>,
    pub debug_sections: Vec<String>,
    
    // Mach-O specific
    pub uuid: Option<String>,
    pub dsym_bundle: Option<PathBuf>,
    
    // Common debug info
    pub debug_file_path: Option<PathBuf>,
    pub debuginfod_available: Option<bool>,
    pub debuginfod_url: Option<String>,
    
    // Binary details
    pub entry_point: Option<String>,
    pub interpreter: Option<String>,
    pub is_pie: bool,
    pub is_executable: bool,
    pub is_library: bool,
    
    // Security features
    pub has_nx: bool,
    pub has_canary: bool,
    pub has_relro: bool,
    pub has_fortify: bool,
}

impl BinaryInfo {
    pub fn has_local_debug_symbols(&self) -> bool {
        self.debug_file_path.is_some() || self.has_debug_info
    }
    
    pub fn has_remote_debug_symbols(&self) -> bool {
        self.debuginfod_available.unwrap_or(false)
    }
}

pub fn scan_binary(path: &Path, args: &Args) -> Result<BinaryInfo> {
    // Read file metadata
    let metadata = fs::metadata(path)?;
    let file_size = metadata.len();
    let file_modified: DateTime<Utc> = metadata.modified()?.into();
    
    // Memory map the file for efficient parsing
    let file = fs::File::open(path)?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    
    // Determine binary type and parse
    let binary_type = detect_binary_type(&mmap)?;
    
    match binary_type.as_str() {
        "ELF" => {
            let analyzer = ElfAnalyzer::new(path, &mmap, file_size, file_modified)?;
            analyzer.analyze(args)
        }
        "Mach-O" => {
            let analyzer = MachoAnalyzer::new(path, &mmap, file_size, file_modified)?;
            analyzer.analyze(args)
        }
        _ => anyhow::bail!("Unsupported binary type"),
    }
}

fn detect_binary_type(data: &[u8]) -> Result<String> {
    if data.len() < 4 {
        anyhow::bail!("File too small");
    }
    
    // Check for ELF magic
    if &data[0..4] == b"\x7fELF" {
        return Ok("ELF".to_string());
    }
    
    // Check for Mach-O magic numbers
    let magic = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    match magic {
        0xfeedface | 0xcefaedfe | // 32-bit Mach-O
        0xfeedfacf | 0xcffaedfe | // 64-bit Mach-O
        0xcafebabe | 0xbebafeca   // Universal/Fat binary
        => return Ok("Mach-O".to_string()),
        _ => {}
    }
    
    anyhow::bail!("Unknown binary format")
}

