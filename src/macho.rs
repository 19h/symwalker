use std::path::{Path, PathBuf};
use anyhow::Result;
use chrono::{DateTime, Utc};
use goblin::mach::{Mach, MachO};
use goblin::mach::constants::cputype::*;
use goblin::mach::load_command::CommandVariant;

use crate::binary::BinaryInfo;
use crate::cli::Args;
use crate::symbol_finder::SymbolFinder;

pub struct MachoAnalyzer<'a> {
    path: &'a Path,
    data: &'a [u8],
    file_size: u64,
    file_modified: DateTime<Utc>,
}

impl<'a> MachoAnalyzer<'a> {
    pub fn new(
        path: &'a Path,
        data: &'a [u8],
        file_size: u64,
        file_modified: DateTime<Utc>,
    ) -> Result<Self> {
        Ok(Self {
            path,
            data,
            file_size,
            file_modified,
        })
    }
    
    pub fn analyze(&self, args: &Args) -> Result<BinaryInfo> {
        let mach = Mach::parse(self.data)?;
        
        // Handle universal/fat binaries - analyze first architecture
        let macho = match mach {
            Mach::Binary(m) => m,
            Mach::Fat(fat) => {
                // Get first architecture
                if let Some(arch) = fat.iter_arches().next() {
                    let arch = arch?;
                    let offset = arch.offset as usize;
                    let size = arch.size as usize;
                    if offset + size <= self.data.len() {
                        MachO::parse(&self.data[offset..offset + size], 0)?
                    } else {
                        anyhow::bail!("Invalid fat binary");
                    }
                } else {
                    anyhow::bail!("Empty fat binary");
                }
            }
        };
        
        let architecture = self.get_architecture(&macho);
        let is_64bit = macho.is_64;
        let uuid = self.extract_uuid(&macho);
        let is_stripped = self.is_stripped(&macho);
        let has_debug_info = self.has_debug_info(&macho);
        let (_, is_executable, is_library) = self.get_binary_type(&macho);
        let entry_point = self.get_entry_point(&macho);
        
        // Security features
        let (has_nx, has_canary, has_pie) = self.check_security_features(&macho);
        
        // Find dSYM bundle
        let dsym_bundle = if args.check_dsym {
            self.find_dsym_bundle(&uuid)
        } else {
            None
        };
        
        let debug_file_path = dsym_bundle.clone();
        
        Ok(BinaryInfo {
            file_path: self.path.to_path_buf(),
            file_size: self.file_size,
            file_modified: self.file_modified,
            binary_type: "Mach-O".to_string(),
            architecture,
            is_64bit,
            is_stripped,
            has_debug_info,
            build_id: None,
            gnu_debuglink: None,
            debug_sections: Vec::new(),
            uuid,
            dsym_bundle,
            debug_file_path,
            debuginfod_available: None,
            debuginfod_url: None,
            entry_point,
            interpreter: None,
            is_pie: has_pie,
            is_executable,
            is_library,
            has_nx,
            has_canary,
            has_relro: false,  // Not applicable to Mach-O
            has_fortify: false,  // Check this separately
        })
    }
    
    fn get_architecture(&self, macho: &MachO) -> String {
        match macho.header.cputype() {
            CPU_TYPE_X86_64 => "x86_64".to_string(),
            CPU_TYPE_X86 => "i386".to_string(),
            CPU_TYPE_ARM => "ARM".to_string(),
            CPU_TYPE_ARM64 => "ARM64".to_string(),
            CPU_TYPE_ARM64_32 => "ARM64_32".to_string(),
            CPU_TYPE_POWERPC => "PowerPC".to_string(),
            CPU_TYPE_POWERPC64 => "PowerPC64".to_string(),
            _ => format!("Unknown (0x{:x})", macho.header.cputype()),
        }
    }
    
    fn extract_uuid(&self, macho: &MachO) -> Option<String> {
        for lc in &macho.load_commands {
            if let CommandVariant::Uuid(uuid_cmd) = lc.command {
                return Some(uuid::Uuid::from_bytes(uuid_cmd.uuid).to_string().to_uppercase());
            }
        }
        None
    }
    
    fn is_stripped(&self, macho: &MachO) -> bool {
        // Check if symbol table is empty or stripped
        for lc in &macho.load_commands {
            if let CommandVariant::Symtab(symtab) = lc.command {
                return symtab.nsyms == 0;
            }
        }
        true
    }
    
    fn has_debug_info(&self, macho: &MachO) -> bool {
        // Check for __DWARF segment or debug sections
        for segment in &macho.segments {
            if let Ok(name) = segment.name() {
                if name == "__DWARF" {
                    return true;
                }
            }
            
            // Check sections within segments
            if let Ok(sections) = segment.sections() {
                for (section, _) in sections {
                    if let (Ok(segname), Ok(sectname)) = (section.segname(), section.name()) {
                        if segname == "__DWARF" || sectname.starts_with("__debug") {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
    
    fn get_binary_type(&self, macho: &MachO) -> (bool, bool, bool) {
        use goblin::mach::header::*;
        
        let is_executable = macho.header.filetype == MH_EXECUTE;
        let is_library = macho.header.filetype == MH_DYLIB;
        let is_pie = (macho.header.flags & MH_PIE) != 0;
        
        (is_pie, is_executable, is_library)
    }
    
    fn get_entry_point(&self, macho: &MachO) -> Option<String> {
        for lc in &macho.load_commands {
            match lc.command {
                CommandVariant::Main(main_cmd) => {
                    return Some(format!("0x{:x}", main_cmd.entryoff));
                }
                CommandVariant::Unixthread(thread) => {
                    // For older binaries, entry point is in thread state
                    // This is architecture-specific
                    return Some(format!("0x{:x}", thread.flavor));
                }
                _ => {}
            }
        }
        None
    }
    
    fn check_security_features(&self, macho: &MachO) -> (bool, bool, bool) {
        use goblin::mach::header::*;
        
        let has_nx = (macho.header.flags & MH_NO_HEAP_EXECUTION) != 0;
        let has_pie = (macho.header.flags & MH_PIE) != 0;
        
        // Check for stack canary by looking for symbols
        let mut has_canary = false;
        for symbol in macho.symbols() {
            if let Ok((name, _)) = symbol {
                if name.contains("stack_chk") {
                    has_canary = true;
                    break;
                }
            }
        }
        
        (has_nx, has_canary, has_pie)
    }
    
    fn find_dsym_bundle(&self, uuid: &Option<String>) -> Option<PathBuf> {
        let finder = SymbolFinder::new(self.path);
        
        // Try multiple strategies
        if let Some(ref uuid_str) = uuid {
            // Look for dSYM bundle in standard locations
            if let Some(path) = finder.find_dsym_by_uuid(uuid_str) {
                return Some(path);
            }
        }
        
        // Look for adjacent dSYM bundle
        finder.find_adjacent_dsym()
    }
}

