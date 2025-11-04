use std::path::{Path, PathBuf};
use anyhow::Result;
use chrono::{DateTime, Utc};
use goblin::elf::{Elf, header::*, program_header::*};

use crate::binary::BinaryInfo;
use crate::cli::Args;
use crate::symbol_finder::SymbolFinder;
use crate::debuginfod::DebuginfodClient;

pub struct ElfAnalyzer<'a> {
    path: &'a Path,
    data: &'a [u8],
    elf: Elf<'a>,
    file_size: u64,
    file_modified: DateTime<Utc>,
}

impl<'a> ElfAnalyzer<'a> {
    pub fn new(
        path: &'a Path,
        data: &'a [u8],
        file_size: u64,
        file_modified: DateTime<Utc>,
    ) -> Result<Self> {
        let elf = Elf::parse(data)?;
        Ok(Self {
            path,
            data,
            elf,
            file_size,
            file_modified,
        })
    }
    
    pub fn analyze(&self, args: &Args) -> Result<BinaryInfo> {
        let architecture = self.get_architecture();
        let is_64bit = self.elf.is_64;
        let is_stripped = self.is_stripped();
        let debug_sections = self.find_debug_sections();
        let has_debug_info = !debug_sections.is_empty();
        let build_id = self.extract_build_id();
        let gnu_debuglink = self.extract_gnu_debuglink();
        let (is_pie, is_executable, is_library) = self.get_binary_type();
        let entry_point = if self.elf.entry > 0 {
            Some(format!("0x{:x}", self.elf.entry))
        } else {
            None
        };
        let interpreter = self.get_interpreter();
        
        // Security features
        let (has_nx, has_relro) = self.check_security_features();
        let has_canary = self.check_stack_canary();
        let has_fortify = self.check_fortify();
        
        // Find local debug symbols
        let debug_file_path = self.find_local_debug_file(&build_id, &gnu_debuglink);
        
        // Check remote symbols via debuginfod
        let (debuginfod_available, debuginfod_url) = if args.check_remote {
            self.check_debuginfod(&build_id, args)
        } else {
            (None, None)
        };
        
        Ok(BinaryInfo {
            file_path: self.path.to_path_buf(),
            file_size: self.file_size,
            file_modified: self.file_modified,
            binary_type: "ELF".to_string(),
            architecture,
            is_64bit,
            is_stripped,
            has_debug_info,
            build_id,
            gnu_debuglink,
            debug_sections,
            uuid: None,
            dsym_bundle: None,
            debug_file_path,
            debuginfod_available,
            debuginfod_url,
            entry_point,
            interpreter,
            is_pie,
            is_executable,
            is_library,
            has_nx,
            has_canary,
            has_relro,
            has_fortify,
        })
    }
    
    fn get_architecture(&self) -> String {
        match self.elf.header.e_machine {
            EM_X86_64 => "x86_64".to_string(),
            EM_386 => "i386".to_string(),
            EM_ARM => "ARM".to_string(),
            EM_AARCH64 => "AArch64".to_string(),
            EM_RISCV => "RISC-V".to_string(),
            EM_PPC => "PowerPC".to_string(),
            EM_PPC64 => "PowerPC64".to_string(),
            EM_MIPS => "MIPS".to_string(),
            EM_S390 => "S390".to_string(),
            _ => format!("Unknown (0x{:x})", self.elf.header.e_machine),
        }
    }
    
    fn is_stripped(&self) -> bool {
        // Check if .symtab section exists
        !self.elf.section_headers.iter().any(|sh| {
            if let Some(name) = self.elf.shdr_strtab.get_at(sh.sh_name) {
                name == ".symtab"
            } else {
                false
            }
        })
    }
    
    fn find_debug_sections(&self) -> Vec<String> {
        let mut sections = Vec::new();
        
        for sh in &self.elf.section_headers {
            if let Some(name) = self.elf.shdr_strtab.get_at(sh.sh_name) {
                if name.starts_with(".debug_") || name == ".zdebug_info" {
                    sections.push(name.to_string());
                }
            }
        }
        
        sections.sort();
        sections
    }
    
    fn extract_build_id(&self) -> Option<String> {
        // Look for .note.gnu.build-id section
        for sh in &self.elf.section_headers {
            if let Some(name) = self.elf.shdr_strtab.get_at(sh.sh_name) {
                if name == ".note.gnu.build-id" {
                    let offset = sh.sh_offset as usize;
                    let size = sh.sh_size as usize;
                    
                    if offset + size <= self.data.len() {
                        if let Some(build_id) = self.parse_build_id_note(&self.data[offset..offset + size]) {
                            return Some(build_id);
                        }
                    }
                }
            }
        }
        
        // Also check PT_NOTE segments
        for ph in &self.elf.program_headers {
            if ph.p_type == PT_NOTE {
                let offset = ph.p_offset as usize;
                let size = ph.p_filesz as usize;
                
                if offset + size <= self.data.len() {
                    if let Some(build_id) = self.parse_build_id_note(&self.data[offset..offset + size]) {
                        return Some(build_id);
                    }
                }
            }
        }
        
        None
    }
    
    fn parse_build_id_note(&self, data: &[u8]) -> Option<String> {
        if data.len() < 12 {
            return None;
        }
        
        let mut offset = 0;
        while offset + 12 <= data.len() {
            let namesz = u32::from_ne_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]) as usize;
            let descsz = u32::from_ne_bytes([data[offset+4], data[offset+5], data[offset+6], data[offset+7]]) as usize;
            let note_type = u32::from_ne_bytes([data[offset+8], data[offset+9], data[offset+10], data[offset+11]]);
            
            offset += 12;
            
            // Align to 4 bytes
            let namesz_aligned = (namesz + 3) & !3;
            let descsz_aligned = (descsz + 3) & !3;
            
            if offset + namesz_aligned + descsz_aligned > data.len() {
                break;
            }
            
            // NT_GNU_BUILD_ID = 3
            if note_type == 3 && namesz >= 4 && &data[offset..offset+4] == b"GNU\0" {
                let build_id_offset = offset + namesz_aligned;
                if build_id_offset + descsz <= data.len() {
                    let build_id_bytes = &data[build_id_offset..build_id_offset + descsz];
                    return Some(hex::encode(build_id_bytes));
                }
            }
            
            offset += namesz_aligned + descsz_aligned;
        }
        
        None
    }
    
    fn extract_gnu_debuglink(&self) -> Option<String> {
        for sh in &self.elf.section_headers {
            if let Some(name) = self.elf.shdr_strtab.get_at(sh.sh_name) {
                if name == ".gnu_debuglink" {
                    let offset = sh.sh_offset as usize;
                    let size = sh.sh_size as usize;
                    
                    if offset + size <= self.data.len() {
                        let data = &self.data[offset..offset + size];
                        // Find null terminator
                        if let Some(null_pos) = data.iter().position(|&b| b == 0) {
                            if let Ok(filename) = std::str::from_utf8(&data[..null_pos]) {
                                return Some(filename.to_string());
                            }
                        }
                    }
                }
            }
        }
        None
    }
    
    fn get_binary_type(&self) -> (bool, bool, bool) {
        let is_executable = self.elf.header.e_type == ET_EXEC || self.elf.header.e_type == ET_DYN;
        let is_library = self.elf.header.e_type == ET_DYN;
        
        // Check if PIE by looking for PT_INTERP (which indicates executable)
        // and ET_DYN type together
        let has_interp = self.elf.program_headers.iter()
            .any(|ph| ph.p_type == PT_INTERP);
        let is_pie = self.elf.header.e_type == ET_DYN && has_interp;
        
        (is_pie, is_executable, is_library)
    }
    
    fn get_interpreter(&self) -> Option<String> {
        for ph in &self.elf.program_headers {
            if ph.p_type == PT_INTERP {
                let offset = ph.p_offset as usize;
                let size = ph.p_filesz as usize;
                
                if offset + size <= self.data.len() {
                    let data = &self.data[offset..offset + size];
                    if let Some(null_pos) = data.iter().position(|&b| b == 0) {
                        if let Ok(interp) = std::str::from_utf8(&data[..null_pos]) {
                            return Some(interp.to_string());
                        }
                    }
                }
            }
        }
        None
    }
    
    fn check_security_features(&self) -> (bool, bool) {
        let mut has_nx = false;
        let mut has_relro = false;
        
        // Check for GNU_STACK (NX)
        for ph in &self.elf.program_headers {
            if ph.p_type == PT_GNU_STACK {
                has_nx = (ph.p_flags & PF_X) == 0;
            }
            if ph.p_type == PT_GNU_RELRO {
                has_relro = true;
            }
        }
        
        (has_nx, has_relro)
    }
    
    fn check_stack_canary(&self) -> bool {
        // Look for __stack_chk_fail symbol
        for sym in &self.elf.dynsyms {
            if let Some(name) = self.elf.dynstrtab.get_at(sym.st_name) {
                if name.contains("stack_chk_fail") || name.contains("stack_chk_guard") {
                    return true;
                }
            }
        }
        false
    }
    
    fn check_fortify(&self) -> bool {
        // Look for fortified functions like __memcpy_chk
        for sym in &self.elf.dynsyms {
            if let Some(name) = self.elf.dynstrtab.get_at(sym.st_name) {
                if name.ends_with("_chk") {
                    return true;
                }
            }
        }
        false
    }
    
    fn find_local_debug_file(&self, build_id: &Option<String>, gnu_debuglink: &Option<String>) -> Option<PathBuf> {
        let finder = SymbolFinder::new(self.path);
        
        // Try multiple strategies
        if let Some(ref bid) = build_id {
            if let Some(path) = finder.find_by_build_id(bid) {
                return Some(path);
            }
        }
        
        if let Some(ref link) = gnu_debuglink {
            if let Some(path) = finder.find_by_debuglink(link) {
                return Some(path);
            }
        }
        
        // Look for .debug file next to binary
        finder.find_adjacent_debug()
    }
    
    fn check_debuginfod(&self, build_id: &Option<String>, args: &Args) -> (Option<bool>, Option<String>) {
        if let Some(ref bid) = build_id {
            let client = DebuginfodClient::new(args.debuginfod_urls.clone());
            
            if let Ok((available, url)) = client.check_available(bid) {
                return (Some(available), url);
            }
        }
        (Some(false), None)
    }
}

