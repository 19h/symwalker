use std::path::{Path, PathBuf};
use std::fs;

/// Intelligent heuristics for finding debug symbols
pub struct SymbolFinder<'a> {
    binary_path: &'a Path,
}

impl<'a> SymbolFinder<'a> {
    pub fn new(binary_path: &'a Path) -> Self {
        Self { binary_path }
    }
    
    /// Find debug file using build-id (ELF)
    /// Standard locations:
    /// - /usr/lib/debug/.build-id/XX/YYYYYYYY.debug
    /// - /usr/lib/debug/.build-id/XX/YYYYYYYY
    pub fn find_by_build_id(&self, build_id: &str) -> Option<PathBuf> {
        if build_id.len() < 3 {
            return None;
        }
        
        let (prefix, suffix) = build_id.split_at(2);
        
        let standard_paths = vec![
            format!("/usr/lib/debug/.build-id/{}/{}.debug", prefix, suffix),
            format!("/usr/lib/debug/.build-id/{}/{}", prefix, suffix),
            format!("/lib/debug/.build-id/{}/{}.debug", prefix, suffix),
            format!("/lib/debug/.build-id/{}/{}", prefix, suffix),
        ];
        
        for path_str in standard_paths {
            let path = PathBuf::from(path_str);
            if path.exists() && path.is_file() {
                return Some(path);
            }
        }
        
        None
    }
    
    /// Find debug file using .gnu_debuglink (ELF)
    /// Looks in:
    /// - Same directory as binary
    /// - Same directory/.debug/
    /// - /usr/lib/debug/<path>
    pub fn find_by_debuglink(&self, debuglink: &str) -> Option<PathBuf> {
        if let Some(parent) = self.binary_path.parent() {
            // Same directory
            let same_dir = parent.join(debuglink);
            if same_dir.exists() && same_dir.is_file() {
                return Some(same_dir);
            }
            
            // .debug subdirectory
            let debug_subdir = parent.join(".debug").join(debuglink);
            if debug_subdir.exists() && debug_subdir.is_file() {
                return Some(debug_subdir);
            }
            
            // /usr/lib/debug/<full-path>
            let full_path = self.binary_path.to_string_lossy();
            if full_path.starts_with('/') {
                let debug_path = format!("/usr/lib/debug{}", full_path);
                let debug_file = PathBuf::from(debug_path).with_file_name(debuglink);
                if debug_file.exists() && debug_file.is_file() {
                    return Some(debug_file);
                }
            }
        }
        
        None
    }
    
    /// Find .debug file adjacent to binary (ELF)
    pub fn find_adjacent_debug(&self) -> Option<PathBuf> {
        if let Some(parent) = self.binary_path.parent() {
            if let Some(filename) = self.binary_path.file_name() {
                let mut debug_name = filename.to_os_string();
                debug_name.push(".debug");
                
                let debug_path = parent.join(debug_name);
                if debug_path.exists() && debug_path.is_file() {
                    return Some(debug_path);
                }
                
                // Try in .debug subdirectory
                let debug_subdir = parent.join(".debug").join(filename);
                if debug_subdir.exists() && debug_subdir.is_file() {
                    return Some(debug_subdir);
                }
            }
        }
        
        None
    }
    
    /// Find dSYM bundle by UUID (Mach-O)
    /// Standard locations:
    /// - <binary>.dSYM
    /// - <binary-dir>/<binary>.dSYM
    /// - ~/Library/Developer/Xcode/DerivedData/*/Build/Products/*/*.dSYM
    pub fn find_dsym_by_uuid(&self, uuid: &str) -> Option<PathBuf> {
        // Try adjacent dSYM first
        if let Some(dsym) = self.find_adjacent_dsym() {
            if self.verify_dsym_uuid(&dsym, uuid) {
                return Some(dsym);
            }
        }
        
        // Search in common Xcode locations
        if let Some(home) = dirs::home_dir() {
            let derived_data = home.join("Library/Developer/Xcode/DerivedData");
            if derived_data.exists() {
                if let Some(dsym) = self.search_derived_data(&derived_data, uuid) {
                    return Some(dsym);
                }
            }
        }
        
        None
    }
    
    /// Find adjacent dSYM bundle (Mach-O)
    pub fn find_adjacent_dsym(&self) -> Option<PathBuf> {
        if let Some(parent) = self.binary_path.parent() {
            if let Some(filename) = self.binary_path.file_name() {
                let mut dsym_name = filename.to_os_string();
                dsym_name.push(".dSYM");
                
                let dsym_path = parent.join(dsym_name);
                if dsym_path.exists() && dsym_path.is_dir() {
                    return Some(dsym_path);
                }
            }
        }
        
        None
    }
    
    fn verify_dsym_uuid(&self, dsym_path: &Path, expected_uuid: &str) -> bool {
        // Look for DWARF file inside dSYM bundle
        // Structure: <name>.dSYM/Contents/Resources/DWARF/<name>
        let contents = dsym_path.join("Contents/Resources/DWARF");
        
        if !contents.exists() {
            return false;
        }
        
        // Read directory and check first file (usually matches binary name)
        if let Ok(entries) = fs::read_dir(contents) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    // Try to extract UUID from this file and compare
                    if let Ok(file) = fs::File::open(&path) {
                        if let Ok(mmap) = unsafe { memmap2::Mmap::map(&file) } {
                            if let Ok(mach) = goblin::mach::Mach::parse(&mmap) {
                                let macho = match mach {
                                    goblin::mach::Mach::Binary(m) => m,
                                    _ => return false,
                                };
                                
                                for lc in &macho.load_commands {
                                    if let goblin::mach::load_command::CommandVariant::Uuid(uuid_cmd) = lc.command {
                                        let uuid = uuid::Uuid::from_bytes(uuid_cmd.uuid).to_string().to_uppercase();
                                        return uuid == expected_uuid;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        false
    }
    
    fn search_derived_data(&self, derived_data: &Path, uuid: &str) -> Option<PathBuf> {
        // This is a simplified search - could be made more sophisticated
        // Walk through DerivedData looking for matching dSYM bundles
        
        use walkdir::WalkDir;
        
        for entry in WalkDir::new(derived_data)
            .max_depth(5)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_dir() && path.extension().and_then(|s| s.to_str()) == Some("dSYM") {
                if self.verify_dsym_uuid(path, uuid) {
                    return Some(path.to_path_buf());
                }
            }
        }
        
        None
    }
}

// Add dirs crate for home_dir
mod dirs {
    use std::path::PathBuf;
    use std::env;
    
    pub fn home_dir() -> Option<PathBuf> {
        env::var_os("HOME").map(PathBuf::from)
    }
}

