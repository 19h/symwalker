# Symbol Discovery Heuristics

This document details the intelligent heuristics used by symwalker to locate debug symbols for ELF and Mach-O binaries.

## ELF Symbol Discovery

### 1. Embedded Debug Information

**Priority:** Highest  
**Detection:** Direct section analysis

Symwalker first checks if debug information is embedded directly in the binary:

```
.debug_info       # DWARF debug information
.debug_abbrev     # DWARF abbreviations
.debug_line       # Source line mappings
.debug_str        # Debug strings
.debug_ranges     # Address ranges
.debug_frame      # Call frame information
.zdebug_*         # Compressed debug sections
```

**Advantages:**
- No external files needed
- Always available with the binary
- Fastest to access

**Disadvantages:**
- Increases binary size significantly
- Typically removed in production builds

### 2. Build-ID Resolution

**Priority:** High  
**Detection:** `.note.gnu.build-id` section or `PT_NOTE` segment

Build-ID is a unique identifier embedded in ELF binaries by GNU linkers:

**Format:** 20-byte SHA1 hash (typically)

**Standard Locations:**
```
/usr/lib/debug/.build-id/XX/YYYYYYYY.debug
/usr/lib/debug/.build-id/XX/YYYYYYYY
/lib/debug/.build-id/XX/YYYYYYYY.debug
```

Where `XXYYYYYYYY` is the hex build-id split at 2 characters.

**Example:**
- Build-ID: `4c3c4698f3e7e1d8b8f9a8c2d5e6f7a8b9c0d1e2`
- Location: `/usr/lib/debug/.build-id/4c/3c4698f3e7e1d8b8f9a8c2d5e6f7a8b9c0d1e2.debug`

**Distribution Support:**
- Ubuntu/Debian: Yes (`debuginfod` package)
- Fedora/RHEL: Yes
- Arch Linux: Yes
- Gentoo: Yes
- Alpine: Partial

### 3. GNU Debuglink

**Priority:** Medium  
**Detection:** `.gnu_debuglink` section

The `.gnu_debuglink` section contains:
- Filename of separate debug file (null-terminated string)
- CRC32 checksum (4 bytes)

**Search Order:**
1. Same directory as binary
   ```
   /usr/bin/program
   /usr/bin/program.debug
   ```

2. `.debug` subdirectory
   ```
   /usr/bin/program
   /usr/bin/.debug/program.debug
   ```

3. Global debug directory with mirrored path
   ```
   /usr/bin/program
   /usr/lib/debug/usr/bin/program.debug
   ```

**Advantages:**
- Works without build-id
- Explicitly specified by binary
- CRC verification available

**Disadvantages:**
- Relative path only
- Manual installation required

### 4. Debuginfod Protocol

**Priority:** Remote fallback  
**Detection:** Requires network connectivity

Debuginfod is a web service providing debug resources indexed by build-id.

**URL Format:**
```
https://SERVER/buildid/BUILDID/debuginfo
https://SERVER/buildid/BUILDID/executable
https://SERVER/buildid/BUILDID/source/PATH
```

**Public Servers:**
- `https://debuginfod.elfutils.org/` - Generic elfutils
- `https://debuginfod.ubuntu.com/` - Ubuntu packages
- `https://debuginfod.fedoraproject.org/` - Fedora packages
- `https://debuginfod.debian.net/` - Debian packages

**Detection Process:**
1. Extract build-id from binary
2. Construct URL for each server
3. Send HTTP HEAD request
4. Check for 200 OK response

**Environment Variable:**
```bash
export DEBUGINFOD_URLS="https://server1/ https://server2/"
```

### 5. Adjacent Debug File

**Priority:** Low  
**Detection:** Filesystem search

Looks for debug file with `.debug` extension in same directory:

```
/path/to/binary
/path/to/binary.debug
/path/to/.debug/binary
```

**Common In:**
- Custom build systems
- Development environments
- Manual debug installations

## Mach-O Symbol Discovery (macOS)

### 1. Embedded DWARF

**Priority:** Highest  
**Detection:** `__DWARF` segment analysis

Check for DWARF debug information embedded in the binary:

```
__DWARF segment containing:
  __debug_info       # Debug information
  __debug_abbrev     # Abbreviations
  __debug_str        # Debug strings
  __debug_line       # Line number information
  __debug_ranges     # Address ranges
  __debug_aranges    # Address ranges
```

**Usage:**
- Debug builds in Xcode
- Development/testing
- Some distributed applications

### 2. dSYM Bundle Location

**Priority:** High  
**Detection:** UUID matching via `LC_UUID` load command

dSYM (Debug Symbol) bundles are directories containing debug information separate from the binary.

**Structure:**
```
MyApp.dSYM/
└── Contents/
    ├── Info.plist          # Bundle information
    └── Resources/
        └── DWARF/
            └── MyApp       # Debug Mach-O file
```

**Search Locations (in order):**

1. **Adjacent to binary**
   ```
   /path/to/MyApp
   /path/to/MyApp.dSYM/
   ```

2. **Xcode build products**
   ```
   ~/Library/Developer/Xcode/DerivedData/*/Build/Products/Debug/
   ~/Library/Developer/Xcode/DerivedData/*/Build/Products/Release/
   ```

3. **Spotlight search** (macOS)
   - Query: `kMDItemFSName == "*.dSYM"`
   - Filter by UUID match

4. **Archive locations**
   ```
   ~/Library/Developer/Xcode/Archives/*/dSYMs/
   ```

### 3. UUID Verification

**Process:**
1. Extract UUID from binary (`LC_UUID` load command)
2. Find candidate dSYM bundles
3. Extract UUID from DWARF file inside bundle
4. Verify UUIDs match

**UUID Format:**
- 16 bytes (128 bits)
- Displayed as: `12345678-90AB-CDEF-1234-567890ABCDEF`
- Unique per compilation

**Importance:**
- Ensures debug symbols match exact binary version
- Prevents using outdated symbols
- Critical for crash report symbolication

### 4. System Symbol Cache

**Location:** `/System/Library/Caches/com.apple.dyld/`

macOS maintains a cache of system shared libraries. Debug information may be available through:
- Separate system symbol packages
- Developer tools installation
- Manual symbol installation

## Symbol Resolution Flow

### ELF Resolution Algorithm

```
1. Check for embedded debug sections
   ├─ Yes → Use embedded debug info
   └─ No → Continue

2. Extract build-id
   ├─ Found → Check /usr/lib/debug/.build-id/
   │   ├─ Found → Return debug file
   │   └─ Not found → Continue to debuginfod
   └─ Not found → Check gnu_debuglink

3. Check debuginfod (if --check-remote)
   ├─ Available → Return remote URL
   └─ Not available → Continue

4. Check gnu_debuglink
   ├─ Found → Search standard locations
   │   ├─ Found → Return debug file
   │   └─ Not found → Continue
   └─ Not found → Continue

5. Check adjacent .debug file
   ├─ Found → Return debug file
   └─ Not found → No symbols found
```

### Mach-O Resolution Algorithm

```
1. Check for embedded __DWARF segment
   ├─ Yes → Use embedded debug info
   └─ No → Continue

2. Extract UUID
   └─ Found → Search for dSYM bundle

3. Check adjacent directory
   ├─ Found dSYM → Verify UUID
   │   ├─ Match → Return dSYM
   │   └─ Mismatch → Continue
   └─ Not found → Continue

4. Search Xcode DerivedData (if --check-dsym)
   ├─ Found candidates → Verify UUIDs
   │   ├─ Match → Return dSYM
   │   └─ No match → Continue
   └─ Not found → No symbols found
```

## Performance Considerations

### Fast Operations
- Embedded debug detection (mmap'd file access)
- Build-ID extraction (direct section read)
- UUID extraction (load command parsing)

### Moderate Operations
- Build-ID resolution (filesystem stat calls)
- Adjacent file search (directory listing)
- GNU debuglink resolution (multiple stat calls)

### Slow Operations
- Debuginfod queries (network latency: 50-200ms per request)
- Xcode DerivedData search (recursive directory traversal)
- UUID verification (requires parsing multiple files)

## Best Practices

### For Developers

1. **Always embed build-ids**
   ```bash
   gcc -Wl,--build-id=sha1 ...
   ```

2. **Strip symbols properly**
   ```bash
   objcopy --only-keep-debug binary binary.debug
   objcopy --strip-debug --strip-unneeded binary
   objcopy --add-gnu-debuglink=binary.debug binary
   ```

3. **Preserve dSYM bundles** (macOS)
   - Archive dSYMs for every release
   - Use same UUID for symbolication

4. **Use debuginfod for distribution**
   - Host your own debuginfod server
   - Upload debug packages to distro repos

### For Users

1. **Install debug packages**
   ```bash
   # Ubuntu/Debian
   apt install package-dbgsym
   
   # Fedora
   dnf debuginfo-install package
   
   # Arch
   pacman -S package-debug
   ```

2. **Configure debuginfod**
   ```bash
   export DEBUGINFOD_URLS="https://debuginfod.elfutils.org/"
   ```

3. **Keep dSYMs organized** (macOS)
   - Don't delete Xcode DerivedData immediately
   - Use Xcode Organizer for archives
   - Store dSYMs with release builds

## Further Reading

- [DWARF Debugging Standard](http://dwarfstd.org/)
- [ELF Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [Debuginfod Protocol](https://sourceware.org/elfutils/Debuginfod.html)
- [Mach-O File Format](https://developer.apple.com/documentation/xcode/mach-o-file-format-reference)
- [GNU Debuglink](https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html)

