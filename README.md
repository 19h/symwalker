<h1 align="center">symwalker</h1>

<h5 align="center">Advanced ELF/Mach-O binary scanner with intelligent debug symbol detection and analysis</h5>

<div align="center">
  <a href="https://crates.io/crates/symwalker">
    crates.io
  </a>
  —
  <a href="https://github.com/19h/symwalker">
    Github
  </a>
</div>

<br />

`symwalker` is a powerful command-line utility that recursively scans directories for ELF (Linux) and Mach-O (macOS) binaries, providing comprehensive analysis of debug symbols, security features, and binary characteristics. It employs intelligent heuristics to locate debug symbols in standard locations, checks debuginfod servers for remote availability, and analyzes dSYM bundles for macOS binaries.

## Features

### Core Capabilities
*   **🎨 Beautiful CLI Output:** Color-coded status indicators with organized, structured information display
*   **🔍 Multi-Format Support:** Handles both ELF (Linux) and Mach-O (macOS) binary formats
*   **🏗️ Intelligent Symbol Discovery:** Advanced heuristics for finding debug symbols in standard locations
*   **📊 Comprehensive Binary Analysis:** Architecture, file size, timestamps, entry points, interpreters, and more
*   **🔐 Security Analysis:** Detects PIE, NX, RELRO, stack canaries, FORTIFY_SOURCE, and other security features
*   **🌐 Remote Symbol Checking:** Query debuginfod servers for ELF debug symbols
*   **🍎 dSYM Support:** Locate and verify Mach-O dSYM bundles with UUID matching
*   **📦 Symbol Extraction:** Copy binaries and debug symbols to output directory
*   **📄 Multiple Output Formats:** Human-readable colorful output or JSON for scripting
*   **⚡ High Performance:** Efficient binary parsing with memory-mapped files

### Symbol Discovery Heuristics

#### ELF Binaries
*   **Build-ID Based:** `/usr/lib/debug/.build-id/XX/YYYYYYYY.debug`
*   **GNU Debuglink:** Adjacent `.debug` files and standard debug directories
*   **Embedded Sections:** Detects `.debug_*` sections within binaries
*   **Debuginfod Protocol:** Queries multiple public symbol servers
*   **Strip Detection:** Identifies binaries with removed symbol tables

#### Mach-O Binaries
*   **UUID Matching:** Extracts and matches LC_UUID load commands
*   **dSYM Bundles:** Locates `.dSYM` bundles in adjacent and standard locations
*   **Xcode Integration:** Searches `~/Library/Developer/Xcode/DerivedData`
*   **DWARF Sections:** Detects embedded `__DWARF` segments
*   **Symbol Table Analysis:** Checks for stripped symbol tables

## Installation

```shell
cargo install symwalker
```

Or build from source:

```shell
git clone https://github.com/19h/symwalker
cd symwalker
cargo build --release
```

## Usage

### Basic Usage

```shell
# Scan a directory (shows all binaries with debug info)
symwalker /usr/bin

# Verbose output with detailed information
symwalker -v /usr/local/bin

# Check remote symbol availability via debuginfod
symwalker --check-remote /usr/bin

# Only show binaries with local debug symbols
symwalker --local-only ~/my-project/target/debug

# Only show binaries with remote symbols available
symwalker --remote-only --check-remote /usr/bin

# Show all binaries including stripped ones
symwalker --show-stripped /usr/bin
```

### macOS-Specific Usage

```shell
# Check for dSYM bundles in standard locations
symwalker --check-dsym /Applications/MyApp.app/Contents/MacOS

# Verbose security analysis
symwalker -v --security /usr/local/bin

# Scan Xcode build products
symwalker --check-dsym ~/Library/Developer/Xcode/DerivedData/*/Build/Products
```

### Advanced Usage

```shell
# Copy binaries and debug symbols to output directory
symwalker --copy-binaries -o ./analysis /usr/bin

# Download remote debug symbols via debuginfod
symwalker --check-remote --download-remote -o ./symbols /usr/bin

# JSON output for scripting
symwalker --json /usr/bin > binaries.json

# Custom debuginfod servers
symwalker --check-remote --debuginfod-urls https://my-server.com/debuginfod /usr/bin

# Limit recursion depth
symwalker --max-depth 2 /usr

# Follow symbolic links
symwalker --follow-symlinks /usr/bin
```

## Example Output

### Standard Output (ELF)

```
Symbol Walker - ELF/Mach-O Binary Scanner
==================================================
Scanning directory: /usr/bin

Found 3 binaries

● Binary #1 (EXE)
   Path: /usr/bin/bash
   Size: 1.18 MB
   Architecture: x86_64 (64-bit)
   Type: ELF
   Modified: 2024-03-15 14:32:10 UTC

   Symbols: Present
   Debug Info: ✓ Embedded
   Build ID: 4c3c4698f3e7e1d8b8f9a8c2d5e6f7a8b9c0d1e2
   GNU Debuglink: bash.debug

   Local Debug: ✓ Found
      Path: /usr/lib/debug/usr/bin/bash.debug

   Remote Debug: ✓ Available

────────────────────────────────────────────────────────────

● Binary #2 (LIB)
   Path: /usr/bin/libssl.so.3
   Size: 623.45 KB
   Architecture: x86_64 (64-bit)
   Type: ELF
   Modified: 2024-03-10 09:15:22 UTC

   Symbols: Stripped
   Build ID: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b

   Local Debug: ✗ Not found

   Remote Debug: ✓ Available

────────────────────────────────────────────────────────────
```

### Verbose Mode with Security Analysis

```shell
symwalker -v --security /usr/bin/sudo
```

```
● Binary #1 (EXE)
   Path: /usr/bin/sudo
   Size: 234.56 KB
   Architecture: x86_64 (64-bit)
   Type: ELF
   Modified: 2024-02-28 11:45:33 UTC
   Entry Point: 0x4520
   Interpreter: /lib64/ld-linux-x86-64.so.2

   Security Features:
      PIE: ✓
      NX: ✓
      Canary: ✓
      RELRO: ✓
      Fortify: ✓

   Symbols: Present
   Build ID: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
   Debug Sections: .debug_info, .debug_abbrev, .debug_line, .debug_str
```

### macOS Output (Mach-O)

```
● Binary #1 (EXE)
   Path: /Applications/Calculator.app/Contents/MacOS/Calculator
   Size: 456.78 KB
   Architecture: ARM64 (64-bit)
   Type: Mach-O
   Modified: 2024-04-01 16:20:15 UTC

   Symbols: Present
   UUID: 12345678-90AB-CDEF-1234-567890ABCDEF

   dSYM Bundle: ✓ Found
      Path: /Applications/Calculator.app/Contents/MacOS/Calculator.dSYM

   Security Features:
      PIE: ✓
      NX: ✓
      Canary: ✓
```

### JSON Output

```shell
symwalker --json /usr/bin/ls
```

```json
[
  {
    "file_path": "/usr/bin/ls",
    "file_size": 147480,
    "file_modified": "2024-03-15T14:32:10Z",
    "binary_type": "ELF",
    "architecture": "x86_64",
    "is_64bit": true,
    "is_stripped": false,
    "has_debug_info": true,
    "build_id": "4c3c4698f3e7e1d8b8f9a8c2d5e6f7a8b9c0d1e2",
    "gnu_debuglink": null,
    "debug_sections": [".debug_info", ".debug_abbrev", ".debug_line"],
    "uuid": null,
    "dsym_bundle": null,
    "debug_file_path": "/usr/lib/debug/usr/bin/ls.debug",
    "debuginfod_available": true,
    "debuginfod_url": "https://debuginfod.ubuntu.com/buildid/4c3c4698f3e7e1d8b8f9a8c2d5e6f7a8b9c0d1e2/debuginfo",
    "entry_point": "0x5850",
    "interpreter": "/lib64/ld-linux-x86-64.so.2",
    "is_pie": true,
    "is_executable": true,
    "is_library": false,
    "has_nx": true,
    "has_canary": true,
    "has_relro": true,
    "has_fortify": true
  }
]
```

## Command-Line Options

```
Advanced ELF/Mach-O binary scanner with intelligent debug symbol detection

Usage: symwalker [OPTIONS] <DIRECTORY>

Arguments:
  <DIRECTORY>  Directory to scan for binaries

Options:
  -v, --verbose              Show detailed information about each binary
      --local-only           Only show binaries with local debug symbols
      --remote-only          Only show binaries with remote symbols available
      --check-remote         Check if remote symbols exist via debuginfod
  -o, --output <DIR>         Copy binaries and debug symbols to output directory
      --copy-binaries        Copy binaries in addition to debug symbols
      --download-remote      Download remote debug symbols (requires --output)
  -f, --force                Overwrite existing files in output directory
      --json                 Output results as JSON
      --max-depth <N>        Maximum recursion depth
      --follow-symlinks      Follow symbolic links
      --show-stripped        Show stripped binaries (without debug info)
      --debuginfod-urls <URLS>  Custom debuginfod server URLs (comma-separated)
      --check-dsym           Check for dSYM bundles in standard macOS locations
      --security             Analyze binary security features (NX, PIE, RELRO, etc.)
  -h, --help                 Print help
  -V, --version              Print version
```

## Use Cases

### Linux Development & Debugging

```shell
# Verify debug symbols for your build
symwalker --local-only ~/project/target/debug

# Find which system libraries have debug info available
symwalker --check-remote --remote-only /usr/lib

# Download debug symbols for offline debugging
symwalker --check-remote --download-remote -o ./debug-symbols /usr/lib
```

### macOS Application Analysis

```shell
# Check if app bundles have dSYM files
symwalker --check-dsym /Applications

# Analyze security features of system binaries
symwalker -v --security /usr/local/bin

# Find all ARM64 binaries
symwalker /Applications | grep ARM64
```

### Security Research

```shell
# Analyze security mitigations in system binaries
symwalker -v --security /usr/bin

# Find binaries without PIE/NX
symwalker --show-stripped --security /usr/bin | grep "✗"

# Export security analysis as JSON
symwalker --json --security /usr/bin > security-audit.json
```

### Reverse Engineering

```shell
# Find binaries with embedded debug info
symwalker --show-stripped /usr/bin | grep "Embedded"

# Collect binaries and symbols for analysis
symwalker --copy-binaries --check-remote --download-remote -o ./re-analysis /target/dir

# Search for specific architectures
symwalker --json /usr/bin | jq '.[] | select(.architecture == "ARM64")'
```

### Build System Verification

```shell
# Check if release builds are properly stripped
symwalker target/release | grep "Stripped"

# Verify debug builds have symbols
symwalker --local-only target/debug

# Compare debug info across builds
diff <(symwalker --json target/debug) <(symwalker --json target/release)
```

## Technical Background

### ELF Debug Information

ELF binaries store debug information in multiple ways:

1. **Embedded Sections:** `.debug_*` sections containing DWARF data
2. **Build-ID:** Unique identifier in `.note.gnu.build-id` section
3. **GNU Debuglink:** Reference to external `.debug` file
4. **Symbol Table:** `.symtab` section (removed when stripped)

### Build-ID Resolution

Build-IDs follow this format:
```
/usr/lib/debug/.build-id/XX/YYYYYYYY.debug
```

Where `XXYYYYYYYY` is the hex build-id, with first 2 chars as directory.

### Debuginfod Protocol

Debuginfod is a web service providing debug resources indexed by build-id:
```
https://debuginfod.example.com/buildid/<buildid>/debuginfo
https://debuginfod.example.com/buildid/<buildid>/executable
```

Default servers:
- `https://debuginfod.elfutils.org/`
- `https://debuginfod.ubuntu.com/`
- `https://debuginfod.fedoraproject.org/`
- `https://debuginfod.debian.net/`

### Mach-O Debug Information

Mach-O binaries use different mechanisms:

1. **UUID:** Unique identifier in `LC_UUID` load command
2. **dSYM Bundles:** Separate `.dSYM` directory containing debug info
3. **DWARF Sections:** `__DWARF` segment with debug data
4. **Symbol Table:** `LC_SYMTAB` load command (stripped in release builds)

### dSYM Bundle Structure

```
MyApp.dSYM/
└── Contents/
    ├── Info.plist
    └── Resources/
        └── DWARF/
            └── MyApp  (contains debug info)
```

### Security Features Detection

**ELF:**
- **PIE:** ET_DYN type with PT_INTERP segment
- **NX:** PT_GNU_STACK segment without execute permission
- **RELRO:** PT_GNU_RELRO segment
- **Canary:** `__stack_chk_fail` symbol present
- **FORTIFY:** `*_chk` function variants

**Mach-O:**
- **PIE:** MH_PIE flag in header
- **NX:** MH_NO_HEAP_EXECUTION flag
- **Canary:** Stack guard symbols

## Performance

`symwalker` is optimized for speed and efficiency:

*   **Memory-mapped I/O:** Zero-copy binary parsing
*   **Parallel-ready:** Clean architecture for future multi-threading
*   **Lazy evaluation:** Remote checks only when requested
*   **Smart caching:** Reuses parsed data structures
*   **Efficient traversal:** Uses walkdir for fast directory scanning

**Typical performance:**
*   Local scans: 100-500 binaries/second
*   With remote checks: Limited by network latency (50-200ms per request)
*   JSON parsing: 1000+ binaries/second

## Environment Variables

```shell
# Custom debuginfod servers
export DEBUGINFOD_URLS="https://debuginfod.example.com/ https://debuginfod.company.net/"

# Disable colors
export NO_COLOR=1
```

## Output Files

When using `--output` to copy files, the following structure is created:

```
output_directory/
├── binary1
├── binary1.debug      (ELF debug file)
├── binary2
├── binary2.dSYM/      (Mach-O dSYM bundle)
│   └── Contents/
│       └── Resources/
│           └── DWARF/
└── manifest.json
```

The `manifest.json` contains metadata:

```json
{
  "files": [
    {
      "binary": "/usr/bin/ls",
      "binary_copied": "output_directory/ls",
      "symbols_copied": "output_directory/ls.debug",
      "symbols_downloaded": null
    }
  ],
  "count": 1
}
```

## Compatibility

*   **Platforms:** Linux, macOS, *BSD (any platform with ELF or Mach-O binaries)
*   **Architectures:** x86, x86_64, ARM, AArch64, RISC-V, PowerPC, MIPS, S390
*   **Binary Formats:** ELF (32/64-bit), Mach-O (32/64-bit, Universal/Fat)

## Notes

*   Debuginfod requires internet connectivity; corporate firewalls may block access
*   dSYM bundle detection requires `--check-dsym` flag for comprehensive search
*   Some binaries may fail to parse if corrupted, packed, or use non-standard structures
*   Strip detection is based on symbol table presence, not section removal
*   Security feature detection is heuristic-based and may not catch all variants

## Comparison with Similar Tools

| Feature | symwalker | pdbwalker | eu-unstrip | dsymutil |
|---------|-----------|-----------|------------|----------|
| ELF Support | ✓ | ✗ | ✓ | ✗ |
| Mach-O Support | ✓ | ✗ | ✗ | ✓ |
| PE Support | ✗ | ✓ | ✗ | ✗ |
| Build-ID | ✓ | N/A | ✓ | N/A |
| Debuginfod | ✓ | N/A | ✓ | N/A |
| dSYM Detection | ✓ | N/A | N/A | ✓ |
| Security Analysis | ✓ | ✗ | ✗ | ✗ |
| JSON Output | ✓ | ✓ | ✗ | ✗ |
| Color Output | ✓ | ✓ | ✗ | ✗ |
| Recursive Scan | ✓ | ✓ | ✗ | ✗ |

## License

MIT License

Copyright (c) 2025 Kenan Sulayman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

