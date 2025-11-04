# Quick Reference Guide

## Common Commands

### Basic Scanning

```bash
# Scan a directory
symwalker /usr/bin

# Scan with verbose output
symwalker -v /usr/local/bin

# Scan with security analysis
symwalker --security /usr/bin

# Limit recursion depth
symwalker --max-depth 2 /usr

# JSON output
symwalker --json /usr/bin > results.json
```

### Filtering

```bash
# Only binaries with local debug symbols
symwalker --local-only ~/project/target/debug

# Only binaries with remote symbols (requires network)
symwalker --check-remote --remote-only /usr/bin

# Show stripped binaries
symwalker --show-stripped /usr/bin
```

### macOS Specific

```bash
# Check for dSYM bundles
symwalker --check-dsym /Applications

# Scan app bundle
symwalker /Applications/MyApp.app/Contents/MacOS

# Find ARM64 binaries
symwalker --json /usr/bin | jq '.[] | select(.architecture == "ARM64")'
```

### Linux Specific

```bash
# Check debuginfod availability
symwalker --check-remote /usr/bin

# Download debug symbols
symwalker --check-remote --download-remote -o ./symbols /usr/bin

# Custom debuginfod server
symwalker --check-remote --debuginfod-urls https://my-server.com/ /usr/bin

# Find binaries with build-id
symwalker --json /usr/bin | jq '.[] | select(.build_id != null)'
```

### Output and Analysis

```bash
# Copy binaries and symbols
symwalker --copy-binaries -o ./analysis /usr/local/bin

# Security audit
symwalker --json --security /usr/bin | jq '.[] | {path: .file_path, pie: .is_pie, nx: .has_nx, canary: .has_canary}'

# Find vulnerable binaries (no canary)
symwalker --json --security /usr/bin | jq '.[] | select(.has_canary == false) | .file_path'

# Architecture distribution
symwalker --json /usr/bin | jq 'group_by(.architecture) | map({arch: .[0].architecture, count: length})'
```

## JSON Output Fields

### Common Fields
- `file_path` - Full path to binary
- `file_size` - Size in bytes
- `file_modified` - Last modification timestamp
- `binary_type` - "ELF" or "Mach-O"
- `architecture` - CPU architecture (x86_64, ARM64, etc.)
- `is_64bit` - Boolean, 64-bit vs 32-bit
- `is_stripped` - Boolean, symbols removed
- `has_debug_info` - Boolean, embedded debug info

### ELF Specific
- `build_id` - Build-ID hex string (null if not present)
- `gnu_debuglink` - Debug link filename (null if not present)
- `debug_sections` - Array of debug section names
- `interpreter` - Dynamic linker path (null if none)

### Mach-O Specific
- `uuid` - UUID string (null if not present)
- `dsym_bundle` - Path to dSYM bundle (null if not found)

### Security Features
- `is_pie` - Position Independent Executable
- `has_nx` - Non-executable stack/heap
- `has_canary` - Stack canary protection
- `has_relro` - RELRO (ELF only)
- `has_fortify` - FORTIFY_SOURCE (ELF only)

### Debug Information
- `debug_file_path` - Path to local debug file/bundle
- `debuginfod_available` - Boolean, remote symbols available (null if not checked)
- `debuginfod_url` - URL for remote symbols

### Binary Properties
- `entry_point` - Entry point address (hex string)
- `is_executable` - Boolean
- `is_library` - Boolean

## Exit Codes

- `0` - Success
- `1` - General error
- `2` - Command-line argument error

## Environment Variables

```bash
# Debuginfod servers
export DEBUGINFOD_URLS="https://debuginfod.elfutils.org/ https://debuginfod.ubuntu.com/"

# Disable colors
export NO_COLOR=1
```

## Output Symbols

- `✓` - Available/Present/Enabled
- `✗` - Not available/Missing/Disabled
- `?` - Unknown/Not checked
- `●` - Binary entry marker

## Tips and Tricks

### Performance

```bash
# Fast local scan (no network)
symwalker /usr/bin --max-depth 1

# Remote checks are slow - use sparingly
symwalker --check-remote /usr/bin  # Can take minutes for large directories
```

### Filtering with jq

```bash
# Large binaries
symwalker --json /usr/bin | jq '.[] | select(.file_size > 10000000)'

# Recent files
symwalker --json /usr/bin | jq '.[] | select(.file_modified > "2024-01-01")'

# Executables only
symwalker --json /usr/bin | jq '.[] | select(.is_executable == true and .is_library == false)'
```

### Security Analysis

```bash
# Security score (custom)
symwalker --json --security /usr/bin | jq '.[] | {
  path: .file_path,
  score: (
    (if .is_pie then 1 else 0 end) +
    (if .has_nx then 1 else 0 end) +
    (if .has_canary then 1 else 0 end) +
    (if .has_relro then 1 else 0 end)
  )
}'

# Find old binaries without PIE
symwalker --json --security /usr/bin | jq '.[] | select(.is_pie == false and .file_modified < "2020-01-01")'
```

### Comparison

```bash
# Compare two directories
diff <(symwalker --json /usr/bin | jq -S) <(symwalker --json /usr/local/bin | jq -S)

# Find unique architectures
symwalker --json /usr/bin | jq -r '.[].architecture' | sort -u
```

## Common Issues

### No binaries found
- Check directory contains ELF/Mach-O files
- Try `--show-stripped` to see stripped binaries
- Increase `--max-depth` if scanning shallow

### Remote checks failing
- Check internet connectivity
- Try custom debuginfod server
- Some binaries may not have public symbols

### Permission denied
- Use `sudo` if scanning system directories
- Some directories may be protected

### Slow scanning
- Use `--max-depth` to limit recursion
- Avoid `--check-remote` for large scans
- Use parallel scans: `find /usr -type f -name "*.so" | xargs -P 4 -I {} symwalker {}`

## See Also

- Full documentation: [README.md](../README.md)
- Symbol heuristics: [HEURISTICS.md](HEURISTICS.md)
- Contributing guide: [CONTRIBUTING.md](../CONTRIBUTING.md)
- Example scripts: [examples/](../examples/)

