#!/bin/bash
# Debuginfod examples for ELF binaries (Linux)

# Example 1: Check remote symbol availability
echo "=== Checking remote symbol availability via debuginfod ==="
symwalker --check-remote /usr/bin --max-depth 1 | grep "Remote Debug"

# Example 2: Find binaries with remote symbols available
echo ""
echo "=== Finding binaries with remote symbols available ==="
symwalker --check-remote --remote-only /usr/bin --max-depth 1

# Example 3: Download remote symbols
echo ""
echo "=== Downloading remote debug symbols ==="
mkdir -p /tmp/debug-symbols
symwalker --check-remote --download-remote -o /tmp/debug-symbols /usr/bin --max-depth 1

# Example 4: Use custom debuginfod server
echo ""
echo "=== Using custom debuginfod server ==="
symwalker --check-remote --debuginfod-urls https://debuginfod.example.com/ /usr/local/bin

# Example 5: Extract build IDs
echo ""
echo "=== Extracting build IDs from ELF binaries ==="
symwalker --json /usr/bin --max-depth 1 | jq '.[] | select(.build_id != null) | {path: .file_path, build_id: .build_id}' | head -20

# Example 6: Check both local and remote availability
echo ""
echo "=== Checking local and remote debug symbol availability ==="
symwalker --check-remote -v /usr/bin --max-depth 1 | grep -E "(Local Debug|Remote Debug)"

