#!/bin/bash
# Advanced usage examples for symwalker

# Example 1: Find all ARM64 binaries
echo "=== Finding all ARM64 binaries ==="
symwalker --json /usr/bin | jq '.[] | select(.architecture == "ARM64") | .file_path'

# Example 2: Find binaries without PIE
echo ""
echo "=== Finding binaries without PIE (Position Independent Executable) ==="
symwalker --json --security /usr/bin | jq '.[] | select(.is_pie == false) | {path: .file_path, pie: .is_pie, nx: .has_nx}'

# Example 3: Security audit - binaries without stack canary
echo ""
echo "=== Security Audit: Binaries without stack canary ==="
symwalker --json --security /usr/local/bin | jq '.[] | select(.has_canary == false) | .file_path'

# Example 4: Copy binaries and symbols to analysis directory
echo ""
echo "=== Copying binaries and symbols for analysis ==="
mkdir -p /tmp/symwalker-analysis
symwalker --copy-binaries -o /tmp/symwalker-analysis /usr/local/bin --max-depth 1
cat /tmp/symwalker-analysis/manifest.json | jq .

# Example 5: Find stripped vs unstripped binaries
echo ""
echo "=== Comparing stripped vs unstripped binaries ==="
echo "Stripped:"
symwalker --json /usr/bin --max-depth 1 | jq '[.[] | select(.is_stripped == true)] | length'
echo "Not stripped:"
symwalker --json /usr/bin --max-depth 1 | jq '[.[] | select(.is_stripped == false)] | length'

# Example 6: Extract all UUIDs (macOS)
echo ""
echo "=== Extracting UUIDs from Mach-O binaries ==="
symwalker --json /usr/bin --max-depth 1 | jq '.[] | select(.uuid != null) | {path: .file_path, uuid: .uuid}' | head -20

