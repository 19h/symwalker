#!/bin/bash
# Basic scanning examples for symwalker

echo "=== Example 1: Basic scan of /usr/bin ==="
symwalker /usr/bin --max-depth 1 | head -50

echo ""
echo "=== Example 2: Verbose scan with security analysis ==="
symwalker -v --security /usr/local/bin --max-depth 1 | head -50

echo ""
echo "=== Example 3: Find binaries with local debug symbols ==="
symwalker --local-only /usr/bin --max-depth 1

echo ""
echo "=== Example 4: JSON output for scripting ==="
symwalker --json /usr/bin --max-depth 1 | jq '.[0]'

echo ""
echo "=== Example 5: Check for dSYM bundles (macOS) ==="
symwalker --check-dsym /Applications --max-depth 3

