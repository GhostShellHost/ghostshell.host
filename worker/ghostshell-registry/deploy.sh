#!/bin/bash
set -e
echo "=== Deploying ghostshell-registry ==="
echo "Version: 2026-02-11.010"
echo ""
echo "1. Setting TEST_KEY secret (if not already set)..."
echo "   wrangler secret put TEST_KEY"
echo ""
echo "2. Deploying worker..."
echo "   wrangler deploy"
echo ""
echo "3. After deploy, test with:"
echo "   curl -X POST https://ghostshell.host/api/cert/test-checkout \\"
echo "     -d 'test_key=YOUR_TEST_KEY'"
