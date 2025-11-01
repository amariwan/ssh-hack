#!/bin/bash
# Example: Production SSH Audit Script

set -euo pipefail

# Configuration
SCAN_NAME="prod-ssh-audit-$(date +%Y%m%d-%H%M%S)"
REPORT_DIR="./reports/${SCAN_NAME}"
CONFIG_DIR="./configs"

# Network targets (CUSTOMIZE THIS!)
PROD_CIDRS="10.0.0.0/8,172.16.0.0/12"
SSH_PORTS="22,2222"

# Scan settings
CONCURRENCY=200
RATE_LIMIT=500
TIMEOUT=10

# Output formats
OUTPUT_JSON="${REPORT_DIR}/audit.json"
OUTPUT_MD="${REPORT_DIR}/audit.md"
OUTPUT_SARIF="${REPORT_DIR}/audit.sarif"

# CI/CD settings
FAIL_ON="high"  # Options: critical, high, medium, low

echo "🔐 Starting SSH Security Audit"
echo "================================"
echo "Scan ID: ${SCAN_NAME}"
echo "Targets: ${PROD_CIDRS}"
echo "Ports: ${SSH_PORTS}"
echo ""

# Create report directory
mkdir -p "${REPORT_DIR}"

# Run audit
./build/ssh-audit \
  --allowlist "${PROD_CIDRS}" \
  --ports "${SSH_PORTS}" \
  --concurrency "${CONCURRENCY}" \
  --rate-limit "${RATE_LIMIT}" \
  --timeout "${TIMEOUT}" \
  --dns-reverse \
  --baseline "${CONFIG_DIR}/baseline.yml" \
  --vulns "${CONFIG_DIR}/vulns.yml" \
  --output-json "${OUTPUT_JSON}" \
  --output-markdown "${OUTPUT_MD}" \
  --output-sarif "${OUTPUT_SARIF}" \
  --fail-on "${FAIL_ON}" \
  --log-level info \
  --i-am-authorized

EXIT_CODE=$?

echo ""
echo "================================"
echo "📊 Audit Complete"
echo "Exit Code: ${EXIT_CODE}"
echo "Reports:"
echo "  - JSON: ${OUTPUT_JSON}"
echo "  - Markdown: ${OUTPUT_MD}"
echo "  - SARIF: ${OUTPUT_SARIF}"
echo ""

# Optional: Upload to S3, send to Slack, etc.
# aws s3 cp "${REPORT_DIR}" s3://my-bucket/ssh-audits/ --recursive
# curl -X POST https://hooks.slack.com/... -d "Audit complete: ${SCAN_NAME}"

exit ${EXIT_CODE}
