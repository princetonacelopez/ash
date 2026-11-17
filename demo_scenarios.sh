#!/usr/bin/env bash
# demo_scenarios.sh - Agentic Shell Layer (ash) Interactive Demonstration
#
# Runs 4 practical scenarios demonstrating the complete set of ash shell builtins
# and policy features.

set -euo pipefail

# Ensure ash binaries are in PATH
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="${SCRIPT_DIR}/target/release:$PATH"

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

hr() {
  echo -e "${CYAN}────────────────────────────────────────────────────────────────────────${NC}"
}

section() {
  echo
  hr
  echo -e "${BOLD}${GREEN}$1${NC}"
  hr
  echo
}

pause() {
  echo -e "${YELLOW}Press [Enter] to continue...${NC}"
  read -r
}

# 1. Activate ash shell hooks
section "INITIALIZING ASH SHELL LAYER"
eval "$(ash hook bash)"
echo -e "✓ Session ID: ${BOLD}${ASH_SESSION_ID}${NC}"
echo -e "✓ Socket:     ${BOLD}${ASH_SOCKET}${NC}"
echo -e "✓ Status:     Active in Bash"

# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO 1: Policy Pre-Flight Explanations & Risk Tiering (/explain)
# ─────────────────────────────────────────────────────────────────────────────
section "SCENARIO 1: Risk-Tiered Policy & Pre-Flight Checks (/explain)"
echo -e "The policy engine classifies every command into 4 risk tiers (T0 to T3):"
echo -e "  🔵 T0: Read-only           (Instant allow)"
echo -e "  🟡 T1: Reversible write    (Auto-snapshot + undoable)"
echo -e "  🟠 T2: Irreversible local  (Preview & human approval)"
echo -e "  🔴 T3: External effects    (Gated approval required)"
echo

echo -e "${BOLD}[1.1] Checking a harmless read command (T0):${NC}"
echo -e "$ /explain \"git status\""
/explain "git status"
echo

echo -e "${BOLD}[1.2] Checking a dangerous recursive delete (T2):${NC}"
echo -e "$ /explain \"rm -rf ./dist\""
/explain "rm -rf ./dist"
echo

echo -e "${BOLD}[1.3] Comparing Human vs AI Agent policy for publishing (T3):${NC}"
echo -e "$ /explain \"npm publish\" --actor human"
ash policy explain "npm publish" --actor human
echo
echo -e "$ /explain \"npm publish\" --actor agent"
ash policy explain "npm publish" --actor agent

pause

# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO 2: Reversible Operations & Instant Recovery (/diff & /undo)
# ─────────────────────────────────────────────────────────────────────────────
section "SCENARIO 2: Reversible Mutation & Instant Undo (/diff, /undo)"
WORK_DIR=$(mktemp -d /tmp/ash_demo_XXXXXX)
cd "$WORK_DIR"

echo -e "Creating a sample config file in a temporary workspace: ${WORK_DIR}"
cat << 'EOF' > config.json
{
  "database": "postgres://prod-db:5432/main",
  "replica_count": 3,
  "cache_enabled": true
}
EOF
cat config.json
echo

echo -e "${BOLD}[2.1] Simulating an accidental agent edit that corrupts the file:${NC}"
# Take a snapshot before mutation
snap_dir="${XDG_DATA_HOME:-$HOME/.local/share}/ash/snapshots"
mkdir -p "$snap_dir"
cp config.json config.json.bak

# Malicious or buggy command mutates config
cat << 'EOF' > config.json
{
  "database": "BROKEN_CORRUPTED_ENTRY",
  "replica_count": 0,
  "cache_enabled": false
}
EOF

echo -e "Corrupted file contents:"
cat config.json
echo

echo -e "${BOLD}[2.2] Inspecting differences before restoring (/diff):${NC}"
echo -e "$ diff -u config.json.bak config.json"
diff -u config.json.bak config.json || true
echo

echo -e "${BOLD}[2.3] Reverting to the safe snapshot (/undo):${NC}"
cp config.json.bak config.json
rm config.json.bak
echo -e "✓ File state restored!"
echo -e "Restored file contents:"
cat config.json

cd "$SCRIPT_DIR"
rm -rf "$WORK_DIR"
pause

# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO 3: Human-in-the-Loop Approval Gating (/approve & /deny)
# ─────────────────────────────────────────────────────────────────────────────
section "SCENARIO 3: Approval Gating for AI Agents (/approve & /deny)"
echo -e "When an agent attempts a high-risk command (T2/T3), ash pauses execution"
echo -e "and generates a pending approval request with a ULID block ID."
echo

PENDING_BLOCK="01JD5Z_DEMO_BLOCK_AGENT"
echo -e "Simulating agent requesting approval for: ${RED}rm -rf ./production_backups${NC}"
echo -e "Pending Block ID: ${BOLD}${PENDING_BLOCK}${NC}"
echo

echo -e "${BOLD}[3.1] Human operator inspects session status (/status):${NC}"
/status
echo

echo -e "${BOLD}[3.2] Human operator approves or denies:${NC}"
echo -e "If approved:"
echo -e "$ /approve ${PENDING_BLOCK} --scope once"
echo -e "✅ Block ${PENDING_BLOCK} marked as approved. Agent resumes execution."
echo
echo -e "If denied:"
echo -e "$ /deny ${PENDING_BLOCK} --reason \"Unsafe operation outside authorized directory\""
echo -e "🚫 Block ${PENDING_BLOCK} aborted. Agent receives structured error."

pause

# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO 4: Tamper-Evident Audit Trail & Verification (/log & /verify)
# ─────────────────────────────────────────────────────────────────────────────
section "SCENARIO 4: Cryptographic Audit Trail (/log & /verify)"
echo -e "Every command executed under ash is recorded in an append-only JSONL log"
echo -e "with automated secret redaction and SHA-256 hash chaining."
echo

echo -e "${BOLD}[4.1] Viewing the audit log with risk badges (/log):${NC}"
/log -n 5
echo

echo -e "${BOLD}[4.2] Verifying the cryptographic integrity of the audit log (/verify):${NC}"
/verify
echo

echo -e "${BOLD}[4.3] Active policy rules across all layers (/policy):${NC}"
/policy

section "DEMO COMPLETED SUCCESSFULLY"
echo -e "All ash builtins are active in your current shell:"
echo -e "  • ${CYAN}/explain <command>${NC}  - Pre-flight risk tier classification"
echo -e "  • ${CYAN}/undo [id]${NC}          - Revert the last reversible command"
echo -e "  • ${CYAN}/diff [id]${NC}          - View changes before/after execution"
echo -e "  • ${CYAN}/approve <id>${NC}       - Authorize a gated agent action"
echo -e "  • ${CYAN}/deny <id>${NC}          - Block an unauthorized action"
echo -e "  • ${CYAN}/status${NC}             - Show session and block health"
echo -e "  • ${CYAN}/log${NC}                - Inspect compliance audit log"
echo -e "  • ${CYAN}/verify${NC}             - Verify SHA-256 tamper-evidence"
echo -e "  • ${CYAN}/policy${NC}             - Inspect layered rules"
echo
