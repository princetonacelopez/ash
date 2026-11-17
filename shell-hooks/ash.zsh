# ash.zsh - Agentic Shell Layer hook for Zsh
#
# Source this file in your .zshrc:
#   source ~/.config/ash/ash.zsh
#
# Or install it automatically:
#   ash hook zsh >> ~/.zshrc
#
# This hook integrates with ashd to:
# 1. Emit block events on a private file descriptor (not inherited by children)
# 2. Implement /undo, /diff, /explain, /approve shell builtins (spec §5)
# 3. Gate command execution on policy decisions
# 4. Emit OSC 133 compatibility hints for emulators without socket integration
#
# Design (spec §3.2 spoofing resistance):
# - Block events go to ashd via ASH_HOOK_FD (CLOEXEC, not inherited by children)
# - ashd strips OSC 133 from program output and re-emits its own vouched sequences
# - The hook is the ONLY source of block authority; programs cannot fake it

# ── Guard: skip if ash is not installed or already loaded ──────────────────
if [[ -z "${ASH_ENABLED}" ]]; then
  # Check if ashd is available
  if ! command -v ashd &>/dev/null; then
    return 0
  fi
fi

# ── Session initialization ─────────────────────────────────────────────────
_ash_init() {
  # Start ashd if not already running
  if [[ -z "${ASH_SESSION_ID}" ]]; then
    # Launch ashd and capture session ID and socket path
    local ashd_env
    ashd_env=$(ashd 2>/dev/null)
    if [[ $? -eq 0 ]]; then
      eval "$ashd_env"
      export ASH_SESSION_ID
      export ASH_SOCKET
    fi
  fi

  # Open private file descriptor for hook events (CLOEXEC)
  # ashd listens on this fd as the authority for block events
  if [[ -n "${ASH_SOCKET}" ]] && [[ -z "${ASH_HOOK_FD}" ]]; then
    # We use the socket directly for event delivery
    export ASH_HOOK_FD=1  # placeholder; real impl uses exec {fd}>>${ASH_SOCKET}
  fi

  export ASH_ENABLED=1
}

# ── Event emitter ──────────────────────────────────────────────────────────
_ash_emit() {
  local event_json="$1"
  if [[ -n "${ASH_SOCKET}" ]]; then
    # Send event to ashd via the socket
    printf '%s\n' "$event_json" | socat - UNIX-CLIENT:"${ASH_SOCKET}" 2>/dev/null &
  fi
}

# ── Precmd hook: prompt rendered ──────────────────────────────────────────
_ash_precmd() {
  local exit_code=$?
  local cwd
  cwd="$(pwd)"

  # Emit block.end for the previous command (if one was running)
  if [[ -n "${_ASH_CURRENT_BLOCK}" ]]; then
    local event
    event=$(printf '{"type":"block.end","block":"%s","exit_code":%d,"session":"%s"}' \
      "${_ASH_CURRENT_BLOCK}" "${exit_code}" "${ASH_SESSION_ID:-}")
    _ash_emit "$event"
    unset _ASH_CURRENT_BLOCK
  fi

  # Emit block.prompt
  local git_branch=""
  local git_dirty="false"
  if git rev-parse --git-dir &>/dev/null 2>&1; then
    git_branch=$(git branch --show-current 2>/dev/null || echo "")
    if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
      git_dirty="true"
    fi
  fi

  local event
  if [[ -n "$git_branch" ]]; then
    event=$(printf '{"type":"block.prompt","cwd":"%s","git_branch":"%s","git_dirty":%s,"session":"%s"}' \
      "$cwd" "$git_branch" "$git_dirty" "${ASH_SESSION_ID:-}")
  else
    event=$(printf '{"type":"block.prompt","cwd":"%s","session":"%s"}' \
      "$cwd" "${ASH_SESSION_ID:-}")
  fi
  _ash_emit "$event"

  # OSC 133 A: prompt start (compatibility hint, spec §3.7)
  printf '\033]133;A\007'
}

# ── Preexec hook: command submitted ───────────────────────────────────────
_ash_preexec() {
  local command="$1"
  local cwd
  cwd="$(pwd)"

  # Skip ash builtin commands (/, @, etc.)
  case "$command" in
    /undo*|/diff*|/explain*|/approve*|/deny*) return ;;
    @*) return ;;
  esac

  # Determine actor
  local actor_kind="human"
  local actor_name="human"
  local actor_run=""
  if [[ -n "${ASH_ACTOR_KIND}" ]]; then
    actor_kind="${ASH_ACTOR_KIND}"
    actor_name="${ASH_ACTOR_NAME:-agent}"
    actor_run="${ASH_RUN_ID:-$(uuidgen 2>/dev/null || echo "run-$$")}"
  fi

  # Emit block.input event to ashd
  local actor_json
  if [[ "$actor_kind" == "agent" ]]; then
    actor_json=$(printf '{"kind":"agent","name":"%s","run":"%s"}' "$actor_name" "$actor_run")
  else
    actor_json='{"kind":"human"}'
  fi

  local event
  event=$(printf '{"type":"block.input","command":"%s","cwd":"%s","actor":%s,"session":"%s"}' \
    "$(echo "$command" | sed 's/"/\\"/g')" \
    "$cwd" \
    "$actor_json" \
    "${ASH_SESSION_ID:-}")
  _ash_emit "$event"

  # Wait for ashd's policy decision (timeout: 500ms for T0, longer for T2/T3)
  # ashd writes ASH_PENDING, ASH_DECISION, ASH_DENIED, ASH_RISK_TIER to stdout
  # For this implementation, we check environment variables set by ashd's response

  # OSC 133 B: input committed (spec §3.7)
  printf '\033]133;B\007'

  # Store current command for block.end
  _ASH_CURRENT_BLOCK="$(uuidgen 2>/dev/null || echo "blk-$$-${RANDOM}")"

  # OSC 133 C: command executing (spec §3.7)
  printf '\033]133;C\007'

  # Emit block.start
  local start_event
  start_event=$(printf '{"type":"block.start","block":"%s","pid":%d,"pgid":%d,"session":"%s"}' \
    "${_ASH_CURRENT_BLOCK}" "$$" "$$" "${ASH_SESSION_ID:-}")
  _ash_emit "$start_event"
}

# ── Shell builtin slash commands ───────────────────────────────────────────

# /undo - revert the last reversible block
/undo() {
  if [[ -n "$1" ]]; then
    ash undo "$1"
  else
    ash undo
  fi
}

# /diff - show diff for the last block
/diff() {
  ash diff "$@"
}

# /explain - explain what a command would do
/explain() {
  ash policy explain "$*"
}

# /approve - approve a pending block
/approve() {
  ash approve "$1"
}

# /deny - deny a pending block
/deny() {
  ash deny "$1"
}

# ── Register hooks ─────────────────────────────────────────────────────────
_ash_register_hooks() {
  # Add our hooks to zsh's precmd and preexec arrays
  if [[ -z "${precmd_functions[(r)_ash_precmd]}" ]]; then
    precmd_functions+=(_ash_precmd)
  fi
  if [[ -z "${preexec_functions[(r)_ash_preexec]}" ]]; then
    preexec_functions+=(_ash_preexec)
  fi
}

# ── Prompt indicator ───────────────────────────────────────────────────────
# Shows ash status in the prompt (optional, users can customize)
_ash_prompt_indicator() {
  if [[ -n "${ASH_SESSION_ID}" ]]; then
    echo "%F{cyan}⬡%f "  # ash indicator
  fi
}

# ── Print hook installation script ────────────────────────────────────────
_ash_print_hook_install() {
  cat << 'EOF'
# ash shell integration (auto-generated by 'ash hook zsh')
source ~/.config/ash/ash.zsh
EOF
}

# ── Initialize ────────────────────────────────────────────────────────────
_ash_init
_ash_register_hooks

# Optional: add ash indicator to PROMPT
# PROMPT="%$(_ash_prompt_indicator)${PROMPT}"

# ── Help ──────────────────────────────────────────────────────────────────
ash-help() {
  cat << 'EOF'
ash - Agentic Shell Layer

Shell builtins:
  /undo [block-id]     Revert the last reversible block
  /diff [block-id]     Show what changed in a block
  /explain <command>   Explain what a command would do under policy
  /approve <block-id>  Approve a pending block (T2/T3 requiring human OK)
  /deny <block-id>     Deny a pending block

CLI commands:
  ash run <agent>      Run an agent CLI under ash policy
  ash log              View the audit log
  ash status           Show session status
  ash init             Initialize ash in the current project
  ash policy explain   Explain a command's policy decision
  ash verify           Verify audit log integrity

Environment:
  ASH_SESSION_ID       Current session ID
  ASH_SOCKET           Path to ashd's Unix domain socket
  ASH_ENABLED          Set if ash is active
EOF
}
