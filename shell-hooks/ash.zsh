# ash.zsh - Agentic Shell Layer hook for Zsh
#
# Source this file in your .zshrc:
#   source <(ash hook zsh)
# Or:
#   eval "$(ash hook zsh)"

if command -v ashd &>/dev/null && [[ -z "${ASH_ENABLED}" ]]; then

# ── Session initialization ─────────────────────────────────────────────────
_ash_init() {
  if [[ -z "${ASH_SESSION_ID}" ]]; then
    local session_id="session-$$-${RANDOM}"
    local runtime_dir="${XDG_RUNTIME_DIR:-/tmp/ash-$UID}"
    local socket_path="${runtime_dir}/ash/${session_id}.sock"

    ashd --session-id "${session_id}" &>/dev/null &
    disown %1 2>/dev/null || true

    export ASH_SESSION_ID="${session_id}"
    export ASH_SOCKET="${socket_path}"
  fi
  export ASH_ENABLED=1
}

# ── Event emitter ──────────────────────────────────────────────────────────
_ash_emit() {
  local event_json="$1"
  if [[ -n "${ASH_SOCKET}" ]]; then
    if command -v nc &>/dev/null; then
      printf '%s\n' "$event_json" | nc -U "${ASH_SOCKET}" 2>/dev/null &
    elif command -v ash &>/dev/null; then
      ash emit "$event_json" 2>/dev/null &
    elif command -v socat &>/dev/null; then
      printf '%s\n' "$event_json" | socat - UNIX-CLIENT:"${ASH_SOCKET}" 2>/dev/null &
    fi
  fi
}

# ── Precmd hook: prompt rendered ──────────────────────────────────────────
_ash_precmd() {
  local exit_code=$?
  local cwd
  cwd="$(pwd)"

  if [[ -n "${_ASH_CURRENT_BLOCK}" ]]; then
    local event
    event=$(printf '{"type":"block.end","block":"%s","exit_code":%d,"session":"%s"}' \
      "${_ASH_CURRENT_BLOCK}" "${exit_code}" "${ASH_SESSION_ID:-}")
    _ash_emit "$event"
    unset _ASH_CURRENT_BLOCK
  fi

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

  # OSC 133 A: prompt start
  printf '\033]133;A\007'
}

# ── Preexec hook: command submitted ───────────────────────────────────────
_ash_preexec() {
  local command="$1"
  local cwd
  cwd="$(pwd)"

  case "$command" in
    /undo*|/diff*|/explain*|/approve*|/deny*|/status*|/log*|/policy*|/verify*) return ;;
    @*) return ;;
  esac

  local actor_kind="human"
  local actor_name="human"
  local actor_run=""
  if [[ -n "${ASH_ACTOR_KIND}" ]]; then
    actor_kind="${ASH_ACTOR_KIND}"
    actor_name="${ASH_ACTOR_NAME:-agent}"
    actor_run="${ASH_RUN_ID:-run-$$}"
  fi

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

  # OSC 133 B + C
  printf '\033]133;B\007'
  _ASH_CURRENT_BLOCK="blk-$$-${RANDOM}"
  printf '\033]133;C\007'

  local start_event
  start_event=$(printf '{"type":"block.start","block":"%s","pid":%d,"pgid":%d,"session":"%s"}' \
    "${_ASH_CURRENT_BLOCK}" "$$" "$$" "${ASH_SESSION_ID:-}")
  _ash_emit "$start_event"
}

# ── Shell builtins ─────────────────────────────────────────────────────────
/undo() { ash undo "$@"; }
/diff() { ash diff "$@"; }
/explain() { ash policy explain "$*"; }
/approve() { ash approve "$@"; }
/deny() { ash deny "$@"; }
/status() { ash status "$@"; }
/log() { ash log "$@"; }
/policy() { ash policy show "$@"; }
/verify() { ash verify "$@"; }

# ── Register hooks ─────────────────────────────────────────────────────────
_ash_register_hooks() {
  if [[ -z "${precmd_functions[(r)_ash_precmd]}" ]]; then
    precmd_functions+=(_ash_precmd)
  fi
  if [[ -z "${preexec_functions[(r)_ash_preexec]}" ]]; then
    preexec_functions+=(_ash_preexec)
  fi
}

_ash_init
_ash_register_hooks

fi
