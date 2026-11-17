# ash.bash - Agentic Shell Layer hook for Bash
#
# Source this file in your .bashrc:
#   source ~/.config/ash/ash.bash
#
# Or install it automatically:
#   ash hook bash >> ~/.bashrc

# ── Guard ─────────────────────────────────────────────────────────────────
if [[ -z "${ASH_ENABLED}" ]]; then
  if ! command -v ashd &>/dev/null; then
    return 0
  fi
fi

# ── Session initialization ─────────────────────────────────────────────────
_ash_init() {
  if [[ -z "${ASH_SESSION_ID}" ]]; then
    local ashd_env
    ashd_env=$(ashd 2>/dev/null)
    if [[ $? -eq 0 ]]; then
      eval "$ashd_env"
      export ASH_SESSION_ID
      export ASH_SOCKET
    fi
  fi
  export ASH_ENABLED=1
}

# ── Event emitter ──────────────────────────────────────────────────────────
_ash_emit() {
  local event_json="$1"
  if [[ -n "${ASH_SOCKET}" ]]; then
    printf '%s\n' "$event_json" | socat - UNIX-CLIENT:"${ASH_SOCKET}" 2>/dev/null &
  fi
}

# ── Bash DEBUG trap (fires before each command) ────────────────────────────
_ash_debug_trap() {
  local command="${BASH_COMMAND}"

  # Skip ash internals
  case "$command" in
    _ash_*|ash *) return ;;
  esac

  if [[ "${_ASH_SKIP_NEXT}" == "1" ]]; then
    unset _ASH_SKIP_NEXT
    return
  fi

  local cwd
  cwd="$(pwd)"

  local actor_kind="human"
  if [[ -n "${ASH_ACTOR_KIND}" ]]; then
    actor_kind="${ASH_ACTOR_KIND}"
  fi

  local event
  event=$(printf '{"type":"block.input","command":"%s","cwd":"%s","actor":{"kind":"%s"},"session":"%s"}' \
    "$(echo "$command" | sed 's/"/\\"/g')" \
    "$cwd" \
    "$actor_kind" \
    "${ASH_SESSION_ID:-}")
  _ash_emit "$event"

  # OSC 133 B+C
  printf '\033]133;B\007'
  printf '\033]133;C\007'

  _ASH_LAST_COMMAND="$command"
  _ASH_CURRENT_BLOCK="blk-$$-${RANDOM}"
}

# ── PROMPT_COMMAND hook ────────────────────────────────────────────────────
_ash_prompt_command() {
  local exit_code=$?

  if [[ -n "${_ASH_CURRENT_BLOCK}" ]]; then
    local event
    event=$(printf '{"type":"block.end","block":"%s","exit_code":%d,"session":"%s"}' \
      "${_ASH_CURRENT_BLOCK}" "${exit_code}" "${ASH_SESSION_ID:-}")
    _ash_emit "$event"
    unset _ASH_CURRENT_BLOCK
  fi

  local cwd
  cwd="$(pwd)"
  local event
  event=$(printf '{"type":"block.prompt","cwd":"%s","session":"%s"}' \
    "$cwd" "${ASH_SESSION_ID:-}")
  _ash_emit "$event"

  # OSC 133 A: prompt start
  printf '\033]133;A\007'
}

# ── Shell builtins ─────────────────────────────────────────────────────────
undo() { ash undo "$@"; }
explain() { ash policy explain "$*"; }

# ── Register hooks ─────────────────────────────────────────────────────────
_ash_register_hooks() {
  # Prepend to PROMPT_COMMAND
  if [[ "${PROMPT_COMMAND}" != *"_ash_prompt_command"* ]]; then
    PROMPT_COMMAND="_ash_prompt_command${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
  fi

  # Set DEBUG trap (note: this may conflict with other traps)
  trap '_ash_debug_trap' DEBUG
}

_ash_init
_ash_register_hooks
