# ash.fish - Agentic Shell Layer hook for Fish
#
# Source this file (fish sources config.fish automatically):
#   source ~/.config/ash/ash.fish
#
# Or add to ~/.config/fish/config.fish:
#   source ~/.config/ash/ash.fish

# ── Guard ─────────────────────────────────────────────────────────────────
if not command -q ashd
    exit 0
end

# ── Session initialization ─────────────────────────────────────────────────
function _ash_init
    if test -z "$ASH_SESSION_ID"
        set -l ashd_env (ashd 2>/dev/null)
        if test $status -eq 0
            for line in $ashd_env
                set -l parts (string split '=' $line)
                if test (count $parts) -ge 2
                    set -gx $parts[1] $parts[2]
                end
            end
        end
    end
    set -gx ASH_ENABLED 1
end

# ── Event emitter ──────────────────────────────────────────────────────────
function _ash_emit
    set -l event_json $argv[1]
    if test -n "$ASH_SOCKET"
        echo $event_json | socat - UNIX-CLIENT:"$ASH_SOCKET" 2>/dev/null &
    end
end

# ── fish_preexec event ─────────────────────────────────────────────────────
function _ash_preexec --on-event fish_preexec
    set -l command $argv[1]
    set -l cwd (pwd)

    set -l actor_kind "human"
    if test -n "$ASH_ACTOR_KIND"
        set actor_kind $ASH_ACTOR_KIND
    end

    set -l event (printf '{"type":"block.input","command":"%s","cwd":"%s","actor":{"kind":"%s"},"session":"%s"}' \
        (string escape --style=json -- $command) \
        $cwd \
        $actor_kind \
        (or $ASH_SESSION_ID ""))
    _ash_emit $event

    # OSC 133 B+C
    printf '\033]133;B\007'
    printf '\033]133;C\007'

    set -g _ASH_CURRENT_BLOCK "blk-$fish_pid-$RANDOM"
end

# ── fish_postexec event ────────────────────────────────────────────────────
function _ash_postexec --on-event fish_postexec
    set -l exit_code $status

    if test -n "$_ASH_CURRENT_BLOCK"
        set -l event (printf '{"type":"block.end","block":"%s","exit_code":%d,"session":"%s"}' \
            $_ASH_CURRENT_BLOCK $exit_code (or $ASH_SESSION_ID ""))
        _ash_emit $event
        set -e _ASH_CURRENT_BLOCK
    end
end

# ── fish_prompt event ──────────────────────────────────────────────────────
function _ash_prompt --on-event fish_prompt
    set -l cwd (pwd)

    set -l git_branch ""
    if command -q git; and git rev-parse --git-dir &>/dev/null 2>&1
        set git_branch (git branch --show-current 2>/dev/null)
    end

    if test -n "$git_branch"
        set -l event (printf '{"type":"block.prompt","cwd":"%s","git_branch":"%s","session":"%s"}' \
            $cwd $git_branch (or $ASH_SESSION_ID ""))
        _ash_emit $event
    else
        set -l event (printf '{"type":"block.prompt","cwd":"%s","session":"%s"}' \
            $cwd (or $ASH_SESSION_ID ""))
        _ash_emit $event
    end

    # OSC 133 A
    printf '\033]133;A\007'
end

# ── Shell abbreviations for slash commands ─────────────────────────────────
# /undo and /diff aren't valid fish syntax; use functions instead
function ash-undo
    ash undo $argv
end

function ash-diff
    ash diff $argv
end

function ash-approve
    ash approve $argv
end

function ash-deny
    ash deny $argv
end

# ── Initialize ────────────────────────────────────────────────────────────
_ash_init
