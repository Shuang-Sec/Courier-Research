#!/usr/bin/env bash
set -euo pipefail

# One-shot Adaptix teamserver restart helper for the direct_https_agent worktree.
# Default behavior:
#   1. kill old adaptixserver processes and anything still holding 4321/8443
#   2. start a fresh server from ./dist/start-adaptix-server.sh in background
#   3. write pid/log files under ./dist/run and ./dist/logs
#   4. print verification hints, including listener ports and stale deleted plugin maps

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$ROOT_DIR/dist"
START_SCRIPT="$DIST_DIR/start-adaptix-server.sh"
PID_FILE="$DIST_DIR/run/adaptixserver.pid"
LOG_DIR="$DIST_DIR/logs"
PROFILE="profile-direct-https.yaml"
PORTS=(4321 8443)
TERM_TIMEOUT=8
START_TIMEOUT=15
FOREGROUND=0
TAIL_LOG=0
KILL_PORT_HOLDERS=1

usage() {
    cat <<USAGE
Usage: $0 [options]

Options:
  --foreground        Start server in foreground after stopping old processes.
  --tail             Start in background, then tail -f the new log.
  --no-port-kill     Only kill adaptixserver PIDs; do not kill non-adaptix port holders.
  --profile FILE     Profile file under ./dist to use. Default: $PROFILE
  -h, --help         Show this help.

Examples:
  $0
  $0 --tail
  $0 --foreground
USAGE
}

log()  { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[-] %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --foreground)
            FOREGROUND=1
            shift
            ;;
        --tail)
            TAIL_LOG=1
            shift
            ;;
        --no-port-kill)
            KILL_PORT_HOLDERS=0
            shift
            ;;
        --profile)
            [[ $# -ge 2 ]] || die "--profile needs a value"
            PROFILE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Unknown option: $1"
            ;;
    esac
done

[[ -d "$DIST_DIR" ]] || die "dist directory not found: $DIST_DIR"
[[ -x "$DIST_DIR/adaptixserver" ]] || die "adaptixserver binary not executable: $DIST_DIR/adaptixserver"
[[ -f "$DIST_DIR/$PROFILE" ]] || die "profile not found: $DIST_DIR/$PROFILE"
[[ -x "$START_SCRIPT" ]] || die "start script not executable: $START_SCRIPT"

mkdir -p "$(dirname "$PID_FILE")" "$LOG_DIR"

collect_adaptix_pids() {
    local pid exe exe_clean
    while read -r pid; do
        [[ -n "$pid" ]] || continue
        [[ "$pid" == "$$" ]] && continue
        exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
        exe_clean="${exe% (deleted)}"
        if [[ "$exe_clean" == "$DIST_DIR/adaptixserver" || "$exe_clean" == *"/adaptixserver" ]]; then
            printf '%s\n' "$pid"
        fi
    done < <(pgrep -x 'adaptixserver' || true)
}

collect_port_pids() {
    local port pid
    for port in "${PORTS[@]}"; do
        while read -r pid; do
            [[ -n "$pid" ]] || continue
            [[ "$pid" == "$$" ]] && continue
            printf '%s\n' "$pid"
        done < <(fuser -n tcp "$port" 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+$' || true)
    done
}

is_alive() {
    local pid="$1"
    [[ -d "/proc/$pid" ]]
}

kill_pids() {
    local -a pids=("$@")
    local -a alive=()
    local pid deadline now

    [[ ${#pids[@]} -gt 0 ]] || return 0

    log "Sending SIGTERM to: ${pids[*]}"
    kill -TERM "${pids[@]}" 2>/dev/null || true

    deadline=$((SECONDS + TERM_TIMEOUT))
    while (( SECONDS < deadline )); do
        alive=()
        for pid in "${pids[@]}"; do
            is_alive "$pid" && alive+=("$pid")
        done
        [[ ${#alive[@]} -eq 0 ]] && return 0
        sleep 0.5
    done

    alive=()
    for pid in "${pids[@]}"; do
        is_alive "$pid" && alive+=("$pid")
    done
    if [[ ${#alive[@]} -gt 0 ]]; then
        warn "Still alive after ${TERM_TIMEOUT}s, sending SIGKILL to: ${alive[*]}"
        kill -KILL "${alive[@]}" 2>/dev/null || true
    fi
}

unique_lines() {
    awk 'NF && !seen[$0]++'
}

wait_ports_free() {
    local deadline=$((SECONDS + TERM_TIMEOUT))
    local busy
    while (( SECONDS < deadline )); do
        busy=0
        for port in "${PORTS[@]}"; do
            if fuser -n tcp "$port" >/dev/null 2>&1; then
                busy=1
                break
            fi
        done
        [[ "$busy" -eq 0 ]] && return 0
        sleep 0.5
    done
    return 1
}

wait_server_ready() {
    local pid="$1"
    local deadline=$((SECONDS + START_TIMEOUT))
    local ready port
    while (( SECONDS < deadline )); do
        if ! is_alive "$pid"; then
            return 1
        fi
        ready=1
        for port in "${PORTS[@]}"; do
            if ! ss -ltnp "( sport = :$port )" 2>/dev/null | grep -q "pid=$pid,"; then
                ready=0
                break
            fi
        done
        [[ "$ready" -eq 1 ]] && return 0
        sleep 1
    done
    return 1
}

show_status() {
    local pid="${1:-}"
    echo
    log "Process status:"
    if [[ -n "$pid" ]]; then
        ps -fp "$pid" || true
    else
        ps -eo pid,ppid,lstart,stat,cmd | grep -E '[a]daptixserver' || true
    fi

    echo
    log "Listening sockets:"
    ss -ltnp '( sport = :4321 or sport = :8443 )' || true

    echo
    log "Deleted direct_https plugin mappings:"
    local found=0 p
    for p in $(pgrep -x adaptixserver || true); do
        if grep -H 'agent_direct_https.*deleted' "/proc/$p/maps" 2>/dev/null; then
            found=1
        fi
    done
    [[ "$found" -eq 0 ]] && ok "No deleted agent_direct_https.so mapping found."
}

main() {
    cd "$DIST_DIR"

    log "Root: $ROOT_DIR"
    log "Dist: $DIST_DIR"
    log "Profile: $PROFILE"

    local -a pids=()
    mapfile -t pids < <({ collect_adaptix_pids; if [[ "$KILL_PORT_HOLDERS" -eq 1 ]]; then collect_port_pids; fi; } | unique_lines)

    if [[ ${#pids[@]} -gt 0 ]]; then
        log "Stopping old server/port-holder PIDs: ${pids[*]}"
        ps -fp "${pids[@]}" || true
        kill_pids "${pids[@]}"
    else
        ok "No old adaptixserver process found."
    fi

    if ! wait_ports_free; then
        warn "Ports still busy after stop attempt:"
        ss -ltnp '( sport = :4321 or sport = :8443 )' || true
        die "Cannot start new server while ports are busy."
    fi
    ok "Ports 4321/8443 are free."

    if [[ "$FOREGROUND" -eq 1 ]]; then
        log "Starting server in foreground..."
        exec "$DIST_DIR/adaptixserver" -profile "$PROFILE"
    fi

    local ts log_file pid
    ts="$(date +%Y%m%d-%H%M%S)"
    log_file="$LOG_DIR/adaptixserver-$ts.log"

    log "Starting fresh server in background..."
    (
        cd "$DIST_DIR"
        if [[ -n "${GO_BIN_DIR:-}" ]]; then export PATH="$GO_BIN_DIR:$PATH"; fi
        if [[ -n "${MINGW_BIN_DIR:-}" ]]; then export PATH="$MINGW_BIN_DIR:$PATH"; fi
        if [[ -n "${GOPATH:-}" ]]; then export GOPATH; fi
        if [[ -n "${GOCACHE:-}" ]]; then export GOCACHE; fi
        export GOPROXY="${GOPROXY:-off}"
        exec nohup setsid ./adaptixserver -profile "$PROFILE"
    ) >"$log_file" 2>&1 < /dev/null &
    pid=$!
    echo "$pid" > "$PID_FILE"

    if wait_server_ready "$pid"; then
        ok "New adaptixserver is ready. PID=$pid"
        ok "Log: $log_file"
        ok "PID file: $PID_FILE"
    else
        warn "Server did not become fully ready within ${START_TIMEOUT}s. Recent log follows:"
        tail -80 "$log_file" || true
        show_status "$pid"
        exit 1
    fi

    show_status "$pid"

    if grep -q 'cmd_hello' "$DIST_DIR/extenders/direct_https_agent/ax_config.axs" 2>/dev/null; then
        ok "direct_https ax_config.axs contains cmd_hello."
    else
        warn "cmd_hello not found in direct_https ax_config.axs."
    fi

    echo
    ok "Restart complete. Reconnect/re-login Adaptix Client if it was connected to the old server."
    log "To watch logs: tail -f '$log_file'"

    if [[ "$TAIL_LOG" -eq 1 ]]; then
        tail -f "$log_file"
    fi
}

main "$@"
