#!/usr/bin/env bash
# collect-logs.sh — one-shot PVM diagnostics bundle (脱敏后打包 tar.gz).
#
# Purpose:
#   Collect everything an operator needs to troubleshoot a PVM deployment
#   (process/task status, per-task console logs, system info, config
#   presence) into a single redacted tar.gz that is safe to attach to a
#   bug report. Secrets NEVER leave the machine in cleartext:
#     - Bearer/token/key/secret VALUES are masked as ***
#     - environment variables are recorded as NAME=set/unset only
#     - pvm.env-style files contribute KEY NAMES only
#     - MAC addresses have their last three octets masked (IPs are kept —
#       they are needed for troubleshooting)
#
# Usage:
#   ./deploy/collect-logs.sh                          # defaults: 200 lines, /tmp
#   ./deploy/collect-logs.sh --module web --module ai # only tasks matching
#   ./deploy/collect-logs.sh --lines 500 --out /var/tmp/pvm-diag
#   ./deploy/collect-logs.sh --selftest              # fake data end-to-end test
#
# Options:
#   --module NAME   only collect console logs whose task path matches NAME
#                   (repeatable; state files are always collected)
#   --lines N       tail -n N per log/dmesg (default 200)
#   --out DIR       output directory (default /tmp, created if missing)
#   --selftest      run the built-in end-to-end test on fake data, then exit
#   -h | --help     this help
#
# Environment:
#   PVM_STATE_ROOT  state dir override (default ~/.local/share/pvm)
#   PVM_LOG_DIR     log dir override   (default ~/.local/share/pvm/logs)
#   PVM_ENV_FILE    extra pvm.env-style file to record KEY NAMES of
#
# Exit codes:
#   0  success (including a passing --selftest)
#   1  fatal error (bad --lines, tar failed, selftest assertion failed)
#   2  usage error (unknown option)
#
# Style follows scripts/*.sh and deploy/install.sh: bash, set -euo pipefail,
# prefixed [collect-logs] log lines, no external deps beyond coreutils+tar.

set -euo pipefail

SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

STAGING=""
trap '[ -n "$STAGING" ] && rm -rf "$STAGING" || true' EXIT

log()  { printf '[collect-logs] %s\n' "$*"; }
warn() { printf '[collect-logs][warn] %s\n' "$*" >&2; }
die()  { printf '[collect-logs][error] %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# redact — the single masking pipe every collected byte goes through.
# Runs BEFORE packing as a second pass too (defense in depth). IP addresses
# are intentionally preserved; MAC last three octets become xx:xx:xx.
# ---------------------------------------------------------------------------
redact() {
    sed -E \
        -e 's/(Bearer|bearer)[[:space:]]+[A-Za-z0-9._~+\/=:-]+/\1 ***/g' \
        -e 's/((api[_-]?key|apikey|token|tokens|secret|password|passwd|pwd|key|keys)[[:space:]]*[=:][[:space:]]*)[^[:space:],;"'"'"']{1,}/\1***/Ig' \
        -e 's/(PVM_API_KEYS|API_SECRET|PVM_SECRET|PVM_API_SECRET)([[:space:]]*[=:][[:space:]]*)[^[:space:],;"'"'"']{1,}/\1\2***/g' \
        -e 's/("(api_secret|secret|token|api_key|apikey|password|key)"[[:space:]]*:[[:space:]]*")[^"]*"/\1***"/Ig' \
        -e 's/([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}):[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}/\1:xx:xx:xx/g'
}

redact_file() { # in-place, inode-preserving, sed-implementation agnostic
    local f=$1 tmp
    tmp=$(mktemp)
    if redact < "$f" > "$tmp"; then
        cat "$tmp" > "$f"
    else
        warn "redact failed for $f (kept as-is)"
    fi
    rm -f "$tmp"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
LINES=200
OUT_DIR=""
MODULES=()
SELFTEST=0

while [ $# -gt 0 ]; do
    case "$1" in
        --module)   [ $# -ge 2 ] || die "--module requires a value"; MODULES+=("$2"); shift 2 ;;
        --lines)    [ $# -ge 2 ] || die "--lines requires a value"
                    [[ "$2" =~ ^[0-9]+$ ]] && [ "$2" -gt 0 ] || die "--lines must be a positive integer"
                    LINES=$2; shift 2 ;;
        --out)      [ $# -ge 2 ] || die "--out requires a value"; OUT_DIR=$2; shift 2 ;;
        --selftest) SELFTEST=1; shift ;;
        -h|--help)  usage 0 ;;
        *)          printf '[collect-logs][error] unknown option: %s\n' "$1" >&2; usage 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# Step runner: every collector runs in a subshell so a failure (missing tool,
# EACCES, empty grep) can never abort the bundle. The result — ok or failed —
# is appended to manifest.txt inside the bundle itself, exactly as
# "[collect] <what>: failed" per the ops runbook convention.
# ---------------------------------------------------------------------------
STAGING=""
MANIFEST=""

step() { # step <what> <relpath> <collector-function>
    local what=$1 rel=$2 fn=$3 out
    mkdir -p "$STAGING/$(dirname "$rel")"
    out="$STAGING/$rel"
    if ("$fn") > "$out" 2>/dev/null; then
        printf '[collect] %s: ok (%s lines)\n' "$what" "$(wc -l < "$out")" >> "$MANIFEST"
    else
        printf '[collect] %s: failed\n' "$what" >> "$MANIFEST"
        : > "$out"   # don't ship a half-written/empty-error file
    fi
}

# --- 1. process & task status ------------------------------------------------

collect_ps() {
    ps aux | grep -E 'agentpvm|umlctl|linux.*ubd0' || echo "(no matching processes)"
}

collect_state_list() {
    local root=${PVM_STATE_ROOT:-$HOME/.local/share/pvm}
    [ -d "$root" ] || { echo "(state dir not found: $root)"; return 0; }
    ls -la "$root"
    find "$root" -type f -name '*.json' | sort
}

collect_state_files() { # copy every *.json state file (contents, redacted later)
    local root=${PVM_STATE_ROOT:-$HOME/.local/share/pvm} f rel
    [ -d "$root" ] || { echo "(state dir not found: $root)"; return 0; }
    while IFS= read -r f; do
        rel=${f#"$root"/}
        echo "==== $rel ===="
        cat "$f" || echo "(unreadable)"
        echo
    done < <(find "$root" -type f -name '*.json' | sort)
}

# --- 2. per-task console logs --------------------------------------------------

collect_logs() {
    local dir=${PVM_LOG_DIR:-$HOME/.local/share/pvm/logs} f rel want m keep
    [ -d "$dir" ] || { echo "(log dir not found: $dir)"; return 0; }
    local found=0
    while IFS= read -r f; do
        rel=${f#"$dir"/}
        keep=1
        if [ ${#MODULES[@]} -gt 0 ]; then
            keep=0
            for m in "${MODULES[@]}"; do
                case "$rel" in *"$m"*) keep=1; break ;; esac
            done
        fi
        [ "$keep" -eq 1 ] || continue
        found=1
        echo "==== $rel (tail -n $LINES) ===="
        tail -n "$LINES" "$f" 2>/dev/null || echo "(unreadable)"
        echo
    done < <(find "$dir" -type f -name 'console.log' | sort)
    [ "$found" -eq 1 ] || echo "(no console.log files matched filters under $dir)"
}

# --- 3. system ------------------------------------------------------------------

collect_uname()   { uname -a; }
collect_uptime()  { uptime; }
collect_df()      { df -h; }
collect_free()    { free -m; }
collect_ip()      { ip addr 2>/dev/null || ifconfig -a 2>/dev/null || echo "(ip/ifconfig unavailable)"; }
collect_sysctl()  { sysctl kernel.unprivileged_userns_clone 2>/dev/null || true; }

collect_dmesg() {
    local out
    if out=$(dmesg 2>/dev/null | tail -n "$LINES") && [ -n "$out" ]; then
        printf '%s\n' "$out"
    else
        # Unprivileged dmesg is commonly restricted (kernel.dmesg_restrict=1):
        # skip, but leave an explicit note in the bundle.
        echo "[collect] dmesg: skipped (no permission or empty output)"
    fi
}

# --- 4. config presence (names only — NEVER values) -----------------------------

collect_env_names() {
    local name
    # Probe the union of (PVM_* / *SECRET* currently exported) and a few
    # well-known names, reporting only NAME=set / NAME=(unset).
    {
        env | cut -d= -f1 | grep -E '^(PVM_|API_SECRET|.*SECRET.*)$' | sort -u
        printf '%s\n' API_SECRET PVM_API_KEYS PVM_STATE_ROOT PVM_LOG_DIR \
                      PVM_AUDIT_ROOT PVM_CGROUP_ROOT PVM_KERNEL PVM_ENVD_ENABLED
    } | sort -u | while IFS= read -r name; do
        if [ -n "${!name+x}" ]; then
            printf '%s=set\n' "$name"
        else
            printf '%s=(unset)\n' "$name"
        fi
    done
}

collect_env_file_keys() {
    local f candidates=("$PVM_ENV_FILE" /etc/pvm/pvm.env "$SCRIPT_DIR/pvm.env")
    for f in "${candidates[@]}"; do
        [ -n "$f" ] && [ -f "$f" ] || continue
        echo "==== $f (key names only) ===="
        # KEY=VALUE lines contribute the KEY only; comments/blanks dropped.
        grep -E '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=' "$f" \
            | sed -E 's/^[[:space:]]*([A-Za-z0-9_]+)[[:space:]]*=.*/\1/' | sort -u
    done
    [ -f /etc/pvm/pvm.env ] || [ -n "${PVM_ENV_FILE:-}" ] || echo "(no pvm.env-style file found)"
}

# ---------------------------------------------------------------------------
# Main collection flow
# ---------------------------------------------------------------------------
collect_all() {
    STAGING=$(mktemp -d "${TMPDIR:-/tmp}/pvm-diag-staging.XXXXXX")
    MANIFEST="$STAGING/manifest.txt"
    : > "$MANIFEST"

    step "ps aux (pvm processes)" "process/ps-pvm.txt"            collect_ps
    step "state dir listing"      "state/listing.txt"              collect_state_list
    step "state *.json contents"  "state/state-files.txt"          collect_state_files
    step "console logs"           "logs/console-logs.txt"          collect_logs
    step "uname -a"               "system/uname.txt"               collect_uname
    step "uptime"                 "system/uptime.txt"              collect_uptime
    step "df -h"                  "system/df.txt"                  collect_df
    step "free -m"                "system/free.txt"                collect_free
    step "ip addr"                "system/ip-addr.txt"             collect_ip
    step "dmesg tail"             "system/dmesg.txt"               collect_dmesg
    step "sysctl userns_clone"    "system/sysctl.txt"              collect_sysctl
    step "env var names"          "config/env-vars.txt"            collect_env_names
    step "env file key names"      "config/env-file-keys.txt"       collect_env_file_keys

    # Second redaction pass over EVERYTHING in staging (manifest included):
    # collectors are supposed to pipe through redact(), but one missed path
    # must not leak a secret into the shipped bundle.
    local f
    while IFS= read -r f; do
        redact_file "$f"
    done < <(find "$STAGING" -type f)

    # Pack.
    [ -n "$OUT_DIR" ] || OUT_DIR=/tmp
    mkdir -p "$OUT_DIR"
    local tgz="$OUT_DIR/pvm-diag-$(hostname)-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
    tar -czf "$tgz" -C "$STAGING" .
    rm -rf "$STAGING"
    STAGING=""

    # Summary.
    log "artifact: $tgz"
    log "size:     $(du -sh "$tgz" | cut -f1)"
    log "contents:"
    tar -tzf "$tgz" | sed 's/^/  /'
}

# ---------------------------------------------------------------------------
# --selftest: fake state/logs/env-file seeded with canary secrets, full run,
# then assert the tar is non-empty and no canary survives in cleartext.
# ---------------------------------------------------------------------------
selftest() {
    local tmp out tgz xdir canary
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' RETURN

    mkdir -p "$tmp/state/task-alpha" "$tmp/state/task-beta" \
             "$tmp/logs/task-alpha/logs" "$tmp/logs/task-beta/logs" "$tmp/deploy"
    printf '{"name":"task-alpha","pid":123,"api_secret":"SELFTEST_CANARY_STATE"}\n' \
        > "$tmp/state/task-alpha/state.json"
    printf '{"name":"task-beta","pid":456,"api_secret":"SELFTEST_CANARY_STATE"}\n' \
        > "$tmp/state/task-beta/state.json"
    printf 'boot ok\nAuthorization: Bearer SELFTEST_CANARY_BEARER\ntoken=SELFTEST_CANARY_TOKEN\nPVM_API_KEYS=SELFTEST_CANARY_KEY\nlink/ether 52:54:00:aa:bb:cc addr 10.0.0.5\n' \
        > "$tmp/logs/task-alpha/logs/console.log"
    printf 'beta boot ok\n' > "$tmp/logs/task-beta/logs/console.log"
    printf '# comment\nAPI_SECRET=SELFTEST_CANARY_ENVFILE\nPVM_STATE_ROOT=/var/lib/pvm/state\n' \
        > "$tmp/deploy/pvm.env"

    log "selftest: running full collection against fake data in $tmp"
    PVM_STATE_ROOT="$tmp/state" \
    PVM_LOG_DIR="$tmp/logs" \
    PVM_ENV_FILE="$tmp/deploy/pvm.env" \
    PVM_API_KEYS=SELFTEST_CANARY_ENVVAR \
    API_SECRET=SELFTEST_CANARY_ENVVAR2 \
        "$BASH" "${BASH_SOURCE[0]}" --out "$tmp/out" --lines 10 > "$tmp/run.log" 2>&1 \
        || { cat "$tmp/run.log"; die "selftest: collection run failed"; }

    tgz=$(find "$tmp/out" -name 'pvm-diag-*.tar.gz' | head -n 1)
    [ -n "$tgz" ] || die "selftest: no pvm-diag-*.tar.gz produced"
    tar -tzf "$tgz" | grep -qE '(state|logs)/' || die "selftest: tar has no state/log content"

    xdir="$tmp/extracted"
    mkdir -p "$xdir"
    tar -xzf "$tgz" -C "$xdir"

    local failed=0
    for canary in SELFTEST_CANARY_STATE SELFTEST_CANARY_BEARER SELFTEST_CANARY_TOKEN \
                  SELFTEST_CANARY_KEY SELFTEST_CANARY_ENVFILE \
                  SELFTEST_CANARY_ENVVAR SELFTEST_CANARY_ENVVAR2 'aa:bb:cc'; do
        if grep -r -F -q "$canary" "$xdir"; then
            warn "selftest: canary leaked: $canary"
            failed=1
        fi
    done
    # Positive checks: masking actually happened, IPs preserved.
    grep -r -F -q 'Bearer ***' "$xdir/logs"   || { warn "selftest: Bearer not masked"; failed=1; }
    grep -r -F -q '52:54:00:xx:xx:xx' "$xdir" || { warn "selftest: MAC not masked";   failed=1; }
    grep -r -F -q '10.0.0.5' "$xdir"          || { warn "selftest: IP not preserved"; failed=1; }
    grep -r -F -q '***' "$xdir/state"         || { warn "selftest: state secret not masked"; failed=1; }
    grep -r -F -q 'API_SECRET' "$xdir/config" || { warn "selftest: env file keys missing"; failed=1; }

    [ "$failed" -eq 0 ] || die "selftest: FAILED (see warnings above)"
    log "selftest: PASS (bundle at $tgz)"
}

# ---------------------------------------------------------------------------
if [ "$SELFTEST" -eq 1 ]; then
    selftest
else
    collect_all
fi
