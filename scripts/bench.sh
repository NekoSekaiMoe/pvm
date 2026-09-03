#!/usr/bin/env bash
# bench.sh — latency benchmark for a running agentpvm REST API.
#
# Purpose:
#   Drive the real PVM lifecycle endpoints (create/pause/resume/snapshot/
#   clone/rollback) N times each, record curl's time_total per call, and
#   report min/avg/p50/p95/max/wall plus success counts per operation.
#   Failures (HTTP 4xx/5xx, connection errors) are counted, never abort
#   the run; every created task is cleaned up at the end (best effort).
#
# Usage:
#   ./scripts/bench.sh --api http://127.0.0.1:8080 --key "$API_SECRET" \
#       --op create,pause,resume,snapshot,clone,rollback --n 20 \
#       --template rootfs.img [--pause 0.2] [--json] [--dry-run]
#   ./scripts/bench.sh --list-ops
#   ./scripts/bench.sh --selftest
#
# Options:
#   --api URL        base URL of the API       (default http://127.0.0.1:8080)
#   --key KEY        API key (Bearer first, X-API-KEY fallback; also read
#                    from $API_SECRET) — required unless --dry-run/--list-ops
#   --op LIST        comma-separated ops       (default: all, see --list-ops)
#   --n N            lifecycle iterations      (default 10; each selected op
#                    is measured N times)
#   --template PATH  rootfs passed to create   (required when 'create' or any
#                    dependent op is selected; absolute path under the
#                    server's image dir, e.g. /var/lib/uml-container/images/…)
#   --pause SEC      sleep between ops         (default 0.2, be gentle)
#   --timeout SEC    per-request curl timeout  (default 120)
#   --json           one JSON line per op instead of the human table
#   --dry-run        print the curl command sequence, send nothing
#   --list-ops       list supported operations and exit
#   --selftest       run the built-in dry-run assertions and exit
#
# Dependencies: bash, curl, awk, and standard coreutils (sort/head/tail/grep).
# No jq, no python. Task names are unique per run: bench-<pid>-<i> (and
# bench-<pid>-<i>-c for clones) — they satisfy the API's ^[a-zA-Z0-9_-]+$ id
# regex. Rollback targets the snapshot taken in the same iteration.
#
# Exit codes:
#   0  success (including --dry-run/--selftest)
#   1  fatal error (missing --key/--template, unreachable setup, selftest
#      assertion failure) — HTTP failures of individual calls are NOT fatal
#   2  usage error (unknown option, unknown op, bad --n/--pause)
#
# wall per op = Σ time_total over ALL N attempts (successes + failures);
# latency percentiles are computed over successful attempts only
# (nearest-rank method), so p50/p95 need ≥1 success else they print "-".

set -euo pipefail

SCRIPT_NAME=$(basename "$0")

log()  { printf '[bench] %s\n' "$*"; }
warn() { printf '[bench][warn] %s\n' "$*" >&2; }
die()  { printf '[bench][error] %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '2,48p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# Configuration (overridden by argv in main)
# ---------------------------------------------------------------------------
API="http://127.0.0.1:8080"
KEY="${API_SECRET:-}"
OPS_STR="create,pause,resume,snapshot,clone,rollback"
N=10
TEMPLATE=""
PAUSE_SEC=0.2
TIMEOUT=120
JSON_OUT=0
DRY_RUN=0
LIST_OPS=0
SELFTEST=0

ALL_OPS=(create pause resume snapshot clone rollback)
TMPDIR_BENCH=$(mktemp -d "${TMPDIR:-/tmp}/pvm-bench.XXXXXX")
trap 'rm -rf "$TMPDIR_BENCH"' EXIT

AUTH_MODE="bearer"        # probed at start: bearer | xapikey
CREATED=()                # task ids to DELETE at cleanup (clones included)
BODY=""                   # last response body
R_CODE=""                 # last http code (000 = curl-level failure)
R_TIME=""                 # last time_total seconds

# ---------------------------------------------------------------------------
# op endpoint map (the real PVM routes, see internal/api/e2b_server.go)
# ---------------------------------------------------------------------------
op_endpoint() { # op -> "METHOD PATH" (path is API-relative)
    case "$1" in
        create)   echo "POST /api/containers/start" ;;
        pause)    echo "POST /api/tasks/ID/pause" ;;
        resume)   echo "POST /api/tasks/ID/resume" ;;
        snapshot) echo "POST /api/tasks/ID/snapshots" ;;
        clone)    echo "POST /api/tasks/ID/clone" ;;
        rollback) echo "POST /api/tasks/ID/rollback" ;;
        *)        return 1 ;;
    esac
}

list_ops() {
    cat <<'EOF'
Supported operations and their PVM API endpoints:

  op        method  endpoint                     request body
  ----      ------  --------                     ------------
  create    POST    /api/containers/start        {"name":"bench-PID-i","rootfs":TEMPLATE}
  pause     POST    /api/tasks/:id/pause         (none; task must be RUNNING)
  resume    POST    /api/tasks/:id/resume        (none)
  snapshot  POST    /api/tasks/:id/snapshots     {"event_id":""}
  clone     POST    /api/tasks/:id/clone         {"new_id":"bench-PID-i-c"}
  rollback  POST    /api/tasks/:id/rollback      {"snapshot_id":<this iteration's snapshot>}

Lifecycle per iteration i: create -> pause -> resume -> snapshot -> clone ->
rollback, so every selected op gets one sample per iteration. Tasks created
for setup (when 'create' itself is not selected) are also cleaned up.
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# request layer
# ---------------------------------------------------------------------------
curl_request() { # method url [json-body] -> BODY / R_CODE / R_TIME
    local method=$1 url=$2 body=${3:-} out hdr
    if [ "$DRY_RUN" -eq 1 ]; then
        hdr="-H 'Authorization: Bearer <KEY>'"
        [ "$AUTH_MODE" = "xapikey" ] && hdr="-H 'X-API-KEY: <KEY>'"
        printf 'curl -X %s %s' "$method" "$hdr"
        if [ -n "$body" ]; then
            printf " -H 'Content-Type: application/json' -d '%s'" "$body"
        fi
        printf " '%s'\n" "$url"
        BODY='{"id":"dry-run"}'
        R_CODE=200
        R_TIME=0.000000
        return 0
    fi
    local args=( -s -X "$method" -w $'\n%{http_code} %{time_total}'
                 --max-time "$TIMEOUT" )
    case "$AUTH_MODE" in
        bearer)  args+=( -H "Authorization: Bearer $KEY" ) ;;
        xapikey) args+=( -H "X-API-KEY: $KEY" ) ;;
    esac
    if [ -n "$body" ]; then
        args+=( -H 'Content-Type: application/json' --data "$body" )
    fi
    # curl exits nonzero on connect/timeout errors: synthesize code 000 so the
    # caller counts a failure instead of dying under set -e.
    if ! out=$(curl "${args[@]}" "$url" 2>"$TMPDIR_BENCH/curl.err"); then
        warn "curl $method $url failed: $(head -n1 "$TMPDIR_BENCH/curl.err")"
        out=$'\n000 0.000000'
    fi
    BODY=${out%$'\n'*}
    read -r R_CODE R_TIME <<< "${out##*$'\n'}"
    return 0
}

request_ok() { # was the last request a 2xx/3xx?
    [ "$R_CODE" -ge 200 ] 2>/dev/null && [ "$R_CODE" -lt 400 ] 2>/dev/null
}

probe_auth() { # pick Bearer vs X-API-KEY once, via GET /api/tasks
    [ "$DRY_RUN" -eq 1 ] && return 0
    local mode code
    for mode in bearer xapikey; do
        AUTH_MODE=$mode
        if [ "$mode" = "bearer" ]; then
            code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
                        -H "Authorization: Bearer $KEY" "$API/api/tasks" 2>/dev/null) || code=000
        else
            code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
                        -H "X-API-KEY: $KEY" "$API/api/tasks" 2>/dev/null) || code=000
        fi
        if [ "$code" -ge 200 ] 2>/dev/null && [ "$code" -lt 400 ] 2>/dev/null; then
            log "auth: '$mode' header accepted (probe GET /api/tasks -> $code)"
            return 0
        fi
        warn "auth probe with '$mode' header rejected (code $code)"
    done
    AUTH_MODE=bearer
    warn "both auth styles rejected; continuing with Bearer (check --key)"
}

# ---------------------------------------------------------------------------
# benchmark bookkeeping
# ---------------------------------------------------------------------------
wants() { # is op selected?
    case ",$OPS_STR," in *",$1,"*) return 0 ;; esac
    return 1
}

record() { # op code time
    printf '%s\t%s\n' "$2" "$3" >> "$TMPDIR_BENCH/$1.tsv"
}

run_op() { # op method path-template-with-ID [body] -> records, returns ok?
    local op=$1 method=$2 path=$3 body=${4:-}
    curl_request "$method" "$API$path" "$body"
    record "$op" "$R_CODE" "$R_TIME"
    request_ok
}

record_fail() { # op (dependency missing — no request was sent)
    record "$1" 000 0.000000
    return 0
}

between_ops() { # throttle, skipped in dry-run for speed
    [ "$DRY_RUN" -eq 1 ] && return 0
    [ "$PAUSE_SEC" != "0" ] && sleep "$PAUSE_SEC"
    return 0
}

json_field() { # extract "key":"value" from BODY without jq
    printf '%s' "$BODY" | grep -o "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
        | head -n1 | sed 's/.*"\([^"]*\)"$/\1/'
}

# ---------------------------------------------------------------------------
# cleanup: DELETE every created task (clones first — a parent with live
# clones is refused with 409). Best effort: failures only warn.
# ---------------------------------------------------------------------------
cleanup() {
    local i id
    # reverse order: clones are pushed after their parent, and the API
    # refuses to delete a parent that still has live clones (409).
    for (( i=${#CREATED[@]}-1; i>=0; i-- )); do
        id=${CREATED[$i]}
        curl_request DELETE "$API/api/containers/$id"
        [ "$DRY_RUN" -eq 1 ] || request_ok \
            || warn "cleanup: DELETE /api/containers/$id -> $R_CODE (left behind?)"
    done
    # main()'s `trap cleanup EXIT` REPLACED the mktemp trap registered at
    # startup, so the temp dir must be removed here or every run leaks one.
    rm -rf "$TMPDIR_BENCH"
}

# ---------------------------------------------------------------------------
# main benchmark loop
# ---------------------------------------------------------------------------
main() {
    local i name clone_name snap_id create_ok
    trap cleanup EXIT

    API=${API%/}
    for op in ${ALL_OPS[@]}; do
        wants "$op" && : > "$TMPDIR_BENCH/$op.tsv"
    done

    probe_auth
    log "benchmark: api=$API ops=$OPS_STR n=$N pause=${PAUSE_SEC}s auth=$AUTH_MODE dry_run=$DRY_RUN"

    for i in $(seq 1 "$N"); do
        name="bench-$$-$i"
        clone_name="bench-$$-$i-c"
        snap_id=""

        # -- create (timed when selected; otherwise untimed setup) ----------
        create_ok=0
        if wants create; then
            if run_op create POST /api/containers/start \
                    "{\"name\":\"$name\",\"rootfs\":\"$TEMPLATE\"}"; then
                create_ok=1
            fi
        else
            curl_request POST "$API/api/containers/start" \
                "{\"name\":\"$name\",\"rootfs\":\"$TEMPLATE\"}"
            request_ok && create_ok=1
            [ "$DRY_RUN" -eq 1 ] && create_ok=1
        fi
        if [ "$create_ok" -eq 1 ]; then
            CREATED+=("$name")
        else
            warn "iteration $i: create failed ($R_CODE); marking dependent ops failed"
            wants pause    && record_fail pause
            wants resume   && record_fail resume
            wants snapshot && record_fail snapshot
            wants clone    && record_fail clone
            wants rollback && record_fail rollback
            continue
        fi
        between_ops

        # -- pause / resume --------------------------------------------------
        if wants pause; then
            run_op pause POST "/api/tasks/$name/pause" || warn "pause $name -> $R_CODE"
            between_ops
        fi
        if wants resume; then
            run_op resume POST "/api/tasks/$name/resume" || warn "resume $name -> $R_CODE"
            between_ops
        fi

        # -- snapshot (remember id for rollback) ------------------------------
        if wants snapshot; then
            if run_op snapshot POST "/api/tasks/$name/snapshots" '{"event_id":""}'; then
                snap_id=$(json_field id)
            else
                warn "snapshot $name -> $R_CODE"
            fi
            between_ops
        fi

        # -- clone ------------------------------------------------------------
        if wants clone; then
            if run_op clone POST "/api/tasks/$name/clone" "{\"new_id\":\"$clone_name\"}"; then
                CREATED+=("$clone_name")
            else
                warn "clone $name -> $R_CODE"
            fi
            between_ops
        fi

        # -- rollback (needs this iteration's snapshot) ------------------------
        if wants rollback; then
            if [ -n "$snap_id" ]; then
                run_op rollback POST "/api/tasks/$name/rollback" \
                    "{\"snapshot_id\":\"$snap_id\"}" || warn "rollback $name -> $R_CODE"
            else
                warn "rollback $name skipped: no snapshot id from this iteration"
                record_fail rollback
            fi
        fi
    done

    report
}

# ---------------------------------------------------------------------------
# stats: min/avg/p50/p95/max over successes (nearest-rank), wall over all
# ---------------------------------------------------------------------------
pctl() { # sorted-times-on-stdin percentile -> stdout
    awk -v p="$1" 'NR { v[NR] = $1; n = NR }
        END {
            if (n == 0) { print "-"; exit }
            i = int(p * n + 0.999999); if (i < 1) i = 1; if (i > n) i = n
            printf "%.6f\n", v[i]
        }'
}

report() {
    local op f ok fail wall sorted min avg p50 p95 max
    if [ "$JSON_OUT" -eq 0 ]; then
        printf '%-10s %5s %5s %5s %10s %10s %10s %10s %10s %10s\n' \
            OP N OK FAIL MIN AVG P50 P95 MAX WALL
    fi
    for op in ${ALL_OPS[@]}; do
        wants "$op" || continue
        f="$TMPDIR_BENCH/$op.tsv"
        read -r ok fail wall <<< "$(awk -F'\t' '
            { t = $2 + 0; wall += t
              if ($1 + 0 >= 200 && $1 + 0 < 400) ok++; else fail++ }
            END { printf "%d %d %.6f\n", ok + 0, fail + 0, wall }' "$f")"
        if [ "$ok" -gt 0 ]; then
            sorted=$(awk -F'\t' '$1 + 0 >= 200 && $1 + 0 < 400 { printf "%.6f\n", $2 }' "$f" | sort -n)
            min=$(head -n1 <<< "$sorted")
            max=$(tail -n1 <<< "$sorted")
            avg=$(awk '{ s += $1 } END { printf "%.6f\n", s / NR }' <<< "$sorted")
            p50=$(pctl 0.50 <<< "$sorted")
            p95=$(pctl 0.95 <<< "$sorted")
        else
            # NOT a chained assignment: bash would store the literal
            # "avg=p50=p95=max=-" into min and leave the rest unset,
            # which set -u turns into a hard crash while printing the
            # report — exactly when an op's requests all failed.
            min="-"; avg="-"; p50="-"; p95="-"; max="-"
        fi
        if [ "$JSON_OUT" -eq 1 ]; then
            printf '{"op":"%s","n":%d,"ok":%d,"fail":%d,"min":%s,"avg":%s,"p50":%s,"p95":%s,"max":%s,"wall":%s}\n' \
                "$op" "$N" "$ok" "$fail" \
                "$(json_num "$min")" "$(json_num "$avg")" "$(json_num "$p50")" \
                "$(json_num "$p95")" "$(json_num "$max")" "$(json_num "$wall")"
        else
            printf '%-10s %5d %5d %5d %10s %10s %10s %10s %10s %10s\n' \
                "$op" "$N" "$ok" "$fail" "$min" "$avg" "$p50" "$p95" "$max" "$wall"
        fi
    done
}

json_num() { # "-" -> null (unquoted), numbers pass through
    if [ "$1" = "-" ]; then echo null; else printf '%s' "$1"; fi
}

# ---------------------------------------------------------------------------
# selftest: run the full flow in --dry-run and assert the generated command
# sequence hits every real endpoint with the right method. Nothing is sent.
# ---------------------------------------------------------------------------
selftest() {
    local out failed=0
    out=$(mktemp)
    trap 'rm -f "$out"' RETURN

    log "selftest: dry-run flow (no requests are sent)"
    # NOTE: plain assignments inside the subshell (NOT `V=x main` prefix
    # form): prefix assignments on a function call are UNDONE when the
    # function returns, but main's EXIT-trap cleanup fires afterwards and
    # would then see the reverted (live) settings.
    (
        API="http://dryrun.invalid:8080"
        KEY="selftest-key"
        DRY_RUN=1
        N=2
        OPS_STR="create,pause,resume,snapshot,clone,rollback"
        TEMPLATE="/var/lib/uml-container/images/rootfs.img"
        main
    ) > "$out" 2>&1

    local check
    for check in \
        "-X POST .*dryrun\.invalid:8080/api/containers/start" \
        "-X POST .*dryrun\.invalid:8080/api/tasks/bench-[^/]+/pause" \
        "-X POST .*dryrun\.invalid:8080/api/tasks/bench-[^/]+/resume" \
        "-X POST .*dryrun\.invalid:8080/api/tasks/bench-[^/]+/snapshots" \
        "-X POST .*dryrun\.invalid:8080/api/tasks/bench-[^/]+/clone" \
        "-X POST .*dryrun\.invalid:8080/api/tasks/bench-[^/]+/rollback" \
        "-X DELETE .*dryrun\.invalid:8080/api/containers/bench-[^/]+" \
        "Authorization: Bearer <KEY>" \
        '"rootfs":"/var/lib/uml-container/images/rootfs.img"' \
        '"event_id":""' \
    ; do
        if ! grep -Eq -- "$check" "$out"; then
            warn "selftest: missing expected command matching: $check"
            failed=1
        fi
    done
    # rollback must reference the (dry-run) snapshot id, not an empty string
    if grep -q '"snapshot_id":""' "$out"; then
        warn "selftest: rollback body has an empty snapshot_id"
        failed=1
    fi

    if [ "$failed" -ne 0 ]; then
        sed 's/^/  | /' "$out" >&2
        die "selftest: FAILED"
    fi
    log "selftest: PASS ($(grep -c '^curl ' "$out") commands generated)"
}

# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --api)      [ $# -ge 2 ] || die "--api requires a value"; API=$2; shift 2 ;;
            --key)      [ $# -ge 2 ] || die "--key requires a value"; KEY=$2; shift 2 ;;
            --op)       [ $# -ge 2 ] || die "--op requires a value"; OPS_STR=$2; shift 2 ;;
            --n)        [ $# -ge 2 ] || die "--n requires a value"
                        [[ "$2" =~ ^[0-9]+$ ]] && [ "$2" -gt 0 ] || die "--n must be a positive integer"
                        N=$2; shift 2 ;;
            --template) [ $# -ge 2 ] || die "--template requires a value"; TEMPLATE=$2; shift 2 ;;
            --pause)    [ $# -ge 2 ] || die "--pause requires a value"
                        [[ "$2" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "--pause must be a non-negative number"
                        PAUSE_SEC=$2; shift 2 ;;
            --timeout)  [ $# -ge 2 ] || die "--timeout requires a value"
                        [[ "$2" =~ ^[0-9]+$ ]] && [ "$2" -gt 0 ] || die "--timeout must be a positive integer"
                        TIMEOUT=$2; shift 2 ;;
            --json)     JSON_OUT=1; shift ;;
            --dry-run)  DRY_RUN=1; shift ;;
            --list-ops) LIST_OPS=1; shift ;;
            --selftest) SELFTEST=1; shift ;;
            -h|--help)  usage 0 ;;
            *)          printf '[bench][error] unknown option: %s\n' "$1" >&2; usage 2 ;;
        esac
    done
}

parse_args "$@"

[ "$LIST_OPS" -eq 1 ] && list_ops

if [ "$SELFTEST" -eq 1 ]; then
    selftest
    exit 0
fi

# validate ops (plain comma-separated list; wants() matches on ",op,")
IFS=',' read -r -a _ops <<< "${OPS_STR//[[:space:]]/}"
[ "${#_ops[@]}" -gt 0 ] && [ -n "${_ops[0]}" ] || die "no ops selected (see --list-ops)"
for op in "${_ops[@]}"; do
    op_endpoint "$op" > /dev/null || die "unknown op '$op' (see --list-ops)"
done

# key: required unless dry-run (a placeholder is fine there)
if [ -z "$KEY" ] && [ "$DRY_RUN" -eq 0 ]; then
    die "missing --key (or export API_SECRET)"
fi

# template: every op in the default set needs a task to exist
if [ -z "$TEMPLATE" ]; then
    die "missing --template (rootfs image path, e.g. /var/lib/uml-container/images/rootfs.img)"
fi

main
