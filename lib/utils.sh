#!/usr/bin/env bash
# sourced, not executed.
# log, die, require, run, skip_if_done,
# targets_from_gnmap, sanitize_tag, resolve_tool, ensure_dir

# colors only if stdout is a tty (so piped output stays clean)
if [[ -t 1 ]]; then
    C_INFO='\033[0;34m'; C_OK='\033[0;32m'; C_WARN='\033[0;33m'
    C_ERR='\033[0;31m';  C_OFF='\033[0m'
else
    C_INFO=''; C_OK=''; C_WARN=''; C_ERR=''; C_OFF=''
fi

# colored, tagged line to stderr; plain timestamped copy to $RUN_LOG if set.
# keeping the timestamp out of the terminal keeps the live output readable while
# the log file stays useful for reconstructing incase of mimimi
_emit() {
    local color=$1 tag=$2; shift 2
    printf "${color}[${tag}]${C_OFF} %s\n" "$*" >&2
    [[ -n ${RUN_LOG:-} ]] && \
        printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$tag" "$*" >> "$RUN_LOG"
}

log()  { _emit "$C_INFO" '*' "$*"; }
ok()   { _emit "$C_OK"   '+' "$*"; }
warn() { _emit "$C_WARN" '!' "$*"; }

# die() — GLOBAL fatal only (bad args, unwritable engagement dir). Hard-exits.
# Do NOT call from inside a step: steps run in subshells (see recon.sh), so a
# die there kills only the subshell and silently changes nothing. Steps signal
# with abort_step / skip_step instead.
die()  { _emit "$C_ERR"  'x' "$*"; exit 1; }

# abort_step "reason" — the step needs an input it does not have (wrong order,
# or the user must supply it). Loud [x]; returns non-zero so the run loop counts
# it as a failed step.   usage:  require nmap || return 1
abort_step() { _emit "$C_ERR"  'x' "$*"; return 1; }

# skip_step "reason" — the step legitimately has nothing to do (empty result,
# optional input absent). Quiet [-]; returns 0, so it is NOT counted a failure.
#   usage:  [[ -n $targets ]] || { skip_step "no TLS ports"; return 0; }
skip_step() { _emit "$C_WARN" '-' "$*"; return 0; }

# require nmap ffuf httpx  -> non-zero (via abort_step) if any are missing.
#   usage:  require nmap jq || return 1
require() {
    local missing=()
    for bin in "$@"; do
        command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
    done
    (( ${#missing[@]} == 0 )) || abort_step "missing tools: ${missing[*]}"
}

# require_file wordlist.txt ...  -> non-zero if any are missing/unreadable.
# Use before handing a path to ffuf/feroxbuster so they fail fast and clearly.
#   usage:  require_file "$WORDLIST" || return 1
require_file() {
    local f
    for f in "$@"; do
        [[ -r $f ]] || { abort_step "missing/unreadable file: $f"; return 1; }
    done
}

# need_file <path> <reason>  -> ok if the file exists and is non-empty, else
# abort_step. For "run the earlier step first" preconditions (hosts.txt, gnmap).
#   usage:  need_file "$hosts" "no live hosts — run ping first" || return 1
need_file() { [[ -s $1 ]] || abort_step "$2"; }

# run "description" cmd arg1 arg2 ...
# Logs the command, runs it, reports failure but doesn't exit.
run() {
    local desc=$1; shift
    log "$desc"
    log "  \$ $*"
    if "$@"; then
        ok "$desc — done"
    else
        warn "$desc — failed (exit $?)"
        return 1
    fi
}

# skip a step if its output file exists and is non-empty.
# Usage:  skip_if_done "$out" && return 0
skip_if_done() {
    local marker=$1
    if [[ -s $marker ]]; then
        ok "skip (exists): $marker"
        return 0
    fi
    return 1
}

# Shared parsing/naming helpers
# Extracted so every module (web, ssl, screenshots, banner-grab, ...) derives
# targets and filenames the same way instead of re-implementing the awk/sed.

# targets_from_gnmap <gnmap-file> [ports-csv]
# Print "ip:port" for each OPEN tcp port in an nmap greppable (-oG/-oA) file.
# With ports-csv (e.g. "443,8443") only those ports are emitted; without it,
# every open port. Output is unsorted — callers pipe through `sort -u`.
# Returns 1 if the gnmap file is missing/empty.
targets_from_gnmap() {
    local gnmap=$1 ports=${2:-}
    [[ -s $gnmap ]] || return 1
    local filter
    filter=$(echo "$ports" | tr -d '[:space:]')
    awk -v want="$filter" '
        BEGIN {
            usefilter = (want != "")
            n = split(want, w, ",")
            for (i = 1; i <= n; i++) wp[w[i]] = 1
        }
        /Ports:/ {
            # IP follows "Host: "
            match($0, /Host: [0-9.]+/)
            ip = substr($0, RSTART + 6, RLENGTH - 6)

            # Everything after "Ports: "; drop a trailing "Ignored State: ..."
            p = index($0, "Ports: ")
            if (p == 0) next
            ports_str = substr($0, p + 7)
            sub(/\tIgnored State:.*/, "", ports_str)

            # Entries look like " 80/open/tcp//http///"
            n = split(ports_str, entries, ",")
            for (i = 1; i <= n; i++) {
                gsub(/^[ \t]+/, "", entries[i])
                split(entries[i], f, "/")
                port = f[1]; state = f[2]
                if (state == "open" && (!usefilter || (port in wp)))
                    print ip ":" port
            }
        }
    ' "$gnmap"
}

# sanitize_tag <url-or-host>  ->  filesystem-safe tag on stdout
# https://10.10.10.3:8443/  ->  10.10.10.3_8443
sanitize_tag() {
    echo "$1" | sed -E 's#https?://##; s#[:/]+#_#g; s#_+$##'
}

# resolve_tool <name> <fallback-path>  -> best location on stdout
# prefer the tool on $PATH; otherwise use the fallback in $TOOLS_DIR
resolve_tool() {
    local name=$1 fallback=$2
    if command -v "$name" >/dev/null 2>&1; then
        command -v "$name"
    else
        printf '%s\n' "$fallback"
    fi
}

# Inverse of resolve_tool: prefer the pinned build at <preferred-path> (a source
# build under $TOOLS_DIR is often newer than the distro package) and fall back
# to $PATH only if that build isn't present. If neither exists, print the
# preferred path so the caller's `require` fails naming the location we expected.
# Use for tools whose packaged version lags the features we need — e.g. httpx on
# Kali (kali-linux-default) is older than the ProjectDiscovery build we compile.
resolve_tool_local() {
    local name=$1 preferred=$2
    if [[ -x $preferred ]]; then
        printf '%s\n' "$preferred"
    elif command -v "$name" >/dev/null 2>&1; then
        command -v "$name"
    else
        printf '%s\n' "$preferred"
    fi
}

# ensure_dir <dir> ...  ->  mkdir -p each
# Lets a module guarantee its own output directory at call time instead of
# relying on the central mkdir in recon.sh — new modules just call this.
ensure_dir() { mkdir -p "$@"; }
