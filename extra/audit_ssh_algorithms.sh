#!/usr/bin/env bash
# before run -> nmap -sC -sV -p22 --script=ssh2-enum-algos -oN ssh2-enum-algo IP
# usage: ./audit_ssh_algorithms.sh <scan-file> [mozilla-file] [legacy-file]
#   green   = on the recommended list   (mozilla.txt)
#   red     = on the explicit legacy/deny list  (legacy.txt), tagged [LEGACY]
#   yellow  = neither listed (unknown / not yet rated)
#

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

SCAN_FILE="${1:?Usage: $0 <scan-file> [mozilla-file] [legacy-file]}"
MOZILLA_FILE="${2:-$SCRIPT_DIR/mozilla.txt}"
LEGACY_FILE="${3:-$SCRIPT_DIR/legacy.txt}"

[[ -f "$SCAN_FILE" ]] || { echo "Scan file not found: $SCAN_FILE" >&2; exit 1; }
[[ -f "$MOZILLA_FILE" ]] || { echo "Mozilla reference file not found: $MOZILLA_FILE" >&2; exit 1; }

RED=$'\e[1;31m'
GREEN=$'\e[32m'
YELLOW=$'\e[33m'
RESET=$'\e[0m'

# parse a "#Section" + comma-list rules into array
load_rules() {
    local file="$1"
    local -n out="$2"
    local current=""
    [[ -f "$file" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        [[ -z "$line" ]] && continue
        if [[ "$line" =~ ^#(.+)$ ]]; then
            current="${BASH_REMATCH[1]}"
            continue
        fi
        if [[ -n "$current" ]]; then
            out["$current"]="$line"
            current=""
        fi
    done < "$file"
}

declare -A MOZ_LIST
declare -A LEGACY_LIST
load_rules "$MOZILLA_FILE" MOZ_LIST
load_rules "$LEGACY_FILE" LEGACY_LIST

list_has() {
    local -n list_ref="$1"
    local section="$2" algo="$3"
    local list="${list_ref[$section]:-}"
    [[ -z "$list" ]] && return 1
    local IFS=','
    local items=($list)
    for item in "${items[@]}"; do
        [[ "$item" == "$algo" ]] && return 0
    done
    return 1
}

# map nmap's block names to the rules-file section names
declare -A SECTION_MAP=(
    [kex_algorithms]="KexAlgorithms"
    [server_host_key_algorithms]="HostKeyAlgorithms"
    [encryption_algorithms]="Ciphers"
    [mac_algorithms]="MACs"
    [compression_algorithms]="Compression"
)

good_count=0
legacy_count=0
unknown_count=0
current_section=""

while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"

    # section header, e.g. "|   kex_algorithms: (10)"
    if [[ "$line" =~ ([a-z_]+algorithms): ]]; then
        current_section="${SECTION_MAP[${BASH_REMATCH[1]}]:-}"
        echo "$line"
        continue
    fi

    # algorithm entry line inside a tracked section, e.g. "|hmac-sha1" or "|_zlib@openssh.com"
    if [[ -n "$current_section" && "$line" =~ ^(\|[_\ ]*[[:space:]]*)([A-Za-z0-9@._-]+)([[:space:]]*)$ ]]; then
        prefix="${BASH_REMATCH[1]}"
        algo="${BASH_REMATCH[2]}"
        trail="${BASH_REMATCH[3]}"
        if list_has LEGACY_LIST "$current_section" "$algo"; then
            echo "${prefix}${RED}${algo} [LEGACY]${RESET}${trail}"
            legacy_count=$((legacy_count + 1))
        elif list_has MOZ_LIST "$current_section" "$algo"; then
            echo "${prefix}${GREEN}${algo}${RESET}${trail}"
            good_count=$((good_count + 1))
        else
            echo "${prefix}${YELLOW}${algo}${RESET}${trail}"
            unknown_count=$((unknown_count + 1))
        fi
        continue
    fi

    # leaving the "|"-indented block resets section tracking
    [[ "$line" != \|* ]] && current_section=""
    echo "$line"
done < "$SCAN_FILE"

echo
echo "Summary: ${GREEN}${good_count} recommended${RESET}, ${RED}${legacy_count} legacy${RESET}, ${YELLOW}${unknown_count} unlisted${RESET}"
