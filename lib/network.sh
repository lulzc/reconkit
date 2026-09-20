#!/usr/bin/env bash

net_ping_sweep() {
    require nmap || return 1
    local scope=$ENGAGEMENT/scope.txt
    local out=$ENGAGEMENT/evidence/scans/network/alive
    local hosts=$ENGAGEMENT/evidence/scans/network/hosts.txt

    need_file "$scope" "missing scope file: $scope" || return 1
    skip_if_done "$hosts" && return 0

    run "ping sweep" \
        sudo nmap -sn -n -PE -iL "$scope" -oG "$out"

    # gnmap has one line per host; "Status: Up" filters cleanly.
    awk '/Status: Up/ {print $2}' "$out" > "$hosts"
    ok "live hosts: $(wc -l < "$hosts")"
}

net_tcp_fast() {
    require nmap || return 1
    local hosts=$ENGAGEMENT/evidence/scans/network/hosts.txt
    local out=$ENGAGEMENT/evidence/scans/network/tcp_fast

    need_file "$hosts" "no live hosts — run ping sweep first" || return 1
    skip_if_done "$out.gnmap" && return 0

    # two-stage pattern: fast port discovery, then deep scan only on open ports.
    # stage 1: find open ports fast (skip if a previous run already did it).
    if [[ -s $out.discovery.gnmap ]]; then
        ok "skip discovery (exists): $out.discovery.gnmap"
    else
        run "tcp discovery (all ports, fast)" \
            sudo nmap --stats-every=30s -p- -vvv --min-rate "$NMAP_MIN_RATE" -T4 -Pn -n \
                -iL "$hosts" -oG "$out.discovery.gnmap"
    fi

    # extract open ports per host for stage 2
    local ports
    ports=$(awk -F'Ports: ' '/Ports:/ {print $2}' "$out.discovery.gnmap" \
            | grep -oE '[0-9]+/open' | cut -d/ -f1 | sort -un | paste -sd,)

    [[ -n $ports ]] || { skip_step "no open tcp ports found"; return 0; }
    log "open ports across scope: $ports"

    # Stage 2: version + default scripts on just those ports
    run "tcp deep scan (-sV -sC on discovered ports)" \
        sudo nmap --stats-every=30s -sV -sC -Pn -n -p "$ports" \
            -iL "$hosts" -oA "$out"
}

# net_tcp_rustscan — faster alternative to net_tcp_fast's discovery stage.
# RustScan sweeps all ports quickly, then hands the open ones to nmap for -sV -sC.
# writes the SAME tcp_fast.* output, so it's a drop-in for the `tcp_fast` step
# Caution: aggressive; don't point it at fragile/sensitive hosts.
net_tcp_rustscan() {
    require "$RUSTSCAN_BIN" nmap || return 1
    local hosts=$ENGAGEMENT/evidence/scans/network/hosts.txt
    local out=$ENGAGEMENT/evidence/scans/network/tcp_fast

    need_file "$hosts" "no live hosts — run ping sweep first" || return 1
    skip_if_done "$out.gnmap" && return 0

    # RustScan takes a comma-separated address list, not nmap's -iL. Skip blank
    # lines and comments, then join.
    local addrs
    addrs=$(grep -vE '^[[:space:]]*(#|$)' "$hosts" | paste -sd,)
    [[ -n $addrs ]] || { skip_step "no addresses in $hosts"; return 0; }

    # -b batch size, -t per-port timeout (ms), --ulimit raises the fd cap.
    # Everything after `--` is passed through to nmap on the discovered ports.
    run "rustscan (fast discovery -> nmap -sV -sC)" \
        "$RUSTSCAN_BIN" -a "$addrs" \
            -b "$RUSTSCAN_BATCH" -t "$RUSTSCAN_TT" --ulimit 65000 \
            -- -sV -sC -Pn -n -oA "$out"
}

net_tcp_full() {
    require nmap || return 1
    local hosts=$ENGAGEMENT/evidence/scans/network/hosts.txt
    local out=$ENGAGEMENT/evidence/scans/network/tcp_full

    need_file "$hosts" "no live hosts — run ping sweep first" || return 1
    skip_if_done "$out.xml" && return 0
    run "tcp full scan (-p- -sV -sC, slow)" \
        sudo nmap --stats-every=30s -p- -sV -sC -Pn -n --min-rate "$NMAP_MIN_RATE" \
            -iL "$hosts" -oA "$out"
}

net_udp_top() {
    require nmap || return 1
    local hosts=$ENGAGEMENT/evidence/scans/network/hosts.txt
    local out=$ENGAGEMENT/evidence/scans/network/udp_top

    need_file "$hosts" "no live hosts — run ping sweep first" || return 1
    skip_if_done "$out.gnmap" && return 0
    # UDP is slow; top 100 is usually good tradeoff?
    run "udp top-100 scan" \
        sudo nmap --stats-every=30s -sU --top-ports 100 -Pn -n \
            -iL "$hosts" -oA "$out"
}
