#!/usr/bin/env bash
# TLS/SSL enumeration
# targets come from the fast TCP scan (tcp_fast.gnmap), filtered to SSL_PORTS

# for each ip:port on a TLS port (SSL_PORTS), gather:
# - certificate details + supported cipher suites via nmap NSE
# - a fuller audit (protocol versions, cert chain, known TLS weaknesses) via sslyze

SSL_DIR() { echo "$ENGAGEMENT/evidence/scans/ssl"; }

# nmap ssl-cert + ssl-enum-ciphers in one connect scan. ssl-enum-ciphers also
# grades each suite (A–F), which is the quick "is the TLS config weak" answer.
ssl_nmap() {
    local ip=$1 port=$2
    local tag out
    tag=$(sanitize_tag "$ip:$port")
    out=$(SSL_DIR)/nmap_${tag}.txt
    skip_if_done "$out" && return 0
    run "nmap ssl scripts $ip:$port" \
        nmap -Pn -n -sV -p "$port" \
             --script ssl-cert,ssl-enum-ciphers \
             "$ip" -oN "$out"
}

# full sslyze audit human-readable output -> .txt, machine-readable -> .json.
# (it exec's its args). Mirrors the direct-redirect style in services.sh.
ssl_sslyze() {
    local ip=$1 port=$2
    local tag txt json
    tag=$(sanitize_tag "$ip:$port")
    txt=$(SSL_DIR)/sslyze_${tag}.txt
    json=$(SSL_DIR)/sslyze_${tag}.json
    skip_if_done "$txt" && return 0
    log "sslyze $ip:$port"
    if sslyze --json_out="$json" "$ip:$port" > "$txt" 2>&1; then
        ok "sslyze $ip:$port — done"
    else
        # sslyze exits non-zero when it can't connect; keep going, log where.
        warn "sslyze $ip:$port — failed (see $txt)"
        return 1
    fi
}

# ssl_scan — dispatch both scanners across every TLS target in scope.
ssl_scan() {
    require nmap sslyze || return 1
    ensure_dir "$(SSL_DIR)"
    local gnmap=$ENGAGEMENT/evidence/scans/network/tcp_fast.gnmap
    need_file "$gnmap" "no tcp scan results — run net_tcp_fast (tcp) first" || return 1

    local targets
    targets=$(targets_from_gnmap "$gnmap" "$SSL_PORTS" | sort -u)
    [[ -n $targets ]] || { skip_step "no TLS ports in scope (SSL_PORTS=$SSL_PORTS)"; return 0; }

    log "ssl targets: $(echo "$targets" | wc -l)"
    while IFS=: read -r ip port; do
        [[ -z $ip ]] && continue
        ssl_nmap   "$ip" "$port"
        ssl_sslyze "$ip" "$port"
    done <<< "$targets"

    ok "ssl enum complete: $(SSL_DIR)"
}
