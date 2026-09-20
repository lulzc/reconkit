#!/usr/bin/env bash

# per-port handlers, each takes an IP, writes to services/<tool>_<ip>.txt
svc_smb() {
    local ip=$1
    local out=$ENGAGEMENT/evidence/scans/services/smb_$ip.txt
    skip_if_done "$out" && return 0
    { nxc smb "$ip"; echo; nxc smb "$ip" --shares; } > "$out" 2>&1
}

svc_ldap() {
    local ip=$1
    local out=$ENGAGEMENT/evidence/scans/services/ldap_$ip.txt
    skip_if_done "$out" && return 0
    ldapsearch -x -H "ldap://$ip" -s base namingcontexts > "$out" 2>&1
}

svc_dns() {
    local ip=$1
    local domain_file=$ENGAGEMENT/domain.txt
    [[ -s $domain_file ]] || { skip_step "no domain.txt — skipping dns enum"; return 0; }
    local out=$ENGAGEMENT/evidence/scans/services/dns_$ip.txt
    skip_if_done "$out" && return 0
    while read -r d; do
        echo "=== AXFR $d @ $ip ===" >> "$out"
        dig +time=5 "axfr" "$d" "@$ip" >> "$out" 2>&1
    done < "$domain_file"
}

# reports the algorithms in ssh2 (for encryption, compression, etc.)
# for CTF meh - for real-engagement yay

# per-IP handler (called by svc_dispatch when tcp/22 is open)
_svc_ssh_algorithms_ip() {
    local ip=$1
    local out=$ENGAGEMENT/evidence/scans/services/ssh_algorithms_$ip.nmap
    skip_if_done "$out" && return 0
    run "ssh2 algo audit $ip" \
        nmap -sC -sV -p22 --script=ssh2-enum-algos -oN "$out" "$ip"
}

# standalone step: audit every host with tcp/22 open in the fast scan.
# mirrors svc_banner_grab; also reachable per-IP via svc_dispatch.
svc_ssh_algorithms() {
    require nmap || return 1
    local gnmap=$ENGAGEMENT/evidence/scans/network/tcp_fast.gnmap
    need_file "$gnmap" "no tcp scan results — run tcp first" || return 1
    ensure_dir "$ENGAGEMENT/evidence/scans/services"

    local targets ip
    targets=$(targets_from_gnmap "$gnmap" 22 | cut -d: -f1 | sort -u)
    [[ -n $targets ]] || { skip_step "no hosts with tcp/22 open"; return 0; }
    while read -r ip; do
        [[ -z $ip ]] && continue
        _svc_ssh_algorithms_ip "$ip"
    done <<< "$targets"
}

# svc_banner_grab — grab service banners on every open TCP port found
svc_banner_grab() {
    require nmap || return 1
    local gnmap=$ENGAGEMENT/evidence/scans/network/tcp_fast.gnmap
    need_file "$gnmap" "no tcp scan results — run tcp first" || return 1
    ensure_dir "$ENGAGEMENT/evidence/scans/services"

    # ip:port lines "ip port1,port2,..." per host.
    local grouped
    grouped=$(targets_from_gnmap "$gnmap" \
        | awk -F: '{p[$1]=p[$1] (p[$1]?",":"") $2} END{for(i in p) print i, p[i]}')
    [[ -n $grouped ]] || { skip_step "no open ports for banner grab"; return 0; }

    local ip ports out
    while read -r ip ports; do
        [[ -z $ip ]] && continue
        out=$ENGAGEMENT/evidence/scans/services/banner_${ip}.txt
        skip_if_done "$out" && continue
        run "banner grab $ip ($ports)" \
            nmap -sV -Pn -n -p "$ports" --script=banner "$ip" -oN "$out"
    done <<< "$grouped"
}

# dispatch: read gnmap, route each (ip, port) to the right handler
svc_dispatch() {
    local gnmap=$ENGAGEMENT/evidence/scans/network/tcp_fast.gnmap
    need_file "$gnmap" "no tcp scan results" || return 1

    # extract ip,port pairs
    awk -F'Host: | \\(|\\)|Ports: |,' '
        /Ports:/ {
            ip=$2;
            for (i=1;i<=NF;i++) if ($i ~ /\/open\//) {
                split($i, a, "/"); print ip, a[1]
            }
        }
    ' "$gnmap" | while read -r ip port; do
        case $port in
            22)        _svc_ssh_algorithms_ip "$ip" ;;
            53)        svc_dns  "$ip" ;;
            139|445)   svc_smb  "$ip" ;;
            389|636)   svc_ldap "$ip" ;;
            # add more as you need them
        esac
    done
}
