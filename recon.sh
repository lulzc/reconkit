#!/usr/bin/env bash
set -uo pipefail
# Note: NOT set -e. in recon, tools fail all the time (closed ports, timeouts, ...)
# log failures and keep going, not abort the run

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$HERE/lib/utils.sh"
source "$HERE/lib/config.sh"
source "$HERE/lib/network.sh"
source "$HERE/lib/services.sh"
source "$HERE/lib/web.sh"
source "$HERE/lib/ssl.sh"


usage() {
    cat <<EOF
Usage: $0 -e <engagement-dir> -s step[,step...]

## Inputs — files you provide under <engagement-dir>/
- scope.txt
  REQUIRED by ping: hosts/CIDRs/ranges, one per line
- domain.txt
  optional: enables vhost fuzzing + DNS AXFR (one domain per line)
- web_targets.txt
  optional: full URLs (e.g. https://10.10.10.5:8443, scheme required)
  lets the web_* steps run WITHOUT web_probe
  and is used as web_probe's input too (takes precedence over the gnmap list)
- ../evidence/scans/network/hosts.txt
  auto-written by ping; drop your own here to skip discovery when
  ICMP is filtered but you know a host is up

## Network
  ping - Host discovery (scope.txt -> network/hosts.txt)
  tcp_fast - Fast TCP scan on live hosts
  tcp_rustscan - Fast TCP via rustscan
  tcp_fullscan - Full TCP -p- scan (slow)
  udp_fast  - UDP top-ports scan
## Service
  svc - service enum (smb/ldap/dns/etc.) from tcp results
  svc_banner_grab - banner grab all open ports (nmap -sV --script=banner)
  svc_ssh_algorithms - more for real audits not for CTF
## Web
  web_probe Probe HTTP with httpx
  web_fuzz_vhost FUZZ VHOST with ffuf
  web_fuzz_dir_ferox FUZZ dir with feroxbuster
  web_all  web_probe -> web_fuzz_vhost + web_fuzz_dir_ferox
  web_crawl      Crawl probed URLs with katana
  web_screenshot Screenshot probed URLs with gowitness
  web_screenshot_eyewitness  Same, via eyewitness (backup)
  web_enum_common  Fetch robots/sitemap/.well-known/* per probed URL (curl)
  web_enum_header  Check security/info headers per probed URL (curl)
## SSL
  ssl      TLS enum (nmap ssl-cert/ciphers + sslyze) on SSL_PORTS

Examples:
  $0 -e ctf-lab -s ping,tcp_fast
  $0 -e ctf-lab -s web_probe
EOF
    exit 1
}

ENGAGEMENT=""
STEPS=""
while getopts ":e:s:h" opt; do
    case $opt in
        e) ENGAGEMENT=$OPTARG ;;
        s) STEPS=$OPTARG ;;
        h|*) usage ;;
    esac
done
[[ -n $ENGAGEMENT ]] || usage
# create the output tree up front; that never fails due missing directory
# matches the paths the lib functions actually write to
mkdir -p "$ENGAGEMENT"/logs "$ENGAGEMENT"/evidence/scans/{network,web,ssl,services} \
    || die "cannot create output tree under: $ENGAGEMENT"
export ENGAGEMENT
# Central, timestamped run log (the lib log helpers append here).
export RUN_LOG="$ENGAGEMENT/logs/recon.log"

run_step() {
    case $1 in
        ping)               net_ping_sweep ;;
        tcp_fast)           net_tcp_fast ;;
        tcp_rustscan)       net_tcp_rustscan ;;
        tcp_fullscan)       net_tcp_full ;;
        udp_fast)           net_udp_top ;;
        svc)                svc_dispatch ;;
        svc_banner_grab)    svc_banner_grab ;;
        svc_ssh_algorithms) svc_ssh_algorithms ;;
        web_probe)          web_probe ;;
        web_fuzz_vhost)          web_fuzz_vhost ;;
        web_fuzz_dir_ferox) web_fuzz_dir_ferox ;;
        # probe gates vhost+dirs (real data dependency), but a vhost failure must
        # not block dir fuzzing of the IP targets.
        web_all)            web_probe && { web_fuzz_vhost; web_fuzz_dir_ferox; } ;;
        web_crawl)          web_crawl ;;
        web_screenshot)     web_screenshot ;;
        web_screenshot_eyewitness) web_screenshot_eyewitness ;;
        web_enum_common)    web_enum_common ;;
        web_enum_header)    web_enum_header ;;
        ssl)                ssl_scan ;;

        *)       warn "unknown step: $1"; return 1 ;;
    esac
}

# Run each step in its own subshell so a die/abort inside kills only that step,
# not the whole run. Steps share state through files, so isolation costs
# nothing. rc is non-zero if any step failed to complete.
run_steps() {
    local rc=0 s
    for s in "$@"; do
        ( run_step "$s" ) || { rc=1; warn "step '$s' incomplete"; }
    done
    return $rc
}

# Steps must be given explicitly with -s: no interactive menu and no "run all",
# so it is always clear from the command line exactly what will run.
[[ -n $STEPS ]] || usage
IFS=',' read -ra arr <<< "$STEPS"
run_steps "${arr[@]}"
exit $?
