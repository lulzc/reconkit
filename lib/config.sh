#!/usr/bin/env bash
# defaults. Override per-engagement by exporting before sourcing, or via CLI flags.
# never store secrets in this file.

: "${WORDLIST_DIR_MEDIUM:=/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt}"
: "${WORDLIST_DIR_BIG:=/opt/SecLists/Discovery/Web-Content/raft-big-directories.txt}"
: "${WORDLIST_DIRBUSTER_MEDIUM:=/opt/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt}"
: "${WORDLIST_VHOSTS1:=/opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt}"
: "${WORDLIST_VHOSTS2:=/opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt}"
: "${NMAP_MIN_RATE:=5000}" # CTF_RATE = 10000
: "${FFUF_THREADS:=20}" # CTF_RATE = 50
: "${HTTP_PORTS:=80,443,8000,8080,8443,8888}"
: "${SSL_PORTS:=443,8443,993,995,465,636,990,992}"
: "${FEROX_THREADS:=30}"
: "${FEROX_DEPTH:=2}"
: "${FEROX_EXTENSIONS:=php,html,txt,bak,old,zip}"
: "${KATANA_DEPTH:=3}"
: "${WEB_DIRS_MODE:=all}"   # all | domains | ips
: "${RUSTSCAN_BATCH:=1000}" # scan X ports at time
: "${RUSTSCAN_TT:=5000}" # wait for a response on a port for up to 5 seconds

# external tool locations
# some tools live under a downloads tree rather than on $PATH.
# TOOLS_DIR is the base; each *_BIN prefers the tool on $PATH and otherwise falls back to its
# TOOLS_DIR location
# override any single one from the environment, e.g.  export HTTPX_BIN=/opt/httpx/httpx
# NOTE: relies on utils.sh being sourced first (recon.sh does this).
: "${TOOLS_DIR:=$HOME/Downloads/tools}"
: "${RUSTSCAN_BIN:=$(resolve_tool rustscan "$TOOLS_DIR/rustscan/rustscan")}"
: "${KATANA_BIN:=$(resolve_tool katana   "$TOOLS_DIR/web_crawler/katana")}"
: "${GOWITNESS_BIN:=$(resolve_tool gowitness "$TOOLS_DIR/gowitness/gowitness")}"
: "${EYEWITNESS_BIN:=$(resolve_tool eyewitness "$TOOLS_DIR/eyewitness/eyewitness")}"

# httpx: prefer the pinned $TOOLS_DIR build over $PATH
# kali's packaged httpx lags the ProjectDiscovery features (= not up2date)
# prefer $PATH via resolve_tool; flip them to resolve_tool_local as needed.)
: "${HTTPX_BIN:=$(resolve_tool_local httpx "$TOOLS_DIR/httpx/httpx")}"
