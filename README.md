# reconkit

`reconkit` is not a scanner; it's a thin ,,frankenstein" orchestrator that drives
the tools you maybe already use (nmap, httpx, ffuf, feroxbuster, katana, gowitness, sslyze,...).
I created it initially for the CPTS-Exam to speed up thinks.

> **Authorized testing only.** This launches intrusive scans 
> (`sudo nmap`, aggressive port sweeps, directory/vhost fuzzing)
> Only run it against systems you have explicit, written permission to test.

## Highlights

- **Explicit steps, no magic.** You name exactly what runs (`-s ping,tcp_fast`);
  there is no interactive menu and no "run everything" button.
- **Resumable.** Every step skips work whose output already exists, so a rerun
  continues where you left off. Outputs that depend on stale inputs re-run.
- **Fail-isolated.** A failing step never aborts the others; the run's exit code
  reflects whether any step actually failed (vs. simply having nothing to do).
- **Modular.** Each phase lives in `lib/*.sh`; add a step by adding a function.

## Requirements

Core: `bash`, `nmap`, `jq`, `curl`.
Web: `httpx` (+v1.10.0), `ffuf`, `feroxbuster`; optional `katana`,
`gowitness`, `eyewitness`.
Other: `sslyze` (TLS), `rustscan` (optional fast scan), and for service enum `ldapsearch`, `dig`.

Tools not on `$PATH` can live under `$TOOLS_DIR` (default `~/Downloads/tools`);
see [Configuration](#configuration). `httpx` prefers the pinned build there
(the distro package is often too old).

## Installation

Tested on Kali

```bash
git clone https://github.com/lulzc/reconkit.git reconkit
cd reconkit
chmod +x recon.sh lib/*.sh extra/*.sh
```

**1. Wordlists (SecLists).** The web-fuzzing defaults point at `/opt/SecLists`:

Point the `WORDLIST_*` variables elsewhere if your copy lives somewhere else
(see [Configuration](#configuration)).

**2. Tools.** Most are packaged on Kali:

```bash
sudo apt install nmap jq curl ffuf feroxbuster sslyze \
    dnsutils ldap-utils netexec rustscan eyewitness katana gowitness
```

On other distros install what your package manager has and put the rest on
`$PATH` (or under `$TOOLS_DIR`, default `~/Downloads/tools`).

**3. httpx (ProjectDiscovery) — mind the version.** The distro package
(`httpx-toolkit` on Kali) is often older than the features `web_probe` uses, so
reconkit prefers a build under `$TOOLS_DIR` over the one on `$PATH`:

```bash
# option A: Go build into the expected location
GOBIN="$HOME/Downloads/tools/httpx" go install github.com/projectdiscovery/httpx/cmd/httpx@latest
# option B: point HTTPX_BIN at any build you trust
export HTTPX_BIN=/opt/httpx/httpx
```

If neither exists it falls back to `httpx` on `$PATH`. 
(You may **not** remove the apt package to force this — the fallback handles it.)

**4. Privileges.** The nmap-based steps (`ping`, `tcp_*`, `udp_fast`) call
`sudo nmap`; make sure your user can `sudo` non-interactively or run those steps
in a session where you've already authenticated.

**5. Smoke test.**

```bash
./recon.sh -h          # step list + input-file reference
```

## Usage
Create the Directory + touch the scope.txt file
```
mkdir -p engagement-dir/{notes,exploits,logs,evidence/{findings,scans/{web,network}}}
touch engagement-dir/scope.txt
```

```
./recon.sh -e <engagement-dir> -s step[,step...]
```

Steps run left to right; each is isolated. Example:

```bash
./recon.sh -e ctf-lab -s ping,tcp_fast,svc
./recon.sh -e ctf-lab -s web_probe
```

Run `./recon.sh -h` for the full step list and input-file reference.

### Steps

| Phase | Steps |
|-------|-------|
| Network | `ping`, `tcp_fast`, `tcp_rustscan`, `tcp_fullscan`, `udp_fast` |
| Service | `svc`, `svc_banner_grab`, `svc_ssh_algorithms` |
| Web | `web_probe`, `web_fuzz_vhost`, `web_fuzz_dir_ferox`, `web_all`, `web_crawl`, `web_screenshot`, `web_screenshot_eyewitness`, `web_enum_common`, `web_enum_header` |
| SSL | `ssl` |

### Input files (place under `<engagement-dir>/`)

| File | Required? | Purpose |
|------|-----------|---------|
| `scope.txt` | required by `ping` | hosts / CIDRs / ranges, one per line |
| `domain.txt` | optional | enables vhost fuzzing + DNS AXFR (one domain per line) |
| `web_targets.txt` | optional | full URLs (e.g. `https://10.10.10.5:8443`); lets the web steps run without `web_probe`, and is `web_probe`'s input when present |
| `evidence/scans/network/hosts.txt` | auto | written by `ping`; supply your own to skip discovery when ICMP is filtered |

### Output layout

```
<engagement-dir>/
├── scope.txt / domain.txt / web_targets.txt   # your inputs
├── logs/recon.log                             # timestamped run log
└── evidence/scans/
    ├── network/   # nmap host discovery + TCP/UDP scans (gnmap/xml)
    ├── services/  # per-service enum (smb, ldap, dns, ssh algos, banners)
    ├── web/       # httpx probe, ffuf vhosts, feroxbuster dirs, crawl, shots, headers
    ├── ssl/       # nmap ssl scripts + sslyze
```

## Configuration

Defaults live in `lib/config.sh` and are overridable via environment variables
(export before running). Common ones:

| Variable | Default | Notes |
|----------|---------|-------|
| `HTTP_PORTS` | `80,443,8000,8080,8443,8888` | ports `web_probe` treats as HTTP |
| `SSL_PORTS` | `443,8443,993,995,...` | TLS ports for the `ssl` step |
| `WEB_DIRS_MODE` | `all` | dir-fuzz sources: `ips` (URLs), `domains`, or `all` |
| `NMAP_MIN_RATE` | `5000` | raise for lab/CTF, lower for fragile targets |
| `FEROX_THREADS` / `FFUF_THREADS` | `30` | tune to the client rate limit |
| `WORDLIST_*` | SecLists paths | directory/vhost wordlists |
| `TOOLS_DIR` | `~/Downloads/tools` | fallback location for off-`$PATH` tools |


## Repository layout

```
recon.sh        # entrypoint: arg parsing + step dispatch
lib/
  utils.sh      # logging, run/skip helpers, tool + target resolution
  config.sh     # overridable defaults
  network.sh    # host discovery + TCP/UDP scans
  services.sh   # per-service enum + dispatch
  web.sh        # httpx probe, fuzzing, crawl, screenshots, header/path enum
  ssl.sh        # TLS enumeration
extra/          # standalone helpers (e.g. SSH algorithm audit)
```
