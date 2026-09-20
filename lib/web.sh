#!/usr/bin/env bash

# web_urls
# precedence (re-run web_probe to fold newly added web_targets.txt entries in):
# 1. httpx.json (from web_probe) — validated, scheme-correct, deduped
# 2. web_targets.txt (user-injected URLs, one full URL per line, scheme required)
#  —> with it you can run web_fuzz_dir_ferox / web_crawl / screenshots / enum directly
web_urls() {
    local probe=$ENGAGEMENT/evidence/scans/web/httpx.json
    local injected=$ENGAGEMENT/web_targets.txt
    if [[ -s $probe ]]; then
        jq -r '.url' "$probe" | sort -u
    elif [[ -s $injected ]]; then
        grep -vE '^[[:space:]]*(#|$)' "$injected" | sort -u
    else
        return 1
    fi
}

# _httpx_urls_from_hosts <hostfile> <out.json> — probe bare hostnames/domains
# result cached in <out.json>
_httpx_urls_from_hosts() {
    local hostfile=$1 out=$2
    [[ -s $hostfile ]] || return 0
    skip_if_done "$out" || run "httpx probing hostnames ($(basename "$out"))" \
        "$HTTPX_BIN" -l "$hostfile" -json -o "$out" \
              -status-code -follow-redirects -silent
    [[ -s $out ]] && jq -r '.url' "$out"
}

# httpx - experimental tool
web_probe() {
    require "$HTTPX_BIN" || return 1
    local out=$ENGAGEMENT/evidence/scans/web/httpx.json
    local targets=$ENGAGEMENT/evidence/scans/web/targets.txt
    local injected=$ENGAGEMENT/web_targets.txt
    local gnmap=$ENGAGEMENT/evidence/scans/network/tcp_fast.gnmap

    # Refresh if httpx.json is missing or older than its inputs, so editing
    # web_targets.txt (or rescanning) actually re-probes. A blind skip_if_done
    # here would make "re-run web_probe" a silent no-op. `-nt` treats a missing
    # input as older, so an absent web_targets.txt / gnmap won't force a reprobe.
    if [[ -s $out && ! $injected -nt $out && ! $gnmap -nt $out ]]; then
        ok "skip (up to date): $out"
        return 0
    fi
    ensure_dir "$ENGAGEMENT/evidence/scans/web"

    # input precedence: user-injected URLs > gnmap-derived ip:port on HTTP_PORTS
    if [[ -s $injected ]]; then
        log "web_probe: using injected targets ($injected)"
        grep -vE '^[[:space:]]*(#|$)' "$injected" | sort -u > "$targets"
    else
        need_file "$gnmap" "no tcp scan — run net_tcp_fast first (or add $injected)" || return 1
        # targets_from_gnmap strips whitespace in the port filter itself
        targets_from_gnmap "$gnmap" "$(echo "$HTTP_PORTS" | tr -d '[:space:]')" \
            | sort -u > "$targets"
    fi

    if [[ ! -s $targets ]]; then
        skip_step "no web targets (no $injected, and no HTTP_PORTS open in gnmap)"
        if [[ -s $gnmap ]]; then
            warn "  gnmap: $gnmap ($(wc -l < "$gnmap") lines)"
            warn "  open ports in gnmap:"
            grep -oE '[0-9]+/open' "$gnmap" | sort -u | sed 's/^/    /' >&2
            warn "  HTTP_PORTS filter: $HTTP_PORTS"
        fi
        return 0
    fi

    log "web targets: $(wc -l < "$targets")"

    # httpx probes http:// and https://
    # warning / caveat: -tech-detect on older httpx builds fetches a model
    # and can stall without the Hugging Face opt-out (needs the v1.10+)
    # fyi: drop -tech-detect if a probe hangs
    run "httpx probe" \
        "$HTTPX_BIN" -list "$targets" -json -o "$out" \
              -status-code -title -tech-detect -content-length \
              -follow-redirects -silent
}

web_fuzz_vhost() {
    require ffuf jq || return 1
    require_file "$WORDLIST_VHOSTS2" || return 1
    local domain_file=$ENGAGEMENT/domain.txt

    # vhost fuzzing needs a base domain -> hard requirement for THIS step.
    need_file "$domain_file" "vhost enum needs domain.txt (one domain per line)" || return 1

    # normalize to bare hosts (strip scheme/path/port) and dedup, so http://x and
    # https://x collapse to a single 'x' fuzzed once per target URL.
    local domains
    domains=$(grep -vE '^[[:space:]]*(#|$)' "$domain_file" \
              | sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s#:[0-9]+$##' \
              | sort -u)
    [[ -n $domains ]] || { abort_step "domain.txt has no usable domains"; return 1; }

    local urls
    urls=$(web_urls) || { abort_step "no web targets — run web_probe or add $ENGAGEMENT/web_targets.txt"; return 1; }

    # for every target URL x every in-scope domain, fuzz Host: FUZZ.<domain>
    local url domain tag out
    while read -r url; do
        [[ -z $url ]] && continue
        while read -r domain; do
            [[ -z $domain ]] && continue
            # sanitize for filenames: https://10.10.10.3:8443 -> 10.10.10.3_8443
            tag=$(sanitize_tag "$url")
            out=$ENGAGEMENT/evidence/scans/web/vhosts_${tag}_${domain}.json

            skip_if_done "$out" && continue
            # -ac (auto-calibration) replaces a manual baseline.
            # too many false positives with -ac? swap in:
            # -fs $(curl -s -H "Host: nope.$domain" "$url/" | wc -c)
            run "vhost fuzz $url (Host: *.$domain)" \
                ffuf -s -u "$url/" \
                     -H "Host: FUZZ.$domain" \
                     -w "$WORDLIST_VHOSTS2" \
                     -ac \
                     -mc 200,204,301,302,307,401,403 \
                     -of json -o "$out"
        done <<< "$domains"
    done <<< "$urls"
}

# check with the client rate-limit and adjust FEROX_THREADS in config
web_fuzz_dir_ferox() {
    require feroxbuster jq "$HTTPX_BIN" || return 1
    require_file "$WORDLIST_DIR_MEDIUM" || return 1
    local domain_file=$ENGAGEMENT/domain.txt
    local mode=${1:-$WEB_DIRS_MODE}
    ensure_dir "$ENGAGEMENT/evidence/scans/web"

    local targets=$ENGAGEMENT/evidence/scans/web/dir_targets.txt
    : > "$targets"

    # URL targets (scheme already known) vs probed URLs or injected web_targets
    if [[ $mode == all || $mode == ips ]]; then
        web_urls >> "$targets" || true
    fi

    # hostname targets (scheme unknown): base domains + discovered vhosts
    if [[ $mode == all || $mode == domains ]]; then
        local hostlist=$ENGAGEMENT/evidence/scans/web/dir_hostnames.txt
        : > "$hostlist"
        [[ -s $domain_file ]] && grep -vE '^[[:space:]]*(#|$)' "$domain_file" >> "$hostlist"

        # discovered vhosts from web_fuzz_vhost -> FUZZ.<domain> FQDNs
        local f base domain
        for f in "$ENGAGEMENT"/evidence/scans/web/vhosts_*.json; do
            [[ -e $f ]] || continue
            base=$(basename "$f" .json)
            domain=${base##*_}
            jq -r --arg d "$domain" '
                .results[]?.input.FUZZ
                | select(. != null)
                | . + "." + $d
            ' "$f" >> "$hostlist"
        done

        if [[ -s $hostlist ]]; then
            sort -u "$hostlist" -o "$hostlist"
            _httpx_urls_from_hosts "$hostlist" \
                "$ENGAGEMENT/evidence/scans/web/httpx_hostnames.json" >> "$targets"
        fi
    fi

    # dedupe
    sort -u "$targets" -o "$targets"
    [[ -s $targets ]] || { skip_step "no web targets for dir fuzzing (mode=$mode)"; return 0; }

    log "dir fuzzing $(wc -l < "$targets") targets (mode=$mode)"

    while read -r url; do
        [[ -z $url ]] && continue

        local tag
        tag=$(sanitize_tag "$url")
        local out=$ENGAGEMENT/evidence/scans/web/dirs_${tag}.json
        local errlog=$ENGAGEMENT/evidence/scans/web/dirs_${tag}.stderr

        skip_if_done "$out" && continue

        run "feroxbuster $url" \
            feroxbuster \
                --insecure \
                --url "$url" \
                --wordlist "$WORDLIST_DIR_MEDIUM" \
                --threads "$FEROX_THREADS" \
                --depth "$FEROX_DEPTH" \
                --extensions "$FEROX_EXTENSIONS" \
                --status-codes 200,204,301,302,307,401,403,405 \
                --auto-tune \
                --no-state \
                --silent \
                --json \
                --output "$out" 2> "$errlog" || true
    done < "$targets"

    # summary
    local summary=$ENGAGEMENT/evidence/scans/web/dirs_summary.txt
    : > "$summary"
    for f in "$ENGAGEMENT"/evidence/scans/web/dirs_*.json; do
        [[ -e $f ]] || continue
        {
            echo "=== $(basename "$f" .json) ==="
            jq -r 'select(.type=="response")
                   | "\(.status)  \(.content_length)  \(.url)"' "$f" \
                | sort -u
            echo
        } >> "$summary"
    done
    ok "summary written: $summary"
}

# web_crawl — crawl each target URL with katana to collect endpoints/links
# source: web_urls (httpx.json, else web_targets.txt)
# one output file per target so a rerun resumes past URLs already crawled
web_crawl() {
    require "$KATANA_BIN" jq || return 1
    local urls
    urls=$(web_urls) || { abort_step "no web targets — run web_probe or add $ENGAGEMENT/web_targets.txt"; return 1; }

    local url tag out
    while read -r url; do
        [[ -z $url ]] && continue
        tag=$(sanitize_tag "$url")
        out=$ENGAGEMENT/evidence/scans/web/crawl_${tag}.txt
        skip_if_done "$out" && continue
        # -jc also crawls endpoints referenced from JavaScript; -d caps depth.
        run "katana crawl $url" \
            "$KATANA_BIN" -u "$url" -d "$KATANA_DEPTH" -jc -silent -o "$out"
    done <<< "$urls"
}

# _screenshot_targets — (re)write the deduped URL list both screenshotters
# consume, and echo its path. Regenerated each call so it tracks web_urls;
# a stale cache would keep pointing at old targets (e.g. IPs after you add a
# domain to web_targets.txt).
_screenshot_targets() {
    local targets=$ENGAGEMENT/evidence/scans/web/screenshot_targets.txt
    local urls
    urls=$(web_urls) || return 1
    printf '%s\n' "$urls" > "$targets"
    echo "$targets"
}

# web_screenshot — primary screenshotter (gowitness) over every probed URL
web_screenshot() {
    require "$GOWITNESS_BIN" jq || return 1
    local targets shots
    targets=$(_screenshot_targets) || return 1
    shots=$ENGAGEMENT/evidence/scans/web/screenshots_gowitness
    [[ -s $targets ]] || { skip_step "no URLs to screenshot"; return 0; }

    # resume: skip if we already have screenshots on disk.
    if [[ -d $shots && -n $(ls -A "$shots" 2>/dev/null) ]]; then
        ok "skip (exists): $shots"
        return 0
    fi
    ensure_dir "$shots"

    log "gowitness: $(wc -l < "$targets") targets"
    run "gowitness screenshots" \
        "$GOWITNESS_BIN" scan file -f "$targets" --screenshot-path "$shots"
}

# web_screenshot_eyewitness - backup screenshotter
# use when gowitness fails on a target (headless-chrome quirks, TLS, etc)
# note: EyeWitness insists on creating its output dir itself
web_screenshot_eyewitness() {
    require "$EYEWITNESS_BIN" jq || return 1
    local targets outdir
    targets=$(_screenshot_targets) || return 1
    outdir=$ENGAGEMENT/evidence/scans/web/screenshots_eyewitness
    [[ -s $targets ]] || { skip_step "no URLs to screenshot"; return 0; }

    run "eyewitness screenshots" \
        "$EYEWITNESS_BIN" -f "$targets" -d "$outdir" --no-prompt --web
}

# web_enum_common — fetch well-known / metadata paths from each probed URL
web_enum_common() {
    require curl jq || return 1
    local urls
    urls=$(web_urls) || { abort_step "no web targets — run web_probe or add $ENGAGEMENT/web_targets.txt"; return 1; }

    local paths
    if [[ -n ${WEB_COMMON_PATHS:-} ]]; then
        read -ra paths <<< "$WEB_COMMON_PATHS"
    else
        paths=(
            /robots.txt
            /sitemap.xml
            /security.txt
            /.well-known/security.txt
            /.well-known/change-password
            /.well-known/assetlinks.json
            /.well-known/apple-app-site-association
            /.well-known/mta-sts.txt
            /.well-known/openid-configuration
            /crossdomain.xml
            /clientaccesspolicy.xml
            # high-value extras — trim if out of scope
            /.git/HEAD
            /.env
            /.DS_Store
        )
    fi

    local url tag dir summary path body code size pathtag
    while read -r url; do
        [[ -z $url ]] && continue
        tag=$(sanitize_tag "$url")
        dir=$ENGAGEMENT/evidence/scans/web/common_${tag}
        summary=$dir/summary.txt
        skip_if_done "$summary" && continue
        ensure_dir "$dir"

        log "common paths: $url"
        : > "$summary"
        for path in "${paths[@]}"; do
            # /.well-known/openid-configuration -> well-known_openid-configuration
            # real path is still recorded in summary.txt)
            pathtag=$(echo "$path" | sed -E 's#^/##; s#/#_#g; s#^\.##')
            body=$dir/$pathtag
            # -w prints the final status (after -L redirects); body -> file.
            code=$(curl -sk -L --max-time 10 \
                        -o "$body" -w '%{http_code}' "$url$path" 2>/dev/null)
            size=$(wc -c < "$body" 2>/dev/null | tr -d ' ')
            printf '%s  %8s  %s\n' "${code:-000}" "${size:-0}" "$path" >> "$summary"
            # Keep only real hits; drop 404s/errors/empties to cut noise.
            if [[ $code == 200 && ${size:-0} -gt 0 ]]; then
                ok "  hit 200 $path (${size} b)"
            else
                rm -f "$body"
            fi
        done
        ok "summary: $summary"
    done <<< "$urls"
}

# web_enum_header — inspect HTTP response headers of each probed URL
# saves the raw redirect chain as evidence, then evaluates the FINAL response
# for missing security headers and any info-disclosure headers
web_enum_header() {
    require curl jq || return 1
    local urls
    urls=$(web_urls) || { abort_step "no web targets — run web_probe or add $ENGAGEMENT/web_targets.txt"; return 1; }

    # Security headers whose ABSENCE is the finding.
    local sec_headers=(
        Strict-Transport-Security
        Content-Security-Policy
        X-Frame-Options
        X-Content-Type-Options
        Referrer-Policy
        Permissions-Policy
        Cross-Origin-Opener-Policy
        Cross-Origin-Embedder-Policy
        Cross-Origin-Resource-Policy
    )
    # headers whose PRESENCE leaks stack/version info (minor finding)
    local leak_headers=(
        Server
        X-Powered-By
        X-AspNet-Version
        X-AspNetMvc-Version
    )

    local url tag dir raw final summary h val
    while read -r url; do
        [[ -z $url ]] && continue
        tag=$(sanitize_tag "$url")
        dir=$ENGAGEMENT/evidence/scans/web/headers_${tag}
        raw=$dir/headers_raw.txt
        summary=$dir/summary.txt
        skip_if_done "$summary" && continue
        ensure_dir "$dir"

        log "headers: $url"
        # -D dumps response headers of every hop; -o discards the body.
        curl -sSk -L --max-time 10 -o /dev/null -D "$raw" "$url" 2>"$dir/curl.err"
        if [[ ! -s $raw ]]; then
            warn "  no response headers ($url) — see $dir/curl.err"
            printf 'NO RESPONSE (see curl.err)\n' > "$summary"
            continue
        fi

        # final response = last header block. strip CR, then paragraph-mode awk
        # keeps the last block (curl -L appends one block per redirect hop).
        final=$(tr -d '\r' < "$raw" | awk -v RS='' 'END{print}')

        {
            echo "=== $url ==="
            echo "$final" | head -n1          # final status line
            echo
            echo "-- security headers --"
            for h in "${sec_headers[@]}"; do
                val=$(echo "$final" | grep -i "^$h:" | head -n1)
                if [[ -n $val ]]; then
                    echo "[present] $val"
                else
                    echo "[MISSING] $h"
                fi
            done
            echo
            echo "-- info-disclosure headers --"
            for h in "${leak_headers[@]}"; do
                val=$(echo "$final" | grep -i "^$h:" | head -n1)
                [[ -n $val ]] && echo "[info] $val"
            done
        } > "$summary"
        ok "summary: $summary"
    done <<< "$urls"
}
