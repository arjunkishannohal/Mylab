# Recon Workflow (Strict Run-Cards)

This repo is a **deterministic recon pipeline** governed by strict “run-cards”.

**Important:** Run tools **only** on targets you are explicitly authorized to test.

## Repo conventions

- `task/taskN/` contains **run-cards** (text files) you execute step-by-step.
- `outputs/` contains **final / important / downstream** artifacts (deduped, canonical).
- `temp/agent1/` contains **intermediate, raw, logs, chunks**.
- `manual/` contains **manual inputs** (e.g., HAR captures).
- `tools/` contains helper scripts (stdlib-only where possible).

Time governance: see `rules.txt` (9-minute command limit; batch/chunk if needed).

## Canonical artifacts (what other steps consume)

These are the “producer → consumer” contracts across the pipeline:

- `outputs/activesubdomain.txt` — in-scope hostname allowlist (created by Tool 7).
- `outputs/live_base_urls.txt` — live base URLs (created by Tool 8).
- `outputs/ports_open_hostport.txt` — open ports as `host:port` (created by Tool 12 naabu).
- `outputs/live_hostport_urls.txt` — live URLs discovered from `host:port` (Tool 12/13 httpx-hostport).
- `outputs/katana_urls.txt` — crawler URL corpus (Tool 13/14 katana).
- `outputs/gau_urls.txt` — historical URL corpus (Tool 14/15 gau).
- `outputs/gau_urls_in_scope.txt`, `outputs/katana_urls_in_scope.txt` — allowlist-filtered URL corpora (Tool 15/16).
- `outputs/url_corpus_all_in_scope.txt` — combined in-scope URL corpus (maintained by Task 8 + Task 15/16 merge step).
- `outputs/api_endpoints_live.txt` — validated API endpoints (Tool 18/19 httpx-probe-api-endpoints).
- `outputs/js_urls.txt` — discovered JS asset URLs (Tool 19/20).
- `outputs/js_endpoints_from_js.txt` — endpoints/paths extracted offline from JS (Tool 21/22).
- `outputs/js_urls_live.txt`, `outputs/js_composed_live.txt` — validated JS-derived URLs (Tool 22/23).

## End-to-end workflow (recommended order)

You can run all steps, but this ordering is the typical “full pipeline”:

1) Subdomains + allowlist
- Task 1: `subfinder` → `temp/agent1/list_1_passive.txt`
- Task 2: `amass` (passive) → merge into `temp/agent1/list_1_passive.txt`
- Task 3: `github-subdomains` → merge into `temp/agent1/list_1_passive.txt`
- Task 4: `waymore` → `temp/agent1/list_2_archives.txt`
- Task 5: wordlist + `puredns bruteforce` → `temp/agent1/list_3_bruteforce.txt`
- Task 10 (optional): `hakrevdns` → `temp/agent1/list_4_reverse.txt`
  - If you’re running tasks strictly in numeric order (1,2,3,4,…) and you want reverse DNS to contribute to permutations/candidates, run Task 10 **before** Task 6 and Task 7. (If you run Task 10 later, it won’t be consumed.)
- Task 6: `alterx` permutations → `temp/agent1/list_5_permutations.txt`
- Task 7: `puredns resolve + wildcard filtering` → **`outputs/activesubdomain.txt`** (+ audit copies)

2) Live discovery
- Task 8: `httpx` (host probe) → **`outputs/live_base_urls.txt`**
  - Also runs `cariddi` enrichment → `outputs/cariddi/*` and updates `outputs/url_corpus_all_in_scope.txt`
- Task 12: `naabu` (ports) → **`outputs/ports_open_hostport.txt`**
- Task 12/13: `httpx` (host:port probe) → **`outputs/live_hostport_urls.txt`**
- Task 9: `httpx` (knownfiles + api-docs probe) → `outputs/web_knownfiles_robots_sitemaps_security_urls.txt`, `outputs/api_docs_urls.txt`

3) URL discovery + scope filtering
- Task 13/14: `katana` → `outputs/katana_urls.txt`
- Task 14/15: `gau` → `outputs/gau_urls.txt`
- Task 15/16: allowlist filter → `outputs/gau_urls_in_scope.txt`, `outputs/katana_urls_in_scope.txt` (and optionally `outputs/url_corpus_all_in_scope.txt`)

4) API + params
- Task 17/18: `kiterunner` → `outputs/queue_api_endpoints_kiterunner.txt`
- Task 18/19: `httpx` probe API queue → `outputs/api_endpoints_live.txt`
- Task 16/17: `arjun` → `outputs/arjun_found_params.txt`

5) JS pipeline
- Task 19/20: JS URL discovery → `outputs/js_urls.txt`
- Task 21: fetch JS responses → `temp/agent1/js_fetch_dir/` + `temp/agent1/js_fetch_index.txt`
- Task 21/22: offline JS analysis → `outputs/js_endpoints_from_js.txt`
- Task 22/23: probe JS-extracted endpoints → `outputs/js_urls_live.txt`, `outputs/js_composed_live.txt`

6) Coverage / scanning
- Task 23/24: `nuclei` → `outputs/nuclei_findings.txt`
- Task 24/25: `gowitness` → `outputs/gowitness/` + `outputs/coverage_screenshots_index_gowitness.txt`
- Task 25/26: `ffuf` → `outputs/ffuf_findings.txt`
- Task 26/27: `nmap` → `outputs/nmap/` + `outputs/nmap_index.txt`
- Task 27/28: `subjack` → `outputs/coverage_takeover_candidates_subjack.txt`
- Task 30: `tlsx` → `outputs/coverage_tls_sans_in_scope.txt`

7) Manual enrichment (HAR analysis)
- Task 29: HAR analysis → `outputs/har/*`
  - Account-specific: `outputs/har/accounts/<harname>_auth.txt` (tokens, IDs, cookies)
  - Common data: `outputs/har/common_data.txt` (endpoints, headers, CORS)
  - Deep analysis guide included — not just script, do manual investigation

## Run-card reference (inputs → outputs)

Below is the per-run-card “tool I/O contract”. If a task folder contains multiple run-cards, they are listed under the same task.

### Task 1 — Subfinder
- Run-card: `task/task1/subfinder.txt`
- Input: `<domain>`
- Outputs:
  - `temp/agent1/subfinder.txt`
  - `temp/agent1/subfinder.log`
  - `temp/agent1/list_1_passive.txt` (deduped)

### Task 2 — Amass (passive)
- Run-card: `task/task2/amass.txt`
- Input: `<domain>`
- Outputs:
  - `temp/agent1/amass.txt`
  - Updates `temp/agent1/list_1_passive.txt` (merged + deduped)

### Task 3 — github-subdomains
- Run-card: `task/task3/github-subdomains.txt`
- Input: `<domain>` + `GITHUB_TOKEN`
- Outputs:
  - `temp/agent1/github-subdomains.txt`
  - Updates `temp/agent1/list_1_passive.txt` (merged + deduped)

### Task 4 — waymore
- Run-card: `task/task4/waymore.txt`
- Input: `<domain>`
- Outputs:
  - `temp/agent1/waymore_urls.log`
  - `temp/agent1/list_2_archives.txt`

### Task 5 — Resolver + bruteforce prep
- Run-cards:
  - `task/task5/resolver-prune-test.txt` (optional but recommended)
  - `task/task5/wordlist-download.txt`
  - `task/task5/puredns-bruteforce.txt`
  - `task/task5/resolvers_curated.txt` (fallback resolver list)
- Inputs:
  - `temp/agent1/subdomain_wordlist.txt`
  - `temp/agent1/resolvers_good.txt` (from prune test) OR `task/task5/resolvers_curated.txt`
- Outputs:
  - `temp/agent1/resolvers_good.txt` (if you prune)
  - `temp/agent1/subdomain_wordlist.txt`
  - `temp/agent1/list_3_bruteforce.txt`

### Task 6 — alterx permutations
- Run-card: `task/task6/alterx.txt`
- Inputs:
  - `temp/agent1/list_1_passive.txt`
  - `temp/agent1/list_2_archives.txt`
  - `temp/agent1/list_3_bruteforce.txt`
  - `temp/agent1/list_4_reverse.txt` (optional)
- Output:
  - `temp/agent1/list_5_permutations.txt`

### Task 7 — puredns resolve + wildcard filtering (creates allowlist)
- Run-card: `task/task7/puredns-resolve.txt`
- Inputs:
  - `temp/agent1/list_*` inputs (passive/archives/bruteforce/permutations)
  - `temp/agent1/resolvers_good.txt`
- Outputs:
  - `temp/agent1/candidates_all.txt`
  - `temp/agent1/resolved.txt`
  - `outputs/activesubdomain.txt` (deduped final allowlist)
  - `outputs/subdomains_candidates_all.txt` (audit copy)
  - `outputs/subdomains_resolved.txt` (audit copy)
  - Optional debug: `temp/agent1/wildcards.txt`, `temp/agent1/massdns.txt`

### Task 8 — httpx (live base URLs)
- Run-card: `task/task8/httpx.txt`
- Input: `outputs/activesubdomain.txt`
- Outputs:
  - `outputs/live_base_urls.txt`
  - Optional: `outputs/live_seeds.txt`
  - `outputs/cariddi/cariddi_findings.txt` (cariddi findings)
  - `outputs/cariddi/cariddi_urls_in_scope.txt` (scope-filtered URLs)
  - `outputs/url_corpus_all_in_scope.txt` (combined URL corpus; created/updated)

### Task 9 — httpx knownfiles + api-docs quick probe
- Run-card: `task/task9/httpx-knownfiles-apidocs.txt`
- Inputs:
  - `outputs/live_base_urls.txt`
  - `outputs/live_hostport_urls.txt` (optional)
- Outputs:
  - `outputs/web_knownfiles_robots_sitemaps_security_urls.txt`
  - `outputs/api_docs_urls.txt`
  - Intermediates: `temp/agent1/knownfiles_*`

### Task 10 — hakrevdns (reverse DNS, optional)
- Run-card: `task/task10/hakrevdns.txt`
- Input: `temp/agent1/in_scope_cidrs.txt`
- Output:
  - `temp/agent1/list_4_reverse.txt`

### Task 11 — dnsx (optional alternative)
- Run-card: `task/task11/dnsx.txt`
- Inputs:
  - `temp/agent1/candidates_all.txt` (for validation) OR CIDR/ASN files (for PTR)
  - `temp/agent1/resolvers_good.txt`
- Outputs:
  - `temp/agent1/resolved_dnsx.txt` (validation)
  - `temp/agent1/list_4_reverse.txt` (PTR mode)

### Task 12 — naabu + httpx (host:port)
- Run-cards:
  - `task/task12/naabu.txt`
  - `task/task12/httpx-hostport.txt`
- Inputs:
  - `outputs/activesubdomain.txt`
  - `outputs/ports_open_hostport.txt` (for httpx-hostport)
- Outputs:
  - `outputs/ports_open_hostport.txt`
  - `outputs/ports_open_hosts.txt`
  - `outputs/ports_open_ports.txt`
  - `outputs/live_hostport_urls.txt`
  - Intermediates/logs under `temp/agent1/`

### Task 13 — httpx-hostport + katana
- Run-cards:
  - `task/task13/httpx-hostport.txt`
  - `task/task13/katana.txt`
- Inputs:
  - `outputs/ports_open_hostport.txt`
  - `outputs/live_base_urls.txt`
- Outputs:
  - `outputs/live_hostport_urls.txt`
  - `outputs/katana_urls.txt`

### Task 14 — gau + katana
- Run-cards:
  - `task/task14/gau.txt`
  - `task/task14/katana.txt`
- Inputs:
  - `outputs/activesubdomain.txt` (gau)
  - `outputs/live_base_urls.txt` (katana)
- Outputs:
  - `outputs/gau_urls.txt`
  - `outputs/katana_urls.txt`

### Task 15 — gau + allowlist filter
- Run-cards:
  - `task/task15/gau.txt`
  - `task/task15/allowlist-filter-urls.txt` (uses `task/task21/allowlist_filter_urls.py`)
- Inputs:
  - `outputs/gau_urls.txt`, `outputs/katana_urls.txt`, `outputs/activesubdomain.txt`
- Outputs:
  - `outputs/gau_urls_in_scope.txt`
  - `outputs/katana_urls_in_scope.txt`

### Task 16 — allowlist filter + arjun
- Run-cards:
  - `task/task16/allowlist-filter-urls.txt` (uses `task/task21/allowlist_filter_urls.py`)
  - `task/task16/arjun.txt`
- Inputs:
  - `outputs/*_urls_in_scope.txt`
  - `outputs/activesubdomain.txt`
- Output:
  - `outputs/arjun_found_params.txt`

### Task 17 — arjun + kiterunner
- Run-cards:
  - `task/task17/arjun.txt`
  - `task/task17/kiterunner.txt`
- Inputs:
  - `outputs/gau_urls_in_scope.txt` and/or `outputs/katana_urls_in_scope.txt`
  - `outputs/live_base_urls.txt`
- Outputs:
  - `outputs/arjun_found_params.txt`
  - `outputs/queue_api_endpoints_kiterunner.txt`

### Task 18 — kiterunner + httpx probe API queue
- Run-cards:
  - `task/task18/kiterunner.txt`
  - `task/task18/httpx-probe-api-endpoints.txt`
- Inputs:
  - `outputs/live_base_urls.txt`
  - API queue file
- Outputs:
  - `outputs/queue_api_endpoints_kiterunner.txt`
  - `outputs/api_endpoints_live.txt`

### Task 19 — httpx probe API queue + JS URL discovery
- Run-cards:
  - `task/task19/httpx-probe-api-endpoints.txt`
  - `task/task19/js-urls.txt`
- Inputs:
  - `outputs/queue_api_endpoints_kiterunner.txt`
  - `outputs/gau_urls_in_scope.txt` and/or `outputs/katana_urls_in_scope.txt`
- Outputs:
  - `outputs/api_endpoints_live.txt`
  - `outputs/js_urls.txt`

### Task 20 — JS URL discovery
- Run-card: `task/task20/js-urls.txt`
- Inputs:
  - `outputs/gau_urls_in_scope.txt` and/or `outputs/katana_urls_in_scope.txt`
- Output:
  - `outputs/js_urls.txt`

### Task 21 — fetch JS + offline analyze
- Run-cards:
  - `task/task21/httpx-fetch-js.txt`
  - `task/task21/js-analyze-offline.txt` (uses `task/task21/js_analyzer.py`)
- Inputs:
  - `outputs/js_urls.txt`
- Outputs:
  - `temp/agent1/js_fetch_dir/` + `temp/agent1/js_fetch_index.txt`
  - `outputs/js_endpoints_from_js.txt`

### Task 22 — offline analyze + probe JS-extracted
- Run-cards:
  - `task/task22/js-analyze-offline.txt` (uses `task/task21/js_analyzer.py`)
  - `task/task22/httpx-probe-js-extracted.txt`
- Inputs:
  - `temp/agent1/js_fetch_*` (analysis)
  - `outputs/js_endpoints_from_js.txt` + `outputs/activesubdomain.txt`
- Outputs:
  - `outputs/js_urls_live.txt`
  - `outputs/js_composed_live.txt`

### Task 23 — probe JS-extracted + nuclei
- Run-cards:
  - `task/task23/httpx-probe-js-extracted.txt`
  - `task/task23/nuclei.txt`
- Outputs:
  - `outputs/js_urls_live.txt`, `outputs/js_composed_live.txt`
  - `outputs/nuclei_findings.txt`

### Task 24 — nuclei + gowitness
- Run-cards:
  - `task/task24/nuclei.txt`
  - `task/task24/gowitness.txt`
- Outputs:
  - `outputs/nuclei_findings.txt`
  - `outputs/gowitness/` + `outputs/coverage_screenshots_index_gowitness.txt`

### Task 25 — gowitness + ffuf
- Run-cards:
  - `task/task25/gowitness.txt`
  - `task/task25/ffuf-content-discovery.txt`
- Outputs:
  - `outputs/gowitness/` + `outputs/coverage_screenshots_index_gowitness.txt`
  - `outputs/ffuf_findings.txt`

### Task 26 — ffuf + nmap
- Run-cards:
  - `task/task26/ffuf-content-discovery.txt`
  - `task/task26/nmap-service-enum.txt`
- Outputs:
  - `outputs/ffuf_findings.txt`
  - `outputs/nmap/` + `outputs/nmap_index.txt`

### Task 27 — nmap + subjack
- Run-cards:
  - `task/task27/nmap-service-enum.txt`
  - `task/task27/subjack-takeover.txt`
- Outputs:
  - `outputs/nmap/` + `outputs/nmap_index.txt`
  - `outputs/coverage_takeover_candidates_subjack.txt`

### Task 29 — HAR Analysis (Manual Enrichment)
- Run-card: `task/task29/har-analysis.txt` (includes deep analysis guide)
- Base script: `task/task29/har_analyzer.py` (starting point — do manual analysis too)
- Inputs:
  - `manual/har/*.har` (e.g., `user1.har`, `user2.har` for 2-account IDOR testing)
  - `outputs/activesubdomain.txt` (scope allowlist)
- Outputs:
  - `outputs/har/accounts/<harname>_auth.txt` — per-account: tokens, cookies, IDs (FULL VALUES)
  - `outputs/har/accounts/<harname>_auth.json` — per-account: machine-readable
  - `outputs/har/common_data.txt` — shared: endpoints, headers, CORS
  - `outputs/har/har-report.md` — summary report
  - `outputs/har/har_summary.json` — machine-readable summary
- Notes:
  - Script is a starting point; manual investigation is MORE IMPORTANT
  - Run-card includes: HAR structure, deep analysis checklist, custom script examples
  - Designed for test accounts (no redaction — full token/ID values preserved)

### Task 30 — tlsx
- Run-card: `task/task30/tlsx.txt`
- Inputs:
  - `outputs/activesubdomain.txt`
  - `<domain>` (root domain string for suffix filter)
- Outputs:
  - `outputs/coverage_tls_sans_in_scope.txt` (plus temp intermediates)

## Helpers

- `tools/agent1/assets/allowlist_filter_urls.py` — filter URLs by scope allowlist
- `tools/agent1/assets/openapi_extractor.py` — extract endpoints from OpenAPI specs
- `task/task29/har_analyzer.py` — HAR analysis base script (account-specific + common data)

## Notes on duplicates

Some tasks repeat the same step (e.g., Task 12 vs 13 httpx-hostport, Task 14 vs 13 katana). Treat them as **equivalent run-cards** unless you intentionally prefer one version; the canonical outputs remain the same in `outputs/`.
