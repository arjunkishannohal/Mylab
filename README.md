# Recon Workflow (Strict Run-Cards) — 106 Tasks

This repo is a **deterministic security testing pipeline** governed by strict "run-cards".

**GO AGGRESSIVE.** This toolkit is designed for authorized penetration testing with full exploitation capability.

## Repo conventions

- `task/taskN/` contains **run-cards** (text files) you execute step-by-step.
- `outputs/` contains **final / important / downstream** artifacts (deduped, canonical).
- `temp/agent1/` contains **intermediate, raw, logs, chunks**.
- `manual/` contains **manual inputs** (e.g., HAR captures).
- `tools/` contains helper scripts (stdlib-only where possible).

Time governance: see `rules.txt` (9-minute command limit; batch/chunk if needed).

## Pipeline Phases (16 Phases, 106 Tasks)

### Phase 0: Subdomain Discovery (Tasks 1-11)
| Task | Tool | Output |
|------|------|--------|
| 1 | subfinder | temp/agent1/list_1_passive.txt |
| 2 | amass | temp/agent1/list_1_passive.txt |
| 3 | github-subdomains | temp/agent1/list_1_passive.txt |
| 4 | waymore | temp/agent1/list_2_archives.txt |
| 5 | puredns bruteforce | temp/agent1/list_3_bruteforce.txt |
| 6 | alterx | temp/agent1/list_5_permutations.txt |
| 7 | puredns resolve | **outputs/activesubdomain.txt** |
| 8 | httpx | **outputs/live_base_urls.txt** |
| 9 | httpx knownfiles | outputs/api_docs_urls.txt |
| 10 | hakrevdns | temp/agent1/list_4_reverse.txt |
| 11 | dnsx | temp/agent1/resolved_dnsx.txt |

### Phase 1: Port & Service Discovery (Tasks 12-13)
| Task | Tool | Output |
|------|------|--------|
| 12 | naabu | outputs/ports_open_hostport.txt |
| 13 | httpx-hostport + katana | outputs/live_hostport_urls.txt |

### Phase 2: URL Discovery & Filtering (Tasks 14-22)
| Task | Tool | Output |
|------|------|--------|
| 14 | gau | outputs/gau_urls.txt |
| 15 | allowlist filter | outputs/url_corpus_all_in_scope.txt |
| 16 | arjun | outputs/arjun_found_params.txt |
| 17 | kiterunner | outputs/queue_api_endpoints_kiterunner.txt |
| 18 | httpx probe API | outputs/api_endpoints_live.txt |
| 19 | js-urls | outputs/js_urls.txt |
| 21 | httpx-fetch-js + analyze | outputs/js_endpoints_from_js.txt |
| 22 | httpx probe JS | outputs/js_urls_live.txt |

### Phase 3: Broad Coverage Scanning (Tasks 23-42)
| Task | Tool | Output |
|------|------|--------|
| 23 | nuclei | outputs/nuclei_findings.txt |
| 24 | gowitness | outputs/gowitness/ |
| 25 | ffuf | outputs/ffuf_findings.txt |
| 26 | nmap | outputs/nmap/ |
| 27 | subjack | outputs/coverage_takeover_candidates_subjack.txt |
| 29 | HAR analysis | outputs/har/ |
| 30 | tlsx | outputs/coverage_tls_sans_in_scope.txt |
| 31 | playwright-ui-capture | temp/agent1/playwright_har/ |
| 32 | WAF fingerprinting | outputs/waf_fingerprints.txt |
| 33 | role-diff access control | outputs/access_control_findings.json |
| 34 | IDOR/BOLA fuzzing | outputs/idor_findings.json |
| 35-39 | nuclei (tech, exposures, CVEs) | outputs/nuclei/ |
| 40 | ZAP baseline | outputs/zap/zap_baseline_report.json |
| 41 | ZAP full scan | outputs/zap/injection_candidates.txt |
| 42 | source extraction | outputs/source/ |

### Phase 4: Injection Testing (Tasks 43-49)
| Task | Tool | Output |
|------|------|--------|
| 43 | ghauri SQLi triage | outputs/sqli/ghauri_vulnerable.txt |
| 44 | sqlmap deep exploit | outputs/sqli/sqlmap_dumps/ |
| 45 | nosqlmap | outputs/sqli/nosql_vulnerable.txt |
| 46 | commix CMDi | outputs/cmdi/commix_vulnerable.txt |
| 47 | CMDi bypass + OOB | outputs/cmdi/oob_vulnerable.txt |
| 48 | SSTI scanner | outputs/ssti/ssti_vulnerable.txt |
| 49 | LDAP/XPath injection | outputs/ldap_xpath/ |

### Phase 5: SSRF & XXE (Tasks 50-53)
| Task | Tool | Output |
|------|------|--------|
| 50 | SSRF detection | outputs/ssrf/ssrf_candidates.txt |
| 51 | SSRF exploitation | outputs/ssrf/ssrf_confirmed.txt |
| 52 | XXE detection | outputs/xxe/xxe_candidates.txt |
| 53 | XXE exploitation | outputs/xxe/xxe_confirmed.txt |

### Phase 6: Client-Side Attacks (Tasks 54-60)
| Task | Tool | Output |
|------|------|--------|
| 54 | XSS reflection scanner | outputs/xss_reflections_kxss.txt |
| 55 | XSS deep exploitation | outputs/xss/reflected_xss.txt |
| 56 | blind XSS campaign | outputs/xss/blind_xss_triggered.txt |
| 57 | prototype pollution | outputs/prototype_pollution/ |
| 58 | DOM clobbering | outputs/dom_clobbering/ |
| 59 | CSS injection | outputs/css_injection/ |
| 60 | dangling markup | outputs/dangling_markup/ |

### Phase 7: Auth & Session (Tasks 61-66)
| Task | Tool | Output |
|------|------|--------|
| 61 | JWT attacks | outputs/jwt/ |
| 62 | OAuth/SSO exploitation | outputs/oauth/ |
| 63 | session fixation | outputs/session/ |
| 64 | session lifecycle | outputs/session/ |
| 65 | 2FA bypass | outputs/2fa/ |
| 66 | password reset poisoning | outputs/reset/ |

### Phase 8: API Attacks (Tasks 67-71)
| Task | Tool | Output |
|------|------|--------|
| 67 | GraphQL discovery | outputs/graphql/ |
| 68 | GraphQL DoS | outputs/graphql/ |
| 69 | GraphQL exploitation | outputs/graphql/ |
| 70 | REST API attacks | outputs/rest/ |
| 71 | rate limit bypass | outputs/ratelimit/ |

### Phase 9: File Handling (Tasks 72-77)
| Task | Tool | Output |
|------|------|--------|
| 72 | LFI detection | outputs/lfi/lfi_confirmed.txt |
| 73 | LFI to RCE | outputs/lfi/rce_confirmed.txt |
| 74 | file upload detection | outputs/upload/upload_endpoints.txt |
| 75 | file upload exploitation | outputs/upload/ |
| 76 | deserialization detection | outputs/deser/ |
| 77 | deserialization RCE | outputs/deser/java_rce_confirmed.txt |

### Phase 10: Business Logic (Tasks 78-80)
| Task | Tool | Output |
|------|------|--------|
| 78 | race conditions | outputs/race/ |
| 79 | payment logic | outputs/payment/ |
| 80 | business logic flaws | outputs/business_logic/ |

### Phase 11: HTTP Protocol (Tasks 81-83)
| Task | Tool | Output |
|------|------|--------|
| 81 | request smuggling | outputs/smuggling/ |
| 82 | HTTP/2 attacks | outputs/http2/ |
| 83 | browser desync | outputs/desync/ |

### Phase 12: Cache & CDN (Tasks 84-86)
| Task | Tool | Output |
|------|------|--------|
| 84 | cache poisoning | outputs/cache/ |
| 85 | cache deception | outputs/cache/ |
| 86 | ESI injection | outputs/esi/ |

### Phase 13: Infrastructure (Tasks 87-90)
| Task | Tool | Output |
|------|------|--------|
| 87 | cloud metadata SSRF | outputs/cloud/iam_credentials.txt |
| 88 | cloud bucket abuse | outputs/cloud/buckets_public_write.txt |
| 89 | subdomain takeover | outputs/takeover/ |
| 90 | DNS zone attacks | outputs/dns/ |

### Phase 14: Supply Chain (Tasks 91-92)
| Task | Tool | Output |
|------|------|--------|
| 91 | dependency confusion | outputs/supply_chain/ |
| 92 | second-order attacks | outputs/second_order/ |

### Phase 15: Miscellaneous (Tasks 93-103)
| Task | Tool | Output |
|------|------|--------|
| 93 | CORS misconfiguration | outputs/cors/ |
| 94 | clickjacking | outputs/clickjacking/ |
| 95 | CSP bypass | outputs/csp/ |
| 96 | host header attacks | outputs/host_header/ |
| 97 | open redirect | outputs/openredirect/ |
| 98 | verb tampering | outputs/verb_tampering/ |
| 99 | rate limiting | outputs/ratelimit/ |
| 100 | session management | outputs/session/ |
| 101 | business logic | outputs/business_logic/ |
| 102 | GraphQL attacks | outputs/graphql/ |
| 103 | WebSocket security | outputs/websocket/ |

### Phase 16: Closeout (Tasks 104-106)
| Task | Tool | Output |
|------|------|--------|
| 104 | vulnerability consolidation | outputs/reports/vulnerability_consolidation.md |
| 105 | final report | outputs/reports/final_report.md |
| 106 | evidence closeout | outputs/final_delivery/ |

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

### Task 12 — naabu (host:port)
- Run-card: `task/task12/naabu.txt`
- Input: `outputs/activesubdomain.txt`
- Outputs:
  - `outputs/ports_open_hostport.txt`
  - `outputs/ports_open_hosts.txt`
  - `outputs/ports_open_ports.txt`
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

### Task 14 — gau
- Run-card: `task/task14/gau.txt`
- Input: `outputs/activesubdomain.txt`
- Output: `outputs/gau_urls.txt`

### Task 15 — allowlist filter (URLs)
- Run-card: `task/task15/allowlist-filter-urls.txt` (uses `task/task21/allowlist_filter_urls.py`)
- Inputs:
  - `outputs/gau_urls.txt`, `outputs/katana_urls.txt`, `outputs/activesubdomain.txt`
- Outputs:
  - `outputs/gau_urls_in_scope.txt`
  - `outputs/katana_urls_in_scope.txt`

### Task 16 — arjun
- Run-card: `task/task16/arjun.txt`
- Input: `outputs/url_corpus_all_in_scope.txt`
- Output: `outputs/arjun_found_params.txt`

### Task 17 — kiterunner
- Run-card: `task/task17/kiterunner.txt`
- Input: `outputs/live_base_urls.txt`
- Output: `outputs/queue_api_endpoints_kiterunner.txt`

### Task 18 — httpx probe API queue
- Run-card: `task/task18/httpx-probe-api-endpoints.txt`
- Inputs:
  - `outputs/live_base_urls.txt`
  - API queue file
- Outputs:
  - `outputs/queue_api_endpoints_kiterunner.txt`
  - `outputs/api_endpoints_live.txt`

### Task 19 — JS URL discovery
- Run-card: `task/task19/js-urls.txt`
- Inputs:
  - `outputs/gau_urls_in_scope.txt` and/or `outputs/katana_urls_in_scope.txt`
- Outputs:
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

### Task 22 — probe JS-extracted
- Run-card: `task/task22/httpx-probe-js-extracted.txt`
- Input: `outputs/js_endpoints_from_js.txt` + `outputs/activesubdomain.txt`
- Outputs:
  - `outputs/js_urls_live.txt`
  - `outputs/js_composed_live.txt`

### Task 23 — nuclei
- Run-card: `task/task23/nuclei.txt`
- Input: validated URLs
- Output: `outputs/nuclei_findings.txt`

### Task 24 — gowitness
- Run-card: `task/task24/gowitness.txt`
- Input: validated URLs
- Outputs: `outputs/gowitness/` + `outputs/coverage_screenshots_index_gowitness.txt`

### Task 25 — ffuf
- Run-card: `task/task25/ffuf-content-discovery.txt`
- Input: validated URLs
- Output: `outputs/ffuf_findings.txt`

### Task 26 — nmap
- Run-card: `task/task26/nmap-service-enum.txt`
- Input: `outputs/ports_open_hostport.txt`
- Outputs: `outputs/nmap/` + `outputs/nmap_index.txt`

### Task 27 — subjack
- Run-card: `task/task27/subjack-takeover.txt`
- Input: `outputs/activesubdomain.txt`
- Output: `outputs/coverage_takeover_candidates_subjack.txt`

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

Run-cards are intended to be single-source-of-truth (no duplicate copies across task folders).
