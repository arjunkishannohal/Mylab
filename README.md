# Mylab

This workspace contains a 3-step recon workflow for a **single target root domain**.

- **Step 1:** Subdomain enumeration → produces an in-scope, resolving host allowlist.
- **Step 2:** URL/API discovery + artifacts + merge → produces a clean URL corpus and supporting artifacts.
- **Step 3:** Analysis + prioritized scanning → produces testing queues and final recon decisions.

## Folder Layout

- `tools/agent1/` → instruction files for the agent
- `temp/agent1/` → intermediate files and downloaded artifacts
- `outputs/` → final outputs used for vulnerability testing
- `outputs/reports/` → saved analysis report

## Step 1: Subdomain Enumeration

Instructions: [tools/agent1/step1-subdomain-enumeration.txt](tools/agent1/step1-subdomain-enumeration.txt)

### Step 1 Outputs

- Host allowlist (input to Step 2): `outputs/activesubdomain.txt`
- Running report (Step 1 notes/decisions): `outputs/reports/agent1-recon-report.md`

## Step 2: URL / API Discovery + Artifacts + Merge

Instructions: [tools/agent1/step2-url-discovery.txt](tools/agent1/step2-url-discovery.txt)

### Step 2 Input

- `outputs/activesubdomain.txt` (from Step 1)

### Step 2 Outputs

Non-web surface coverage:
- `outputs/coverage_open_ports_hostport.txt`
- `outputs/coverage_non_http_services.txt`
- `outputs/coverage_tls_sans_in_scope.txt`
- `outputs/coverage_takeover_candidates_subjack.txt`
- `outputs/coverage_screenshots_index_gowitness.txt`

Web testing queues:
- (Created in Step 3)

API/parameter coverage:
- `outputs/api_docs_urls.txt`
- `outputs/api_endpoints_from_openapi.txt`
- `outputs/web_knownfiles_robots_sitemaps_security_urls.txt`
- (Created in Step 3): `outputs/queue_api_endpoints_kiterunner.txt`, `outputs/queue_hidden_params_arjun.txt`

Saved analysis report:
- `outputs/reports/agent1-recon-report.md`

### Step 2 Intermediate Artifacts

- Merged normalized URL corpus: `temp/agent1/url_corpus_all_in_scope.txt`
- Saved HTML responses: `temp/agent1/html_responses/`

### Step 3 Intermediate Artifacts

- Saved JS responses: `temp/agent1/js_responses/`
- Optional mapping of URLs → stored files: `temp/agent1/response_manifest.txt`

## Step 3: Analysis + Prioritized Scanning

Instructions: [tools/agent1/step3-analysis-and-prioritized-scanning.txt](tools/agent1/step3-analysis-and-prioritized-scanning.txt)

### Step 3 Final Outputs (for vulnerability testing)

Web testing queues:
- `outputs/queue_dynamic_endpoints_urls.txt`
- `outputs/queue_login_panels_urls.txt`
- `outputs/queue_sensitive_files_urls.txt`
- `outputs/queue_cloud_bucket_urls.txt`
- `outputs/queue_static_assets_urls.txt`

API/parameter coverage:
- `outputs/queue_api_endpoints_kiterunner.txt`
- `outputs/queue_hidden_params_arjun.txt`