# Mylab

This workspace contains a 2-step recon workflow for a **single target root domain**.

- **Step 1:** Subdomain enumeration → produces an in-scope, resolving host allowlist.
- **Step 2:** URL + API discovery + artifacts + prioritization → produces testing queues and a saved recon report.

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

## Step 2: URL / API Discovery + Artifacts + Buckets

Instructions: [tools/agent1/step2-url-discovery.txt](tools/agent1/step2-url-discovery.txt)

### Step 2 Input

- `outputs/activesubdomain.txt` (from Step 1)

### Step 2 Final Outputs (for vulnerability testing)

Non-web surface coverage:
- `outputs/open_ports.txt`
- `outputs/non_http_services.txt`
- `outputs/tls_hosts.txt`
- `outputs/takeover_candidates.txt`
- `outputs/screenshots_index.txt`

Web testing queues:
- `outputs/endpoints.txt`
- `outputs/login_panels.txt`
- `outputs/sensitive_files.txt`
- `outputs/cloud_buckets.txt`
- `outputs/static_assets.txt`

API/parameter coverage:
- `outputs/api_docs_hits.txt`
- `outputs/robots_sitemaps_security.txt`
- `outputs/kiterunner_endpoints.txt`
- `outputs/hidden_params.txt`

Saved analysis report:
- `outputs/reports/agent1-recon-report.md`

### Step 2 Intermediate Artifacts

- Merged normalized URL corpus: `temp/agent1/all_urls.txt`
- Saved HTML responses: `temp/agent1/html_responses/`
- Saved JS responses: `temp/agent1/js_responses/`
- Optional mapping of URLs → stored files: `temp/agent1/response_manifest.txt`