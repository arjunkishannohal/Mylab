# Recon Workflow Mindmap (Inputs + Outputs)

This file includes:
1) A mindmap listing each task with its main inputs/outputs
2) A flowchart that connects inputs → task → outputs with arrows

```mermaid
mindmap
  root((Recon Workflow))
    Conventions
      outputs/ => final artifacts
      temp/agent1/ => intermediates
      manual/ => manual inputs
      task/taskN/ => run-cards
    Subdomains_&_Scope
      Task_1_Subfinder
        input: domain
        output: temp/agent1/list_1_passive.txt
      Task_2_Amass
        input: domain
        output: temp/agent1/list_1_passive.txt
      Task_3_GitHub_Subdomains
        input: domain + token
        output: temp/agent1/list_1_passive.txt
      Task_4_Waymore
        input: domain
        output: temp/agent1/list_2_archives.txt
      Task_5_Bruteforce
        input: wordlist + resolvers
        output: temp/agent1/list_3_bruteforce.txt
      Task_10_Hakrevdns_optional
        input: CIDRs
        output: temp/agent1/list_4_reverse.txt
      Task_6_Alterx
        input: temp/agent1/list_{1,2,3,4,5}*
        output: temp/agent1/list_5_permutations.txt
      Task_7_Puredns_Resolve
        input: temp/agent1/candidates_all.txt
        output: outputs/activesubdomain.txt
    Live_Discovery
      Task_8_Httpx
        input: outputs/activesubdomain.txt
        output: outputs/live_base_urls.txt
      Task_8_Cariddi_inline
        input: outputs/live_base_urls.txt
        output: outputs/cariddi/cariddi_urls_in_scope.txt
        output: outputs/url_corpus_all_in_scope.txt
      Task_12_Naabu
        input: outputs/activesubdomain.txt
        output: outputs/ports_open_hostport.txt
      Task_12_13_Httpx_Hostport
        input: outputs/ports_open_hostport.txt
        output: outputs/live_hostport_urls.txt
      Task_9_Knownfiles_&_API_Docs
        input: outputs/live_base_urls.txt
        output: outputs/web_knownfiles_robots_sitemaps_security_urls.txt
        output: outputs/api_docs_urls.txt
    URL_Corpus
      Task_13_14_Katana
        input: outputs/live_base_urls.txt
        output: outputs/katana_urls.txt
      Task_14_15_GAU
        input: outputs/activesubdomain.txt
        output: outputs/gau_urls.txt
      Task_15_16_Allowlist_Filter
        input: outputs/{gau,katana}_urls.txt
        input: outputs/activesubdomain.txt
        output: outputs/{gau,katana}_urls_in_scope.txt
        output: outputs/url_corpus_all_in_scope.txt
    API_&_Params
      Task_17_18_Kiterunner
        input: outputs/live_base_urls.txt
        output: outputs/queue_api_endpoints_kiterunner.txt
      Task_18_19_Httpx_Probe_API
        input: outputs/queue_api_endpoints_kiterunner.txt
        output: outputs/api_endpoints_live.txt
      Task_16_17_Arjun
        input: outputs/url_corpus_all_in_scope.txt
        output: outputs/arjun_found_params.txt
    JS_Pipeline
      Task_19_20_JS_URL_Discovery
        input: outputs/{gau,katana}_urls_in_scope.txt
        output: outputs/js_urls.txt
      Task_21_Fetch_JS
        input: outputs/js_urls.txt
        output: temp/agent1/js_fetch_dir/
      Task_21_22_Offline_JS_Analysis
        input: temp/agent1/js_fetch_dir/
        output: outputs/js_endpoints_from_js.txt
      Task_22_23_Probe_JS_Extracted
        input: outputs/js_endpoints_from_js.txt
        output: outputs/js_urls_live.txt
    Coverage_&_Scanning
      Task_23_24_Nuclei
        input: validated URLs
        output: outputs/nuclei_findings.txt
      Task_24_25_Gowitness
        input: validated URLs
        output: outputs/coverage_screenshots_index_gowitness.txt
      Task_25_26_Ffuf
        input: validated URLs
        output: outputs/ffuf_findings.txt
      Task_26_27_Nmap
        input: outputs/ports_open_hostport.txt
        output: outputs/nmap_index.txt
      Task_27_28_Subjack
        input: outputs/activesubdomain.txt
        output: outputs/coverage_takeover_candidates_subjack.txt
      Task_30_Tlsx
        input: outputs/activesubdomain.txt
        output: outputs/coverage_tls_sans_in_scope.txt
    Manual_Enrichment
      Task_29_HAR_Analysis
        input: manual/har/*.har
        input: outputs/activesubdomain.txt
        output: outputs/har/common_data.txt
        output: outputs/har/accounts/<harname>_auth.txt

```

```mermaid
flowchart TD
  A[outputs/activesubdomain.txt] --> T8[Task 8: httpx]
  T8 --> B[outputs/live_base_urls.txt]

  B --> C8[Task 8: cariddi (inline)]
  A --> C8
  C8 --> C1[outputs/cariddi/cariddi_findings.txt]
  C8 --> C2[outputs/cariddi/cariddi_urls_in_scope.txt]
  C8 --> UC[outputs/url_corpus_all_in_scope.txt]

  A --> N12[Task 12: naabu]
  N12 --> HP[outputs/ports_open_hostport.txt]
  HP --> HXHP[Task 12/13: httpx-hostport]
  HXHP --> LHP[outputs/live_hostport_urls.txt]

  B --> K9[Task 9: knownfiles + api-docs]
  K9 --> KF[outputs/web_knownfiles_robots_sitemaps_security_urls.txt]
  K9 --> AD[outputs/api_docs_urls.txt]

  B --> KAT[Task 13/14: katana]
  KAT --> KU[outputs/katana_urls.txt]
  A --> GAU[Task 14/15: gau]
  GAU --> GU[outputs/gau_urls.txt]

  A --> FLT[Task 15/16: allowlist filter]
  KU --> FLT
  GU --> FLT
  FLT --> KUS[outputs/katana_urls_in_scope.txt]
  FLT --> GUS[outputs/gau_urls_in_scope.txt]
  FLT --> UC

  UC --> ARJ[Task 16/17: arjun]
  ARJ --> AP[outputs/arjun_found_params.txt]

  B --> KR[Task 17/18: kiterunner]
  KR --> QAPI[outputs/queue_api_endpoints_kiterunner.txt]
  QAPI --> HAPI[Task 18/19: httpx probe API]
  HAPI --> AEL[outputs/api_endpoints_live.txt]

  KUS --> JS1[Task 19/20: JS URL discovery]
  GUS --> JS1
  JS1 --> JSU[outputs/js_urls.txt]

  JSU --> JSF[Task 21: fetch JS]
  JSF --> JSD[temp/agent1/js_fetch_dir/]
  JSD --> JSA[Task 21/22: offline JS analysis]
  JSA --> JSE[outputs/js_endpoints_from_js.txt]
  JSE --> JSP[Task 22/23: probe JS extracted]
  JSP --> JSL[outputs/js_urls_live.txt]

  MAN[manual/har/*.har] --> HAR[Task 29: HAR analysis]
  A --> HAR
  HAR --> HCOM[outputs/har/common_data.txt]
  HAR --> HAUT[outputs/har/accounts/<harname>_auth.txt]

```

Notes
- Mermaid rendering depends on your Markdown preview setup.
- This flowchart focuses on the canonical artifacts and how they connect.
