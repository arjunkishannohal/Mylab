# temp/agent1 reference inventory

Generated: 2026-01-11T07:12:42.694497Z
Unique refs: 243
Total occurrences: 913

## temp\agent1\_httpx_part.txt (count=32)
- task/task12/httpx-hostport.txt#L65: `#   httpx -l temp\agent1\httpx_hostport_targets.txt -silent -timeout 9 -retries 1 -threads 50 -o temp\agent1\_httpx_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task12/httpx-hostport.txt#L66: `#   if (Test-Path temp\agent1\_httpx_part.txt) { Get-Content temp\agent1\_httpx_part.txt | Add-Content temp\agent1\live_hostport_urls_raw.txt; Remove-Item temp\agent1\_httpx_part.txt }`
- task/task12/httpx-hostport.txt#L66: `#   if (Test-Path temp\agent1\_httpx_part.txt) { Get-Content temp\agent1\_httpx_part.txt | Add-Content temp\agent1\live_hostport_urls_raw.txt; Remove-Item temp\agent1\_httpx_part.txt }`
- task/task12/httpx-hostport.txt#L66: `#   if (Test-Path temp\agent1\_httpx_part.txt) { Get-Content temp\agent1\_httpx_part.txt | Add-Content temp\agent1\live_hostport_urls_raw.txt; Remove-Item temp\agent1\_httpx_part.txt }`
- task/task13/httpx-hostport.txt#L65: `#   httpx -l temp\agent1\httpx_hostport_targets.txt -silent -timeout 9 -retries 1 -threads 50 -o temp\agent1\_httpx_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task13/httpx-hostport.txt#L66: `#   if (Test-Path temp\agent1\_httpx_part.txt) { Get-Content temp\agent1\_httpx_part.txt | Add-Content temp\agent1\live_hostport_urls_raw.txt; Remove-Item temp\agent1\_httpx_part.txt }`
- task/task13/httpx-hostport.txt#L66: `#   if (Test-Path temp\agent1\_httpx_part.txt) { Get-Content temp\agent1\_httpx_part.txt | Add-Content temp\agent1\live_hostport_urls_raw.txt; Remove-Item temp\agent1\_httpx_part.txt }`
- task/task13/httpx-hostport.txt#L66: `#   if (Test-Path temp\agent1\_httpx_part.txt) { Get-Content temp\agent1\_httpx_part.txt | Add-Content temp\agent1\live_hostport_urls_raw.txt; Remove-Item temp\agent1\_httpx_part.txt }`
- task/task18/httpx-probe-api-endpoints.txt#L55: `#   httpx -l temp\agent1\httpx_api_endpoints_targets.txt -silent -timeout 9 -retries 1 -threads 50 -o temp\agent1\_httpx_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task18/httpx-probe-api-endpoints.txt#L56: `#   if (Test-Path temp\agent1\_httpx_part.txt) { Get-Content temp\agent1\_httpx_part.txt | Add-Content temp\agent1\api_endpoints_live_raw.txt; Remove-Item temp\agent1\_httpx_part.txt }`
- … 22 more

## temp\agent1\logs (count=30)
- task/task12/httpx-hostport.txt#L32: `#   New-Item -ItemType Directory -Force temp\agent1\logs | Out-Null`
- task/task12/naabu.txt#L43: `#   New-Item -ItemType Directory -Force temp\agent1\logs | Out-Null`
- task/task13/httpx-hostport.txt#L32: `#   New-Item -ItemType Directory -Force temp\agent1\logs | Out-Null`
- task/task13/katana.txt#L33: `#   New-Item -ItemType Directory -Force temp\agent1\logs | Out-Null`
- task/task14/gau.txt#L31: `#   New-Item -ItemType Directory -Force temp\agent1\logs | Out-Null`
- task/task14/katana.txt#L33: `#   New-Item -ItemType Directory -Force temp\agent1\logs | Out-Null`
- task/task15/gau.txt#L31: `#   New-Item -ItemType Directory -Force temp\agent1\logs | Out-Null`
- task/task16/arjun.txt#L29: `#   New-Item -ItemType Directory -Force temp\agent1\logs | Out-Null`
- task/task17/arjun.txt#L29: `#   New-Item -ItemType Directory -Force temp\agent1\logs | Out-Null`
- task/task17/kiterunner.txt#L34: `#   New-Item -ItemType Directory -Force temp\agent1\logs | Out-Null`
- … 20 more

## temp\\agent1\\_httpx_part.txt (count=24)
- task/task12/httpx-hostport.txt#L108: `#     httpx -l $chunk -silent -timeout 9 -retries 1 -threads 50 -o temp\\agent1\\_httpx_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task12/httpx-hostport.txt#L109: `#     if (Test-Path temp\\agent1\\_httpx_part.txt) {`
- task/task12/httpx-hostport.txt#L110: `#       Get-Content temp\\agent1\\_httpx_part.txt | Add-Content temp\\agent1\\live_hostport_urls_raw.txt`
- task/task12/httpx-hostport.txt#L111: `#       Remove-Item temp\\agent1\\_httpx_part.txt`
- task/task13/httpx-hostport.txt#L108: `#     httpx -l $chunk -silent -timeout 9 -retries 1 -threads 50 -o temp\\agent1\\_httpx_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task13/httpx-hostport.txt#L109: `#     if (Test-Path temp\\agent1\\_httpx_part.txt) {`
- task/task13/httpx-hostport.txt#L110: `#       Get-Content temp\\agent1\\_httpx_part.txt | Add-Content temp\\agent1\\live_hostport_urls_raw.txt`
- task/task13/httpx-hostport.txt#L111: `#       Remove-Item temp\\agent1\\_httpx_part.txt`
- task/task18/httpx-probe-api-endpoints.txt#L97: `#     httpx -l $chunk -silent -timeout 9 -retries 1 -threads 50 -o temp\\agent1\\_httpx_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task18/httpx-probe-api-endpoints.txt#L98: `#     if (Test-Path temp\\agent1\\_httpx_part.txt) {`
- … 14 more

## temp\agent1\_url_corpus_in_scope.txt (count=22)
- task/task16/arjun.txt#L36: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\_url_corpus_in_scope.txt`
- task/task16/arjun.txt#L37: `#   if (Test-Path outputs\gau_urls_in_scope.txt) { Get-Content outputs\gau_urls_in_scope.txt | Add-Content temp\agent1\_url_corpus_in_scope.txt }`
- task/task16/arjun.txt#L38: `#   if (Test-Path outputs\katana_urls_in_scope.txt) { Get-Content outputs\katana_urls_in_scope.txt | Add-Content temp\agent1\_url_corpus_in_scope.txt }`
- task/task16/arjun.txt#L39: `#   if (!(Test-Path temp\agent1\_url_corpus_in_scope.txt)) { throw "Missing in-scope URL corpus (expected gau_urls_in_scope.txt and/or katana_urls_in_scope.txt)" }`
- task/task16/arjun.txt#L42: `#   Get-Content temp\agent1\_url_corpus_in_scope.txt |`
- task/task17/arjun.txt#L37: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\_url_corpus_in_scope.txt`
- task/task17/arjun.txt#L38: `#   if (Test-Path outputs\gau_urls_in_scope.txt) { Get-Content outputs\gau_urls_in_scope.txt | Add-Content temp\agent1\_url_corpus_in_scope.txt }`
- task/task17/arjun.txt#L39: `#   if (Test-Path outputs\katana_urls_in_scope.txt) { Get-Content outputs\katana_urls_in_scope.txt | Add-Content temp\agent1\_url_corpus_in_scope.txt }`
- task/task17/arjun.txt#L40: `#   if (!(Test-Path temp\agent1\_url_corpus_in_scope.txt)) { throw "Missing in-scope URL corpus (expected gau_urls_in_scope.txt and/or katana_urls_in_scope.txt)" }`
- task/task17/arjun.txt#L43: `#   Get-Content temp\agent1\_url_corpus_in_scope.txt |`
- … 12 more

## temp/agent1/resolvers_good.txt (count=18)
- task/task10/hakrevdns.txt#L19: `-R temp/agent1/resolvers_good.txt`
- task/task10/hakrevdns.txt#L30: `| hakrevdns -d -t 50 -R temp/agent1/resolvers_good.txt \`
- task/task11/dnsx.txt#L14: `- Preferred: temp/agent1/resolvers_good.txt (pruned)`
- task/task11/dnsx.txt#L39: `cat temp/agent1/candidates_all.txt | dnsx -silent -r temp/agent1/resolvers_good.txt -o temp/agent1/resolved_dnsx.txt`
- task/task11/dnsx.txt#L76: `dnsx -l temp/agent1/candidates_all.txt -wd <root-domain> -r temp/agent1/resolvers_good.txt -o temp/agent1/dnsx_wildcard.json`
- task/task11/dnsx.txt#L85: `cat temp/agent1/in_scope_cidrs.txt | dnsx -silent -resp-only -ptr -r temp/agent1/resolvers_good.txt \`
- task/task11/dnsx.txt#L90: `cat temp/agent1/in_scope_asns.txt | dnsx -silent -resp-only -ptr -r temp/agent1/resolvers_good.txt \`
- task/task5/puredns-bruteforce.txt#L9: `# - temp/agent1/resolvers_good.txt (recommended; generated by resolver prune test)`
- task/task5/puredns-bruteforce.txt#L20: `Copy-Item task/task5/resolvers_curated.txt temp/agent1/resolvers_good.txt -Force`
- task/task5/puredns-bruteforce.txt#L24: `--resolvers temp/agent1/resolvers_good.txt \`
- … 8 more

## temp\agent1\live_hostport_urls_raw.txt (count=14)
- task/task12/httpx-hostport.txt#L54: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\live_hostport_urls_raw.txt`
- task/task12/httpx-hostport.txt#L66: `#   if (Test-Path temp\agent1\_httpx_part.txt) { Get-Content temp\agent1\_httpx_part.txt | Add-Content temp\agent1\live_hostport_urls_raw.txt; Remove-Item temp\agent1\_httpx_part.txt }`
- task/task12/httpx-hostport.txt#L67: `#   if (Test-Path temp\agent1\live_hostport_urls_raw.txt) { Write-Host "[httpx host:port] raw lines so far: $((Get-Content temp\agent1\live_hostport_urls_raw.txt).Count)" }`
- task/task12/httpx-hostport.txt#L67: `#   if (Test-Path temp\agent1\live_hostport_urls_raw.txt) { Write-Host "[httpx host:port] raw lines so far: $((Get-Content temp\agent1\live_hostport_urls_raw.txt).Count)" }`
- task/task12/httpx-hostport.txt#L75: `#   if (!(Test-Path temp\agent1\live_hostport_urls_raw.txt)) { Write-Host "[httpx host:port] No raw output yet (no live services found or probe failed)." }`
- task/task12/httpx-hostport.txt#L76: `#   if (Test-Path temp\agent1\live_hostport_urls_raw.txt) {`
- task/task12/httpx-hostport.txt#L77: `#     Get-Content temp\agent1\live_hostport_urls_raw.txt |`
- task/task13/httpx-hostport.txt#L54: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\live_hostport_urls_raw.txt`
- task/task13/httpx-hostport.txt#L66: `#   if (Test-Path temp\agent1\_httpx_part.txt) { Get-Content temp\agent1\_httpx_part.txt | Add-Content temp\agent1\live_hostport_urls_raw.txt; Remove-Item temp\agent1\_httpx_part.txt }`
- task/task13/httpx-hostport.txt#L67: `#   if (Test-Path temp\agent1\live_hostport_urls_raw.txt) { Write-Host "[httpx host:port] raw lines so far: $((Get-Content temp\agent1\live_hostport_urls_raw.txt).Count)" }`
- … 4 more

## temp\agent1\katana_seeds_urls.txt (count=14)
- task/task13/katana.txt#L38: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\katana_seeds_urls.txt`
- task/task13/katana.txt#L39: `#   Get-Content outputs\live_base_urls.txt | Where-Object { $_ -and $_.Trim() -ne "" } | ForEach-Object { $_.Trim() } | Add-Content temp\agent1\katana_seeds_urls.txt`
- task/task13/katana.txt#L41: `#     Get-Content outputs\live_hostport_urls.txt | Where-Object { $_ -and $_.Trim() -ne "" } | ForEach-Object { $_.Trim() } | Add-Content temp\agent1\katana_seeds_urls.txt`
- task/task13/katana.txt#L43: `#   Get-Content temp\agent1\katana_seeds_urls.txt | Sort-Object -Unique | Set-Content temp\agent1\katana_seeds_urls.txt`
- task/task13/katana.txt#L43: `#   Get-Content temp\agent1\katana_seeds_urls.txt | Sort-Object -Unique | Set-Content temp\agent1\katana_seeds_urls.txt`
- task/task13/katana.txt#L44: `#   $n = (Get-Content temp\agent1\katana_seeds_urls.txt).Count`
- task/task13/katana.txt#L62: `#   katana -list temp\agent1\katana_seeds_urls.txt -silent -o temp\agent1\_katana_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task14/katana.txt#L38: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\katana_seeds_urls.txt`
- task/task14/katana.txt#L39: `#   Get-Content outputs\live_base_urls.txt | Where-Object { $_ -and $_.Trim() -ne "" } | ForEach-Object { $_.Trim() } | Add-Content temp\agent1\katana_seeds_urls.txt`
- task/task14/katana.txt#L41: `#     Get-Content outputs\live_hostport_urls.txt | Where-Object { $_ -and $_.Trim() -ne "" } | ForEach-Object { $_.Trim() } | Add-Content temp\agent1\katana_seeds_urls.txt`
- … 4 more

## temp\agent1\kiterunner_targets_urls.txt (count=14)
- task/task17/kiterunner.txt#L39: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\kiterunner_targets_urls.txt`
- task/task17/kiterunner.txt#L40: `#   Get-Content outputs\live_base_urls.txt | Where-Object { $_ -and $_.Trim() -ne "" } | ForEach-Object { $_.Trim() } | Add-Content temp\agent1\kiterunner_targets_urls.txt`
- task/task17/kiterunner.txt#L42: `#     Get-Content outputs\live_hostport_urls.txt | Where-Object { $_ -and $_.Trim() -ne "" } | ForEach-Object { $_.Trim() } | Add-Content temp\agent1\kiterunner_targets_urls.txt`
- task/task17/kiterunner.txt#L44: `#   Get-Content temp\agent1\kiterunner_targets_urls.txt | Sort-Object -Unique | Set-Content temp\agent1\kiterunner_targets_urls.txt`
- task/task17/kiterunner.txt#L44: `#   Get-Content temp\agent1\kiterunner_targets_urls.txt | Sort-Object -Unique | Set-Content temp\agent1\kiterunner_targets_urls.txt`
- task/task17/kiterunner.txt#L45: `#   $n = (Get-Content temp\agent1\kiterunner_targets_urls.txt).Count`
- task/task17/kiterunner.txt#L75: `#   kr scan temp\agent1\kiterunner_targets_urls.txt -w $routes -o temp\agent1\kiterunner_raw.json 2>&1 | Tee-Object -FilePath $log -Append`
- task/task18/kiterunner.txt#L39: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\kiterunner_targets_urls.txt`
- task/task18/kiterunner.txt#L40: `#   Get-Content outputs\live_base_urls.txt | Where-Object { $_ -and $_.Trim() -ne "" } | ForEach-Object { $_.Trim() } | Add-Content temp\agent1\kiterunner_targets_urls.txt`
- task/task18/kiterunner.txt#L42: `#     Get-Content outputs\live_hostport_urls.txt | Where-Object { $_ -and $_.Trim() -ne "" } | ForEach-Object { $_.Trim() } | Add-Content temp\agent1\kiterunner_targets_urls.txt`
- … 4 more

## temp\agent1\ports_open_hostport_raw.txt (count=10)
- task/task12/naabu.txt#L60: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\ports_open_hostport_raw.txt`
- task/task12/naabu.txt#L79: `#   if (Test-Path temp\agent1\_ports_open_hostport_part.txt) { Get-Content temp\agent1\_ports_open_hostport_part.txt | Add-Content temp\agent1\ports_open_hostport_raw.txt; Remove-Item temp\agent1\_ports_open_hostport_part.txt }`
- task/task12/naabu.txt#L80: `#   if (Test-Path temp\agent1\ports_open_hostport_raw.txt) { Write-Host "[naabu] raw lines so far: $((Get-Content temp\agent1\ports_open_hostport_raw.txt).Count)" }`
- task/task12/naabu.txt#L80: `#   if (Test-Path temp\agent1\ports_open_hostport_raw.txt) { Write-Host "[naabu] raw lines so far: $((Get-Content temp\agent1\ports_open_hostport_raw.txt).Count)" }`
- task/task12/naabu.txt#L90: `#   if (Test-Path temp\agent1\_ports_open_hostport_part.txt) { Get-Content temp\agent1\_ports_open_hostport_part.txt | Add-Content temp\agent1\ports_open_hostport_raw.txt; Remove-Item temp\agent1\_ports_open_hostport_part.txt }`
- task/task12/naabu.txt#L91: `#   if (Test-Path temp\agent1\ports_open_hostport_raw.txt) { Write-Host "[naabu] raw lines so far: $((Get-Content temp\agent1\ports_open_hostport_raw.txt).Count)" }`
- task/task12/naabu.txt#L91: `#   if (Test-Path temp\agent1\ports_open_hostport_raw.txt) { Write-Host "[naabu] raw lines so far: $((Get-Content temp\agent1\ports_open_hostport_raw.txt).Count)" }`
- task/task12/naabu.txt#L103: `#   if (!(Test-Path temp\agent1\ports_open_hostport_raw.txt)) { Write-Host "[naabu] No raw output yet (no open ports found or scan failed)." }`
- task/task12/naabu.txt#L104: `#   if (Test-Path temp\agent1\ports_open_hostport_raw.txt) {`
- task/task12/naabu.txt#L105: `#     Get-Content temp\agent1\ports_open_hostport_raw.txt |`

## temp\agent1\_ports_open_hostport_part.txt (count=10)
- task/task12/naabu.txt#L77: `#   naabu -l temp\agent1\naabu_targets_hosts.txt -top-ports 1000 -rate 3000 -retries 1 -timeout 1000 -silent -o temp\agent1\_ports_open_hostport_part.txt`
- task/task12/naabu.txt#L78: `#   naabu -l temp\agent1\naabu_targets_hosts.txt -top-ports 1000 -rate 3000 -retries 1 -timeout 1000 -silent -o temp\agent1\_ports_open_hostport_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task12/naabu.txt#L79: `#   if (Test-Path temp\agent1\_ports_open_hostport_part.txt) { Get-Content temp\agent1\_ports_open_hostport_part.txt | Add-Content temp\agent1\ports_open_hostport_raw.txt; Remove-Item temp\agent1\_ports_open_hostport_part.txt }`
- task/task12/naabu.txt#L79: `#   if (Test-Path temp\agent1\_ports_open_hostport_part.txt) { Get-Content temp\agent1\_ports_open_hostport_part.txt | Add-Content temp\agent1\ports_open_hostport_raw.txt; Remove-Item temp\agent1\_ports_open_hostport_part.txt }`
- task/task12/naabu.txt#L79: `#   if (Test-Path temp\agent1\_ports_open_hostport_part.txt) { Get-Content temp\agent1\_ports_open_hostport_part.txt | Add-Content temp\agent1\ports_open_hostport_raw.txt; Remove-Item temp\agent1\_ports_open_hostport_part.txt }`
- task/task12/naabu.txt#L89: `#   naabu -l temp\agent1\naabu_targets_hosts.txt -p (Get-Content temp\agent1\naabu_ports_webish.txt) -rate 2500 -retries 1 -timeout 1000 -silent -o temp\agent1\_ports_open_hostport_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task12/naabu.txt#L90: `#   if (Test-Path temp\agent1\_ports_open_hostport_part.txt) { Get-Content temp\agent1\_ports_open_hostport_part.txt | Add-Content temp\agent1\ports_open_hostport_raw.txt; Remove-Item temp\agent1\_ports_open_hostport_part.txt }`
- task/task12/naabu.txt#L90: `#   if (Test-Path temp\agent1\_ports_open_hostport_part.txt) { Get-Content temp\agent1\_ports_open_hostport_part.txt | Add-Content temp\agent1\ports_open_hostport_raw.txt; Remove-Item temp\agent1\_ports_open_hostport_part.txt }`
- task/task12/naabu.txt#L90: `#   if (Test-Path temp\agent1\_ports_open_hostport_part.txt) { Get-Content temp\agent1\_ports_open_hostport_part.txt | Add-Content temp\agent1\ports_open_hostport_raw.txt; Remove-Item temp\agent1\_ports_open_hostport_part.txt }`
- task/task12/naabu.txt#L96: `#       naabu -l temp\agent1\naabu_targets_hosts.txt -top-ports 10000 -rate 1500 -retries 1 -timeout 1000 -silent -o temp\agent1\_ports_open_hostport_part.txt 2>&1 | Tee-Object -FilePath $log -Append`

## temp\agent1\katana_urls_raw.txt (count=10)
- task/task13/katana.txt#L54: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\katana_urls_raw.txt`
- task/task13/katana.txt#L63: `#   if (Test-Path temp\agent1\_katana_part.txt) { Get-Content temp\agent1\_katana_part.txt | Add-Content temp\agent1\katana_urls_raw.txt; Remove-Item temp\agent1\_katana_part.txt }`
- task/task13/katana.txt#L74: `#   if (!(Test-Path temp\agent1\katana_urls_raw.txt)) { Write-Host "[katana] No raw output yet (crawl found nothing or failed)." }`
- task/task13/katana.txt#L75: `#   if (Test-Path temp\agent1\katana_urls_raw.txt) {`
- task/task13/katana.txt#L76: `#     Get-Content temp\agent1\katana_urls_raw.txt |`
- task/task14/katana.txt#L54: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\katana_urls_raw.txt`
- task/task14/katana.txt#L63: `#   if (Test-Path temp\agent1\_katana_part.txt) { Get-Content temp\agent1\_katana_part.txt | Add-Content temp\agent1\katana_urls_raw.txt; Remove-Item temp\agent1\_katana_part.txt }`
- task/task14/katana.txt#L74: `#   if (!(Test-Path temp\agent1\katana_urls_raw.txt)) { Write-Host "[katana] No raw output yet (crawl found nothing or failed)." }`
- task/task14/katana.txt#L75: `#   if (Test-Path temp\agent1\katana_urls_raw.txt) {`
- task/task14/katana.txt#L76: `#     Get-Content temp\agent1\katana_urls_raw.txt |`

## temp\agent1\gau_urls_raw.txt (count=10)
- task/task14/gau.txt#L53: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\gau_urls_raw.txt`
- task/task14/gau.txt#L60: `#   Get-Content temp\agent1\gau_targets_hosts.txt | gau 2>&1 | Tee-Object -FilePath $log -Append | Set-Content temp\agent1\gau_urls_raw.txt`
- task/task14/gau.txt#L70: `#   if (!(Test-Path temp\agent1\gau_urls_raw.txt)) { Write-Host "[gau] No raw output yet (no URLs found or command failed)." }`
- task/task14/gau.txt#L71: `#   if (Test-Path temp\agent1\gau_urls_raw.txt) {`
- task/task14/gau.txt#L72: `#     Get-Content temp\agent1\gau_urls_raw.txt |`
- task/task15/gau.txt#L53: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\gau_urls_raw.txt`
- task/task15/gau.txt#L60: `#   Get-Content temp\agent1\gau_targets_hosts.txt | gau 2>&1 | Tee-Object -FilePath $log -Append | Set-Content temp\agent1\gau_urls_raw.txt`
- task/task15/gau.txt#L70: `#   if (!(Test-Path temp\agent1\gau_urls_raw.txt)) { Write-Host "[gau] No raw output yet (no URLs found or command failed)." }`
- task/task15/gau.txt#L71: `#   if (Test-Path temp\agent1\gau_urls_raw.txt) {`
- task/task15/gau.txt#L72: `#     Get-Content temp\agent1\gau_urls_raw.txt |`

## temp\agent1\arjun_found_params_raw.txt (count=10)
- task/task16/arjun.txt#L68: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\arjun_found_params_raw.txt`
- task/task16/arjun.txt#L79: `#   arjun -i temp\agent1\arjun_targets_urls.txt -oT temp\agent1\arjun_found_params_raw.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task16/arjun.txt#L84: `#   if (!(Test-Path temp\agent1\arjun_found_params_raw.txt)) { Write-Host "[arjun] No raw output yet (no params found or command failed)." }`
- task/task16/arjun.txt#L85: `#   if (Test-Path temp\agent1\arjun_found_params_raw.txt) {`
- task/task16/arjun.txt#L86: `#     Get-Content temp\agent1\arjun_found_params_raw.txt |`
- task/task17/arjun.txt#L69: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\arjun_found_params_raw.txt`
- task/task17/arjun.txt#L80: `#   arjun -i temp\agent1\arjun_targets_urls.txt -oT temp\agent1\arjun_found_params_raw.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task17/arjun.txt#L85: `#   if (!(Test-Path temp\agent1\arjun_found_params_raw.txt)) { Write-Host "[arjun] No raw output yet (no params found or command failed)." }`
- task/task17/arjun.txt#L86: `#   if (Test-Path temp\agent1\arjun_found_params_raw.txt) {`
- task/task17/arjun.txt#L87: `#     Get-Content temp\agent1\arjun_found_params_raw.txt |`

## temp\agent1\api_endpoints_live_raw.txt (count=10)
- task/task18/httpx-probe-api-endpoints.txt#L45: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\api_endpoints_live_raw.txt`
- task/task18/httpx-probe-api-endpoints.txt#L56: `#   if (Test-Path temp\agent1\_httpx_part.txt) { Get-Content temp\agent1\_httpx_part.txt | Add-Content temp\agent1\api_endpoints_live_raw.txt; Remove-Item temp\agent1\_httpx_part.txt }`
- task/task18/httpx-probe-api-endpoints.txt#L64: `#   if (!(Test-Path temp\agent1\api_endpoints_live_raw.txt)) { Write-Host "[httpx api endpoints] No raw output yet (no live endpoints found or probe failed)." }`
- task/task18/httpx-probe-api-endpoints.txt#L65: `#   if (Test-Path temp\agent1\api_endpoints_live_raw.txt) {`
- task/task18/httpx-probe-api-endpoints.txt#L66: `#     Get-Content temp\agent1\api_endpoints_live_raw.txt |`
- task/task19/httpx-probe-api-endpoints.txt#L46: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\api_endpoints_live_raw.txt`
- task/task19/httpx-probe-api-endpoints.txt#L57: `#   if (Test-Path temp\agent1\_httpx_part.txt) { Get-Content temp\agent1\_httpx_part.txt | Add-Content temp\agent1\api_endpoints_live_raw.txt; Remove-Item temp\agent1\_httpx_part.txt }`
- task/task19/httpx-probe-api-endpoints.txt#L65: `#   if (!(Test-Path temp\agent1\api_endpoints_live_raw.txt)) { Write-Host "[httpx api endpoints] No raw output yet (no live endpoints found or probe failed)." }`
- task/task19/httpx-probe-api-endpoints.txt#L66: `#   if (Test-Path temp\agent1\api_endpoints_live_raw.txt) {`
- task/task19/httpx-probe-api-endpoints.txt#L67: `#     Get-Content temp\agent1\api_endpoints_live_raw.txt |`

## temp\agent1\js_urls_raw.txt (count=10)
- task/task19/js-urls.txt#L32: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\js_urls_raw.txt`
- task/task19/js-urls.txt#L41: `#     Set-Content temp\agent1\js_urls_raw.txt`
- task/task19/js-urls.txt#L46: `#   if (!(Test-Path temp\agent1\js_urls_raw.txt)) { Write-Host "[js urls] No raw output yet (none found)." }`
- task/task19/js-urls.txt#L47: `#   if (Test-Path temp\agent1\js_urls_raw.txt) {`
- task/task19/js-urls.txt#L48: `#     Get-Content temp\agent1\js_urls_raw.txt |`
- task/task20/js-urls.txt#L33: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\js_urls_raw.txt`
- task/task20/js-urls.txt#L42: `#     Set-Content temp\agent1\js_urls_raw.txt`
- task/task20/js-urls.txt#L47: `#   if (!(Test-Path temp\agent1\js_urls_raw.txt)) { Write-Host "[js urls] No raw output yet (none found)." }`
- task/task20/js-urls.txt#L48: `#   if (Test-Path temp\agent1\js_urls_raw.txt) {`
- task/task20/js-urls.txt#L49: `#     Get-Content temp\agent1\js_urls_raw.txt |`

## temp\agent1\queue_js_absolute_urls_in_scope.txt (count=10)
- task/task22/httpx-probe-js-extracted.txt#L42: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\queue_js_absolute_urls_in_scope.txt`
- task/task22/httpx-probe-js-extracted.txt#L64: `#   python task\task21\allowlist_filter_urls.py --allowlist outputs\activesubdomain.txt --in temp\agent1\queue_js_absolute_urls.txt --out temp\agent1\queue_js_absolute_urls_in_scope.txt`
- task/task22/httpx-probe-js-extracted.txt#L67: `#   $n = (Get-Content temp\agent1\queue_js_absolute_urls_in_scope.txt).Count`
- task/task22/httpx-probe-js-extracted.txt#L75: `#   httpx -l temp\agent1\queue_js_absolute_urls_in_scope.txt -silent -timeout 9 -retries 1 -threads 50 -o temp\agent1\_httpx_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task22/httpx-probe-js-extracted.txt#L79: `#   httpx -l temp\agent1\queue_js_absolute_urls_in_scope.txt -silent -timeout 9 -retries 1 -threads 50 -status-code -title -server -tech-detect -o temp\agent1\js_urls_live_seeds.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task23/httpx-probe-js-extracted.txt#L43: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\queue_js_absolute_urls_in_scope.txt`
- task/task23/httpx-probe-js-extracted.txt#L65: `#   python task\task21\allowlist_filter_urls.py --allowlist outputs\activesubdomain.txt --in temp\agent1\queue_js_absolute_urls.txt --out temp\agent1\queue_js_absolute_urls_in_scope.txt`
- task/task23/httpx-probe-js-extracted.txt#L68: `#   $n = (Get-Content temp\agent1\queue_js_absolute_urls_in_scope.txt).Count`
- task/task23/httpx-probe-js-extracted.txt#L76: `#   httpx -l temp\agent1\queue_js_absolute_urls_in_scope.txt -silent -timeout 9 -retries 1 -threads 50 -o temp\agent1\_httpx_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task23/httpx-probe-js-extracted.txt#L80: `#   httpx -l temp\agent1\queue_js_absolute_urls_in_scope.txt -silent -timeout 9 -retries 1 -threads 50 -status-code -title -server -tech-detect -o temp\agent1\js_urls_live_seeds.txt 2>&1 | Tee-Object -FilePath $log -Append`

## temp\agent1\nuclei_findings_raw.txt (count=10)
- task/task23/nuclei.txt#L40: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\nuclei_findings_raw.txt`
- task/task23/nuclei.txt#L83: `#   nuclei -l outputs\nuclei_targets_urls.txt -timeout 9 -retries 1 -c 25 -rl 50 -silent -o temp\agent1\nuclei_findings_raw.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task23/nuclei.txt#L86: `#   nuclei -l outputs\nuclei_targets_urls.txt -timeout 9 -retries 1 -c 25 -rl 50 -silent -jsonl -o temp\agent1\nuclei_findings_raw.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task23/nuclei.txt#L91: `#   if (Test-Path temp\agent1\nuclei_findings_raw.txt) {`
- task/task23/nuclei.txt#L92: `#     Get-Content temp\agent1\nuclei_findings_raw.txt |`
- task/task24/nuclei.txt#L41: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\nuclei_findings_raw.txt`
- task/task24/nuclei.txt#L84: `#   nuclei -l outputs\nuclei_targets_urls.txt -timeout 9 -retries 1 -c 25 -rl 50 -silent -o temp\agent1\nuclei_findings_raw.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task24/nuclei.txt#L87: `#   nuclei -l outputs\nuclei_targets_urls.txt -timeout 9 -retries 1 -c 25 -rl 50 -silent -jsonl -o temp\agent1\nuclei_findings_raw.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task24/nuclei.txt#L92: `#   if (Test-Path temp\agent1\nuclei_findings_raw.txt) {`
- task/task24/nuclei.txt#L93: `#     Get-Content temp\agent1\nuclei_findings_raw.txt |`

## temp\agent1\fingerprints.json (count=10)
- task/task27/subjack-takeover.txt#L21: `# Download once into temp\agent1\fingerprints.json (example):`
- task/task27/subjack-takeover.txt#L23: `#   Invoke-WebRequest -Uri https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -OutFile temp\agent1\fingerprints.json`
- task/task27/subjack-takeover.txt#L26: `#   if (!(Test-Path temp\agent1\fingerprints.json)) { throw "Missing temp\\agent1\\fingerprints.json" }`
- task/task27/subjack-takeover.txt#L35: `#   if (!(Test-Path temp\agent1\fingerprints.json)) { throw "Missing temp\\agent1\\fingerprints.json" }`
- task/task27/subjack-takeover.txt#L68: `#   subjack -w temp\agent1\subjack_targets.txt -t 50 -timeout 10 -ssl -c temp\agent1\fingerprints.json -o temp\agent1\takeover_candidates_subjack_raw.txt -v 2>&1 | Tee-Object -FilePath $log -Append`
- task/task28/subjack-takeover.txt#L21: `# Download once into temp\agent1\fingerprints.json (example):`
- task/task28/subjack-takeover.txt#L23: `#   Invoke-WebRequest -Uri https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -OutFile temp\agent1\fingerprints.json`
- task/task28/subjack-takeover.txt#L26: `#   if (!(Test-Path temp\agent1\fingerprints.json)) { throw "Missing temp\\agent1\\fingerprints.json" }`
- task/task28/subjack-takeover.txt#L36: `#   if (!(Test-Path temp\agent1\fingerprints.json)) { throw "Missing temp\\agent1\\fingerprints.json" }`
- task/task28/subjack-takeover.txt#L69: `#   subjack -w temp\agent1\subjack_targets.txt -t 50 -timeout 10 -ssl -c temp\agent1\fingerprints.json -o temp\agent1\takeover_candidates_subjack_raw.txt -v 2>&1 | Tee-Object -FilePath $log -Append`

## temp/agent1/resolved.txt (count=10)
- task/task7/puredns-resolve.txt#L18: `- temp/agent1/resolved.txt (validated, wildcard-filtered domains)`
- task/task7/puredns-resolve.txt#L71: `--write temp/agent1/resolved.txt \`
- task/task7/puredns-resolve.txt#L76: `cat temp/agent1/resolved.txt \`
- task/task7/puredns-resolve.txt#L84: `cp -f temp/agent1/resolved.txt outputs/subdomains_resolved.txt`
- task/task7/puredns-resolve.txt#L91: `: > temp/agent1/resolved.txt`
- task/task7/puredns-resolve.txt#L95: `cat temp/agent1/_resolved_tmp.txt >> temp/agent1/resolved.txt`
- task/task7/puredns-resolve.txt#L99: `sort -u temp/agent1/resolved.txt -o temp/agent1/resolved.txt`
- task/task7/puredns-resolve.txt#L99: `sort -u temp/agent1/resolved.txt -o temp/agent1/resolved.txt`
- task/task7/puredns-resolve.txt#L100: `cat temp/agent1/resolved.txt | sort -u > outputs/activesubdomain.txt`
- task/task7/puredns-resolve.txt#L104: `cp -f temp/agent1/resolved.txt outputs/subdomains_resolved.txt`

## temp/agent1/candidates_all.txt (count=9)
- task/task11/dnsx.txt#L19: `- temp/agent1/candidates_all.txt`
- task/task11/dnsx.txt#L39: `cat temp/agent1/candidates_all.txt | dnsx -silent -r temp/agent1/resolvers_good.txt -o temp/agent1/resolved_dnsx.txt`
- task/task11/dnsx.txt#L76: `dnsx -l temp/agent1/candidates_all.txt -wd <root-domain> -r temp/agent1/resolvers_good.txt -o temp/agent1/dnsx_wildcard.json`
- task/task7/puredns-resolve.txt#L16: `- Inputs: temp/agent1/candidates_all.txt + temp/agent1/resolvers_good.txt`
- task/task7/puredns-resolve.txt#L56: `> temp/agent1/candidates_all.txt`
- task/task7/puredns-resolve.txt#L59: `cp -f temp/agent1/candidates_all.txt outputs/subdomains_candidates_all.txt`
- task/task7/puredns-resolve.txt#L67: `puredns resolve temp/agent1/candidates_all.txt \`
- task/task7/puredns-resolve.txt#L90: `split -l 200000 temp/agent1/candidates_all.txt temp/agent1/cand_`
- task/task7/puredns-resolve.txt#L103: `cp -f temp/agent1/candidates_all.txt outputs/subdomains_candidates_all.txt`

## temp/agent1/list_1_passive.txt (count=8)
- task/task1/subfinder.txt#L30: `Set-Content -Encoding utf8 temp/agent1/list_1_passive.txt`
- task/task2/amass.txt#L14: `cat temp/agent1/list_1_passive.txt temp/agent1/amass.txt \`
- task/task2/amass.txt#L19: `> temp/agent1/list_1_passive.txt`
- task/task3/github-subdomains.txt#L17: `cat temp/agent1/list_1_passive.txt temp/agent1/github-subdomains.txt \`
- task/task3/github-subdomains.txt#L22: `> temp/agent1/list_1_passive.txt`
- task/task6/alterx.txt#L11: `- temp/agent1/list_1_passive.txt`
- task/task6/alterx.txt#L19: `temp/agent1/list_1_passive.txt \`
- task/task7/puredns-resolve.txt#L47: `temp/agent1/list_1_passive.txt \`

## temp/agent1/list_4_reverse.txt (count=8)
- task/task10/hakrevdns.txt#L14: `- temp/agent1/list_4_reverse.txt   (hostnames from PTR lookups)`
- task/task10/hakrevdns.txt#L35: `> temp/agent1/list_4_reverse.txt`
- task/task11/dnsx.txt#L82: `- temp/agent1/list_4_reverse.txt`
- task/task11/dnsx.txt#L87: `> temp/agent1/list_4_reverse.txt`
- task/task11/dnsx.txt#L92: `> temp/agent1/list_4_reverse.txt`
- task/task6/alterx.txt#L14: `- (optional) temp/agent1/list_4_reverse.txt`
- task/task6/alterx.txt#L22: `temp/agent1/list_4_reverse.txt 2>/dev/null \`
- task/task7/puredns-resolve.txt#L50: `temp/agent1/list_4_reverse.txt 2>/dev/null \`

## temp\agent1\httpx_hostport_targets.txt (count=8)
- task/task12/httpx-hostport.txt#L41: `#     Set-Content temp\agent1\httpx_hostport_targets.txt`
- task/task12/httpx-hostport.txt#L44: `#   $n = (Get-Content temp\agent1\httpx_hostport_targets.txt).Count`
- task/task12/httpx-hostport.txt#L65: `#   httpx -l temp\agent1\httpx_hostport_targets.txt -silent -timeout 9 -retries 1 -threads 50 -o temp\agent1\_httpx_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task12/httpx-hostport.txt#L70: `#   httpx -l temp\agent1\httpx_hostport_targets.txt -silent -timeout 9 -retries 1 -threads 50 -status-code -title -server -tech-detect -o temp\agent1\live_hostport_seeds.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task13/httpx-hostport.txt#L41: `#     Set-Content temp\agent1\httpx_hostport_targets.txt`
- task/task13/httpx-hostport.txt#L44: `#   $n = (Get-Content temp\agent1\httpx_hostport_targets.txt).Count`
- task/task13/httpx-hostport.txt#L65: `#   httpx -l temp\agent1\httpx_hostport_targets.txt -silent -timeout 9 -retries 1 -threads 50 -o temp\agent1\_httpx_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task13/httpx-hostport.txt#L70: `#   httpx -l temp\agent1\httpx_hostport_targets.txt -silent -timeout 9 -retries 1 -threads 50 -status-code -title -server -tech-detect -o outputs\live_hostport_seeds.txt 2>&1 | Tee-Object -FilePath $log -Append`

## temp\\agent1\\_ports_open_hostport_part.txt (count=8)
- task/task12/naabu.txt#L153: `#     naabu -l $chunk -top-ports 1000 -rate 3000 -retries 1 -timeout 1000 -silent -o temp\\agent1\\_ports_open_hostport_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task12/naabu.txt#L154: `#     if (Test-Path temp\\agent1\\_ports_open_hostport_part.txt) {`
- task/task12/naabu.txt#L155: `#       Get-Content temp\\agent1\\_ports_open_hostport_part.txt | Add-Content temp\\agent1\\ports_open_hostport_raw.txt`
- task/task12/naabu.txt#L156: `#       Remove-Item temp\\agent1\\_ports_open_hostport_part.txt`
- task/task12/naabu.txt#L166: `#     naabu -l temp\\agent1\\naabu_targets_hosts.txt -p $r -rate 1200 -retries 1 -timeout 1000 -silent -o temp\\agent1\\_ports_open_hostport_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task12/naabu.txt#L167: `#     if (Test-Path temp\\agent1\\_ports_open_hostport_part.txt) {`
- task/task12/naabu.txt#L168: `#       Get-Content temp\\agent1\\_ports_open_hostport_part.txt | Add-Content temp\\agent1\\ports_open_hostport_raw.txt`
- task/task12/naabu.txt#L169: `#       Remove-Item temp\\agent1\\_ports_open_hostport_part.txt`

## temp\agent1\_katana_part.txt (count=8)
- task/task13/katana.txt#L62: `#   katana -list temp\agent1\katana_seeds_urls.txt -silent -o temp\agent1\_katana_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task13/katana.txt#L63: `#   if (Test-Path temp\agent1\_katana_part.txt) { Get-Content temp\agent1\_katana_part.txt | Add-Content temp\agent1\katana_urls_raw.txt; Remove-Item temp\agent1\_katana_part.txt }`
- task/task13/katana.txt#L63: `#   if (Test-Path temp\agent1\_katana_part.txt) { Get-Content temp\agent1\_katana_part.txt | Add-Content temp\agent1\katana_urls_raw.txt; Remove-Item temp\agent1\_katana_part.txt }`
- task/task13/katana.txt#L63: `#   if (Test-Path temp\agent1\_katana_part.txt) { Get-Content temp\agent1\_katana_part.txt | Add-Content temp\agent1\katana_urls_raw.txt; Remove-Item temp\agent1\_katana_part.txt }`
- task/task14/katana.txt#L62: `#   katana -list temp\agent1\katana_seeds_urls.txt -silent -o temp\agent1\_katana_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task14/katana.txt#L63: `#   if (Test-Path temp\agent1\_katana_part.txt) { Get-Content temp\agent1\_katana_part.txt | Add-Content temp\agent1\katana_urls_raw.txt; Remove-Item temp\agent1\_katana_part.txt }`
- task/task14/katana.txt#L63: `#   if (Test-Path temp\agent1\_katana_part.txt) { Get-Content temp\agent1\_katana_part.txt | Add-Content temp\agent1\katana_urls_raw.txt; Remove-Item temp\agent1\_katana_part.txt }`
- task/task14/katana.txt#L63: `#   if (Test-Path temp\agent1\_katana_part.txt) { Get-Content temp\agent1\_katana_part.txt | Add-Content temp\agent1\katana_urls_raw.txt; Remove-Item temp\agent1\_katana_part.txt }`

## temp\\agent1\\_katana_part.txt (count=8)
- task/task13/katana.txt#L119: `#     katana -list $chunk -silent -o temp\\agent1\\_katana_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task13/katana.txt#L120: `#     if (Test-Path temp\\agent1\\_katana_part.txt) {`
- task/task13/katana.txt#L121: `#       Get-Content temp\\agent1\\_katana_part.txt | Add-Content temp\\agent1\\katana_urls_raw.txt`
- task/task13/katana.txt#L122: `#       Remove-Item temp\\agent1\\_katana_part.txt`
- task/task14/katana.txt#L119: `#     katana -list $chunk -silent -o temp\\agent1\\_katana_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task14/katana.txt#L120: `#     if (Test-Path temp\\agent1\\_katana_part.txt) {`
- task/task14/katana.txt#L121: `#       Get-Content temp\\agent1\\_katana_part.txt | Add-Content temp\\agent1\\katana_urls_raw.txt`
- task/task14/katana.txt#L122: `#       Remove-Item temp\\agent1\\_katana_part.txt`

## temp\\agent1\\_arjun_part.txt (count=8)
- task/task16/arjun.txt#L117: `#     arjun -i $chunk -oT temp\\agent1\\_arjun_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task16/arjun.txt#L118: `#     if (Test-Path temp\\agent1\\_arjun_part.txt) {`
- task/task16/arjun.txt#L119: `#       Get-Content temp\\agent1\\_arjun_part.txt | Add-Content temp\\agent1\\arjun_found_params_raw.txt`
- task/task16/arjun.txt#L120: `#       Remove-Item temp\\agent1\\_arjun_part.txt`
- task/task17/arjun.txt#L118: `#     arjun -i $chunk -oT temp\\agent1\\_arjun_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task17/arjun.txt#L119: `#     if (Test-Path temp\\agent1\\_arjun_part.txt) {`
- task/task17/arjun.txt#L120: `#       Get-Content temp\\agent1\\_arjun_part.txt | Add-Content temp\\agent1\\arjun_found_params_raw.txt`
- task/task17/arjun.txt#L121: `#       Remove-Item temp\\agent1\\_arjun_part.txt`

## temp\agent1\kiterunner_raw.json (count=8)
- task/task17/kiterunner.txt#L64: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\kiterunner_raw.json`
- task/task17/kiterunner.txt#L75: `#   kr scan temp\agent1\kiterunner_targets_urls.txt -w $routes -o temp\agent1\kiterunner_raw.json 2>&1 | Tee-Object -FilePath $log -Append`
- task/task17/kiterunner.txt#L83: `#   if (!(Test-Path temp\agent1\kiterunner_raw.json)) { throw "Missing temp\\agent1\\kiterunner_raw.json" }`
- task/task17/kiterunner.txt#L84: `#   Get-Content temp\agent1\kiterunner_raw.json |`
- task/task18/kiterunner.txt#L64: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\kiterunner_raw.json`
- task/task18/kiterunner.txt#L75: `#   kr scan temp\agent1\kiterunner_targets_urls.txt -w $routes -o temp\agent1\kiterunner_raw.json 2>&1 | Tee-Object -FilePath $log -Append`
- task/task18/kiterunner.txt#L83: `#   if (!(Test-Path temp\agent1\kiterunner_raw.json)) { throw "Missing temp\\agent1\\kiterunner_raw.json" }`
- task/task18/kiterunner.txt#L84: `#   Get-Content temp\agent1\kiterunner_raw.json |`

## temp\\agent1\\_kr_part.json (count=8)
- task/task17/kiterunner.txt#L118: `#     kr scan $chunk -w $routes -o temp\\agent1\\_kr_part.json 2>&1 | Tee-Object -FilePath $log -Append`
- task/task17/kiterunner.txt#L119: `#     if (Test-Path temp\\agent1\\_kr_part.json) {`
- task/task17/kiterunner.txt#L120: `#       Get-Content temp\\agent1\\_kr_part.json | Add-Content temp\\agent1\\kiterunner_raw.json`
- task/task17/kiterunner.txt#L121: `#       Remove-Item temp\\agent1\\_kr_part.json`
- task/task18/kiterunner.txt#L118: `#     kr scan $chunk -w $routes -o temp\\agent1\\_kr_part.json 2>&1 | Tee-Object -FilePath $log -Append`
- task/task18/kiterunner.txt#L119: `#     if (Test-Path temp\\agent1\\_kr_part.json) {`
- task/task18/kiterunner.txt#L120: `#       Get-Content temp\\agent1\\_kr_part.json | Add-Content temp\\agent1\\kiterunner_raw.json`
- task/task18/kiterunner.txt#L121: `#       Remove-Item temp\\agent1\\_kr_part.json`

## temp\agent1\httpx_api_endpoints_targets.txt (count=8)
- task/task18/httpx-probe-api-endpoints.txt#L32: `#     Set-Content temp\agent1\httpx_api_endpoints_targets.txt`
- task/task18/httpx-probe-api-endpoints.txt#L35: `#   $n = (Get-Content temp\agent1\httpx_api_endpoints_targets.txt).Count`
- task/task18/httpx-probe-api-endpoints.txt#L55: `#   httpx -l temp\agent1\httpx_api_endpoints_targets.txt -silent -timeout 9 -retries 1 -threads 50 -o temp\agent1\_httpx_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task18/httpx-probe-api-endpoints.txt#L59: `#   httpx -l temp\agent1\httpx_api_endpoints_targets.txt -silent -timeout 9 -retries 1 -threads 50 -status-code -title -server -tech-detect -o temp\agent1\api_endpoints_live_seeds.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task19/httpx-probe-api-endpoints.txt#L33: `#     Set-Content temp\agent1\httpx_api_endpoints_targets.txt`
- task/task19/httpx-probe-api-endpoints.txt#L36: `#   $n = (Get-Content temp\agent1\httpx_api_endpoints_targets.txt).Count`
- task/task19/httpx-probe-api-endpoints.txt#L56: `#   httpx -l temp\agent1\httpx_api_endpoints_targets.txt -silent -timeout 9 -retries 1 -threads 50 -o temp\agent1\_httpx_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task19/httpx-probe-api-endpoints.txt#L60: `#   httpx -l temp\agent1\httpx_api_endpoints_targets.txt -silent -timeout 9 -retries 1 -threads 50 -status-code -title -server -tech-detect -o outputs\api_endpoints_live_seeds.txt 2>&1 | Tee-Object -FilePath $log -Append`

## temp\agent1\js_fetch_index.txt (count=8)
- task/task21/httpx-fetch-js.txt#L52: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\js_fetch_index.txt`
- task/task21/httpx-fetch-js.txt#L66: `#   Get-ChildItem -Recurse $outDir -File | ForEach-Object { $_.FullName } | Set-Content temp\agent1\js_fetch_index.txt`
- task/task21/httpx-fetch-js.txt#L95: `#   Get-ChildItem -Recurse $outDir -File | ForEach-Object { $_.FullName } | Set-Content temp\agent1\js_fetch_index.txt`
- task/task21/js-analyze-offline.txt#L12: `#   if (!(Test-Path temp\agent1\js_fetch_index.txt) -and !(Test-Path temp\agent1\js_fetch_dir)) {`
- task/task21/js-analyze-offline.txt#L26: `#   python task\task21\js_analyzer.py --index temp\agent1\js_fetch_index.txt --out outputs\js_endpoints_from_js.txt`
- task/task21/js_analyzer.py#L21: `--index temp\agent1\js_fetch_index.txt \`
- task/task22/js-analyze-offline.txt#L12: `#   if (!(Test-Path temp\agent1\js_fetch_index.txt) -and !(Test-Path temp\agent1\js_fetch_dir)) {`
- task/task22/js-analyze-offline.txt#L26: `#   python task\task21\js_analyzer.py --index temp\agent1\js_fetch_index.txt --out outputs\js_endpoints_from_js.txt`

## temp\agent1\js_urls_live_raw.txt (count=8)
- task/task22/httpx-probe-js-extracted.txt#L43: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\js_urls_live_raw.txt`
- task/task22/httpx-probe-js-extracted.txt#L76: `#   if (Test-Path temp\agent1\_httpx_part.txt) { Get-Content temp\agent1\_httpx_part.txt | Add-Content temp\agent1\js_urls_live_raw.txt; Remove-Item temp\agent1\_httpx_part.txt }`
- task/task22/httpx-probe-js-extracted.txt#L82: `#   if (Test-Path temp\agent1\js_urls_live_raw.txt) {`
- task/task22/httpx-probe-js-extracted.txt#L83: `#     Get-Content temp\agent1\js_urls_live_raw.txt |`
- task/task23/httpx-probe-js-extracted.txt#L44: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\js_urls_live_raw.txt`
- task/task23/httpx-probe-js-extracted.txt#L77: `#   if (Test-Path temp\agent1\_httpx_part.txt) { Get-Content temp\agent1\_httpx_part.txt | Add-Content temp\agent1\js_urls_live_raw.txt; Remove-Item temp\agent1\_httpx_part.txt }`
- task/task23/httpx-probe-js-extracted.txt#L83: `#   if (Test-Path temp\agent1\js_urls_live_raw.txt) {`
- task/task23/httpx-probe-js-extracted.txt#L84: `#     Get-Content temp\agent1\js_urls_live_raw.txt |`

## temp\agent1\js_composed_live_raw.txt (count=8)
- task/task22/httpx-probe-js-extracted.txt#L160: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\js_composed_live_raw.txt`
- task/task22/httpx-probe-js-extracted.txt#L162: `#   if (Test-Path temp\agent1\_httpx_part.txt) { Get-Content temp\agent1\_httpx_part.txt | Add-Content temp\agent1\js_composed_live_raw.txt; Remove-Item temp\agent1\_httpx_part.txt }`
- task/task22/httpx-probe-js-extracted.txt#L165: `#   if (Test-Path temp\agent1\js_composed_live_raw.txt) {`
- task/task22/httpx-probe-js-extracted.txt#L166: `#     Get-Content temp\agent1\js_composed_live_raw.txt |`
- task/task23/httpx-probe-js-extracted.txt#L161: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\js_composed_live_raw.txt`
- task/task23/httpx-probe-js-extracted.txt#L163: `#   if (Test-Path temp\agent1\_httpx_part.txt) { Get-Content temp\agent1\_httpx_part.txt | Add-Content temp\agent1\js_composed_live_raw.txt; Remove-Item temp\agent1\_httpx_part.txt }`
- task/task23/httpx-probe-js-extracted.txt#L166: `#   if (Test-Path temp\agent1\js_composed_live_raw.txt) {`
- task/task23/httpx-probe-js-extracted.txt#L167: `#     Get-Content temp\agent1\js_composed_live_raw.txt |`

## temp\\agent1\\_nuclei_part.txt (count=8)
- task/task23/nuclei.txt#L123: `#     nuclei -l $chunk -timeout 9 -retries 1 -c 25 -rl 50 -silent -o temp\\agent1\\_nuclei_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task23/nuclei.txt#L124: `#     if (Test-Path temp\\agent1\\_nuclei_part.txt) {`
- task/task23/nuclei.txt#L125: `#       Get-Content temp\\agent1\\_nuclei_part.txt | Add-Content temp\\agent1\\nuclei_findings_raw.txt`
- task/task23/nuclei.txt#L126: `#       Remove-Item temp\\agent1\\_nuclei_part.txt`
- task/task24/nuclei.txt#L124: `#     nuclei -l $chunk -timeout 9 -retries 1 -c 25 -rl 50 -silent -o temp\\agent1\\_nuclei_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task24/nuclei.txt#L125: `#     if (Test-Path temp\\agent1\\_nuclei_part.txt) {`
- task/task24/nuclei.txt#L126: `#       Get-Content temp\\agent1\\_nuclei_part.txt | Add-Content temp\\agent1\\nuclei_findings_raw.txt`
- task/task24/nuclei.txt#L127: `#       Remove-Item temp\\agent1\\_nuclei_part.txt`

## temp\agent1\ffuf_findings_raw.txt (count=8)
- task/task25/ffuf-content-discovery.txt#L38: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\ffuf_findings_raw.txt`
- task/task25/ffuf-content-discovery.txt#L79: `#     Set-Content temp\agent1\ffuf_findings_raw.txt`
- task/task25/ffuf-content-discovery.txt#L82: `#   if (Test-Path temp\agent1\ffuf_findings_raw.txt) {`
- task/task25/ffuf-content-discovery.txt#L83: `#     Get-Content temp\agent1\ffuf_findings_raw.txt |`
- task/task26/ffuf-content-discovery.txt#L39: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\ffuf_findings_raw.txt`
- task/task26/ffuf-content-discovery.txt#L80: `#     Set-Content temp\agent1\ffuf_findings_raw.txt`
- task/task26/ffuf-content-discovery.txt#L83: `#   if (Test-Path temp\agent1\ffuf_findings_raw.txt) {`
- task/task26/ffuf-content-discovery.txt#L84: `#     Get-Content temp\agent1\ffuf_findings_raw.txt |`

## temp\agent1\takeover_candidates_subjack_raw.txt (count=8)
- task/task27/subjack-takeover.txt#L43: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\takeover_candidates_subjack_raw.txt`
- task/task27/subjack-takeover.txt#L68: `#   subjack -w temp\agent1\subjack_targets.txt -t 50 -timeout 10 -ssl -c temp\agent1\fingerprints.json -o temp\agent1\takeover_candidates_subjack_raw.txt -v 2>&1 | Tee-Object -FilePath $log -Append`
- task/task27/subjack-takeover.txt#L73: `#   if (Test-Path temp\agent1\takeover_candidates_subjack_raw.txt) {`
- task/task27/subjack-takeover.txt#L74: `#     Get-Content temp\agent1\takeover_candidates_subjack_raw.txt |`
- task/task28/subjack-takeover.txt#L44: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\takeover_candidates_subjack_raw.txt`
- task/task28/subjack-takeover.txt#L69: `#   subjack -w temp\agent1\subjack_targets.txt -t 50 -timeout 10 -ssl -c temp\agent1\fingerprints.json -o temp\agent1\takeover_candidates_subjack_raw.txt -v 2>&1 | Tee-Object -FilePath $log -Append`
- task/task28/subjack-takeover.txt#L74: `#   if (Test-Path temp\agent1\takeover_candidates_subjack_raw.txt) {`
- task/task28/subjack-takeover.txt#L75: `#     Get-Content temp\agent1\takeover_candidates_subjack_raw.txt |`

## temp\\agent1\\_subjack_part.txt (count=8)
- task/task27/subjack-takeover.txt#L105: `#     subjack -w $chunk -t 50 -timeout 10 -ssl -c temp\\agent1\\fingerprints.json -o temp\\agent1\\_subjack_part.txt -v 2>&1 | Tee-Object -FilePath $log -Append`
- task/task27/subjack-takeover.txt#L106: `#     if (Test-Path temp\\agent1\\_subjack_part.txt) {`
- task/task27/subjack-takeover.txt#L107: `#       Get-Content temp\\agent1\\_subjack_part.txt | Add-Content temp\\agent1\\takeover_candidates_subjack_raw.txt`
- task/task27/subjack-takeover.txt#L108: `#       Remove-Item temp\\agent1\\_subjack_part.txt`
- task/task28/subjack-takeover.txt#L106: `#     subjack -w $chunk -t 50 -timeout 10 -ssl -c temp\\agent1\\fingerprints.json -o temp\\agent1\\_subjack_part.txt -v 2>&1 | Tee-Object -FilePath $log -Append`
- task/task28/subjack-takeover.txt#L107: `#     if (Test-Path temp\\agent1\\_subjack_part.txt) {`
- task/task28/subjack-takeover.txt#L108: `#       Get-Content temp\\agent1\\_subjack_part.txt | Add-Content temp\\agent1\\takeover_candidates_subjack_raw.txt`
- task/task28/subjack-takeover.txt#L109: `#       Remove-Item temp\\agent1\\_subjack_part.txt`

## temp/agent1/list_3_bruteforce.txt (count=8)
- task/task5/puredns-bruteforce.txt#L25: `--write temp/agent1/list_3_bruteforce.txt`
- task/task5/puredns-bruteforce.txt#L29: `: > temp/agent1/list_3_bruteforce.txt`
- task/task5/puredns-bruteforce.txt#L32: `cat temp/agent1/_brute_tmp.txt >> temp/agent1/list_3_bruteforce.txt`
- task/task5/puredns-bruteforce.txt#L34: `sort -u temp/agent1/list_3_bruteforce.txt -o temp/agent1/list_3_bruteforce.txt`
- task/task5/puredns-bruteforce.txt#L34: `sort -u temp/agent1/list_3_bruteforce.txt -o temp/agent1/list_3_bruteforce.txt`
- task/task6/alterx.txt#L13: `- temp/agent1/list_3_bruteforce.txt`
- task/task6/alterx.txt#L21: `temp/agent1/list_3_bruteforce.txt \`
- task/task7/puredns-resolve.txt#L49: `temp/agent1/list_3_bruteforce.txt \`

## temp/agent1/list_1_passive.txt` (count=7)
- README.md#L38: `- Task 1: `subfinder` → `temp/agent1/list_1_passive.txt``
- README.md#L39: `- Task 2: `amass` (passive) → merge into `temp/agent1/list_1_passive.txt``
- README.md#L40: `- Task 3: `github-subdomains` → merge into `temp/agent1/list_1_passive.txt``
- README.md#L90: `- `temp/agent1/list_1_passive.txt` (deduped)`
- README.md#L97: `- Updates `temp/agent1/list_1_passive.txt` (merged + deduped)`
- README.md#L104: `- Updates `temp/agent1/list_1_passive.txt` (merged + deduped)`
- README.md#L130: `- `temp/agent1/list_1_passive.txt``

## temp\agent1\js_fetch_dir (count=7)
- task/task21/js-analyze-offline.txt#L12: `#   if (!(Test-Path temp\agent1\js_fetch_index.txt) -and !(Test-Path temp\agent1\js_fetch_dir)) {`
- task/task21/js-analyze-offline.txt#L29: `#   python task\task21\js_analyzer.py --dir temp\agent1\js_fetch_dir --out outputs\js_endpoints_from_js.txt`
- task/task21/js-analyze-offline.txt#L41: `#   Get-ChildItem -Recurse temp\agent1\js_fetch_dir -File | Sort-Object Length -Descending | Select-Object -First 30 FullName,Length`
- task/task21/js_analyzer.py#L25: `python task\task21\js_analyzer.py --dir temp\agent1\js_fetch_dir --out outputs\js_endpoints_from_js.txt`
- task/task22/js-analyze-offline.txt#L12: `#   if (!(Test-Path temp\agent1\js_fetch_index.txt) -and !(Test-Path temp\agent1\js_fetch_dir)) {`
- task/task22/js-analyze-offline.txt#L29: `#   python task\task21\js_analyzer.py --dir temp\agent1\js_fetch_dir --out outputs\js_endpoints_from_js.txt`
- task/task22/js-analyze-offline.txt#L41: `#   Get-ChildItem -Recurse temp\agent1\js_fetch_dir -File | Sort-Object Length -Descending | Select-Object -First 30 FullName,Length`

## temp/agent1/list_5_permutations.txt (count=7)
- task/task6/alterx.txt#L8: `- Write output to: temp/agent1/list_5_permutations.txt`
- task/task6/alterx.txt#L30: `alterx -l temp/agent1/_alterx_seed.txt -silent -o temp/agent1/list_5_permutations.txt`
- task/task6/alterx.txt#L34: `: > temp/agent1/list_5_permutations.txt`
- task/task6/alterx.txt#L37: `cat temp/agent1/_alterx_tmp.txt >> temp/agent1/list_5_permutations.txt`
- task/task6/alterx.txt#L41: `sort -u temp/agent1/list_5_permutations.txt -o temp/agent1/list_5_permutations.txt`
- task/task6/alterx.txt#L41: `sort -u temp/agent1/list_5_permutations.txt -o temp/agent1/list_5_permutations.txt`
- task/task7/puredns-resolve.txt#L51: `temp/agent1/list_5_permutations.txt 2>/dev/null \`

## temp\agent1\naabu_targets_hosts.txt (count=6)
- task/task12/naabu.txt#L52: `#     Set-Content temp\agent1\naabu_targets_hosts.txt`
- task/task12/naabu.txt#L55: `#   $n = (Get-Content temp\agent1\naabu_targets_hosts.txt).Count`
- task/task12/naabu.txt#L77: `#   naabu -l temp\agent1\naabu_targets_hosts.txt -top-ports 1000 -rate 3000 -retries 1 -timeout 1000 -silent -o temp\agent1\_ports_open_hostport_part.txt`
- task/task12/naabu.txt#L78: `#   naabu -l temp\agent1\naabu_targets_hosts.txt -top-ports 1000 -rate 3000 -retries 1 -timeout 1000 -silent -o temp\agent1\_ports_open_hostport_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task12/naabu.txt#L89: `#   naabu -l temp\agent1\naabu_targets_hosts.txt -p (Get-Content temp\agent1\naabu_ports_webish.txt) -rate 2500 -retries 1 -timeout 1000 -silent -o temp\agent1\_ports_open_hostport_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task12/naabu.txt#L96: `#       naabu -l temp\agent1\naabu_targets_hosts.txt -top-ports 10000 -rate 1500 -retries 1 -timeout 1000 -silent -o temp\agent1\_ports_open_hostport_part.txt 2>&1 | Tee-Object -FilePath $log -Append`

## temp\agent1\gau_targets_hosts.txt (count=6)
- task/task14/gau.txt#L40: `#     Set-Content temp\agent1\gau_targets_hosts.txt`
- task/task14/gau.txt#L43: `#   $n = (Get-Content temp\agent1\gau_targets_hosts.txt).Count`
- task/task14/gau.txt#L60: `#   Get-Content temp\agent1\gau_targets_hosts.txt | gau 2>&1 | Tee-Object -FilePath $log -Append | Set-Content temp\agent1\gau_urls_raw.txt`
- task/task15/gau.txt#L40: `#     Set-Content temp\agent1\gau_targets_hosts.txt`
- task/task15/gau.txt#L43: `#   $n = (Get-Content temp\agent1\gau_targets_hosts.txt).Count`
- task/task15/gau.txt#L60: `#   Get-Content temp\agent1\gau_targets_hosts.txt | gau 2>&1 | Tee-Object -FilePath $log -Append | Set-Content temp\agent1\gau_urls_raw.txt`

## temp\agent1\arjun_targets_urls.txt (count=6)
- task/task16/arjun.txt#L55: `#     Set-Content temp\agent1\arjun_targets_urls.txt`
- task/task16/arjun.txt#L58: `#   $n = (Get-Content temp\agent1\arjun_targets_urls.txt).Count`
- task/task16/arjun.txt#L79: `#   arjun -i temp\agent1\arjun_targets_urls.txt -oT temp\agent1\arjun_found_params_raw.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task17/arjun.txt#L56: `#     Set-Content temp\agent1\arjun_targets_urls.txt`
- task/task17/arjun.txt#L59: `#   $n = (Get-Content temp\agent1\arjun_targets_urls.txt).Count`
- task/task17/arjun.txt#L80: `#   arjun -i temp\agent1\arjun_targets_urls.txt -oT temp\agent1\arjun_found_params_raw.txt 2>&1 | Tee-Object -FilePath $log -Append`

## temp\\agent1\\kiterunner_raw.json (count=6)
- task/task17/kiterunner.txt#L83: `#   if (!(Test-Path temp\agent1\kiterunner_raw.json)) { throw "Missing temp\\agent1\\kiterunner_raw.json" }`
- task/task17/kiterunner.txt#L114: `#   Remove-Item -ErrorAction SilentlyContinue temp\\agent1\\kiterunner_raw.json`
- task/task17/kiterunner.txt#L120: `#       Get-Content temp\\agent1\\_kr_part.json | Add-Content temp\\agent1\\kiterunner_raw.json`
- task/task18/kiterunner.txt#L83: `#   if (!(Test-Path temp\agent1\kiterunner_raw.json)) { throw "Missing temp\\agent1\\kiterunner_raw.json" }`
- task/task18/kiterunner.txt#L114: `#   Remove-Item -ErrorAction SilentlyContinue temp\\agent1\\kiterunner_raw.json`
- task/task18/kiterunner.txt#L120: `#       Get-Content temp\\agent1\\_kr_part.json | Add-Content temp\\agent1\\kiterunner_raw.json`

## temp\agent1\queue_js_absolute_urls.txt (count=6)
- task/task22/httpx-probe-js-extracted.txt#L41: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\queue_js_absolute_urls.txt`
- task/task22/httpx-probe-js-extracted.txt#L61: `#     Set-Content temp\agent1\queue_js_absolute_urls.txt`
- task/task22/httpx-probe-js-extracted.txt#L64: `#   python task\task21\allowlist_filter_urls.py --allowlist outputs\activesubdomain.txt --in temp\agent1\queue_js_absolute_urls.txt --out temp\agent1\queue_js_absolute_urls_in_scope.txt`
- task/task23/httpx-probe-js-extracted.txt#L42: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\queue_js_absolute_urls.txt`
- task/task23/httpx-probe-js-extracted.txt#L62: `#     Set-Content temp\agent1\queue_js_absolute_urls.txt`
- task/task23/httpx-probe-js-extracted.txt#L65: `#   python task\task21\allowlist_filter_urls.py --allowlist outputs\activesubdomain.txt --in temp\agent1\queue_js_absolute_urls.txt --out temp\agent1\queue_js_absolute_urls_in_scope.txt`

## temp\agent1\js_endpoints_from_js_norm.txt (count=6)
- task/task22/httpx-probe-js-extracted.txt#L55: `#     Set-Content temp\agent1\js_endpoints_from_js_norm.txt`
- task/task22/httpx-probe-js-extracted.txt#L58: `#   Get-Content temp\agent1\js_endpoints_from_js_norm.txt |`
- task/task22/httpx-probe-js-extracted.txt#L131: `#   $paths = Get-Content temp\agent1\js_endpoints_from_js_norm.txt |`
- task/task23/httpx-probe-js-extracted.txt#L56: `#     Set-Content temp\agent1\js_endpoints_from_js_norm.txt`
- task/task23/httpx-probe-js-extracted.txt#L59: `#   Get-Content temp\agent1\js_endpoints_from_js_norm.txt |`
- task/task23/httpx-probe-js-extracted.txt#L132: `#   $paths = Get-Content temp\agent1\js_endpoints_from_js_norm.txt |`

## temp\agent1\ffuf_targets_base.txt (count=6)
- task/task25/ffuf-content-discovery.txt#L48: `#     Set-Content temp\agent1\ffuf_targets_base.txt`
- task/task25/ffuf-content-discovery.txt#L50: `#   $n = (Get-Content temp\agent1\ffuf_targets_base.txt).Count`
- task/task25/ffuf-content-discovery.txt#L64: `#   $targets = Get-Content temp\agent1\ffuf_targets_base.txt`
- task/task26/ffuf-content-discovery.txt#L49: `#     Set-Content temp\agent1\ffuf_targets_base.txt`
- task/task26/ffuf-content-discovery.txt#L51: `#   $n = (Get-Content temp\agent1\ffuf_targets_base.txt).Count`
- task/task26/ffuf-content-discovery.txt#L65: `#   $targets = Get-Content temp\agent1\ffuf_targets_base.txt`

## temp\agent1\ports_open_hostport_norm.txt (count=6)
- task/task26/nmap-service-enum.txt#L46: `#     Set-Content temp\agent1\ports_open_hostport_norm.txt`
- task/task26/nmap-service-enum.txt#L48: `#   $n = (Get-Content temp\agent1\ports_open_hostport_norm.txt).Count`
- task/task26/nmap-service-enum.txt#L65: `#   $pairs = Get-Content temp\agent1\ports_open_hostport_norm.txt`
- task/task27/nmap-service-enum.txt#L47: `#     Set-Content temp\agent1\ports_open_hostport_norm.txt`
- task/task27/nmap-service-enum.txt#L49: `#   $n = (Get-Content temp\agent1\ports_open_hostport_norm.txt).Count`
- task/task27/nmap-service-enum.txt#L66: `#   $pairs = Get-Content temp\agent1\ports_open_hostport_norm.txt`

## temp\\agent1\\fingerprints.json (count=6)
- task/task27/subjack-takeover.txt#L26: `#   if (!(Test-Path temp\agent1\fingerprints.json)) { throw "Missing temp\\agent1\\fingerprints.json" }`
- task/task27/subjack-takeover.txt#L35: `#   if (!(Test-Path temp\agent1\fingerprints.json)) { throw "Missing temp\\agent1\\fingerprints.json" }`
- task/task27/subjack-takeover.txt#L105: `#     subjack -w $chunk -t 50 -timeout 10 -ssl -c temp\\agent1\\fingerprints.json -o temp\\agent1\\_subjack_part.txt -v 2>&1 | Tee-Object -FilePath $log -Append`
- task/task28/subjack-takeover.txt#L26: `#   if (!(Test-Path temp\agent1\fingerprints.json)) { throw "Missing temp\\agent1\\fingerprints.json" }`
- task/task28/subjack-takeover.txt#L36: `#   if (!(Test-Path temp\agent1\fingerprints.json)) { throw "Missing temp\\agent1\\fingerprints.json" }`
- task/task28/subjack-takeover.txt#L106: `#     subjack -w $chunk -t 50 -timeout 10 -ssl -c temp\\agent1\\fingerprints.json -o temp\\agent1\\_subjack_part.txt -v 2>&1 | Tee-Object -FilePath $log -Append`

## temp\agent1\subjack_targets.txt (count=6)
- task/task27/subjack-takeover.txt#L53: `#     Set-Content temp\agent1\subjack_targets.txt`
- task/task27/subjack-takeover.txt#L55: `#   $n = (Get-Content temp\agent1\subjack_targets.txt).Count`
- task/task27/subjack-takeover.txt#L68: `#   subjack -w temp\agent1\subjack_targets.txt -t 50 -timeout 10 -ssl -c temp\agent1\fingerprints.json -o temp\agent1\takeover_candidates_subjack_raw.txt -v 2>&1 | Tee-Object -FilePath $log -Append`
- task/task28/subjack-takeover.txt#L54: `#     Set-Content temp\agent1\subjack_targets.txt`
- task/task28/subjack-takeover.txt#L56: `#   $n = (Get-Content temp\agent1\subjack_targets.txt).Count`
- task/task28/subjack-takeover.txt#L69: `#   subjack -w temp\agent1\subjack_targets.txt -t 50 -timeout 10 -ssl -c temp\agent1\fingerprints.json -o temp\agent1\takeover_candidates_subjack_raw.txt -v 2>&1 | Tee-Object -FilePath $log -Append`

## temp\agent1\resolved_dnsx.txt (count=5)
- task/task11/dnsx.txt#L43: `Get-Content temp\agent1\candidates_all.txt | dnsx -silent -r temp\agent1\resolvers_good.txt -o temp\agent1\resolved_dnsx.txt`
- task/task11/dnsx.txt#L62: `Remove-Item -ErrorAction SilentlyContinue temp\agent1\resolved_dnsx.txt`
- task/task11/dnsx.txt#L65: `Get-Content temp\agent1\_dnsx_tmp.txt | Add-Content temp\agent1\resolved_dnsx.txt`
- task/task11/dnsx.txt#L68: `Get-Content temp\agent1\resolved_dnsx.txt | Sort-Object -Unique | Set-Content -Encoding utf8 temp\agent1\resolved_dnsx.txt`
- task/task11/dnsx.txt#L68: `Get-Content temp\agent1\resolved_dnsx.txt | Sort-Object -Unique | Set-Content -Encoding utf8 temp\agent1\resolved_dnsx.txt`

## temp/agent1/subdomain_wordlist.txt (count=5)
- task/task5/puredns-bruteforce.txt#L8: `# - temp/agent1/subdomain_wordlist.txt`
- task/task5/puredns-bruteforce.txt#L23: `puredns bruteforce temp/agent1/subdomain_wordlist.txt <domain> \`
- task/task5/puredns-bruteforce.txt#L28: `split -l 100000 temp/agent1/subdomain_wordlist.txt temp/agent1/wl_`
- task/task5/wordlist-download.txt#L13: `cp temp/_seclists/Discovery/DNS/subdomains-top1million-110000.txt temp/agent1/subdomain_wordlist.txt`
- task/task5/wordlist-download.txt#L34: `> temp/agent1/subdomain_wordlist.txt`

## temp\agent1\knownfiles_and_apidocs.txt (count=5)
- task/task9/httpx-knownfiles-apidocs.txt#L31: `#   if (!(Test-Path 'temp\agent1\knownfiles_and_apidocs.txt')) {`
- task/task9/httpx-knownfiles-apidocs.txt#L48: `#     ) | Set-Content -Encoding utf8 'temp\agent1\knownfiles_and_apidocs.txt'`
- task/task9/httpx-knownfiles-apidocs.txt#L50: `#   (Get-Content 'temp\agent1\knownfiles_and_apidocs.txt') | Where-Object { $_ -and $_.Trim() -ne '' } | ForEach-Object { $_.Trim().TrimStart('/') } | Sort-Object -Unique | Set-Content -Encoding utf8 'temp\agent1\knownfiles_and_apidocs.txt'`
- task/task9/httpx-knownfiles-apidocs.txt#L50: `#   (Get-Content 'temp\agent1\knownfiles_and_apidocs.txt') | Where-Object { $_ -and $_.Trim() -ne '' } | ForEach-Object { $_.Trim().TrimStart('/') } | Sort-Object -Unique | Set-Content -Encoding utf8 'temp\agent1\knownfiles_and_apidocs.txt'`
- task/task9/httpx-knownfiles-apidocs.txt#L62: `#   $paths = Get-Content 'temp\agent1\knownfiles_and_apidocs.txt'`

## temp/agent1/list_4_reverse.txt` (count=4)
- README.md#L43: `- Task 10 (optional): `hakrevdns` → `temp/agent1/list_4_reverse.txt``
- README.md#L133: `- `temp/agent1/list_4_reverse.txt` (optional)`
- README.md#L171: `- `temp/agent1/list_4_reverse.txt``
- README.md#L180: `- `temp/agent1/list_4_reverse.txt` (PTR mode)`

## temp/agent1/resolvers_good.txt` (count=4)
- README.md#L121: `- `temp/agent1/resolvers_good.txt` (from prune test) OR `task/task5/resolvers_curated.txt``
- README.md#L123: `- `temp/agent1/resolvers_good.txt` (if you prune)`
- README.md#L141: `- `temp/agent1/resolvers_good.txt``
- README.md#L177: `- `temp/agent1/resolvers_good.txt``

## temp/agent1/in_scope_cidrs.txt (count=4)
- task/task10/hakrevdns.txt#L11: `- temp/agent1/in_scope_cidrs.txt   (one CIDR per line, e.g. 203.0.113.0/24)`
- task/task10/hakrevdns.txt#L27: `cat temp/agent1/in_scope_cidrs.txt | while read -r cidr; do`
- task/task11/dnsx.txt#L80: `- temp/agent1/in_scope_cidrs.txt (CIDRs) OR temp/agent1/in_scope_asns.txt (ASNs)`
- task/task11/dnsx.txt#L85: `cat temp/agent1/in_scope_cidrs.txt | dnsx -silent -resp-only -ptr -r temp/agent1/resolvers_good.txt \`

## temp\\agent1\\httpx_hostport_targets.txt (count=4)
- task/task12/httpx-hostport.txt#L45: `#   if ($n -lt 1) { throw "No targets found in temp\\agent1\\httpx_hostport_targets.txt" }`
- task/task12/httpx-hostport.txt#L90: `#   $in = 'temp\\agent1\\httpx_hostport_targets.txt'`
- task/task13/httpx-hostport.txt#L45: `#   if ($n -lt 1) { throw "No targets found in temp\\agent1\\httpx_hostport_targets.txt" }`
- task/task13/httpx-hostport.txt#L90: `#   $in = 'temp\\agent1\\httpx_hostport_targets.txt'`

## temp\\agent1\\live_hostport_urls_raw.txt (count=4)
- task/task12/httpx-hostport.txt#L104: `#   Remove-Item -ErrorAction SilentlyContinue temp\\agent1\\live_hostport_urls_raw.txt`
- task/task12/httpx-hostport.txt#L110: `#       Get-Content temp\\agent1\\_httpx_part.txt | Add-Content temp\\agent1\\live_hostport_urls_raw.txt`
- task/task13/httpx-hostport.txt#L104: `#   Remove-Item -ErrorAction SilentlyContinue temp\\agent1\\live_hostport_urls_raw.txt`
- task/task13/httpx-hostport.txt#L110: `#       Get-Content temp\\agent1\\_httpx_part.txt | Add-Content temp\\agent1\\live_hostport_urls_raw.txt`

## temp\\agent1\\katana_seeds_urls.txt (count=4)
- task/task13/katana.txt#L45: `#   if ($n -lt 1) { throw "No seeds found in temp\\agent1\\katana_seeds_urls.txt" }`
- task/task13/katana.txt#L101: `#   $in = 'temp\\agent1\\katana_seeds_urls.txt'`
- task/task14/katana.txt#L45: `#   if ($n -lt 1) { throw "No seeds found in temp\\agent1\\katana_seeds_urls.txt" }`
- task/task14/katana.txt#L101: `#   $in = 'temp\\agent1\\katana_seeds_urls.txt'`

## temp\agent1\api_docs_raw (count=4)
- task/task13/katana.txt#L93: `#   python tools\agent1\assets\openapi_extractor.py --docs outputs\api_docs_urls.txt --allowlist outputs\activesubdomain.txt --out outputs\api_endpoints_from_openapi.txt --raw-dir temp\agent1\api_docs_raw`
- task/task14/gau.txt#L91: `#   python tools\agent1\assets\openapi_extractor.py --docs outputs\api_docs_urls.txt --allowlist outputs\activesubdomain.txt --out outputs\api_endpoints_from_openapi.txt --raw-dir temp\agent1\api_docs_raw`
- task/task14/katana.txt#L93: `#   python tools\agent1\assets\openapi_extractor.py --docs outputs\api_docs_urls.txt --allowlist outputs\activesubdomain.txt --out outputs\api_endpoints_from_openapi.txt --raw-dir temp\agent1\api_docs_raw`
- task/task15/gau.txt#L91: `#   python tools\agent1\assets\openapi_extractor.py --docs outputs\api_docs_urls.txt --allowlist outputs\activesubdomain.txt --out outputs\api_endpoints_from_openapi.txt --raw-dir temp\agent1\api_docs_raw`

## temp\\agent1\\katana_urls_raw.txt (count=4)
- task/task13/katana.txt#L115: `#   Remove-Item -ErrorAction SilentlyContinue temp\\agent1\\katana_urls_raw.txt`
- task/task13/katana.txt#L121: `#       Get-Content temp\\agent1\\_katana_part.txt | Add-Content temp\\agent1\\katana_urls_raw.txt`
- task/task14/katana.txt#L115: `#   Remove-Item -ErrorAction SilentlyContinue temp\\agent1\\katana_urls_raw.txt`
- task/task14/katana.txt#L121: `#       Get-Content temp\\agent1\\_katana_part.txt | Add-Content temp\\agent1\\katana_urls_raw.txt`

## temp\\agent1\\gau_targets_hosts.txt (count=4)
- task/task14/gau.txt#L44: `#   if ($n -lt 1) { throw "No targets found in temp\\agent1\\gau_targets_hosts.txt" }`
- task/task14/gau.txt#L99: `#   $in = 'temp\\agent1\\gau_targets_hosts.txt'`
- task/task15/gau.txt#L44: `#   if ($n -lt 1) { throw "No targets found in temp\\agent1\\gau_targets_hosts.txt" }`
- task/task15/gau.txt#L99: `#   $in = 'temp\\agent1\\gau_targets_hosts.txt'`

## temp\\agent1\\gau_urls_raw.txt (count=4)
- task/task14/gau.txt#L113: `#   Remove-Item -ErrorAction SilentlyContinue temp\\agent1\\gau_urls_raw.txt`
- task/task14/gau.txt#L117: `#     Get-Content $chunk | gau 2>&1 | Tee-Object -FilePath $log -Append | Add-Content temp\\agent1\\gau_urls_raw.txt`
- task/task15/gau.txt#L113: `#   Remove-Item -ErrorAction SilentlyContinue temp\\agent1\\gau_urls_raw.txt`
- task/task15/gau.txt#L117: `#     Get-Content $chunk | gau 2>&1 | Tee-Object -FilePath $log -Append | Add-Content temp\\agent1\\gau_urls_raw.txt`

## temp\\agent1\\arjun_targets_urls.txt (count=4)
- task/task16/arjun.txt#L59: `#   if ($n -lt 1) { throw "No arjun targets in temp\\agent1\\arjun_targets_urls.txt" }`
- task/task16/arjun.txt#L99: `#   $in = 'temp\\agent1\\arjun_targets_urls.txt'`
- task/task17/arjun.txt#L60: `#   if ($n -lt 1) { throw "No arjun targets in temp\\agent1\\arjun_targets_urls.txt" }`
- task/task17/arjun.txt#L100: `#   $in = 'temp\\agent1\\arjun_targets_urls.txt'`

## temp\\agent1\\arjun_found_params_raw.txt (count=4)
- task/task16/arjun.txt#L113: `#   Remove-Item -ErrorAction SilentlyContinue temp\\agent1\\arjun_found_params_raw.txt`
- task/task16/arjun.txt#L119: `#       Get-Content temp\\agent1\\_arjun_part.txt | Add-Content temp\\agent1\\arjun_found_params_raw.txt`
- task/task17/arjun.txt#L114: `#   Remove-Item -ErrorAction SilentlyContinue temp\\agent1\\arjun_found_params_raw.txt`
- task/task17/arjun.txt#L120: `#       Get-Content temp\\agent1\\_arjun_part.txt | Add-Content temp\\agent1\\arjun_found_params_raw.txt`

## temp\\agent1\\kiterunner_targets_urls.txt (count=4)
- task/task17/kiterunner.txt#L46: `#   if ($n -lt 1) { throw "No targets found in temp\\agent1\\kiterunner_targets_urls.txt" }`
- task/task17/kiterunner.txt#L100: `#   $in = 'temp\\agent1\\kiterunner_targets_urls.txt'`
- task/task18/kiterunner.txt#L46: `#   if ($n -lt 1) { throw "No targets found in temp\\agent1\\kiterunner_targets_urls.txt" }`
- task/task18/kiterunner.txt#L100: `#   $in = 'temp\\agent1\\kiterunner_targets_urls.txt'`

## temp\\agent1\\httpx_api_endpoints_targets.txt (count=4)
- task/task18/httpx-probe-api-endpoints.txt#L36: `#   if ($n -lt 1) { throw "No targets found in temp\\agent1\\httpx_api_endpoints_targets.txt" }`
- task/task18/httpx-probe-api-endpoints.txt#L79: `#   $in = 'temp\\agent1\\httpx_api_endpoints_targets.txt'`
- task/task19/httpx-probe-api-endpoints.txt#L37: `#   if ($n -lt 1) { throw "No targets found in temp\\agent1\\httpx_api_endpoints_targets.txt" }`
- task/task19/httpx-probe-api-endpoints.txt#L80: `#   $in = 'temp\\agent1\\httpx_api_endpoints_targets.txt'`

## temp\\agent1\\api_endpoints_live_raw.txt (count=4)
- task/task18/httpx-probe-api-endpoints.txt#L93: `#   Remove-Item -ErrorAction SilentlyContinue temp\\agent1\\api_endpoints_live_raw.txt`
- task/task18/httpx-probe-api-endpoints.txt#L99: `#       Get-Content temp\\agent1\\_httpx_part.txt | Add-Content temp\\agent1\\api_endpoints_live_raw.txt`
- task/task19/httpx-probe-api-endpoints.txt#L94: `#   Remove-Item -ErrorAction SilentlyContinue temp\\agent1\\api_endpoints_live_raw.txt`
- task/task19/httpx-probe-api-endpoints.txt#L100: `#       Get-Content temp\\agent1\\_httpx_part.txt | Add-Content temp\\agent1\\api_endpoints_live_raw.txt`

## temp\agent1\js_urls_live_seeds.txt (count=4)
- task/task22/httpx-probe-js-extracted.txt#L45: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\js_urls_live_seeds.txt`
- task/task22/httpx-probe-js-extracted.txt#L79: `#   httpx -l temp\agent1\queue_js_absolute_urls_in_scope.txt -silent -timeout 9 -retries 1 -threads 50 -status-code -title -server -tech-detect -o temp\agent1\js_urls_live_seeds.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task23/httpx-probe-js-extracted.txt#L46: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\js_urls_live_seeds.txt`
- task/task23/httpx-probe-js-extracted.txt#L80: `#   httpx -l temp\agent1\queue_js_absolute_urls_in_scope.txt -silent -timeout 9 -retries 1 -threads 50 -status-code -title -server -tech-detect -o temp\agent1\js_urls_live_seeds.txt 2>&1 | Tee-Object -FilePath $log -Append`

## temp\\agent1\\js_urls_live_raw.txt (count=4)
- task/task22/httpx-probe-js-extracted.txt#L108: `#   Remove-Item -ErrorAction SilentlyContinue temp\\agent1\\js_urls_live_raw.txt`
- task/task22/httpx-probe-js-extracted.txt#L114: `#       Get-Content temp\\agent1\\_httpx_part.txt | Add-Content temp\\agent1\\js_urls_live_raw.txt`
- task/task23/httpx-probe-js-extracted.txt#L109: `#   Remove-Item -ErrorAction SilentlyContinue temp\\agent1\\js_urls_live_raw.txt`
- task/task23/httpx-probe-js-extracted.txt#L115: `#       Get-Content temp\\agent1\\_httpx_part.txt | Add-Content temp\\agent1\\js_urls_live_raw.txt`

## temp\\agent1\\... (count=4)
- task/task23/nuclei.txt#L56: `#   if ($existing.Count -lt 1) { throw "No nuclei inputs found. Provide at least one live URL list file (outputs\\... or temp\\agent1\\...)." }`
- task/task24/gowitness.txt#L54: `#   if ($existing.Count -lt 1) { throw "No gowitness inputs found. Provide at least one live URL list file (outputs\\... or temp\\agent1\\...)." }`
- task/task24/nuclei.txt#L57: `#   if ($existing.Count -lt 1) { throw "No nuclei inputs found. Provide at least one live URL list file (outputs\\... or temp\\agent1\\...)." }`
- task/task25/gowitness.txt#L55: `#   if ($existing.Count -lt 1) { throw "No gowitness inputs found. Provide at least one live URL list file (outputs\\... or temp\\agent1\\...)." }`

## temp\\agent1\\nuclei_findings_raw.txt (count=4)
- task/task23/nuclei.txt#L119: `#   Remove-Item -ErrorAction SilentlyContinue temp\\agent1\\nuclei_findings_raw.txt`
- task/task23/nuclei.txt#L125: `#       Get-Content temp\\agent1\\_nuclei_part.txt | Add-Content temp\\agent1\\nuclei_findings_raw.txt`
- task/task24/nuclei.txt#L120: `#   Remove-Item -ErrorAction SilentlyContinue temp\\agent1\\nuclei_findings_raw.txt`
- task/task24/nuclei.txt#L126: `#       Get-Content temp\\agent1\\_nuclei_part.txt | Add-Content temp\\agent1\\nuclei_findings_raw.txt`

## temp\agent1\content_wordlist.txt (count=4)
- task/task25/ffuf-content-discovery.txt#L30: `#   if (!(Test-Path temp\agent1\content_wordlist.txt)) { throw "Missing temp\\agent1\\content_wordlist.txt" }`
- task/task25/ffuf-content-discovery.txt#L63: `#   $wl = 'temp\agent1\content_wordlist.txt'`
- task/task26/ffuf-content-discovery.txt#L31: `#   if (!(Test-Path temp\agent1\content_wordlist.txt)) { throw "Missing temp\\agent1\\content_wordlist.txt" }`
- task/task26/ffuf-content-discovery.txt#L64: `#   $wl = 'temp\agent1\content_wordlist.txt'`

## temp\\agent1\\subjack_targets.txt (count=4)
- task/task27/subjack-takeover.txt#L56: `#   if ($n -lt 1) { throw "No targets in temp\\agent1\\subjack_targets.txt" }`
- task/task27/subjack-takeover.txt#L87: `#   $in = 'temp\\agent1\\subjack_targets.txt'`
- task/task28/subjack-takeover.txt#L57: `#   if ($n -lt 1) { throw "No targets in temp\\agent1\\subjack_targets.txt" }`
- task/task28/subjack-takeover.txt#L88: `#   $in = 'temp\\agent1\\subjack_targets.txt'`

## temp\\agent1\\takeover_candidates_subjack_raw.txt (count=4)
- task/task27/subjack-takeover.txt#L101: `#   Remove-Item -ErrorAction SilentlyContinue temp\\agent1\\takeover_candidates_subjack_raw.txt`
- task/task27/subjack-takeover.txt#L107: `#       Get-Content temp\\agent1\\_subjack_part.txt | Add-Content temp\\agent1\\takeover_candidates_subjack_raw.txt`
- task/task28/subjack-takeover.txt#L102: `#   Remove-Item -ErrorAction SilentlyContinue temp\\agent1\\takeover_candidates_subjack_raw.txt`
- task/task28/subjack-takeover.txt#L108: `#       Get-Content temp\\agent1\\_subjack_part.txt | Add-Content temp\\agent1\\takeover_candidates_subjack_raw.txt`

## temp\agent1\tlsx_raw.txt (count=4)
- task/task30/tlsx.txt#L36: `#   Remove-Item -ErrorAction SilentlyContinue 'temp\agent1\tlsx_raw.txt'`
- task/task30/tlsx.txt#L40: `#   tlsx -l outputs\activesubdomain.txt -silent -json -o temp\agent1\tlsx_raw.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task30/tlsx.txt#L45: `#   if (!(Test-Path 'temp\agent1\tlsx_raw.txt')) { throw 'Missing temp\\agent1\\tlsx_raw.txt (tlsx failed?)' }`
- task/task30/tlsx.txt#L50: `#   Get-Content 'temp\agent1\tlsx_raw.txt' |`

## temp/agent1/list_2_archives.txt (count=4)
- task/task4/waymore.txt#L21: `> temp/agent1/list_2_archives.txt`
- task/task6/alterx.txt#L12: `- temp/agent1/list_2_archives.txt`
- task/task6/alterx.txt#L20: `temp/agent1/list_2_archives.txt \`
- task/task7/puredns-resolve.txt#L48: `temp/agent1/list_2_archives.txt \`

## temp\agent1\knownfiles_targets_urls.txt (count=4)
- task/task9/httpx-knownfiles-apidocs.txt#L54: `#   Remove-Item -ErrorAction SilentlyContinue 'temp\agent1\knownfiles_targets_urls.txt'`
- task/task9/httpx-knownfiles-apidocs.txt#L65: `#       "$b/$p" | Add-Content -Encoding utf8 'temp\agent1\knownfiles_targets_urls.txt'`
- task/task9/httpx-knownfiles-apidocs.txt#L68: `#   $n = (Get-Content 'temp\agent1\knownfiles_targets_urls.txt').Count`
- task/task9/httpx-knownfiles-apidocs.txt#L80: `#   $in = 'temp\agent1\knownfiles_targets_urls.txt'`

## temp\agent1\knownfiles_hits_raw.txt (count=4)
- task/task9/httpx-knownfiles-apidocs.txt#L78: `#   Remove-Item -ErrorAction SilentlyContinue 'temp\agent1\knownfiles_hits_raw.txt'`
- task/task9/httpx-knownfiles-apidocs.txt#L106: `#       Add-Content -Encoding utf8 'temp\agent1\knownfiles_hits_raw.txt'`
- task/task9/httpx-knownfiles-apidocs.txt#L111: `#   if (!(Test-Path 'temp\agent1\knownfiles_hits_raw.txt')) { Write-Host '[knownfiles] no output (no hits or httpx failed)'; return }`
- task/task9/httpx-knownfiles-apidocs.txt#L113: `#   Get-Content 'temp\agent1\knownfiles_hits_raw.txt' |`

## temp/agent1/list_2_archives.txt` (count=3)
- README.md#L41: `- Task 4: `waymore` → `temp/agent1/list_2_archives.txt``
- README.md#L111: `- `temp/agent1/list_2_archives.txt``
- README.md#L131: `- `temp/agent1/list_2_archives.txt``

## temp/agent1/list_3_bruteforce.txt` (count=3)
- README.md#L42: `- Task 5: wordlist + `puredns bruteforce` → `temp/agent1/list_3_bruteforce.txt``
- README.md#L125: `- `temp/agent1/list_3_bruteforce.txt``
- README.md#L132: `- `temp/agent1/list_3_bruteforce.txt``

## temp/agent1/resolved_dnsx.txt (count=3)
- task/task11/dnsx.txt#L21: `- temp/agent1/resolved_dnsx.txt`
- task/task11/dnsx.txt#L39: `cat temp/agent1/candidates_all.txt | dnsx -silent -r temp/agent1/resolvers_good.txt -o temp/agent1/resolved_dnsx.txt`
- task/task11/dnsx.txt#L101: `You can base it on temp/agent1/resolved_dnsx.txt, but wildcard filtering may be weaker than puredns.`

## temp/agent1/url_list.txt (count=3)
- task/task11/dnsx.txt#L28: `# Input: temp/agent1/url_list.txt (full URLs)`
- task/task8/httpx.txt#L22: `# Example input file: temp/agent1/url_list.txt`
- task/task8/httpx.txt#L28: `# httpx -l temp/agent1/url_list.txt -silent -timeout 9 -retries 1 -threads 50 -o temp/agent1/httpx_urls_out.txt`

## temp\agent1\_dnsx_tmp.txt (count=3)
- task/task11/dnsx.txt#L64: `dnsx -silent -l $_.FullName -r temp\agent1\resolvers_good.txt -o temp\agent1\_dnsx_tmp.txt`
- task/task11/dnsx.txt#L65: `Get-Content temp\agent1\_dnsx_tmp.txt | Add-Content temp\agent1\resolved_dnsx.txt`
- task/task11/dnsx.txt#L67: `Remove-Item -ErrorAction SilentlyContinue temp\agent1\_dnsx_tmp.txt`

## temp\\agent1\\naabu_targets_hosts.txt (count=3)
- task/task12/naabu.txt#L56: `#   if ($n -lt 1) { throw "No targets found in temp\\agent1\\naabu_targets_hosts.txt" }`
- task/task12/naabu.txt#L135: `#   $in = 'temp\\agent1\\naabu_targets_hosts.txt'`
- task/task12/naabu.txt#L166: `#     naabu -l temp\\agent1\\naabu_targets_hosts.txt -p $r -rate 1200 -retries 1 -timeout 1000 -silent -o temp\\agent1\\_ports_open_hostport_part.txt 2>&1 | Tee-Object -FilePath $log -Append`

## temp\agent1\url_corpus_raw.txt (count=3)
- task/task15/allowlist-filter-urls.txt#L37: `#   python task\task21\allowlist_filter_urls.py --allowlist outputs\activesubdomain.txt --in temp\agent1\url_corpus_raw.txt --out outputs\url_corpus_all_in_scope.txt`
- task/task16/allowlist-filter-urls.txt#L37: `#   python task\task21\allowlist_filter_urls.py --allowlist outputs\activesubdomain.txt --in temp\agent1\url_corpus_raw.txt --out outputs\url_corpus_all_in_scope.txt`
- task/task21/allowlist_filter_urls.py#L15: `--in temp\agent1\url_corpus_raw.txt \`

## temp/agent1/js_fetch_dir (count=3)
- task/task21/httpx-fetch-js.txt#L6: `#   - temp/agent1/js_fetch_dir/    (saved responses)`
- task/task21/js-analyze-offline.txt#L4: `#   - temp/agent1/js_fetch_index.txt OR temp/agent1/js_fetch_dir/`
- task/task22/js-analyze-offline.txt#L4: `#   - temp/agent1/js_fetch_index.txt OR temp/agent1/js_fetch_dir/`

## temp/agent1/js_fetch_index.txt (count=3)
- task/task21/httpx-fetch-js.txt#L7: `#   - temp/agent1/js_fetch_index.txt`
- task/task21/js-analyze-offline.txt#L4: `#   - temp/agent1/js_fetch_index.txt OR temp/agent1/js_fetch_dir/`
- task/task22/js-analyze-offline.txt#L4: `#   - temp/agent1/js_fetch_index.txt OR temp/agent1/js_fetch_dir/`

## temp\agent1\httpx_js_targets.txt (count=3)
- task/task21/httpx-fetch-js.txt#L35: `#     Set-Content temp\agent1\httpx_js_targets.txt`
- task/task21/httpx-fetch-js.txt#L38: `#   $n = (Get-Content temp\agent1\httpx_js_targets.txt).Count`
- task/task21/httpx-fetch-js.txt#L63: `#   httpx -l temp\agent1\httpx_js_targets.txt -silent -timeout 9 -retries 1 -threads 50 -sr -srd $outDir 2>&1 | Tee-Object -FilePath $log -Append`

## temp\\agent1\\js_fetch_dir (count=3)
- task/task21/httpx-fetch-js.txt#L48: `#   $outDir = 'temp\\agent1\\js_fetch_dir'`
- task/task21/js-analyze-offline.txt#L13: `#     throw "Missing inputs: expected temp\\agent1\\js_fetch_index.txt or temp\\agent1\\js_fetch_dir"`
- task/task22/js-analyze-offline.txt#L13: `#     throw "Missing inputs: expected temp\\agent1\\js_fetch_index.txt or temp\\agent1\\js_fetch_dir"`

## temp/agent1/resolvers_2000.txt (count=3)
- task/task5/puredns-bruteforce.txt#L10: `#   OR temp/agent1/resolvers_2000.txt`
- task/task7/puredns-resolve.txt#L41: `- Put it at: temp/agent1/resolvers_2000.txt`
- task/task7/puredns-resolve.txt#L109: `- Fallback options: temp/agent1/resolvers_2000.txt or task/task5/resolvers_curated.txt`

## temp/agent1/_alterx_seed.txt (count=3)
- task/task6/alterx.txt#L27: `> temp/agent1/_alterx_seed.txt`
- task/task6/alterx.txt#L30: `alterx -l temp/agent1/_alterx_seed.txt -silent -o temp/agent1/list_5_permutations.txt`
- task/task6/alterx.txt#L33: `split -l 50000 temp/agent1/_alterx_seed.txt temp/agent1/ax_`

## temp/agent1/_alterx_tmp.txt (count=3)
- task/task6/alterx.txt#L36: `alterx -l "$f" -silent -o temp/agent1/_alterx_tmp.txt`
- task/task6/alterx.txt#L37: `cat temp/agent1/_alterx_tmp.txt >> temp/agent1/list_5_permutations.txt`
- task/task6/alterx.txt#L38: `rm -f temp/agent1/_alterx_tmp.txt`

## temp/agent1/_resolved_tmp.txt (count=3)
- task/task7/puredns-resolve.txt#L94: `--write temp/agent1/_resolved_tmp.txt --write-wildcards temp/agent1/_wild_tmp.txt --write-massdns temp/agent1/_massdns_tmp.txt`
- task/task7/puredns-resolve.txt#L95: `cat temp/agent1/_resolved_tmp.txt >> temp/agent1/resolved.txt`
- task/task7/puredns-resolve.txt#L96: `rm -f temp/agent1/_resolved_tmp.txt temp/agent1/_wild_tmp.txt temp/agent1/_massdns_tmp.txt`

## temp/agent1/_httpx_tmp.txt (count=3)
- task/task8/httpx.txt#L54: `httpx -l $_.FullName -silent -timeout 9 -retries 1 -threads 50 -o temp/agent1/_httpx_tmp.txt`
- task/task8/httpx.txt#L55: `Get-Content temp/agent1/_httpx_tmp.txt | Add-Content outputs/live_base_urls.txt`
- task/task8/httpx.txt#L57: `Remove-Item -ErrorAction SilentlyContinue temp/agent1/_httpx_tmp.txt`

## temp\agent1\knownfiles_hits.txt (count=3)
- task/task9/httpx-knownfiles-apidocs.txt#L117: `#     Set-Content -Encoding utf8 'temp\agent1\knownfiles_hits.txt'`
- task/task9/httpx-knownfiles-apidocs.txt#L122: `#   Get-Content 'temp\agent1\knownfiles_hits.txt' |`
- task/task9/httpx-knownfiles-apidocs.txt#L133: `#   Get-Content 'temp\agent1\knownfiles_hits.txt' |`

## temp/agent1/` (count=2)
- README.md#L11: `- `temp/agent1/` contains **intermediate, raw, logs, chunks**.`
- README.md#L194: `- Intermediates/logs under `temp/agent1/``

## temp/agent1/list_5_permutations.txt` (count=2)
- README.md#L44: `- Task 6: `alterx` permutations → `temp/agent1/list_5_permutations.txt``
- README.md#L135: `- `temp/agent1/list_5_permutations.txt``

## temp/agent1/js_fetch_dir/` (count=2)
- README.md#L65: `- Task 21: fetch JS responses → `temp/agent1/js_fetch_dir/` + `temp/agent1/js_fetch_index.txt``
- README.md#L285: `- `temp/agent1/js_fetch_dir/` + `temp/agent1/js_fetch_index.txt``

## temp/agent1/js_fetch_index.txt` (count=2)
- README.md#L65: `- Task 21: fetch JS responses → `temp/agent1/js_fetch_dir/` + `temp/agent1/js_fetch_index.txt``
- README.md#L285: `- `temp/agent1/js_fetch_dir/` + `temp/agent1/js_fetch_index.txt``

## temp/agent1/subdomain_wordlist.txt` (count=2)
- README.md#L120: `- `temp/agent1/subdomain_wordlist.txt``
- README.md#L124: `- `temp/agent1/subdomain_wordlist.txt``

## temp/agent1/candidates_all.txt` (count=2)
- README.md#L143: `- `temp/agent1/candidates_all.txt``
- README.md#L176: `- `temp/agent1/candidates_all.txt` (for validation) OR CIDR/ASN files (for PTR)`

## temp/agent1/subfinder.txt (count=2)
- task/task1/subfinder.txt#L23: `subfinder -d <domain> -silent -all -recursive -rl 10 -max-time 9 -timeout 30 -o temp/agent1/subfinder.txt 2>&1 | Tee-Object temp/agent1/subfinder.log`
- task/task1/subfinder.txt#L26: `Get-Content temp/agent1/subfinder.txt |`

## temp\agent1\candidates_all.txt (count=2)
- task/task11/dnsx.txt#L43: `Get-Content temp\agent1\candidates_all.txt | dnsx -silent -r temp\agent1\resolvers_good.txt -o temp\agent1\resolved_dnsx.txt`
- task/task11/dnsx.txt#L53: `Get-Content temp\agent1\candidates_all.txt | Where-Object { $_ } | ForEach-Object {`

## temp\agent1\resolvers_good.txt (count=2)
- task/task11/dnsx.txt#L43: `Get-Content temp\agent1\candidates_all.txt | dnsx -silent -r temp\agent1\resolvers_good.txt -o temp\agent1\resolved_dnsx.txt`
- task/task11/dnsx.txt#L64: `dnsx -silent -l $_.FullName -r temp\agent1\resolvers_good.txt -o temp\agent1\_dnsx_tmp.txt`

## temp/agent1/in_scope_asns.txt (count=2)
- task/task11/dnsx.txt#L80: `- temp/agent1/in_scope_cidrs.txt (CIDRs) OR temp/agent1/in_scope_asns.txt (ASNs)`
- task/task11/dnsx.txt#L90: `cat temp/agent1/in_scope_asns.txt | dnsx -silent -resp-only -ptr -r temp/agent1/resolvers_good.txt \`

## temp/agent1/live_hostport_urls_raw.txt (count=2)
- task/task12/httpx-hostport.txt#L7: `#   - temp/agent1/live_hostport_urls_raw.txt`
- task/task13/httpx-hostport.txt#L7: `#   - temp/agent1/live_hostport_urls_raw.txt`

## temp\\agent1\\logs\\httpx_hostport_$ts.log (count=2)
- task/task12/httpx-hostport.txt#L50: `#   $log = "temp\\agent1\\logs\\httpx_hostport_$ts.log"`
- task/task13/httpx-hostport.txt#L50: `#   $log = "temp\\agent1\\logs\\httpx_hostport_$ts.log"`

## temp\\agent1\\chunks_httpx_hostport (count=2)
- task/task12/httpx-hostport.txt#L92: `#   $outDir = 'temp\\agent1\\chunks_httpx_hostport'`
- task/task13/httpx-hostport.txt#L92: `#   $outDir = 'temp\\agent1\\chunks_httpx_hostport'`

## temp\agent1\naabu_ports_webish.txt (count=2)
- task/task12/naabu.txt#L86: `#   '80,81,443,591,593,8000,8008,8080,8081,8088,8090,8181,8222,8333,8443,8500,8888,9000,9001,9080,9090,9200,9443' | Set-Content temp\agent1\naabu_ports_webish.txt`
- task/task12/naabu.txt#L89: `#   naabu -l temp\agent1\naabu_targets_hosts.txt -p (Get-Content temp\agent1\naabu_ports_webish.txt) -rate 2500 -retries 1 -timeout 1000 -silent -o temp\agent1\_ports_open_hostport_part.txt 2>&1 | Tee-Object -FilePath $log -Append`

## temp\\agent1\\ports_open_hostport_raw.txt (count=2)
- task/task12/naabu.txt#L155: `#       Get-Content temp\\agent1\\_ports_open_hostport_part.txt | Add-Content temp\\agent1\\ports_open_hostport_raw.txt`
- task/task12/naabu.txt#L168: `#       Get-Content temp\\agent1\\_ports_open_hostport_part.txt | Add-Content temp\\agent1\\ports_open_hostport_raw.txt`

## temp/agent1/katana_urls_raw.txt (count=2)
- task/task13/katana.txt#L7: `#   - temp/agent1/katana_urls_raw.txt`
- task/task14/katana.txt#L7: `#   - temp/agent1/katana_urls_raw.txt`

## temp/agent1/logs/katana_YYYYMMDD_HHMMSS.log (count=2)
- task/task13/katana.txt#L9: `#   - temp/agent1/logs/katana_YYYYMMDD_HHMMSS.log`
- task/task14/katana.txt#L9: `#   - temp/agent1/logs/katana_YYYYMMDD_HHMMSS.log`

## temp\\agent1\\logs\\katana_$ts.log (count=2)
- task/task13/katana.txt#L50: `#   $log = "temp\\agent1\\logs\\katana_$ts.log"`
- task/task14/katana.txt#L50: `#   $log = "temp\\agent1\\logs\\katana_$ts.log"`

## temp\\agent1\\chunks_katana (count=2)
- task/task13/katana.txt#L103: `#   $outDir = 'temp\\agent1\\chunks_katana'`
- task/task14/katana.txt#L103: `#   $outDir = 'temp\\agent1\\chunks_katana'`

## temp/agent1/gau_urls_raw.txt (count=2)
- task/task14/gau.txt#L6: `#   - temp/agent1/gau_urls_raw.txt`
- task/task15/gau.txt#L6: `#   - temp/agent1/gau_urls_raw.txt`

## temp/agent1/logs/gau_YYYYMMDD_HHMMSS.log (count=2)
- task/task14/gau.txt#L8: `#   - temp/agent1/logs/gau_YYYYMMDD_HHMMSS.log`
- task/task15/gau.txt#L8: `#   - temp/agent1/logs/gau_YYYYMMDD_HHMMSS.log`

## temp\\agent1\\logs\\gau_$ts.log (count=2)
- task/task14/gau.txt#L49: `#   $log = "temp\\agent1\\logs\\gau_$ts.log"`
- task/task15/gau.txt#L49: `#   $log = "temp\\agent1\\logs\\gau_$ts.log"`

## temp\\agent1\\chunks_gau (count=2)
- task/task14/gau.txt#L101: `#   $outDir = 'temp\\agent1\\chunks_gau'`
- task/task15/gau.txt#L101: `#   $outDir = 'temp\\agent1\\chunks_gau'`

## temp/agent1/arjun_targets_urls.txt (count=2)
- task/task16/arjun.txt#L7: `#   - temp/agent1/arjun_targets_urls.txt`
- task/task17/arjun.txt#L7: `#   - temp/agent1/arjun_targets_urls.txt`

## temp/agent1/arjun_found_params_raw.txt (count=2)
- task/task16/arjun.txt#L8: `#   - temp/agent1/arjun_found_params_raw.txt`
- task/task17/arjun.txt#L8: `#   - temp/agent1/arjun_found_params_raw.txt`

## temp/agent1/logs/arjun_YYYYMMDD_HHMMSS.log (count=2)
- task/task16/arjun.txt#L10: `#   - temp/agent1/logs/arjun_YYYYMMDD_HHMMSS.log`
- task/task17/arjun.txt#L10: `#   - temp/agent1/logs/arjun_YYYYMMDD_HHMMSS.log`

## temp\\agent1\\logs\\arjun_$ts.log (count=2)
- task/task16/arjun.txt#L64: `#   $log = "temp\\agent1\\logs\\arjun_$ts.log"`
- task/task17/arjun.txt#L65: `#   $log = "temp\\agent1\\logs\\arjun_$ts.log"`

## temp\\agent1\\chunks_arjun (count=2)
- task/task16/arjun.txt#L101: `#   $outDir = 'temp\\agent1\\chunks_arjun'`
- task/task17/arjun.txt#L102: `#   $outDir = 'temp\\agent1\\chunks_arjun'`

## temp/agent1/kiterunner_targets_urls.txt (count=2)
- task/task17/kiterunner.txt#L8: `#   - temp/agent1/kiterunner_targets_urls.txt`
- task/task18/kiterunner.txt#L8: `#   - temp/agent1/kiterunner_targets_urls.txt`

## temp/agent1/kiterunner_raw.json (count=2)
- task/task17/kiterunner.txt#L9: `#   - temp/agent1/kiterunner_raw.json`
- task/task18/kiterunner.txt#L9: `#   - temp/agent1/kiterunner_raw.json`

## temp/agent1/logs/kiterunner_YYYYMMDD_HHMMSS.log (count=2)
- task/task17/kiterunner.txt#L11: `#   - temp/agent1/logs/kiterunner_YYYYMMDD_HHMMSS.log`
- task/task18/kiterunner.txt#L11: `#   - temp/agent1/logs/kiterunner_YYYYMMDD_HHMMSS.log`

## temp\agent1\routes-small.kite (count=2)
- task/task17/kiterunner.txt#L52: `#     temp\agent1\routes-small.kite`
- task/task18/kiterunner.txt#L52: `#     temp\agent1\routes-small.kite`

## temp\\agent1\\routes-small.kite (count=2)
- task/task17/kiterunner.txt#L55: `#   $routes = 'temp\\agent1\\routes-small.kite'`
- task/task18/kiterunner.txt#L55: `#   $routes = 'temp\\agent1\\routes-small.kite'`

## temp\\agent1\\logs\\kiterunner_$ts.log (count=2)
- task/task17/kiterunner.txt#L60: `#   $log = "temp\\agent1\\logs\\kiterunner_$ts.log"`
- task/task18/kiterunner.txt#L60: `#   $log = "temp\\agent1\\logs\\kiterunner_$ts.log"`

## temp\\agent1\\chunks_kiterunner (count=2)
- task/task17/kiterunner.txt#L102: `#   $outDir = 'temp\\agent1\\chunks_kiterunner'`
- task/task18/kiterunner.txt#L102: `#   $outDir = 'temp\\agent1\\chunks_kiterunner'`

## temp/agent1/api_endpoints_live_raw.txt (count=2)
- task/task18/httpx-probe-api-endpoints.txt#L6: `#   - temp/agent1/api_endpoints_live_raw.txt`
- task/task19/httpx-probe-api-endpoints.txt#L6: `#   - temp/agent1/api_endpoints_live_raw.txt`

## temp/agent1/logs/httpx_api_endpoints_YYYYMMDD_HHMMSS.log (count=2)
- task/task18/httpx-probe-api-endpoints.txt#L10: `#   - temp/agent1/logs/httpx_api_endpoints_YYYYMMDD_HHMMSS.log`
- task/task19/httpx-probe-api-endpoints.txt#L10: `#   - temp/agent1/logs/httpx_api_endpoints_YYYYMMDD_HHMMSS.log`

## temp\agent1\queue_api_endpoints_kiterunner.txt (count=2)
- task/task18/httpx-probe-api-endpoints.txt#L25: `#   if (!(Test-Path temp\agent1\queue_api_endpoints_kiterunner.txt)) { throw "Missing temp\\agent1\\queue_api_endpoints_kiterunner.txt" }`
- task/task18/httpx-probe-api-endpoints.txt#L28: `#   Get-Content temp\agent1\queue_api_endpoints_kiterunner.txt |`

## temp\\agent1\\logs\\httpx_api_endpoints_$ts.log (count=2)
- task/task18/httpx-probe-api-endpoints.txt#L41: `#   $log = "temp\\agent1\\logs\\httpx_api_endpoints_$ts.log"`
- task/task19/httpx-probe-api-endpoints.txt#L42: `#   $log = "temp\\agent1\\logs\\httpx_api_endpoints_$ts.log"`

## temp\agent1\api_endpoints_live_seeds.txt (count=2)
- task/task18/httpx-probe-api-endpoints.txt#L47: `#   Remove-Item -ErrorAction SilentlyContinue temp\agent1\api_endpoints_live_seeds.txt`
- task/task18/httpx-probe-api-endpoints.txt#L59: `#   httpx -l temp\agent1\httpx_api_endpoints_targets.txt -silent -timeout 9 -retries 1 -threads 50 -status-code -title -server -tech-detect -o temp\agent1\api_endpoints_live_seeds.txt 2>&1 | Tee-Object -FilePath $log -Append`

## temp\\agent1\\chunks_httpx_api_endpoints (count=2)
- task/task18/httpx-probe-api-endpoints.txt#L81: `#   $outDir = 'temp\\agent1\\chunks_httpx_api_endpoints'`
- task/task19/httpx-probe-api-endpoints.txt#L82: `#   $outDir = 'temp\\agent1\\chunks_httpx_api_endpoints'`

## temp/agent1/js_urls_raw.txt (count=2)
- task/task19/js-urls.txt#L7: `#   - temp/agent1/js_urls_raw.txt`
- task/task20/js-urls.txt#L7: `#   - temp/agent1/js_urls_raw.txt`

## temp/agent1/amass.txt (count=2)
- task/task2/amass.txt#L10: `amass enum -passive -d <domain> -o temp/agent1/amass.txt`
- task/task2/amass.txt#L14: `cat temp/agent1/list_1_passive.txt temp/agent1/amass.txt \`

## temp\\agent1\\httpx_js_targets.txt (count=2)
- task/task21/httpx-fetch-js.txt#L39: `#   if ($n -lt 1) { throw "No targets found in temp\\agent1\\httpx_js_targets.txt" }`
- task/task21/httpx-fetch-js.txt#L74: `#   $in = 'temp\\agent1\\httpx_js_targets.txt'`

## temp\\agent1\\js_fetch_index.txt (count=2)
- task/task21/js-analyze-offline.txt#L13: `#     throw "Missing inputs: expected temp\\agent1\\js_fetch_index.txt or temp\\agent1\\js_fetch_dir"`
- task/task22/js-analyze-offline.txt#L13: `#     throw "Missing inputs: expected temp\\agent1\\js_fetch_index.txt or temp\\agent1\\js_fetch_dir"`

## temp/agent1/queue_js_absolute_urls_in_scope.txt (count=2)
- task/task22/httpx-probe-js-extracted.txt#L9: `#   - temp/agent1/queue_js_absolute_urls_in_scope.txt`
- task/task23/httpx-probe-js-extracted.txt#L9: `#   - temp/agent1/queue_js_absolute_urls_in_scope.txt`

## temp/agent1/js_urls_live_raw.txt (count=2)
- task/task22/httpx-probe-js-extracted.txt#L10: `#   - temp/agent1/js_urls_live_raw.txt`
- task/task23/httpx-probe-js-extracted.txt#L10: `#   - temp/agent1/js_urls_live_raw.txt`

## temp/agent1/queue_js_composed_urls.txt (count=2)
- task/task22/httpx-probe-js-extracted.txt#L13: `#   - temp/agent1/queue_js_composed_urls.txt`
- task/task23/httpx-probe-js-extracted.txt#L13: `#   - temp/agent1/queue_js_composed_urls.txt`

## temp/agent1/js_composed_live_raw.txt (count=2)
- task/task22/httpx-probe-js-extracted.txt#L14: `#   - temp/agent1/js_composed_live_raw.txt`
- task/task23/httpx-probe-js-extracted.txt#L14: `#   - temp/agent1/js_composed_live_raw.txt`

## temp/agent1/logs/httpx_js_probe_YYYYMMDD_HHMMSS.log (count=2)
- task/task22/httpx-probe-js-extracted.txt#L17: `#   - temp/agent1/logs/httpx_js_probe_YYYYMMDD_HHMMSS.log`
- task/task23/httpx-probe-js-extracted.txt#L17: `#   - temp/agent1/logs/httpx_js_probe_YYYYMMDD_HHMMSS.log`

## temp\\agent1\\logs\\httpx_js_probe_$ts.log (count=2)
- task/task22/httpx-probe-js-extracted.txt#L37: `#   $log = "temp\\agent1\\logs\\httpx_js_probe_$ts.log"`
- task/task23/httpx-probe-js-extracted.txt#L38: `#   $log = "temp\\agent1\\logs\\httpx_js_probe_$ts.log"`

## temp\\agent1\\queue_js_absolute_urls_in_scope.txt (count=2)
- task/task22/httpx-probe-js-extracted.txt#L94: `#   $in = 'temp\\agent1\\queue_js_absolute_urls_in_scope.txt'`
- task/task23/httpx-probe-js-extracted.txt#L95: `#   $in = 'temp\\agent1\\queue_js_absolute_urls_in_scope.txt'`

## temp\\agent1\\chunks_httpx_js_abs (count=2)
- task/task22/httpx-probe-js-extracted.txt#L96: `#   $outDir = 'temp\\agent1\\chunks_httpx_js_abs'`
- task/task23/httpx-probe-js-extracted.txt#L97: `#   $outDir = 'temp\\agent1\\chunks_httpx_js_abs'`

## temp\\agent1\\queue_js_composed_urls.txt (count=2)
- task/task22/httpx-probe-js-extracted.txt#L151: `#   $out = 'temp\\agent1\\queue_js_composed_urls.txt'`
- task/task23/httpx-probe-js-extracted.txt#L152: `#   $out = 'temp\\agent1\\queue_js_composed_urls.txt'`

## temp\agent1\queue_js_composed_urls.txt (count=2)
- task/task22/httpx-probe-js-extracted.txt#L161: `#   httpx -l temp\agent1\queue_js_composed_urls.txt -silent -timeout 9 -retries 1 -threads 50 -o temp\agent1\_httpx_part.txt 2>&1 | Tee-Object -FilePath $log -Append`
- task/task23/httpx-probe-js-extracted.txt#L162: `#   httpx -l temp\agent1\queue_js_composed_urls.txt -silent -timeout 9 -retries 1 -threads 50 -o temp\agent1\_httpx_part.txt 2>&1 | Tee-Object -FilePath $log -Append`

## temp/agent1/nuclei_findings_raw.txt (count=2)
- task/task23/nuclei.txt#L11: `#   - temp/agent1/nuclei_findings_raw.txt`
- task/task24/nuclei.txt#L11: `#   - temp/agent1/nuclei_findings_raw.txt`

## temp/agent1/logs/nuclei_YYYYMMDD_HHMMSS.log (count=2)
- task/task23/nuclei.txt#L14: `#   - temp/agent1/logs/nuclei_YYYYMMDD_HHMMSS.log`
- task/task24/nuclei.txt#L14: `#   - temp/agent1/logs/nuclei_YYYYMMDD_HHMMSS.log`

## temp\\agent1\\logs\\nuclei_$ts.log (count=2)
- task/task23/nuclei.txt#L35: `#   $log = "temp\\agent1\\logs\\nuclei_$ts.log"`
- task/task24/nuclei.txt#L36: `#   $log = "temp\\agent1\\logs\\nuclei_$ts.log"`

## temp\\agent1\\chunks_nuclei (count=2)
- task/task23/nuclei.txt#L107: `#   $outDir = 'temp\\agent1\\chunks_nuclei'`
- task/task24/nuclei.txt#L108: `#   $outDir = 'temp\\agent1\\chunks_nuclei'`

## temp/agent1/logs/gowitness_YYYYMMDD_HHMMSS.log (count=2)
- task/task24/gowitness.txt#L13: `#   - temp/agent1/logs/gowitness_YYYYMMDD_HHMMSS.log`
- task/task25/gowitness.txt#L13: `#   - temp/agent1/logs/gowitness_YYYYMMDD_HHMMSS.log`

## temp\\agent1\\logs\\gowitness_$ts.log (count=2)
- task/task24/gowitness.txt#L35: `#   $log = "temp\\agent1\\logs\\gowitness_$ts.log"`
- task/task25/gowitness.txt#L36: `#   $log = "temp\\agent1\\logs\\gowitness_$ts.log"`

## temp\\agent1\\chunks_gowitness (count=2)
- task/task24/gowitness.txt#L94: `#   $outChunks = 'temp\\agent1\\chunks_gowitness'`
- task/task25/gowitness.txt#L95: `#   $outChunks = 'temp\\agent1\\chunks_gowitness'`

## temp/agent1/content_wordlist.txt (count=2)
- task/task25/ffuf-content-discovery.txt#L5: `#   - temp/agent1/content_wordlist.txt        (wordlist for FUZZ; one entry per line)`
- task/task26/ffuf-content-discovery.txt#L5: `#   - temp/agent1/content_wordlist.txt        (wordlist for FUZZ; one entry per line)`

## temp/agent1/ffuf_findings_raw.txt (count=2)
- task/task25/ffuf-content-discovery.txt#L8: `#   - temp/agent1/ffuf_findings_raw.txt`
- task/task26/ffuf-content-discovery.txt#L8: `#   - temp/agent1/ffuf_findings_raw.txt`

## temp/agent1/logs/ffuf_YYYYMMDD_HHMMSS.log (count=2)
- task/task25/ffuf-content-discovery.txt#L11: `#   - temp/agent1/logs/ffuf_YYYYMMDD_HHMMSS.log`
- task/task26/ffuf-content-discovery.txt#L11: `#   - temp/agent1/logs/ffuf_YYYYMMDD_HHMMSS.log`

## temp\\agent1\\content_wordlist.txt (count=2)
- task/task25/ffuf-content-discovery.txt#L30: `#   if (!(Test-Path temp\agent1\content_wordlist.txt)) { throw "Missing temp\\agent1\\content_wordlist.txt" }`
- task/task26/ffuf-content-discovery.txt#L31: `#   if (!(Test-Path temp\agent1\content_wordlist.txt)) { throw "Missing temp\\agent1\\content_wordlist.txt" }`

## temp\\agent1\\logs\\ffuf_$ts.log (count=2)
- task/task25/ffuf-content-discovery.txt#L34: `#   $log = "temp\\agent1\\logs\\ffuf_$ts.log"`
- task/task26/ffuf-content-discovery.txt#L35: `#   $log = "temp\\agent1\\logs\\ffuf_$ts.log"`

## temp\\agent1\\ffuf_targets_base.txt (count=2)
- task/task25/ffuf-content-discovery.txt#L51: `#   if ($n -lt 1) { throw "No targets in temp\\agent1\\ffuf_targets_base.txt" }`
- task/task26/ffuf-content-discovery.txt#L52: `#   if ($n -lt 1) { throw "No targets in temp\\agent1\\ffuf_targets_base.txt" }`

## temp/agent1/logs/nmap_YYYYMMDD_HHMMSS.log (count=2)
- task/task26/nmap-service-enum.txt#L9: `#   - temp/agent1/logs/nmap_YYYYMMDD_HHMMSS.log`
- task/task27/nmap-service-enum.txt#L9: `#   - temp/agent1/logs/nmap_YYYYMMDD_HHMMSS.log`

## temp\\agent1\\logs\\nmap_$ts.log (count=2)
- task/task26/nmap-service-enum.txt#L32: `#   $log = "temp\\agent1\\logs\\nmap_$ts.log"`
- task/task27/nmap-service-enum.txt#L33: `#   $log = "temp\\agent1\\logs\\nmap_$ts.log"`

## temp\\agent1\\ports_open_hostport_norm.txt (count=2)
- task/task26/nmap-service-enum.txt#L49: `#   if ($n -lt 1) { throw "No valid host:port entries in temp\\agent1\\ports_open_hostport_norm.txt" }`
- task/task27/nmap-service-enum.txt#L50: `#   if ($n -lt 1) { throw "No valid host:port entries in temp\\agent1\\ports_open_hostport_norm.txt" }`

## temp/agent1/takeover_candidates_subjack_raw.txt (count=2)
- task/task27/subjack-takeover.txt#L6: `#   - temp/agent1/takeover_candidates_subjack_raw.txt`
- task/task28/subjack-takeover.txt#L6: `#   - temp/agent1/takeover_candidates_subjack_raw.txt`

## temp/agent1/logs/subjack_YYYYMMDD_HHMMSS.log (count=2)
- task/task27/subjack-takeover.txt#L9: `#   - temp/agent1/logs/subjack_YYYYMMDD_HHMMSS.log`
- task/task28/subjack-takeover.txt#L9: `#   - temp/agent1/logs/subjack_YYYYMMDD_HHMMSS.log`

## temp\\agent1\\logs\\subjack_$ts.log (count=2)
- task/task27/subjack-takeover.txt#L39: `#   $log = "temp\\agent1\\logs\\subjack_$ts.log"`
- task/task28/subjack-takeover.txt#L40: `#   $log = "temp\\agent1\\logs\\subjack_$ts.log"`

## temp\\agent1\\chunks_subjack (count=2)
- task/task27/subjack-takeover.txt#L89: `#   $outDir = 'temp\\agent1\\chunks_subjack'`
- task/task28/subjack-takeover.txt#L90: `#   $outDir = 'temp\\agent1\\chunks_subjack'`

## temp/agent1/github-subdomains.txt (count=2)
- task/task3/github-subdomains.txt#L14: `github-subdomains -d <domain> -e -o temp/agent1/github-subdomains.txt`
- task/task3/github-subdomains.txt#L17: `cat temp/agent1/list_1_passive.txt temp/agent1/github-subdomains.txt \`

## temp\agent1\tlsx_sans_all.txt (count=2)
- task/task30/tlsx.txt#L55: `#     Set-Content -Encoding utf8 'temp\agent1\tlsx_sans_all.txt'`
- task/task30/tlsx.txt#L63: `#   Get-Content 'temp\agent1\tlsx_sans_all.txt' |`

## temp\agent1\tlsx_sans_in_scope.txt (count=2)
- task/task30/tlsx.txt#L66: `#     Set-Content -Encoding utf8 'temp\agent1\tlsx_sans_in_scope.txt'`
- task/task30/tlsx.txt#L68: `#   Copy-Item -Force 'temp\agent1\tlsx_sans_in_scope.txt' 'outputs\coverage_tls_sans_in_scope.txt'`

## temp/agent1/waymore_urls.log (count=2)
- task/task4/waymore.txt#L10: `waymore -i <domain> > temp/agent1/waymore_urls.log`
- task/task4/waymore.txt#L13: `cat temp/agent1/waymore_urls.log \`

## temp/agent1/_brute_tmp.txt (count=2)
- task/task5/puredns-bruteforce.txt#L31: `puredns bruteforce "$f" <domain> --resolvers temp/agent1/resolvers_good.txt --write temp/agent1/_brute_tmp.txt`
- task/task5/puredns-bruteforce.txt#L32: `cat temp/agent1/_brute_tmp.txt >> temp/agent1/list_3_bruteforce.txt`

## temp\agent1\resolvers_raw.txt (count=2)
- task/task5/resolver-prune-test.txt#L15: `Invoke-WebRequest -Uri "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" -OutFile temp\agent1\resolvers_raw.txt`
- task/task5/resolver-prune-test.txt#L19: `Get-Content temp\agent1\resolvers_raw.txt | Where-Object { $_ -match '^(\d{1,3}\.){3}\d{1,3}$' } | Select-Object -First 2000 | Set-Content -Encoding ascii temp\agent1\resolvers_2000.txt`

## temp/agent1/wildcards.txt (count=2)
- task/task7/puredns-resolve.txt#L23: `- temp/agent1/wildcards.txt`
- task/task7/puredns-resolve.txt#L72: `--write-wildcards temp/agent1/wildcards.txt \`

## temp/agent1/massdns.txt (count=2)
- task/task7/puredns-resolve.txt#L24: `- temp/agent1/massdns.txt`
- task/task7/puredns-resolve.txt#L73: `--write-massdns temp/agent1/massdns.txt`

## temp/agent1/_wild_tmp.txt (count=2)
- task/task7/puredns-resolve.txt#L94: `--write temp/agent1/_resolved_tmp.txt --write-wildcards temp/agent1/_wild_tmp.txt --write-massdns temp/agent1/_massdns_tmp.txt`
- task/task7/puredns-resolve.txt#L96: `rm -f temp/agent1/_resolved_tmp.txt temp/agent1/_wild_tmp.txt temp/agent1/_massdns_tmp.txt`

## temp/agent1/_massdns_tmp.txt (count=2)
- task/task7/puredns-resolve.txt#L94: `--write temp/agent1/_resolved_tmp.txt --write-wildcards temp/agent1/_wild_tmp.txt --write-massdns temp/agent1/_massdns_tmp.txt`
- task/task7/puredns-resolve.txt#L96: `rm -f temp/agent1/_resolved_tmp.txt temp/agent1/_wild_tmp.txt temp/agent1/_massdns_tmp.txt`

## temp/agent1/.gitkeep (count=1)
- .gitignore#L13: `!temp/agent1/.gitkeep`

## temp/agent1/subfinder.txt` (count=1)
- README.md#L88: `- `temp/agent1/subfinder.txt``

## temp/agent1/subfinder.log` (count=1)
- README.md#L89: `- `temp/agent1/subfinder.log``

## temp/agent1/amass.txt` (count=1)
- README.md#L96: `- `temp/agent1/amass.txt``

## temp/agent1/github-subdomains.txt` (count=1)
- README.md#L103: `- `temp/agent1/github-subdomains.txt``

## temp/agent1/waymore_urls.log` (count=1)
- README.md#L110: `- `temp/agent1/waymore_urls.log``

## temp/agent1/list_*` (count=1)
- README.md#L140: `- `temp/agent1/list_*` inputs (passive/archives/bruteforce/permutations)`

## temp/agent1/resolved.txt` (count=1)
- README.md#L144: `- `temp/agent1/resolved.txt``

## temp/agent1/wildcards.txt` (count=1)
- README.md#L148: `- Optional debug: `temp/agent1/wildcards.txt`, `temp/agent1/massdns.txt``

## temp/agent1/massdns.txt` (count=1)
- README.md#L148: `- Optional debug: `temp/agent1/wildcards.txt`, `temp/agent1/massdns.txt``

## temp/agent1/knownfiles_*` (count=1)
- README.md#L165: `- Intermediates: `temp/agent1/knownfiles_*``

## temp/agent1/in_scope_cidrs.txt` (count=1)
- README.md#L169: `- Input: `temp/agent1/in_scope_cidrs.txt``

## temp/agent1/resolved_dnsx.txt` (count=1)
- README.md#L179: `- `temp/agent1/resolved_dnsx.txt` (validation)`

## temp/agent1/js_fetch_*` (count=1)
- README.md#L293: `- `temp/agent1/js_fetch_*` (analysis)`

## temp/agent1/subfinder.log (count=1)
- task/task1/subfinder.txt#L23: `subfinder -d <domain> -silent -all -recursive -rl 10 -max-time 9 -timeout 30 -o temp/agent1/subfinder.txt 2>&1 | Tee-Object temp/agent1/subfinder.log`

## temp/agent1/hosts_from_urls.txt (count=1)
- task/task11/dnsx.txt#L29: `# Output: temp/agent1/hosts_from_urls.txt`

## temp\agent1\url_list.txt (count=1)
- task/task11/dnsx.txt#L31: `Get-Content temp\agent1\url_list.txt | ForEach-Object {`

## temp\agent1\hosts_from_urls.txt (count=1)
- task/task11/dnsx.txt#L35: `} | Where-Object { $_ } | Sort-Object -Unique | Set-Content -Encoding utf8 temp\agent1\hosts_from_urls.txt`

## temp/agent1/dnsx_chunks (count=1)
- task/task11/dnsx.txt#L50: `$chunkDir = 'temp/agent1/dnsx_chunks'`

## temp/agent1/dnsx_wildcard.json (count=1)
- task/task11/dnsx.txt#L76: `dnsx -l temp/agent1/candidates_all.txt -wd <root-domain> -r temp/agent1/resolvers_good.txt -o temp/agent1/dnsx_wildcard.json`

## temp/agent1/live_hostport_seeds.txt (count=1)
- task/task12/httpx-hostport.txt#L10: `#   - temp/agent1/live_hostport_seeds.txt       (status/title/server/tech)`

## temp\agent1\live_hostport_seeds.txt (count=1)
- task/task12/httpx-hostport.txt#L70: `#   httpx -l temp\agent1\httpx_hostport_targets.txt -silent -timeout 9 -retries 1 -threads 50 -status-code -title -server -tech-detect -o temp\agent1\live_hostport_seeds.txt 2>&1 | Tee-Object -FilePath $log -Append`

## temp/agent1/ports_open_hostport_raw.txt (count=1)
- task/task12/naabu.txt#L5: `#   - temp/agent1/ports_open_hostport_raw.txt  (raw host:port, appended across phases)`

## temp/agent1/ports_open_ips.txt (count=1)
- task/task12/naabu.txt#L10: `#   - temp/agent1/ports_open_ips.txt           (ip:port lines)`

## temp\\agent1\\logs\\naabu_$ts.log (count=1)
- task/task12/naabu.txt#L67: `#   $log = "temp\\agent1\\logs\\naabu_$ts.log"`

## temp\\agent1\\chunks_naabu (count=1)
- task/task12/naabu.txt#L137: `#   $outDir = 'temp\\agent1\\chunks_naabu'`

## temp/agent1/queue_api_endpoints_kiterunner.txt (count=1)
- task/task18/httpx-probe-api-endpoints.txt#L4: `#   - temp/agent1/queue_api_endpoints_kiterunner.txt   (URLs)`

## temp/agent1/api_endpoints_live_seeds.txt (count=1)
- task/task18/httpx-probe-api-endpoints.txt#L9: `#   - temp/agent1/api_endpoints_live_seeds.txt         (status/title/server/tech)`

## temp\\agent1\\queue_api_endpoints_kiterunner.txt (count=1)
- task/task18/httpx-probe-api-endpoints.txt#L25: `#   if (!(Test-Path temp\agent1\queue_api_endpoints_kiterunner.txt)) { throw "Missing temp\\agent1\\queue_api_endpoints_kiterunner.txt" }`

## temp/agent1/logs/httpx_fetch_js_YYYYMMDD_HHMMSS.log (count=1)
- task/task21/httpx-fetch-js.txt#L8: `#   - temp/agent1/logs/httpx_fetch_js_YYYYMMDD_HHMMSS.log`

## temp\\agent1\\logs\\httpx_fetch_js_$ts.log (count=1)
- task/task21/httpx-fetch-js.txt#L44: `#   $log = "temp\\agent1\\logs\\httpx_fetch_js_$ts.log"`

## temp\\agent1\\chunks_httpx_fetch_js (count=1)
- task/task21/httpx-fetch-js.txt#L76: `#   $chunkDir = 'temp\\agent1\\chunks_httpx_fetch_js'`

## temp\\agent1\\nuclei_targets_urls.txt (count=1)
- task/task24/nuclei.txt#L106: `#   $in = 'temp\\agent1\\nuclei_targets_urls.txt'`

## temp\\agent1\\gowitness_targets_urls.txt (count=1)
- task/task25/gowitness.txt#L93: `#   $in = 'temp\\agent1\\gowitness_targets_urls.txt'`

## temp/agent1/tlsx_raw.txt (count=1)
- task/task30/tlsx.txt#L10: `# - temp/agent1/tlsx_raw.txt`

## temp/agent1/tlsx_sans_all.txt (count=1)
- task/task30/tlsx.txt#L11: `# - temp/agent1/tlsx_sans_all.txt`

## temp/agent1/tlsx_sans_in_scope.txt (count=1)
- task/task30/tlsx.txt#L12: `# - temp/agent1/tlsx_sans_in_scope.txt`

## temp\\agent1\\logs\\tlsx_$ts.log (count=1)
- task/task30/tlsx.txt#L32: `#   $log = "temp\\agent1\\logs\\tlsx_$ts.log"`

## temp\\agent1\\tlsx_raw.txt (count=1)
- task/task30/tlsx.txt#L45: `#   if (!(Test-Path 'temp\agent1\tlsx_raw.txt')) { throw 'Missing temp\\agent1\\tlsx_raw.txt (tlsx failed?)' }`

## temp/agent1/wl_ (count=1)
- task/task5/puredns-bruteforce.txt#L28: `split -l 100000 temp/agent1/subdomain_wordlist.txt temp/agent1/wl_`

## temp/agent1/wl_* (count=1)
- task/task5/puredns-bruteforce.txt#L30: `for f in temp/agent1/wl_*; do`

## temp\agent1\resolvers_2000.txt (count=1)
- task/task5/resolver-prune-test.txt#L19: `Get-Content temp\agent1\resolvers_raw.txt | Where-Object { $_ -match '^(\d{1,3}\.){3}\d{1,3}$' } | Select-Object -First 2000 | Set-Content -Encoding ascii temp\agent1\resolvers_2000.txt`

## temp/agent1/resolvers_raw.txt (count=1)
- task/task5/resolver-prune-test.txt#L36: `~/.local/bin/dnsvalidator -tL temp/agent1/resolvers_raw.txt -threads 25 -o temp/agent1/resolvers_good.txt --silent`

## temp\agent1\subdomain_wordlist.txt (count=1)
- task/task5/wordlist-download.txt#L17: `Invoke-WebRequest -Uri "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" -OutFile temp\agent1\subdomain_wordlist.txt`

## temp/agent1/subdomains-top1million-110000.txt (count=1)
- task/task5/wordlist-download.txt#L28: `temp/agent1/subdomains-top1million-110000.txt \`

## temp/agent1/commonspeak_subdomains.txt (count=1)
- task/task5/wordlist-download.txt#L29: `temp/agent1/commonspeak_subdomains.txt 2>/dev/null \`

## temp/agent1/ax_ (count=1)
- task/task6/alterx.txt#L33: `split -l 50000 temp/agent1/_alterx_seed.txt temp/agent1/ax_`

## temp/agent1/ax_* (count=1)
- task/task6/alterx.txt#L35: `for f in temp/agent1/ax_*; do`

## temp/agent1/cand_ (count=1)
- task/task7/puredns-resolve.txt#L90: `split -l 200000 temp/agent1/candidates_all.txt temp/agent1/cand_`

## temp/agent1/cand_* (count=1)
- task/task7/puredns-resolve.txt#L92: `for f in temp/agent1/cand_*; do`

## temp/agent1/httpx_urls_out.txt (count=1)
- task/task8/httpx.txt#L28: `# httpx -l temp/agent1/url_list.txt -silent -timeout 9 -retries 1 -threads 50 -o temp/agent1/httpx_urls_out.txt`

## temp/agent1/httpx_chunks (count=1)
- task/task8/httpx.txt#L36: `$chunkDir = 'temp/agent1/httpx_chunks'`

## temp/agent1/knownfiles_and_apidocs.txt (count=1)
- task/task9/httpx-knownfiles-apidocs.txt#L9: `# - temp/agent1/knownfiles_and_apidocs.txt (small wordlist; if missing, this run-card will create a default)`

## temp/agent1/knownfiles_targets_urls.txt (count=1)
- task/task9/httpx-knownfiles-apidocs.txt#L12: `# - temp/agent1/knownfiles_targets_urls.txt`

## temp/agent1/knownfiles_hits_raw.txt (count=1)
- task/task9/httpx-knownfiles-apidocs.txt#L13: `# - temp/agent1/knownfiles_hits_raw.txt`

## temp/agent1/knownfiles_hits.txt (count=1)
- task/task9/httpx-knownfiles-apidocs.txt#L14: `# - temp/agent1/knownfiles_hits.txt`

## temp\\agent1\\logs\\httpx_knownfiles_$ts.log (count=1)
- task/task9/httpx-knownfiles-apidocs.txt#L74: `#   $log = "temp\\agent1\\logs\\httpx_knownfiles_$ts.log"`

## temp\agent1\chunks_knownfiles (count=1)
- task/task9/httpx-knownfiles-apidocs.txt#L81: `#   $chunkDir = 'temp\agent1\chunks_knownfiles'`

## temp\\agent1\\_knownfiles_task9.txt (count=1)
- task/task9/httpx-knownfiles-apidocs.txt#L121: `#   $knownTmp = 'temp\\agent1\\_knownfiles_task9.txt'`

## temp\\agent1\\_api_docs_urls_task9.txt (count=1)
- task/task9/httpx-knownfiles-apidocs.txt#L132: `#   $apiTmp = 'temp\\agent1\\_api_docs_urls_task9.txt'`

## temp/agent1/<token> (count=1)
- tools/scan_temp_agent1_refs.py#L25: `# Match temp/agent1/<token> where token stops at whitespace or typical delimiters.`

