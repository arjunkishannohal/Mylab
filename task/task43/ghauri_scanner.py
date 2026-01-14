#!/usr/bin/env python3
"""
Task 43: Ghauri SQL Injection Triage - AI Brain
================================================

INTELLIGENT SQLi scanner that:
1. Collects targets from ALL 42 previous tasks
2. Adapts to WAF detection (Task 32)
3. Adapts to database type (Task 35 Nuclei)
4. Fast triage to find vulnerable URLs
5. Generates prioritized list for SQLMap (Task 44)

Author: Jules AI Agent
Mode: AGGRESSIVE - Fast triage for SQLi discovery
"""

import os
import sys
import json
import asyncio
import subprocess
import re
import hashlib
import logging
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import shutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class SQLiTarget:
    """A URL target for SQLi testing."""
    url: str
    host: str
    params: List[str]
    source: str  # Where this URL came from
    priority: int = 0
    waf_type: Optional[str] = None
    db_type: Optional[str] = None


@dataclass
class SQLiResult:
    """Result of SQLi scan on a single URL."""
    url: str
    status: str  # vulnerable, possible, clean, error
    technique: Optional[str] = None
    db_type: Optional[str] = None
    payload: Optional[str] = None
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    error: Optional[str] = None
    scan_time: float = 0.0


# =============================================================================
# TARGET COLLECTOR - GATHERS FROM ALL PREVIOUS TASKS
# =============================================================================

class SQLiTargetCollector:
    """
    Collects ALL potential SQLi targets from previous 42 tasks.
    NO HARDCODING - dynamically discovers available inputs.
    """
    
    # Input sources by priority (higher = more likely to have SQLi params)
    INPUT_SOURCES = {
        # Priority 1: ZAP's Phase 4 handoff (specifically for injection testing)
        'zap_injection': {
            'priority': 100,
            'files': [
                'outputs/zap/injection_candidates.txt',
                'outputs/zap/sqli_targets.txt',
            ]
        },
        # Priority 2: Dynamic URLs with parameters
        'dynamic_urls': {
            'priority': 90,
            'files': [
                'outputs/queue_dynamic_endpoints_urls.txt',
            ]
        },
        # Priority 3: Hidden parameters from Arjun
        'hidden_params': {
            'priority': 85,
            'files': [
                'outputs/arjun_found_params.txt',
                'outputs/queue_hidden_params_arjun.txt',
            ]
        },
        # Priority 4: API endpoints (often have injectable params)
        'api_endpoints': {
            'priority': 80,
            'files': [
                'outputs/queue_api_endpoints_kiterunner.txt',
                'outputs/api_endpoints_live.txt',
                'outputs/api_endpoints_from_openapi.txt',
            ]
        },
        # Priority 5: HAR-extracted requests
        'har_requests': {
            'priority': 75,
            'files': [
                'outputs/har/common_data.txt',
            ]
        },
        # Priority 6: Access control testing data
        'access_control': {
            'priority': 70,
            'files': [
                'outputs/access_control/requests_with_params.json',
            ]
        },
        # Priority 7: URL corpus (broad coverage)
        'url_corpus': {
            'priority': 50,
            'files': [
                'outputs/url_corpus_all_in_scope.txt',
                'outputs/katana_urls_in_scope.txt',
                'outputs/gau_urls_in_scope.txt',
            ]
        },
        # Priority 8: JS-extracted endpoints
        'js_endpoints': {
            'priority': 45,
            'files': [
                'outputs/js_endpoints_from_js.txt',
                'outputs/js_endpoints_live.txt',
            ]
        },
    }
    
    # Parameter patterns that indicate SQLi potential
    HIGH_VALUE_PARAMS = [
        'id', 'uid', 'user_id', 'userid', 'account', 'account_id',
        'order', 'order_id', 'product', 'product_id', 'item', 'item_id',
        'category', 'cat', 'cat_id', 'page', 'page_id',
        'search', 'query', 'q', 'filter', 'sort', 'sortby',
        'limit', 'offset', 'start', 'count', 'num',
        'name', 'username', 'email', 'login', 'user',
        'file', 'path', 'dir', 'doc', 'document',
        'action', 'type', 'mode', 'view', 'show',
        'ref', 'reference', 'key', 'token',
    ]
    
    def __init__(self, workspace_path: str):
        self.workspace = Path(workspace_path)
        self.targets: List[SQLiTarget] = []
        self.seen_urls: Set[str] = set()
        
    def collect_all(self) -> List[SQLiTarget]:
        """
        Collect targets from ALL available sources.
        Returns deduplicated, prioritized list.
        """
        logger.info("=" * 60)
        logger.info("COLLECTING SQLi TARGETS FROM ALL SOURCES")
        logger.info("=" * 60)
        
        total_raw = 0
        
        for source_name, config in self.INPUT_SOURCES.items():
            base_priority = config['priority']
            
            for file_path in config['files']:
                full_path = self.workspace / file_path
                
                if full_path.exists():
                    urls = self._read_file(full_path, source_name)
                    count = 0
                    
                    for url in urls:
                        if self._is_valid_sqli_target(url):
                            target = self._create_target(url, source_name, base_priority)
                            if target and target.url not in self.seen_urls:
                                self.targets.append(target)
                                self.seen_urls.add(target.url)
                                count += 1
                    
                    if count > 0:
                        logger.info(f"  [{source_name}] {count} targets from {file_path}")
                        total_raw += count
        
        # Also check for JSON files with request data
        self._collect_from_json_sources()
        
        # Sort by priority
        self.targets.sort(key=lambda t: t.priority, reverse=True)
        
        logger.info(f"\nTOTAL: {len(self.targets)} unique SQLi targets collected")
        logger.info("=" * 60)
        
        return self.targets
    
    def _read_file(self, path: Path, source: str) -> List[str]:
        """Read URLs from file (handles different formats)."""
        urls = []
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Handle different formats
                    if line.startswith('http'):
                        urls.append(line)
                    elif '://' in line:
                        urls.append(line)
                    # HAR/common_data format might have "METHOD URL"
                    elif ' ' in line:
                        parts = line.split()
                        for part in parts:
                            if part.startswith('http'):
                                urls.append(part)
        except Exception as e:
            logger.warning(f"Error reading {path}: {e}")
        
        return urls
    
    def _collect_from_json_sources(self):
        """Collect from JSON files (HAR data, access control data)."""
        # HAR user data files
        har_dir = self.workspace / 'outputs' / 'har'
        if har_dir.exists():
            for json_file in har_dir.glob('*.json'):
                try:
                    with open(json_file, 'r') as f:
                        data = json.load(f)
                    
                    # Extract URLs from HAR-style data
                    if isinstance(data, dict):
                        self._extract_urls_from_dict(data, 'har_json', 75)
                    elif isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict):
                                self._extract_urls_from_dict(item, 'har_json', 75)
                except:
                    pass
        
        # Access control data
        ac_file = self.workspace / 'outputs' / 'access_control' / 'requests_with_params.json'
        if ac_file.exists():
            try:
                with open(ac_file, 'r') as f:
                    data = json.load(f)
                
                for req in data if isinstance(data, list) else []:
                    url = req.get('url', req.get('full_url', ''))
                    if url and self._is_valid_sqli_target(url):
                        target = self._create_target(url, 'access_control', 80)
                        if target and target.url not in self.seen_urls:
                            self.targets.append(target)
                            self.seen_urls.add(target.url)
            except:
                pass
    
    def _extract_urls_from_dict(self, data: dict, source: str, priority: int):
        """Recursively extract URLs from dict."""
        for key, value in data.items():
            if isinstance(value, str) and value.startswith('http'):
                if self._is_valid_sqli_target(value):
                    target = self._create_target(value, source, priority)
                    if target and target.url not in self.seen_urls:
                        self.targets.append(target)
                        self.seen_urls.add(target.url)
            elif isinstance(value, dict):
                self._extract_urls_from_dict(value, source, priority)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item.startswith('http'):
                        if self._is_valid_sqli_target(item):
                            target = self._create_target(item, source, priority)
                            if target and target.url not in self.seen_urls:
                                self.targets.append(target)
                                self.seen_urls.add(target.url)
                    elif isinstance(item, dict):
                        self._extract_urls_from_dict(item, source, priority)
    
    def _is_valid_sqli_target(self, url: str) -> bool:
        """Check if URL is a valid SQLi target (has parameters)."""
        if not url or not url.startswith('http'):
            return False
        
        # Must have query parameters OR path parameters
        parsed = urlparse(url)
        
        # Query params: ?id=1&name=test
        if parsed.query and '=' in parsed.query:
            return True
        
        # Path params: /user/123/profile
        if re.search(r'/\d+/', parsed.path):
            return True
        
        # UUID path params: /doc/550e8400-e29b-41d4-a716-446655440000
        if re.search(r'/[a-f0-9-]{36}/', parsed.path.lower()):
            return True
        
        # API endpoints often have injectable params even without visible ?
        if any(x in parsed.path.lower() for x in ['/api/', '/v1/', '/v2/', '/graphql']):
            return True
        
        return False
    
    def _create_target(self, url: str, source: str, base_priority: int) -> Optional[SQLiTarget]:
        """Create SQLiTarget with priority scoring."""
        try:
            parsed = urlparse(url)
            host = parsed.netloc
            
            # Extract parameter names
            params = []
            if parsed.query:
                query_params = parse_qs(parsed.query)
                params = list(query_params.keys())
            
            # Calculate priority
            priority = base_priority
            url_lower = url.lower()
            
            # Boost for high-value parameters
            for param in params:
                if param.lower() in self.HIGH_VALUE_PARAMS:
                    priority += 15
            
            # Boost for sensitive endpoints
            if any(x in url_lower for x in ['admin', 'manage', 'dashboard', 'internal']):
                priority += 20
            if any(x in url_lower for x in ['login', 'auth', 'session', 'token']):
                priority += 15
            if any(x in url_lower for x in ['/api/', '/v1/', '/v2/']):
                priority += 10
            
            # Boost for ID-like params in path
            if re.search(r'/\d+/', parsed.path):
                priority += 10
            
            return SQLiTarget(
                url=url,
                host=host,
                params=params,
                source=source,
                priority=priority
            )
        except:
            return None


# =============================================================================
# INTELLIGENCE LOADERS
# =============================================================================

class WAFIntelligence:
    """Load WAF detection results from Task 32."""
    
    TAMPER_SCRIPTS = {
        'cloudflare': ['between', 'randomcase', 'space2comment', 'charencode'],
        'akamai': ['charencode', 'chardoubleencode', 'space2plus', 'between'],
        'aws': ['apostrophemask', 'base64encode', 'between', 'randomcase'],
        'imperva': ['modsecurityversioned', 'space2morehash', 'between'],
        'incapsula': ['modsecurityversioned', 'space2morehash'],
        'f5': ['percentage', 'charencode', 'randomcomments', 'space2mssqlblank'],
        'modsecurity': ['modsecurityzeroversioned', 'space2mysqldash', 'between'],
        'fortinet': ['charencode', 'space2comment', 'randomcase'],
        'barracuda': ['apostrophemask', 'percentage', 'charencode'],
        'default': ['between', 'randomcase', 'space2comment'],
    }
    
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.host_waf: Dict[str, str] = {}
        self._load_waf_results()
    
    def _load_waf_results(self):
        """Load WAF results from Task 32."""
        waf_files = [
            self.workspace / 'outputs' / 'waf' / 'waf_results.json',
            self.workspace / 'temp' / 'task32' / 'waf_findings.json',
            self.workspace / 'temp' / 'agent1' / 'waf_results.txt',
        ]
        
        for waf_file in waf_files:
            if waf_file.exists():
                try:
                    if waf_file.suffix == '.json':
                        with open(waf_file, 'r') as f:
                            data = json.load(f)
                        
                        if isinstance(data, list):
                            for entry in data:
                                url = entry.get('url', entry.get('host', ''))
                                waf = entry.get('waf', entry.get('detected', 'none'))
                                if url and waf and waf.lower() != 'none':
                                    host = urlparse(url).netloc if '://' in url else url
                                    self.host_waf[host] = waf.lower()
                        elif isinstance(data, dict):
                            for host, waf in data.items():
                                if waf and str(waf).lower() != 'none':
                                    self.host_waf[host] = str(waf).lower()
                    else:
                        # Text format: "host waf_name" or "URL: x, WAF: y"
                        with open(waf_file, 'r') as f:
                            for line in f:
                                if 'cloudflare' in line.lower():
                                    self.host_waf[line.split()[0]] = 'cloudflare'
                                # Add more patterns as needed
                except Exception as e:
                    logger.warning(f"Error loading WAF data from {waf_file}: {e}")
        
        if self.host_waf:
            logger.info(f"[WAF] Loaded WAF info for {len(self.host_waf)} hosts")
    
    def get_waf_for_host(self, host: str) -> Optional[str]:
        """Get WAF type for host."""
        return self.host_waf.get(host)
    
    def get_tamper_scripts(self, host: str) -> List[str]:
        """Get recommended tamper scripts for host."""
        waf = self.get_waf_for_host(host)
        if waf:
            for waf_name, tampers in self.TAMPER_SCRIPTS.items():
                if waf_name in waf:
                    return tampers
        return self.TAMPER_SCRIPTS['default']


class DatabaseIntelligence:
    """Load database type detection from Nuclei (Task 35)."""
    
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.host_db: Dict[str, str] = {}
        self._load_db_info()
    
    def _load_db_info(self):
        """Load database detection from Nuclei brain."""
        brain_files = [
            self.workspace / 'outputs' / 'nuclei' / 'brain_knowledge.json',
            self.workspace / 'outputs' / 'nuclei' / 'tech_results.json',
        ]
        
        for brain_file in brain_files:
            if brain_file.exists():
                try:
                    with open(brain_file, 'r') as f:
                        data = json.load(f)
                    
                    tech_to_hosts = data.get('tech_to_hosts', {})
                    
                    for tech, hosts in tech_to_hosts.items():
                        tech_lower = tech.lower()
                        db_type = None
                        
                        if 'mysql' in tech_lower or 'mariadb' in tech_lower:
                            db_type = 'mysql'
                        elif 'postgres' in tech_lower or 'pgsql' in tech_lower:
                            db_type = 'postgresql'
                        elif 'mssql' in tech_lower or 'sql server' in tech_lower:
                            db_type = 'mssql'
                        elif 'oracle' in tech_lower:
                            db_type = 'oracle'
                        elif 'sqlite' in tech_lower:
                            db_type = 'sqlite'
                        elif 'mongodb' in tech_lower:
                            db_type = 'mongodb'  # For NoSQLMap
                        
                        if db_type:
                            for host in hosts:
                                if host not in self.host_db:
                                    self.host_db[host] = db_type
                except Exception as e:
                    logger.warning(f"Error loading DB info from {brain_file}: {e}")
        
        if self.host_db:
            logger.info(f"[DB] Loaded DB type for {len(self.host_db)} hosts")
    
    def get_db_for_host(self, host: str) -> str:
        """Get database type for host (default: mysql)."""
        return self.host_db.get(host, 'mysql')


# =============================================================================
# GHAURI SCANNER
# =============================================================================

class GhauriScanner:
    """
    Ghauri SQL injection scanner with AI brain.
    """
    
    BATCH_TIME_LIMIT = 540  # 9 minutes
    URL_TIMEOUT = 90  # 90 seconds per URL
    
    def __init__(self, workspace: Path, output_dir: Path, temp_dir: Path):
        self.workspace = workspace
        self.output_dir = output_dir
        self.temp_dir = temp_dir
        
        # Create directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        (self.workspace / 'outputs' / 'vulnerabilities').mkdir(parents=True, exist_ok=True)
        
        # Load intelligence
        self.waf_intel = WAFIntelligence(workspace)
        self.db_intel = DatabaseIntelligence(workspace)
        
        # Results
        self.results: Dict[str, List[SQLiResult]] = {
            'vulnerable': [],
            'possible': [],
            'clean': [],
            'error': [],
        }
        
        # Checkpoint
        self.checkpoint_file = self.temp_dir / 'checkpoint.json'
        
    def scan_targets(self, targets: List[SQLiTarget], resume: bool = False):
        """Scan all targets with batching and resume."""
        logger.info("=" * 60)
        logger.info("STARTING GHAURI SQLi SCAN")
        logger.info("=" * 60)
        
        # Load checkpoint if resuming
        start_idx = 0
        if resume:
            checkpoint = self._load_checkpoint()
            start_idx = checkpoint.get('last_completed', 0)
            self.results = checkpoint.get('results', self.results)
            logger.info(f"[RESUME] Starting from index {start_idx}")
        
        total = len(targets)
        batch_start = time.time()
        
        for i, target in enumerate(targets[start_idx:], start=start_idx):
            # Check time limit
            elapsed = time.time() - batch_start
            if elapsed > self.BATCH_TIME_LIMIT:
                logger.info(f"[BATCH] Time limit ({self.BATCH_TIME_LIMIT}s) reached at {i}/{total}")
                self._save_checkpoint(i)
                self._save_results()
                return
            
            # Enrich target with intelligence
            target.waf_type = self.waf_intel.get_waf_for_host(target.host)
            target.db_type = self.db_intel.get_db_for_host(target.host)
            
            # Scan
            logger.info(f"[{i+1}/{total}] Scanning: {target.url[:80]}...")
            result = self._scan_single(target)
            
            # Categorize
            self.results[result.status].append(result)
            
            if result.status == 'vulnerable':
                logger.info(f"  [VULN!] SQLi confirmed: {result.technique}")
                self._write_vuln_report(result)
            elif result.status == 'possible':
                logger.info(f"  [POSSIBLE] May be vulnerable: {result.error or 'heuristic'}")
            
            # Periodic checkpoint
            if (i + 1) % 10 == 0:
                self._save_checkpoint(i + 1)
                logger.info(f"[PROGRESS] {i+1}/{total} - V:{len(self.results['vulnerable'])} P:{len(self.results['possible'])}")
        
        # Final save
        self._save_checkpoint(total)
        self._save_results()
        self._generate_sqlmap_targets()
        
        logger.info("=" * 60)
        logger.info(f"SCAN COMPLETE: {total} URLs tested")
        logger.info(f"  Vulnerable: {len(self.results['vulnerable'])}")
        logger.info(f"  Possible:   {len(self.results['possible'])}")
        logger.info(f"  Clean:      {len(self.results['clean'])}")
        logger.info(f"  Errors:     {len(self.results['error'])}")
        logger.info("=" * 60)
    
    def _scan_single(self, target: SQLiTarget) -> SQLiResult:
        """Scan single URL with Ghauri."""
        import time
        start_time = time.time()
        
        result = SQLiResult(
            url=target.url,
            status='clean',
        )
        
        # Build command
        cmd = ['ghauri', '-u', target.url, '--batch']
        
        # Add level/risk based on priority
        if target.priority > 80:
            cmd.extend(['--level', '3', '--risk', '3'])
        else:
            cmd.extend(['--level', '2', '--risk', '2'])
        
        # Add WAF bypass if needed
        if target.waf_type:
            tampers = self.waf_intel.get_tamper_scripts(target.host)
            cmd.extend(['--tamper', ','.join(tampers[:3])])  # Max 3 tampers
        
        # Timeout
        cmd.extend(['--timeout', '30'])
        
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.URL_TIMEOUT,
                cwd=str(self.workspace)
            )
            
            output = proc.stdout + proc.stderr
            
            # Parse Ghauri output
            if self._is_vulnerable(output):
                result.status = 'vulnerable'
                result.technique = self._extract_technique(output)
                result.db_type = self._extract_db_type(output) or target.db_type
                result.payload = self._extract_payload(output)
                result.parameter = self._extract_parameter(output)
                result.evidence = output[:2000]  # First 2000 chars
            elif self._is_possible(output):
                result.status = 'possible'
                result.evidence = output[:1000]
            
        except subprocess.TimeoutExpired:
            result.status = 'possible'  # Timeout often indicates SQLi
            result.error = 'timeout'
        except FileNotFoundError:
            result.status = 'error'
            result.error = 'ghauri not installed'
            logger.error("Ghauri not found! Install with: pip install ghauri")
        except Exception as e:
            result.status = 'error'
            result.error = str(e)
        
        result.scan_time = time.time() - start_time
        return result
    
    def _is_vulnerable(self, output: str) -> bool:
        """Check if output indicates confirmed SQLi."""
        vuln_indicators = [
            'is vulnerable',
            'parameter is vulnerable',
            'injectable',
            'sql injection',
            'sqli confirmed',
            'payload:',
            'type: boolean-based',
            'type: error-based',
            'type: time-based',
            'type: union-based',
            'type: stacked',
        ]
        output_lower = output.lower()
        return any(ind in output_lower for ind in vuln_indicators)
    
    def _is_possible(self, output: str) -> bool:
        """Check if output indicates possible SQLi."""
        possible_indicators = [
            'heuristic',
            'might be',
            'potentially',
            'detected',
            'error in',
            'sql syntax',
            'unterminated',
            'you have an error',
        ]
        output_lower = output.lower()
        return any(ind in output_lower for ind in possible_indicators)
    
    def _extract_technique(self, output: str) -> Optional[str]:
        """Extract SQLi technique from output."""
        techniques = {
            'boolean': 'Boolean-based blind',
            'error': 'Error-based',
            'time': 'Time-based blind',
            'union': 'Union-based',
            'stacked': 'Stacked queries',
        }
        output_lower = output.lower()
        for key, name in techniques.items():
            if key in output_lower:
                return name
        return 'Unknown'
    
    def _extract_db_type(self, output: str) -> Optional[str]:
        """Extract database type from output."""
        db_patterns = {
            'mysql': r'mysql|mariadb',
            'postgresql': r'postgresql|postgres|pgsql',
            'mssql': r'mssql|microsoft sql|sql server',
            'oracle': r'oracle',
            'sqlite': r'sqlite',
        }
        output_lower = output.lower()
        for db, pattern in db_patterns.items():
            if re.search(pattern, output_lower):
                return db
        return None
    
    def _extract_payload(self, output: str) -> Optional[str]:
        """Extract successful payload from output."""
        # Look for payload patterns
        payload_match = re.search(r'payload[:\s]+["\']?([^"\']+)["\']?', output, re.IGNORECASE)
        if payload_match:
            return payload_match.group(1)[:200]
        return None
    
    def _extract_parameter(self, output: str) -> Optional[str]:
        """Extract vulnerable parameter from output."""
        param_match = re.search(r'parameter[:\s]+["\']?(\w+)["\']?', output, re.IGNORECASE)
        if param_match:
            return param_match.group(1)
        return None
    
    def _write_vuln_report(self, result: SQLiResult):
        """Write vulnerability report for confirmed SQLi."""
        vuln_dir = self.workspace / 'outputs' / 'vulnerabilities'
        vuln_id = hashlib.md5(result.url.encode()).hexdigest()[:8]
        report_name = f"SQLI-GHAURI-{vuln_id}-CRITICAL.md"
        report_path = vuln_dir / report_name
        
        parsed = urlparse(result.url)
        
        report = f"""# SQL Injection Vulnerability: SQLI-GHAURI-{vuln_id}

## Summary
| Field | Value |
|-------|-------|
| **ID** | SQLI-GHAURI-{vuln_id} |
| **URL** | {result.url} |
| **Host** | {parsed.netloc} |
| **Parameter** | {result.parameter or 'See evidence'} |
| **Technique** | {result.technique} |
| **Database** | {result.db_type or 'Unknown'} |
| **Severity** | CRITICAL |
| **Discovered** | {datetime.now().isoformat()} |
| **Scanner** | Ghauri (Task 43) |

## Technical Details

### Vulnerable URL
```
{result.url}
```

### Injection Technique
**{result.technique}**

### Payload
```
{result.payload or 'See evidence below'}
```

## Evidence (Ghauri Output)
```
{result.evidence or 'No detailed evidence captured'}
```

## Impact

SQL Injection allows an attacker to:
- **Data Theft**: Extract entire database contents (users, passwords, PII)
- **Authentication Bypass**: Login as any user including admin
- **Data Manipulation**: Modify or delete records
- **Privilege Escalation**: If stacked queries work, potentially execute OS commands
- **Full Database Compromise**: Complete control over backend database

## Recommendations

1. **Immediate**: Use parameterized queries / prepared statements
2. **Immediate**: Implement input validation and sanitization
3. **Short-term**: Apply WAF rules for SQLi protection
4. **Long-term**: Conduct secure code review of all database interactions

## Next Steps

1. Run SQLMap (Task 44) for deep exploitation:
```bash
sqlmap -u "{result.url}" --batch --dbs
```

2. Attempt data extraction:
```bash
sqlmap -u "{result.url}" --batch --dump -D database_name -T users
```

## Proof of Concept
```bash
# Reproduce with:
ghauri -u "{result.url}" --batch --level=3 --risk=3
```
"""
        
        with open(report_path, 'w') as f:
            f.write(report)
        
        logger.info(f"  [REPORT] {report_name}")
    
    def _load_checkpoint(self) -> Dict:
        """Load checkpoint for resume."""
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
            'results': {
                'vulnerable': [r.__dict__ for r in self.results['vulnerable']],
                'possible': [r.__dict__ for r in self.results['possible']],
                'clean': [r.url if isinstance(r, SQLiResult) else r for r in self.results['clean']],
                'error': [r.__dict__ for r in self.results['error']],
            }
        }
        with open(self.checkpoint_file, 'w') as f:
            json.dump(checkpoint, f, indent=2, default=str)
    
    def _save_results(self):
        """Save all results to output files."""
        # Vulnerable URLs
        vuln_file = self.output_dir / 'ghauri_vulnerable.txt'
        with open(vuln_file, 'w') as f:
            for r in self.results['vulnerable']:
                f.write(f"{r.url}\n")
        
        # Possible URLs
        poss_file = self.output_dir / 'ghauri_possible.txt'
        with open(poss_file, 'w') as f:
            for r in self.results['possible']:
                f.write(f"{r.url}\n")
        
        # Clean URLs
        clean_file = self.output_dir / 'ghauri_clean.txt'
        with open(clean_file, 'w') as f:
            for r in self.results['clean']:
                url = r.url if isinstance(r, SQLiResult) else r
                f.write(f"{url}\n")
        
        # Full JSON results
        full_results = {
            'scan_time': datetime.now().isoformat(),
            'total_scanned': sum(len(v) for v in self.results.values()),
            'vulnerable': [r.__dict__ for r in self.results['vulnerable']],
            'possible': [r.__dict__ for r in self.results['possible']],
            'error_count': len(self.results['error']),
        }
        
        results_file = self.output_dir / 'ghauri_full_results.json'
        with open(results_file, 'w') as f:
            json.dump(full_results, f, indent=2, default=str)
        
        logger.info(f"[SAVE] Results saved to {self.output_dir}")
    
    def _generate_sqlmap_targets(self):
        """Generate prioritized target list for SQLMap (Task 44)."""
        targets = []
        
        # Priority 1: Confirmed vulnerable
        for r in self.results['vulnerable']:
            targets.append({
                'url': r.url,
                'priority': 1,
                'reason': f'Confirmed SQLi: {r.technique}',
                'db_type': r.db_type,
                'technique': r.technique,
            })
        
        # Priority 2: Possible vulnerable
        for r in self.results['possible']:
            targets.append({
                'url': r.url,
                'priority': 2,
                'reason': r.error or 'Heuristic detection',
            })
        
        # Save text file
        txt_file = self.output_dir / 'sqlmap_priority_targets.txt'
        with open(txt_file, 'w') as f:
            for t in targets:
                f.write(f"{t['url']}\n")
        
        # Save JSON file with metadata
        json_file = self.output_dir / 'sqlmap_priority_targets.json'
        with open(json_file, 'w') as f:
            json.dump(targets, f, indent=2)
        
        logger.info(f"[SQLMAP] Generated {len(targets)} targets for Task 44")


# =============================================================================
# MAIN
# =============================================================================

def main():
    import time
    
    parser = argparse.ArgumentParser(
        description="Task 43: Ghauri SQL Injection Triage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full scan from all sources
  python ghauri_scanner.py --workspace d:\\wallet\\Mylab

  # Resume interrupted scan
  python ghauri_scanner.py --workspace d:\\wallet\\Mylab --resume

  # Custom output location
  python ghauri_scanner.py --workspace d:\\wallet\\Mylab --output outputs/sqli
        """
    )
    
    parser.add_argument('--workspace', required=True,
                       help='Path to workspace root')
    parser.add_argument('--output', default='outputs/sqli',
                       help='Output directory (relative to workspace)')
    parser.add_argument('--temp', default='temp/task43',
                       help='Temp directory (relative to workspace)')
    parser.add_argument('--resume', action='store_true',
                       help='Resume from checkpoint')
    parser.add_argument('--max-targets', type=int, default=0,
                       help='Max targets to scan (0 = all)')
    
    args = parser.parse_args()
    
    workspace = Path(args.workspace)
    output_dir = workspace / args.output
    temp_dir = workspace / args.temp
    
    # Step 1: Collect targets
    collector = SQLiTargetCollector(str(workspace))
    targets = collector.collect_all()
    
    if not targets:
        logger.error("No SQLi targets found! Run previous tasks first.")
        sys.exit(1)
    
    # Limit targets if specified
    if args.max_targets > 0:
        targets = targets[:args.max_targets]
        logger.info(f"Limited to {args.max_targets} targets")
    
    # Step 2: Scan
    scanner = GhauriScanner(workspace, output_dir, temp_dir)
    scanner.scan_targets(targets, resume=args.resume)


if __name__ == "__main__":
    main()
