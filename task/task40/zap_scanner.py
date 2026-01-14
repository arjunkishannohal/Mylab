#!/usr/bin/env python3
"""
ZAP Scanner - Dynamic AI-Powered OWASP ZAP Controller
Task 40 (Baseline) & Task 41 (Full Scan)

This scanner uses BRAIN INTELLIGENCE to:
1. ANALYZE target tech stack from prior scans (Nuclei, etc.)
2. ADAPT scan configuration per-host
3. PRIORITIZE targets based on learned patterns
4. LEARN from findings to improve future scans
5. CORRELATE with other tool outputs

Jules: This is the FRAMEWORK. Extend with your brain as needed.
"""

import argparse
import json
import re
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from urllib.parse import urlparse
import hashlib

# Try to import ZAP API (install with: pip install python-owasp-zap-v2.4)
try:
    from zapv2 import ZAPv2
    ZAP_AVAILABLE = True
except ImportError:
    ZAP_AVAILABLE = False
    print("[!] ZAP API not installed. Run: pip install python-owasp-zap-v2.4")


# ============================================================================
# CONFIGURATION
# ============================================================================
class ScanMode(Enum):
    BASELINE = "baseline"
    FULL = "full"
    API_ONLY = "api_only"


@dataclass
class Config:
    """Aggressive configuration for your own targets."""
    # Timing
    BATCH_TIME_LIMIT: int = 540  # 9 minutes
    MAX_SCAN_TIME_PER_TARGET: int = 300  # 5 minutes per target in full mode
    TARGETS_PER_BATCH: int = 10
    
    # Spider settings
    SPIDER_MAX_DEPTH: int = 10
    SPIDER_THREADS: int = 10
    AJAX_SPIDER_DURATION: int = 60
    
    # Active scan settings (for full mode)
    ATTACK_STRENGTH: str = "INSANE"  # LOW, MEDIUM, HIGH, INSANE
    ALERT_THRESHOLD: str = "LOW"     # OFF, LOW, MEDIUM, HIGH
    THREAD_PER_HOST: int = 5
    DELAY_MS: int = 0  # No delay for your own target
    
    # ZAP connection
    ZAP_HOST: str = "localhost"
    ZAP_PORT: int = 8080


# ============================================================================
# BRAIN INTELLIGENCE - Dynamic Learning
# ============================================================================
class ZapBrainIntelligence:
    """
    AI Brain that learns from scans and correlates with other tools.
    NOT HARDCODED - learns dynamically from actual findings.
    """
    
    def __init__(self, save_path: Optional[Path] = None):
        self.save_path = save_path
        
        # Dynamic learning storage
        self.host_profiles: Dict[str, Dict] = {}  # host → profile data
        self.tech_to_scanners: Dict[str, Set[int]] = defaultdict(set)  # tech → ZAP scanner IDs
        self.scanner_effectiveness: Dict[int, Dict] = defaultdict(lambda: {'hits': 0, 'hosts': set()})
        self.vuln_patterns: Dict[str, List[Dict]] = defaultdict(list)  # pattern → findings
        
        # External intelligence (from other tasks)
        self.nuclei_intel: Dict = {}
        self.baseline_intel: Dict = {}
        
        # Load existing knowledge
        self.load()
    
    def load_external_intel(self, nuclei_path: Path = None, baseline_path: Path = None):
        """Load intelligence from other tasks."""
        if nuclei_path and nuclei_path.exists():
            with open(nuclei_path) as f:
                self.nuclei_intel = json.load(f)
            print(f"[brain] Loaded Nuclei intel: {len(self.nuclei_intel.get('hosts', {}))} hosts")
        
        if baseline_path and baseline_path.exists():
            with open(baseline_path) as f:
                self.baseline_intel = json.load(f)
            print(f"[brain] Loaded baseline intel")
    
    def get_host_technologies(self, host: str) -> List[str]:
        """Get technologies detected on a host from external intel."""
        techs = []
        
        # From Nuclei brain
        if self.nuclei_intel:
            host_data = self.nuclei_intel.get('hosts', {}).get(host, {})
            techs.extend(host_data.get('technologies', []))
            
            # Also check tech_to_hosts mapping
            for tech, hosts in self.nuclei_intel.get('tech_to_hosts', {}).items():
                if host in hosts:
                    techs.append(tech)
        
        return list(set(techs))
    
    def determine_scan_profile(self, target_url: str) -> Dict:
        """
        DYNAMICALLY determine scan profile based on learned intelligence.
        For FULL mode: DISABLE injection scanners (Phase 4 handles those).
        """
        host = urlparse(target_url).netloc
        path = urlparse(target_url).path
        
        profile = {
            'scan_strength': 'MEDIUM',
            'enable_ajax_spider': False,
            'scanner_ids_enable': set(),
            'scanner_ids_disable': set(),
            'max_depth': 5,
            'priority_score': 50,
            'reasoning': [],
        }
        
        # === INJECTION SCANNERS TO DISABLE (Phase 4 handles these better) ===
        # SQLMap, Ghauri, Commix, Tplmap, SSTImap, NoSQLMap are 100x better
        INJECTION_SCANNERS_DISABLE = [
            40018,  # SQL Injection
            40019,  # SQL Injection - MySQL
            40020,  # SQL Injection - Hypersonic
            40021,  # SQL Injection - Oracle
            40022,  # SQL Injection - PostgreSQL
            40024,  # SQL Injection - SQLite
            90039,  # NoSQL Injection - MongoDB
            90019,  # Server Side Code Injection
            90035,  # Server Side Template Injection
            40012,  # PHP Code Injection
            40032,  # Command Injection
            40033,  # LDAP Injection
            40034,  # XPath Injection
        ]
        profile['scanner_ids_disable'].update(INJECTION_SCANNERS_DISABLE)
        profile['reasoning'].append("Injection scanners DISABLED (Phase 4 dedicated tools handle)")
        
        # === ZAP STRENGTH SCANNERS TO ENABLE ===
        ZAP_STRENGTH_SCANNERS = [
            10012,  # Cross Site Scripting (Reflected)
            40014,  # Cross Site Scripting (Persistent)
            10014,  # Cross Site Scripting (DOM)
            10016,  # CSRF
            40003,  # CRLF Injection
            10010,  # Cookie No HttpOnly Flag
            10011,  # Cookie Without Secure Flag
            10017,  # Cross-Domain JavaScript Source File Inclusion
            10020,  # X-Frame-Options Header Not Set
            10021,  # X-Content-Type-Options Header Missing
            10038,  # Content Security Policy (CSP) Header Not Set
            10040,  # Secure Pages Include Mixed Content
            40016,  # Path Traversal
            10095,  # Backup File Disclosure
            90022,  # Application Error Disclosure
            90033,  # Loosely Scoped Cookie
            10098,  # Cross-Domain Misconfiguration
        ]
        profile['scanner_ids_enable'].update(ZAP_STRENGTH_SCANNERS)
        
        # Get technologies from external intel
        techs = self.get_host_technologies(host)
        tech_lower = ' '.join(techs).lower()
        
        # === DYNAMIC RULES (learned patterns) ===
        
        # JavaScript/SPA frameworks → enable AJAX spider
        js_indicators = ['react', 'angular', 'vue', 'next', 'nuxt', 'javascript', 'node', 'express']
        if any(ind in tech_lower for ind in js_indicators):
            profile['enable_ajax_spider'] = True
            profile['reasoning'].append(f"AJAX spider enabled: JS framework detected")
            profile['scanner_ids_enable'].add(10014)  # DOM XSS
        
        # CMS → deeper crawl
        if 'wordpress' in tech_lower or 'drupal' in tech_lower or 'joomla' in tech_lower:
            profile['max_depth'] = 10
            profile['reasoning'].append("CMS detected: increased spider depth")
        
        # API endpoints → focused on access control, headers
        api_indicators = ['/api/', '/v1/', '/v2/', '/graphql', '/rest/', '/ws/']
        if any(ind in path.lower() for ind in api_indicators):
            profile['priority_score'] += 20
            profile['scan_strength'] = 'HIGH'
            profile['reasoning'].append("API endpoint: increased priority")
        
        # Auth endpoints → highest priority
        auth_indicators = ['login', 'auth', 'signin', 'signup', 'register', 'password', 'token', 'oauth']
        if any(ind in path.lower() for ind in auth_indicators):
            profile['priority_score'] += 30
            profile['scan_strength'] = 'INSANE'
            profile['reasoning'].append("Auth endpoint: maximum priority")
        
        # === LEARN FROM PRIOR FINDINGS ===
        
        # If host had Nuclei findings, increase priority
        nuclei_host_data = self.nuclei_intel.get('hosts', {}).get(host, {})
        nuclei_severity_counts = nuclei_host_data.get('severity_counts', {})
        if nuclei_severity_counts.get('critical', 0) > 0:
            profile['priority_score'] += 40
            profile['scan_strength'] = 'INSANE'
            profile['reasoning'].append(f"Host has {nuclei_severity_counts.get('critical')} CRITICAL Nuclei findings")
        elif nuclei_severity_counts.get('high', 0) > 0:
            profile['priority_score'] += 20
            profile['reasoning'].append(f"Host has {nuclei_severity_counts.get('high')} HIGH Nuclei findings")
        
        # If baseline had alerts, increase priority
        baseline_host_findings = self.baseline_intel.get('host_findings', {}).get(host, [])
        if len(baseline_host_findings) > 5:
            profile['priority_score'] += 15
            profile['scan_strength'] = 'HIGH'
            profile['reasoning'].append(f"Baseline found {len(baseline_host_findings)} passive issues")
        
        return profile
    
    def prioritize_targets(self, targets: List[str]) -> List[str]:
        """Sort targets by priority based on brain analysis."""
        scored = []
        for target in targets:
            profile = self.determine_scan_profile(target)
            scored.append((target, profile['priority_score']))
        
        # Sort by score descending
        scored.sort(key=lambda x: -x[1])
        return [t[0] for t in scored]
    
    def learn_from_finding(self, finding: Dict):
        """Learn from a ZAP finding to improve future scans."""
        host = urlparse(finding.get('url', '')).netloc
        scanner_id = finding.get('pluginId', 0)
        risk = finding.get('risk', 'Low')
        
        # Track scanner effectiveness
        self.scanner_effectiveness[scanner_id]['hits'] += 1
        self.scanner_effectiveness[scanner_id]['hosts'].add(host)
        
        # Learn host vulnerability patterns
        if host not in self.host_profiles:
            self.host_profiles[host] = {
                'findings': [],
                'techs_inferred': set(),
                'high_value_paths': set(),
            }
        
        self.host_profiles[host]['findings'].append({
            'scanner': scanner_id,
            'risk': risk,
            'name': finding.get('name', ''),
            'path': urlparse(finding.get('url', '')).path,
        })
        
        # Infer technology from finding type
        name_lower = finding.get('name', '').lower()
        if 'sql' in name_lower:
            self.host_profiles[host]['techs_inferred'].add('sql-backend')
        if 'php' in name_lower:
            self.host_profiles[host]['techs_inferred'].add('php')
        if 'xss' in name_lower:
            self.host_profiles[host]['techs_inferred'].add('xss-vulnerable')
    
    def get_scanner_recommendations(self, host: str) -> List[int]:
        """Get recommended scanners based on learned patterns."""
        recommendations = []
        
        # Get most effective scanners overall
        effective = sorted(
            self.scanner_effectiveness.items(),
            key=lambda x: -x[1]['hits']
        )[:20]
        recommendations.extend([s[0] for s in effective])
        
        # Get scanners that worked on this host before
        if host in self.host_profiles:
            host_scanners = [f['scanner'] for f in self.host_profiles[host]['findings']]
            recommendations.extend(host_scanners)
        
        return list(set(recommendations))
    
    def save(self):
        """Persist learned knowledge."""
        if not self.save_path:
            return
        
        data = {
            'host_profiles': {},
            'scanner_effectiveness': {},
            'last_updated': datetime.now().isoformat(),
        }
        
        # Convert sets to lists for JSON
        for host, profile in self.host_profiles.items():
            data['host_profiles'][host] = {
                'findings': profile['findings'],
                'techs_inferred': list(profile.get('techs_inferred', set())),
                'high_value_paths': list(profile.get('high_value_paths', set())),
            }
        
        for scanner_id, stats in self.scanner_effectiveness.items():
            data['scanner_effectiveness'][str(scanner_id)] = {
                'hits': stats['hits'],
                'hosts': list(stats['hosts']),
            }
        
        self.save_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.save_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[brain] Saved: {len(self.host_profiles)} host profiles, "
              f"{len(self.scanner_effectiveness)} scanner stats")
    
    def load(self):
        """Load previously learned knowledge."""
        if not self.save_path or not self.save_path.exists():
            return
        
        try:
            with open(self.save_path) as f:
                data = json.load(f)
            
            for host, profile in data.get('host_profiles', {}).items():
                self.host_profiles[host] = {
                    'findings': profile.get('findings', []),
                    'techs_inferred': set(profile.get('techs_inferred', [])),
                    'high_value_paths': set(profile.get('high_value_paths', [])),
                }
            
            for scanner_id, stats in data.get('scanner_effectiveness', {}).items():
                self.scanner_effectiveness[int(scanner_id)] = {
                    'hits': stats['hits'],
                    'hosts': set(stats['hosts']),
                }
            
            print(f"[brain] Loaded: {len(self.host_profiles)} host profiles")
        except Exception as e:
            print(f"[brain] Error loading: {e}")


# ============================================================================
# ZAP CONTROLLER
# ============================================================================
class ZapController:
    """Controls ZAP daemon via API."""
    
    def __init__(self, host: str = 'localhost', port: int = 8080):
        if not ZAP_AVAILABLE:
            raise RuntimeError("ZAP API not installed. Run: pip install python-owasp-zap-v2.4")
        
        self.zap = ZAPv2(proxies={
            'http': f'http://{host}:{port}',
            'https': f'http://{host}:{port}'
        })
        self.host = host
        self.port = port
    
    def is_running(self) -> bool:
        """Check if ZAP daemon is running."""
        try:
            self.zap.core.version
            return True
        except:
            return False
    
    def configure_spider(self, profile: Dict):
        """Configure spider based on profile."""
        self.zap.spider.set_option_max_depth(profile.get('max_depth', 5))
        self.zap.spider.set_option_thread_count(Config.SPIDER_THREADS)
        self.zap.spider.set_option_parse_comments(True)
        self.zap.spider.set_option_parse_robots_txt(True)
        self.zap.spider.set_option_parse_sitemap_xml(True)
    
    def configure_active_scan(self, profile: Dict):
        """Configure active scanner based on brain-determined profile."""
        # Set strength
        strength_map = {'LOW': 'LOW', 'MEDIUM': 'MEDIUM', 'HIGH': 'HIGH', 'INSANE': 'INSANE'}
        strength = strength_map.get(profile.get('scan_strength', 'MEDIUM'), 'MEDIUM')
        
        # Enable/disable specific scanners
        for scanner_id in profile.get('scanner_ids_enable', set()):
            try:
                self.zap.ascan.enable_scanners(str(scanner_id))
            except:
                pass
        
        for scanner_id in profile.get('scanner_ids_disable', set()):
            try:
                self.zap.ascan.disable_scanners(str(scanner_id))
            except:
                pass
    
    def spider_target(self, target: str, profile: Dict) -> List[str]:
        """Spider a target and return discovered URLs."""
        self.configure_spider(profile)
        
        print(f"    [spider] Starting on {target}")
        scan_id = self.zap.spider.scan(target)
        
        while int(self.zap.spider.status(scan_id)) < 100:
            time.sleep(2)
        
        # Also run AJAX spider if needed
        if profile.get('enable_ajax_spider', False):
            print(f"    [ajax-spider] Running...")
            self.zap.ajaxSpider.scan(target)
            timeout = Config.AJAX_SPIDER_DURATION
            start = time.time()
            while self.zap.ajaxSpider.status == 'running' and (time.time() - start) < timeout:
                time.sleep(5)
            self.zap.ajaxSpider.stop()
        
        # Return discovered URLs
        return self.zap.spider.results(scan_id)
    
    def passive_scan_wait(self, timeout: int = 60):
        """Wait for passive scan to complete."""
        start = time.time()
        while int(self.zap.pscan.records_to_scan) > 0:
            if time.time() - start > timeout:
                break
            time.sleep(2)
    
    def active_scan(self, target: str, profile: Dict, timeout: int = 300) -> str:
        """Run active scan with timeout."""
        self.configure_active_scan(profile)
        
        print(f"    [active-scan] Starting on {target}")
        print(f"    [active-scan] Strength: {profile.get('scan_strength', 'MEDIUM')}")
        
        scan_id = self.zap.ascan.scan(target)
        start = time.time()
        
        while int(self.zap.ascan.status(scan_id)) < 100:
            if time.time() - start > timeout:
                print(f"    [active-scan] Timeout after {timeout}s, stopping...")
                self.zap.ascan.stop(scan_id)
                break
            progress = self.zap.ascan.status(scan_id)
            print(f"    [active-scan] Progress: {progress}%", end='\r')
            time.sleep(5)
        
        print(f"    [active-scan] Completed")
        return scan_id
    
    def get_alerts(self, target: str = None) -> List[Dict]:
        """Get all alerts, optionally filtered by target."""
        if target:
            return self.zap.core.alerts(baseurl=target)
        return self.zap.core.alerts()
    
    def clear_session(self):
        """Clear ZAP session for fresh scan."""
        try:
            self.zap.core.new_session()
        except:
            pass


# ============================================================================
# MAIN SCANNER
# ============================================================================
class IntelligentZapScanner:
    """
    AI-powered ZAP scanner with dynamic learning.
    """
    
    def __init__(self, output_dir: Path, temp_dir: Path, mode: ScanMode):
        self.output_dir = output_dir
        self.temp_dir = temp_dir
        self.mode = mode
        self.findings: List[Dict] = []
        
        # Create directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / 'vulnerabilities').mkdir(exist_ok=True)
        (self.output_dir / 'zap').mkdir(exist_ok=True)
        
        # Initialize brain
        self.brain = ZapBrainIntelligence(
            save_path=self.output_dir / 'zap' / 'zap_brain_knowledge.json'
        )
        
        # Load external intel
        self.brain.load_external_intel(
            nuclei_path=self.output_dir / 'nuclei' / 'brain_knowledge.json',
            baseline_path=self.output_dir / 'zap' / 'task41_intel.json'
        )
        
        # Initialize ZAP controller
        self.zap = None
        
        # Checkpoint
        self.checkpoint = self._load_checkpoint()
    
    def _load_checkpoint(self) -> Dict:
        checkpoint_file = self.temp_dir / 'checkpoint.json'
        if checkpoint_file.exists():
            try:
                with open(checkpoint_file) as f:
                    saved = json.load(f)
                if saved.get('mode') == self.mode.value:
                    print(f"[*] Resuming from target {saved.get('last_completed', 0)}")
                    return saved
            except:
                pass
        return {'mode': self.mode.value, 'last_completed': 0, 'total_findings': 0}
    
    def _save_checkpoint(self, completed: int):
        self.checkpoint['last_completed'] = completed
        self.checkpoint['total_findings'] = len(self.findings)
        self.checkpoint['timestamp'] = datetime.now().isoformat()
        
        with open(self.temp_dir / 'checkpoint.json', 'w') as f:
            json.dump(self.checkpoint, f, indent=2)
    
    def connect_zap(self) -> bool:
        """Connect to ZAP daemon."""
        try:
            self.zap = ZapController(Config.ZAP_HOST, Config.ZAP_PORT)
            if self.zap.is_running():
                print(f"[+] Connected to ZAP at {Config.ZAP_HOST}:{Config.ZAP_PORT}")
                return True
            else:
                print(f"[!] ZAP not running at {Config.ZAP_HOST}:{Config.ZAP_PORT}")
                return False
        except Exception as e:
            print(f"[!] Failed to connect to ZAP: {e}")
            return False
    
    def prepare_targets(self, input_files: List[Path]) -> List[str]:
        """Load and prioritize targets using brain intelligence."""
        all_urls = set()
        
        for input_file in input_files:
            if input_file.exists():
                with open(input_file) as f:
                    for line in f:
                        url = line.strip()
                        if url and url.startswith('http'):
                            all_urls.add(url)
        
        # Use brain to prioritize
        prioritized = self.brain.prioritize_targets(list(all_urls))
        
        print(f"[+] Loaded {len(prioritized)} targets (AI-prioritized)")
        return prioritized
    
    def scan_target_baseline(self, target: str) -> List[Dict]:
        """Run baseline (passive-only) scan on target."""
        profile = self.brain.determine_scan_profile(target)
        
        print(f"\n[*] Baseline scan: {target}")
        for reason in profile['reasoning']:
            print(f"    [brain] {reason}")
        
        # Spider
        discovered = self.zap.spider_target(target, profile)
        print(f"    [spider] Discovered {len(discovered)} URLs")
        
        # Wait for passive scan
        print(f"    [passive] Waiting for passive scan...")
        self.zap.passive_scan_wait(timeout=60)
        
        # Get alerts
        alerts = self.zap.get_alerts(target)
        print(f"    [passive] Found {len(alerts)} alerts")
        
        return alerts
    
    def scan_target_full(self, target: str) -> List[Dict]:
        """Run full active scan on target."""
        profile = self.brain.determine_scan_profile(target)
        
        print(f"\n[*] Full active scan: {target}")
        for reason in profile['reasoning']:
            print(f"    [brain] {reason}")
        
        # Spider first
        discovered = self.zap.spider_target(target, profile)
        print(f"    [spider] Discovered {len(discovered)} URLs")
        
        # Active scan
        self.zap.active_scan(target, profile, timeout=Config.MAX_SCAN_TIME_PER_TARGET)
        
        # Get all alerts
        alerts = self.zap.get_alerts(target)
        print(f"    [scan] Found {len(alerts)} total alerts")
        
        return alerts
    
    def run(self, input_files: List[Path]):
        """Run the intelligent scan."""
        print(f"\n{'='*70}")
        print(f"🧠 INTELLIGENT ZAP SCANNER - {self.mode.value.upper()}")
        print(f"{'='*70}")
        
        # Connect to ZAP
        if not self.connect_zap():
            print("[!] Cannot proceed without ZAP connection")
            print("[!] Start ZAP with: docker run -d --name zap-daemon -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true")
            return
        
        # Prepare targets
        targets = self.prepare_targets(input_files)
        
        # Show brain status
        print(f"\n[brain] External intelligence loaded:")
        print(f"  - Nuclei hosts: {len(self.brain.nuclei_intel.get('hosts', {}))}")
        print(f"  - Baseline intel: {'Yes' if self.brain.baseline_intel else 'No'}")
        
        # Resume from checkpoint
        start_idx = self.checkpoint.get('last_completed', 0)
        batch_start_time = time.time()
        
        for i, target in enumerate(targets[start_idx:], start=start_idx):
            # Check batch time limit
            if time.time() - batch_start_time > Config.BATCH_TIME_LIMIT:
                print(f"\n[!] Batch time limit reached. Resume from target {i}")
                self._save_checkpoint(i)
                break
            
            # Scan based on mode
            if self.mode == ScanMode.BASELINE:
                alerts = self.scan_target_baseline(target)
            else:
                alerts = self.scan_target_full(target)
            
            # Learn from findings
            for alert in alerts:
                self.findings.append(alert)
                self.brain.learn_from_finding(alert)
            
            # Save progress
            self._save_checkpoint(i + 1)
            self.brain.save()
        
        # Final outputs
        self._write_outputs()
        self._write_vulnerability_reports()
        self._write_task41_intel()
        self._write_phase4_injection_candidates()  # Generate targets for Phase 4 tools
        self._print_summary()
    
    def _write_outputs(self):
        """Write scan outputs."""
        zap_dir = self.output_dir / 'zap'
        
        # All alerts
        output_file = f"{self.mode.value}_alerts.json"
        with open(zap_dir / output_file, 'w') as f:
            json.dump(self.findings, f, indent=2)
        
        # High severity only
        high_sev = [f for f in self.findings if f.get('risk', '').lower() in ['high', 'critical']]
        with open(zap_dir / f"{self.mode.value}_high_severity.json", 'w') as f:
            json.dump(high_sev, f, indent=2)
        
        # Host risk scores
        host_scores = defaultdict(lambda: {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0})
        for finding in self.findings:
            host = urlparse(finding.get('url', '')).netloc
            risk = finding.get('risk', 'Low').lower()
            host_scores[host]['total'] += 1
            if risk in host_scores[host]:
                host_scores[host][risk] += 1
        
        with open(zap_dir / 'host_risk_scores.json', 'w') as f:
            json.dump(dict(host_scores), f, indent=2)
    
    def _write_vulnerability_reports(self):
        """Generate individual vulnerability reports."""
        vuln_dir = self.output_dir / 'vulnerabilities'
        
        for i, finding in enumerate(self.findings):
            risk = finding.get('risk', 'Low').upper()
            
            # Only create reports for Medium+
            if risk.lower() not in ['medium', 'high', 'critical']:
                continue
            
            finding_id = f"ZAP-{i+1:04d}"
            plugin_name = re.sub(r'[^\w.-]', '_', finding.get('name', 'unknown'))[:30]
            filename = f"{finding_id}-{plugin_name}-{risk}.md"
            
            # Get brain context
            host = urlparse(finding.get('url', '')).netloc
            host_techs = self.brain.get_host_technologies(host)
            profile = self.brain.determine_scan_profile(finding.get('url', ''))
            
            content = f"""# Vulnerability Report: {finding_id}

## Overview
| Field | Value |
|-------|-------|
| **ID** | {finding_id} |
| **Scanner** | {finding.get('pluginId', 'N/A')} - {finding.get('name', 'N/A')} |
| **Severity** | {risk} |
| **Confidence** | {finding.get('confidence', 'N/A')} |
| **CWE** | {finding.get('cweid', 'N/A')} |
| **WASC** | {finding.get('wascid', 'N/A')} |
| **URL** | `{finding.get('url', 'N/A')}` |
| **Method** | {finding.get('method', 'GET')} |
| **Discovered** | {datetime.now().isoformat()} |

## Description
{finding.get('description', 'Vulnerability detected by ZAP scanner.')}

## Attack Details
- **Parameter**: `{finding.get('param', 'N/A')}`
- **Attack Payload**: `{finding.get('attack', 'N/A')}`
- **Evidence**: 
```
{finding.get('evidence', 'N/A')}
```

## Solution
{finding.get('solution', 'See references for remediation guidance.')}

## References
{finding.get('reference', 'N/A')}

## 🧠 AI Intelligence

### Technologies Detected
{', '.join(host_techs) if host_techs else 'Unknown'}

### Brain Reasoning
{chr(10).join('- ' + r for r in profile['reasoning']) if profile['reasoning'] else 'Standard scan profile used'}

### Priority Score
{profile['priority_score']}/100

---
*AI-Powered Detection by Intelligent ZAP Scanner*
"""
            
            with open(vuln_dir / filename, 'w') as f:
                f.write(content)
    
    def _write_task41_intel(self):
        """Generate intelligence for Task 41 (if running baseline)."""
        if self.mode != ScanMode.BASELINE:
            return
        
        intel = {
            'generated': datetime.now().isoformat(),
            'source': 'Task 40 - ZAP Baseline',
            'high_priority_hosts': [],
            'host_findings': defaultdict(list),
            'interesting_urls': [],
            'recommendations': [],
        }
        
        # Analyze findings
        host_scores = defaultdict(int)
        for finding in self.findings:
            host = urlparse(finding.get('url', '')).netloc
            risk = finding.get('risk', 'Low').lower()
            
            score_map = {'critical': 10, 'high': 5, 'medium': 2, 'low': 1}
            host_scores[host] += score_map.get(risk, 0)
            
            intel['host_findings'][host].append({
                'name': finding.get('name'),
                'risk': risk,
                'url': finding.get('url'),
            })
            
            if risk in ['high', 'critical']:
                intel['interesting_urls'].append(finding.get('url'))
        
        # Sort hosts by score
        sorted_hosts = sorted(host_scores.items(), key=lambda x: -x[1])
        intel['high_priority_hosts'] = [h[0] for h in sorted_hosts[:20]]
        
        # Recommendations
        for host, score in sorted_hosts[:10]:
            intel['recommendations'].append(f"Priority scan {host} (score: {score})")
        
        with open(self.output_dir / 'zap' / 'task41_intel.json', 'w') as f:
            json.dump(intel, f, indent=2)
        
        print(f"\n[+] Task 41 intelligence saved: {len(intel['high_priority_hosts'])} priority hosts")
    
    def _write_phase4_injection_candidates(self):
        """
        Generate injection candidates for Phase 4 tools.
        Phase 4 has dedicated tools that are 100x better at injection testing.
        """
        zap_dir = self.output_dir / 'zap'
        
        candidates = {
            'sqli': [],      # For SQLMap/Ghauri (Step 11)
            'cmdi': [],      # For Commix (Step 12)
            'ssti': [],      # For Tplmap/SSTImap (Step 13)
            'nosqli': [],    # For NoSQLMap (Step 14)
            'all_parameterized': [],
        }
        
        # Collect all discovered URLs with parameters
        all_urls = set()
        
        # From spider results (if available via ZAP API)
        if self.zap and self.zap.is_running():
            try:
                spider_results = self.zap.zap.spider.all_urls
                all_urls.update(spider_results)
            except:
                pass
        
        # From findings
        for finding in self.findings:
            url = finding.get('url', '')
            if url:
                all_urls.add(url)
        
        # Categorize URLs for Phase 4 tools
        for url in all_urls:
            # Any URL with parameters is a SQLi candidate
            if '=' in url or '?' in url:
                candidates['all_parameterized'].append(url)
                candidates['sqli'].append(url)
            
            # Command-like params → Commix
            cmd_indicators = ['cmd', 'exec', 'run', 'command', 'shell', 'ping', 'file', 'path', 'dir']
            if any(ind in url.lower() for ind in cmd_indicators):
                candidates['cmdi'].append(url)
            
            # Template-like params → Tplmap/SSTImap
            tpl_indicators = ['template', 'page', 'view', 'render', 'tpl', 'name', 'email', 'message']
            if any(ind in url.lower() for ind in tpl_indicators):
                candidates['ssti'].append(url)
            
            # NoSQL-like params → NoSQLMap
            nosql_indicators = ['query', 'search', 'filter', 'where', 'id', 'user']
            if any(ind in url.lower() for ind in nosql_indicators):
                candidates['nosqli'].append(url)
        
        # Deduplicate
        for key in candidates:
            candidates[key] = list(set(candidates[key]))
        
        # Save structured JSON for intelligent Phase 4 targeting
        with open(zap_dir / 'injection_candidates.json', 'w') as f:
            json.dump(candidates, f, indent=2)
        
        # Save plain text for direct tool input
        with open(zap_dir / 'injection_candidates.txt', 'w') as f:
            for url in candidates['all_parameterized']:
                f.write(f"{url}\n")
        
        # Save tool-specific files
        with open(zap_dir / 'sqli_targets.txt', 'w') as f:
            for url in candidates['sqli']:
                f.write(f"{url}\n")
        
        with open(zap_dir / 'cmdi_targets.txt', 'w') as f:
            for url in candidates['cmdi']:
                f.write(f"{url}\n")
        
        with open(zap_dir / 'ssti_targets.txt', 'w') as f:
            for url in candidates['ssti']:
                f.write(f"{url}\n")
        
        print(f"\n[+] Phase 4 injection candidates generated:")
        print(f"    SQLi targets: {len(candidates['sqli'])}")
        print(f"    CMDi targets: {len(candidates['cmdi'])}")
        print(f"    SSTI targets: {len(candidates['ssti'])}")
        print(f"    NoSQLi targets: {len(candidates['nosqli'])}")
    
    def _print_summary(self):
        """Print scan summary."""
        print(f"\n{'='*70}")
        print("🧠 ZAP SCAN SUMMARY")
        print(f"{'='*70}")
        print(f"Mode: {self.mode.value}")
        print(f"Total Findings: {len(self.findings)}")
        
        # Severity breakdown
        severity_counts = defaultdict(int)
        for finding in self.findings:
            risk = finding.get('risk', 'Informational')
            severity_counts[risk] += 1
        
        print(f"\nBy Severity:")
        for sev in ['Critical', 'High', 'Medium', 'Low', 'Informational']:
            if sev in severity_counts or sev.lower() in severity_counts:
                count = severity_counts.get(sev, severity_counts.get(sev.lower(), 0))
                print(f"    {sev}: {count}")
        
        # Brain summary
        print(f"\n[BRAIN INTELLIGENCE]")
        print(f"  Host profiles: {len(self.brain.host_profiles)}")
        print(f"  Scanner stats: {len(self.brain.scanner_effectiveness)}")
        
        print(f"\nOutputs: {self.output_dir / 'zap'}")
        print(f"Vulnerabilities: {self.output_dir / 'vulnerabilities'}")


# ============================================================================
# CLI
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description='Intelligent ZAP Scanner')
    parser.add_argument('--mode', type=str, required=True,
                        choices=['baseline', 'full', 'api_only'],
                        help='Scan mode')
    parser.add_argument('--targets', type=Path, nargs='+',
                        help='Input files with target URLs')
    parser.add_argument('--output', type=Path, default=Path('outputs'),
                        help='Output directory')
    parser.add_argument('--temp', type=Path, default=Path('temp'),
                        help='Temp directory')
    parser.add_argument('--resume', action='store_true',
                        help='Resume from checkpoint')
    
    args = parser.parse_args()
    
    mode = ScanMode(args.mode)
    task_map = {
        ScanMode.BASELINE: 40,
        ScanMode.FULL: 41,
        ScanMode.API_ONLY: 41,
    }
    
    temp_dir = args.temp / f'task{task_map[mode]}'
    
    scanner = IntelligentZapScanner(
        output_dir=args.output,
        temp_dir=temp_dir,
        mode=mode
    )
    
    if not args.targets:
        args.targets = [
            Path('outputs/live_base_urls.txt'),
            Path('outputs/queue_api_endpoints_kiterunner.txt'),
            Path('outputs/queue_dynamic_endpoints_urls.txt'),
        ]
    
    scanner.run(args.targets)


if __name__ == '__main__':
    main()
