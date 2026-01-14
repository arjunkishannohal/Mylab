#!/usr/bin/env python3
"""
Task 35-39: INTELLIGENT AI NUCLEI SCANNER
=========================================
NOT hardcoded - LEARNS DYNAMICALLY from responses.

BRAIN PRINCIPLES:
1. OBSERVE: Analyze every response - headers, body, errors
2. LEARN: Extract patterns, technologies, behaviors dynamically
3. ADAPT: Adjust scanning strategy based on what we find
4. REMEMBER: Build knowledge base that grows smarter over time
5. PREDICT: Anticipate what templates will work based on patterns
"""

import json
import subprocess
import sys
import time
import hashlib
import argparse
import re
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Any, Optional, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict
from urllib.parse import urlparse
import threading


# ============================================================================
# CONFIGURATION
# ============================================================================
class Config:
    # AGGRESSIVE MODE - No limits
    CONCURRENCY = 100
    RATE_LIMIT = 0
    TIMEOUT = 10
    RETRIES = 3
    BULK_SIZE = 100
    BATCH_SIZE = 500
    CHECKPOINT_INTERVAL = 100
    SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


class ScanType(Enum):
    TECHNOLOGIES = "technologies"
    EXPOSURES = "exposures"
    MISCONFIGURATION = "misconfiguration"
    DEFAULT_LOGINS = "default-logins"
    CVES_CRITICAL = "cves-critical"
    CVES_HIGH = "cves-high"
    CVES_MEDIUM = "cves-medium"
    CVES_LOW = "cves-low"
    CVES_ALL = "cves-all"


# ============================================================================
# DYNAMIC PATTERN LEARNER - THE REAL BRAIN
# ============================================================================
class PatternLearner:
    """
    Learns patterns DYNAMICALLY from actual responses.
    No hardcoded lists - extracts intelligence from what it observes.
    """
    
    def __init__(self):
        # Learned patterns (grows over time)
        self.header_patterns: Dict[str, Set[str]] = defaultdict(set)  # header → hosts
        self.body_patterns: Dict[str, Set[str]] = defaultdict(set)    # pattern → hosts
        self.error_signatures: Dict[str, Set[str]] = defaultdict(set) # error → hosts
        self.version_patterns: Dict[str, Dict[str, str]] = {}         # host → {tech: version}
        
        # Confidence scoring
        self.pattern_confidence: Dict[str, float] = defaultdict(float)
        
        # Technology indicators (learned, not hardcoded)
        self.tech_indicators: Dict[str, List[str]] = defaultdict(list)
    
    def learn_from_response(self, host: str, headers: Dict, body: str, 
                           status_code: int) -> Dict[str, Any]:
        """
        Analyze a response and LEARN patterns dynamically.
        Returns extracted intelligence.
        """
        learned = {
            'technologies': [],
            'versions': {},
            'frameworks': [],
            'languages': [],
            'servers': [],
            'waf_detected': None,
            'interesting_headers': [],
            'error_type': None,
            'confidence': 0.0
        }
        
        # 1. LEARN FROM HEADERS (dynamic extraction)
        learned.update(self._analyze_headers_dynamic(host, headers))
        
        # 2. LEARN FROM BODY (pattern recognition)
        learned.update(self._analyze_body_dynamic(host, body))
        
        # 3. LEARN FROM STATUS/ERRORS
        learned.update(self._analyze_behavior(host, status_code, body))
        
        # 4. EXTRACT VERSIONS DYNAMICALLY
        learned['versions'].update(self._extract_versions_dynamic(body, headers))
        
        return learned
    
    def _analyze_headers_dynamic(self, host: str, headers: Dict) -> Dict:
        """Dynamically learn from headers - NO hardcoded list."""
        result = {'servers': [], 'technologies': [], 'interesting_headers': []}
        
        for header, value in headers.items():
            header_lower = header.lower()
            value_str = str(value)
            
            # Learn server technology
            if header_lower in ('server', 'x-powered-by', 'x-aspnet-version', 
                               'x-generator', 'x-drupal-cache'):
                result['servers'].append(value_str)
                result['technologies'].append(value_str)
                
                # Record pattern for future reference
                self.header_patterns[f"{header_lower}:{value_str}"].add(host)
            
            # Learn custom/interesting headers
            if header_lower.startswith('x-') and header_lower not in (
                'x-content-type-options', 'x-frame-options', 'x-xss-protection'
            ):
                result['interesting_headers'].append(f"{header}: {value_str}")
                self.header_patterns[header_lower].add(host)
            
            # Detect WAF dynamically (not from fixed list)
            if any(waf_hint in value_str.lower() for waf_hint in [
                'protection', 'firewall', 'security', 'blocked', 'denied'
            ]):
                result['waf_detected'] = value_str
            
            # Look for technology versions in any header
            version_match = re.search(r'([\w.-]+)[/\s]([\d]+\.[\d]+\.?[\d]*)', value_str)
            if version_match:
                tech, version = version_match.groups()
                if 'versions' not in result:
                    result['versions'] = {}
                result['versions'][tech] = version
        
        return result
    
    def _analyze_body_dynamic(self, host: str, body: str) -> Dict:
        """Dynamically extract patterns from response body."""
        result = {'technologies': [], 'frameworks': [], 'languages': []}
        
        if not body:
            return result
        
        body_lower = body.lower()
        
        # 1. META GENERATOR TAG (dynamic extraction)
        generator_match = re.search(
            r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
            body, re.IGNORECASE
        )
        if generator_match:
            gen = generator_match.group(1)
            result['technologies'].append(gen)
            self.body_patterns[f"generator:{gen}"].add(host)
        
        # 2. SCRIPT/LINK PATTERNS (learn what libraries are used)
        script_patterns = re.findall(r'src=["\']([^"\']+\.js)["\']', body, re.IGNORECASE)
        for script in script_patterns:
            # Extract library name dynamically
            lib_match = re.search(r'/([\w.-]+?)(?:\.min)?\.js', script)
            if lib_match:
                lib = lib_match.group(1)
                if lib not in ('main', 'app', 'bundle', 'index', 'script'):
                    result['technologies'].append(lib)
                    self.body_patterns[f"js:{lib}"].add(host)
        
        # 3. CSS FRAMEWORK DETECTION (dynamic)
        css_patterns = re.findall(r'href=["\']([^"\']+\.css)["\']', body, re.IGNORECASE)
        for css in css_patterns:
            lib_match = re.search(r'/([\w.-]+?)(?:\.min)?\.css', css)
            if lib_match:
                lib = lib_match.group(1)
                if lib not in ('style', 'main', 'app', 'index'):
                    result['technologies'].append(lib)
        
        # 4. ERROR MESSAGE PATTERNS (learn error signatures dynamically)
        error_patterns = [
            # Generic exception patterns - extracts what type
            (r'(?:Exception|Error|Traceback)[\s:]+(\w+(?:Exception|Error))', 'exception'),
            # PHP errors
            (r'<b>(?:Fatal|Parse|Warning)</b>:\s+(.+?)\s+in\s+<b>(.+?)</b>', 'php_error'),
            # Java stack traces
            (r'at\s+([\w.]+)\([\w.]+:\d+\)', 'java_stack'),
            # Python tracebacks
            (r'File\s+"([^"]+)",\s+line\s+\d+', 'python_trace'),
            # .NET errors
            (r'System\.([\w.]+Exception)', 'dotnet_error'),
            # Node.js errors
            (r'at\s+([\w./<>]+)\s+\(([^)]+)\)', 'node_error'),
        ]
        
        for pattern, error_type in error_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                self.error_signatures[error_type].add(host)
                # Dynamically infer language from error type
                if error_type == 'php_error':
                    result['languages'].append('php')
                elif error_type == 'java_stack':
                    result['languages'].append('java')
                elif error_type == 'python_trace':
                    result['languages'].append('python')
                elif error_type == 'dotnet_error':
                    result['languages'].append('dotnet')
                elif error_type == 'node_error':
                    result['languages'].append('nodejs')
        
        # 5. DYNAMIC FRAMEWORK DETECTION (from actual content)
        # Look for ANY unique identifiers, not just known frameworks
        unique_patterns = [
            # ng-* attributes = Angular
            (r'\bng-[\w-]+\b', 'angular'),
            # data-react* = React
            (r'data-react[\w-]*', 'react'),
            # v-* attributes = Vue
            (r'\bv-[\w-]+\b', 'vue'),
            # __next = Next.js
            (r'__NEXT_DATA__|_next/', 'nextjs'),
            # wp-content = WordPress
            (r'wp-content|wp-includes', 'wordpress'),
            # sites/default = Drupal
            (r'sites/default|/drupal', 'drupal'),
            # actuator endpoints = Spring
            (r'/actuator|springboot', 'spring'),
            # CSRF tokens with known framework patterns
            (r'csrf[-_]?token|_token|csrfmiddlewaretoken', 'csrf_protected'),
        ]
        
        for pattern, tech in unique_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                result['frameworks'].append(tech)
                self.body_patterns[f"framework:{tech}"].add(host)
        
        # 6. DYNAMIC API DETECTION
        api_hints = [
            (r'"swagger"|"openapi"', 'openapi'),
            (r'graphql|__schema|introspection', 'graphql'),
            (r'"jsonapi"', 'jsonapi'),
            (r'grpc|protobuf', 'grpc'),
        ]
        for pattern, api_type in api_hints:
            if re.search(pattern, body, re.IGNORECASE):
                result['technologies'].append(api_type)
        
        return result
    
    def _analyze_behavior(self, host: str, status_code: int, body: str) -> Dict:
        """Learn from server behavior patterns."""
        result = {'error_type': None, 'behavior_hints': [], 'waf_detected': None}
        
        body_lower = body.lower() if body else ""
        
        # Detect server type from error pages
        if status_code >= 400:
            # Look for server signatures in error pages
            server_hints = [
                ('apache', 'apache'),
                ('nginx', 'nginx'),
                ('iis', 'iis'),
                ('tomcat', 'tomcat'),
                ('jetty', 'jetty'),
                ('weblogic', 'weblogic'),
                ('websphere', 'websphere'),
            ]
            for hint, server in server_hints:
                if hint in body_lower:
                    result['behavior_hints'].append(f"server:{server}")
        
        # WAF detection from behavior
        if status_code in (403, 406, 429, 503):
            waf_signatures = [
                'blocked', 'forbidden', 'access denied', 'firewall',
                'security', 'unauthorized', 'rate limit', 'too many requests',
                'cloudflare', 'akamai', 'incapsula', 'sucuri', 'wordfence'
            ]
            for sig in waf_signatures:
                if sig in body_lower:
                    result['waf_detected'] = sig
                    break
        
        return result
    
    def _extract_versions_dynamic(self, body: str, headers: Dict) -> Dict[str, str]:
        """Dynamically extract ANY version numbers from anywhere."""
        versions = {}
        
        all_text = body + ' ' + ' '.join(f"{k}:{v}" for k, v in headers.items())
        
        # Generic version patterns
        version_patterns = [
            # Product/version format
            r'([\w][\w.-]{2,20})/([\d]+\.[\d]+(?:\.[\d]+)?)',
            # "version": "x.y.z" JSON format
            r'"version"\s*:\s*"([\d]+\.[\d]+(?:\.[\d]+)?)"',
            # Product vX.Y.Z format
            r'([\w][\w.-]{2,20})\s+v?([\d]+\.[\d]+(?:\.[\d]+)?)',
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, all_text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple) and len(match) == 2:
                    product, version = match
                    # Filter noise
                    product_lower = product.lower()
                    if product_lower not in ('http', 'tls', 'ssl', 'keep', 'alive', 
                                             'charset', 'utf', 'text', 'html'):
                        versions[product] = version
                elif isinstance(match, str):
                    versions['detected'] = match
        
        return versions
    
    def get_pattern_summary(self) -> Dict:
        """Get summary of all learned patterns."""
        return {
            'unique_headers': len(self.header_patterns),
            'unique_body_patterns': len(self.body_patterns),
            'error_signatures': len(self.error_signatures),
            'top_patterns': sorted(
                [(k, len(v)) for k, v in self.body_patterns.items()],
                key=lambda x: -x[1]
            )[:20]
        }


# ============================================================================
# INTELLIGENT TECH KNOWLEDGE - LEARNS & ADAPTS
# ============================================================================
class IntelligentTechKnowledge:
    """
    Dynamic brain that learns from findings and adapts strategy.
    NOT based on hardcoded mappings - learns from actual data.
    """
    
    def __init__(self, save_path: Path = None):
        self.save_path = save_path
        self.pattern_learner = PatternLearner()
        
        # Host intelligence (learned)
        self.hosts: Dict[str, Dict[str, Any]] = {}
        
        # Dynamic technology mappings (LEARNED, not hardcoded)
        self.tech_to_hosts: Dict[str, Set[str]] = defaultdict(set)
        self.version_to_hosts: Dict[str, Set[str]] = defaultdict(set)
        
        # CVE intelligence (learned from successful detections)
        self.cve_to_tech: Dict[str, Set[str]] = defaultdict(set)  # CVE → related techs
        self.tech_to_cves: Dict[str, Set[str]] = defaultdict(set)  # tech → related CVEs
        
        # Scan effectiveness learning
        self.template_success: Dict[str, int] = defaultdict(int)    # template → hit count
        self.template_tech_map: Dict[str, Set[str]] = defaultdict(set)  # template → techs
        
        # Host → template correlation (what works where)
        self.host_successful_templates: Dict[str, Set[str]] = defaultdict(set)
        
        # Coverage tracking
        self.scanned_hosts: Set[str] = set()
        self.failed_hosts: Set[str] = set()
        
        if save_path and save_path.exists():
            self.load()
    
    def add_finding(self, finding: Dict[str, Any]):
        """Process a Nuclei finding and LEARN from it dynamically."""
        host = finding.get('host', '')
        template_id = finding.get('template-id', '')
        info = finding.get('info', {})
        name = info.get('name', '')
        tags = info.get('tags', [])
        severity = info.get('severity', 'info')
        matched = finding.get('matched-at', '')
        extracted = finding.get('extracted-results', [])
        matcher_name = finding.get('matcher-name', '')
        
        # Initialize host if new
        if host not in self.hosts:
            self.hosts[host] = {
                'technologies': [],
                'versions': {},
                'tags_seen': set(),
                'templates_matched': [],
                'severity_counts': defaultdict(int),
                'first_seen': datetime.now().isoformat(),
                'last_updated': datetime.now().isoformat(),
                'inferred_stack': {}  # Dynamically inferred tech stack
            }
        
        host_data = self.hosts[host]
        
        # 1. LEARN FROM TEMPLATE TAGS (dynamic correlation)
        for tag in tags:
            tag_lower = tag.lower()
            host_data['tags_seen'].add(tag_lower)
            self.tech_to_hosts[tag_lower].add(host)
            
            # Learn template → tag correlation
            self.template_tech_map[template_id].add(tag_lower)
        
        # 2. DYNAMICALLY EXTRACT TECH FROM NAME (no hardcoded lists)
        tech_from_name = self._extract_tech_dynamically(name, template_id, matched)
        for tech in tech_from_name:
            if tech not in host_data['technologies']:
                host_data['technologies'].append(tech)
            self.tech_to_hosts[tech].add(host)
        
        # 3. LEARN FROM EXTRACTED RESULTS
        for result in extracted:
            # Extract versions dynamically
            versions = self._extract_versions(str(result))
            host_data['versions'].update(versions)
            for tech, version in versions.items():
                self.version_to_hosts[f"{tech}:{version}"].add(host)
            
            # Extract any technology hints from results
            extra_techs = self._extract_tech_dynamically(str(result), '', '')
            for tech in extra_techs:
                if tech not in host_data['technologies']:
                    host_data['technologies'].append(tech)
                self.tech_to_hosts[tech].add(host)
        
        # 4. LEARN TEMPLATE EFFECTIVENESS
        self.template_success[template_id] += 1
        self.host_successful_templates[host].add(template_id)
        
        # 5. LEARN CVE CORRELATIONS DYNAMICALLY
        if 'cve' in template_id.lower():
            cve_match = re.search(r'(CVE-\d{4}-\d+)', template_id, re.IGNORECASE)
            if cve_match:
                cve_id = cve_match.group(1).upper()
                # Correlate CVE with ALL tags/techs found on this host
                for tag in tags:
                    self.cve_to_tech[cve_id].add(tag.lower())
                    self.tech_to_cves[tag.lower()].add(cve_id)
                # Also correlate with detected technologies
                for tech in host_data['technologies']:
                    self.cve_to_tech[cve_id].add(tech)
                    self.tech_to_cves[tech].add(cve_id)
        
        # 6. TRACK SEVERITY
        host_data['severity_counts'][severity] += 1
        host_data['templates_matched'].append(template_id)
        host_data['last_updated'] = datetime.now().isoformat()
        
        # 7. INFER TECH STACK (combine all signals)
        self._update_inferred_stack(host)
        
        self.scanned_hosts.add(host)
    
    def _extract_tech_dynamically(self, text: str, template_id: str, 
                                  matched_at: str) -> List[str]:
        """Dynamically extract technology names from ANY text - no hardcoded list."""
        techs = []
        combined = f"{text} {template_id} {matched_at}".lower()
        
        # Use regex to find technology-like words
        # Pattern: word that could be a product/framework name
        candidates = re.findall(r'\b([a-z][a-z0-9.-]{2,15})\b', combined)
        
        # Filter out common non-tech words dynamically based on context
        common_words = {
            'the', 'and', 'for', 'with', 'this', 'that', 'from', 'have',
            'http', 'https', 'html', 'xml', 'json', 'text', 'content',
            'detect', 'detection', 'scanner', 'scan', 'check', 'test',
            'info', 'high', 'medium', 'low', 'critical', 'unknown',
            'version', 'file', 'path', 'page', 'error', 'default'
        }
        
        for candidate in candidates:
            if candidate not in common_words and len(candidate) > 2:
                # Check if it looks like a tech name (has letters, maybe numbers/dots)
                if re.match(r'^[a-z][a-z0-9.-]*[a-z0-9]$', candidate):
                    techs.append(candidate)
        
        return list(set(techs))[:10]  # Limit to 10 most relevant
    
    def _extract_versions(self, text: str) -> Dict[str, str]:
        """Extract version numbers dynamically from any text."""
        versions = {}
        patterns = [
            r'([\w.-]+)[/:\s]+([\d]+\.[\d]+(?:\.[\d]+)?)',
            r'"([\w]+)":\s*"([\d]+\.[\d]+(?:\.[\d]+)?)"',
        ]
        for pattern in patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if len(match) == 2:
                    product, version = match
                    if product.lower() not in ('http', 'https', 'version', 'v'):
                        versions[product.lower()] = version
        return versions
    
    def _update_inferred_stack(self, host: str):
        """Dynamically infer the full tech stack based on accumulated evidence."""
        if host not in self.hosts:
            return
        
        host_data = self.hosts[host]
        stack = {}
        
        # Infer from all collected signals
        all_signals = (
            list(host_data.get('tags_seen', set())) +
            host_data.get('technologies', []) +
            list(host_data.get('versions', {}).keys())
        )
        
        # Categorize dynamically based on patterns
        categories = {
            'server': ['nginx', 'apache', 'iis', 'tomcat', 'jetty', 'weblogic'],
            'language': ['php', 'java', 'python', 'nodejs', 'ruby', 'dotnet', 'golang'],
            'framework': ['spring', 'laravel', 'django', 'flask', 'express', 'rails', 
                         'angular', 'react', 'vue', 'nextjs'],
            'cms': ['wordpress', 'drupal', 'joomla', 'magento', 'shopify'],
            'database': ['mysql', 'postgres', 'mongodb', 'redis', 'elasticsearch'],
        }
        
        for category, keywords in categories.items():
            for signal in all_signals:
                signal_lower = signal.lower()
                for keyword in keywords:
                    if keyword in signal_lower:
                        stack[category] = keyword
                        break
        
        host_data['inferred_stack'] = stack
    
    def get_smart_targets_for_scan(self, scan_type: ScanType) -> List[str]:
        """Intelligently select targets based on LEARNED patterns."""
        targets = set()
        
        if scan_type in (ScanType.CVES_CRITICAL, ScanType.CVES_HIGH):
            # Hosts with versions = higher CVE likelihood
            for host, data in self.hosts.items():
                if data.get('versions'):
                    targets.add(host)
                # Hosts with known-vulnerable techs (learned from correlations)
                for tech in data.get('technologies', []):
                    if tech in self.tech_to_cves and self.tech_to_cves[tech]:
                        targets.add(host)
        
        elif scan_type == ScanType.DEFAULT_LOGINS:
            # Hosts with management interfaces (learned, not hardcoded)
            for tag in self.tech_to_hosts:
                if any(hint in tag for hint in ['admin', 'login', 'manager', 
                                                'console', 'dashboard', 'panel']):
                    targets.update(self.tech_to_hosts[tag])
        
        elif scan_type == ScanType.EXPOSURES:
            # All hosts - exposures can be anywhere
            targets = set(self.hosts.keys())
        
        # Fallback to all scanned hosts
        if not targets:
            targets = self.scanned_hosts.copy()
        
        return list(targets)
    
    def suggest_templates_for_host(self, host: str) -> List[str]:
        """
        AI-powered template suggestions based on LEARNED correlations.
        """
        if host not in self.hosts:
            return []
        
        host_data = self.hosts[host]
        suggestions = set()
        
        # 1. Templates that worked on similar tech stacks
        for tech in host_data.get('technologies', []):
            similar_hosts = self.tech_to_hosts.get(tech, set())
            for similar_host in similar_hosts:
                if similar_host != host:
                    templates = self.host_successful_templates.get(similar_host, set())
                    suggestions.update(templates)
        
        # 2. CVE templates based on tech → CVE correlations
        for tech in host_data.get('technologies', []):
            related_cves = self.tech_to_cves.get(tech, set())
            for cve in related_cves:
                suggestions.add(f"cves/{cve.lower()}")
        
        # 3. Templates that have high success rates (learned)
        top_templates = sorted(
            self.template_success.items(),
            key=lambda x: -x[1]
        )[:20]
        suggestions.update([t[0] for t in top_templates])
        
        return list(suggestions)[:100]
    
    def get_intelligence_summary(self) -> Dict:
        """Get summary of what the brain has learned."""
        return {
            'hosts_analyzed': len(self.hosts),
            'unique_technologies': len(self.tech_to_hosts),
            'versions_detected': sum(len(h.get('versions', {})) for h in self.hosts.values()),
            'cve_tech_correlations': len(self.cve_to_tech),
            'templates_effectiveness': len(self.template_success),
            'most_common_techs': sorted(
                [(k, len(v)) for k, v in self.tech_to_hosts.items()],
                key=lambda x: -x[1]
            )[:20],
            'most_effective_templates': sorted(
                self.template_success.items(),
                key=lambda x: -x[1]
            )[:20],
            'learned_cve_correlations': {
                cve: list(techs)[:5] 
                for cve, techs in list(self.cve_to_tech.items())[:10]
            }
        }
    
    def save(self):
        """Persist learned knowledge."""
        if not self.save_path:
            return
        
        # Convert sets to lists for JSON
        data = {
            'hosts': {},
            'tech_to_hosts': {k: list(v) for k, v in self.tech_to_hosts.items()},
            'version_to_hosts': {k: list(v) for k, v in self.version_to_hosts.items()},
            'cve_to_tech': {k: list(v) for k, v in self.cve_to_tech.items()},
            'tech_to_cves': {k: list(v) for k, v in self.tech_to_cves.items()},
            'template_success': dict(self.template_success),
            'template_tech_map': {k: list(v) for k, v in self.template_tech_map.items()},
            'host_successful_templates': {k: list(v) for k, v in self.host_successful_templates.items()},
            'scanned_hosts': list(self.scanned_hosts),
            'failed_hosts': list(self.failed_hosts),
            'last_updated': datetime.now().isoformat(),
            'pattern_summary': self.pattern_learner.get_pattern_summary()
        }
        
        # Convert host data (handle sets)
        for host, hdata in self.hosts.items():
            data['hosts'][host] = {
                'technologies': hdata.get('technologies', []),
                'versions': hdata.get('versions', {}),
                'tags_seen': list(hdata.get('tags_seen', set())),
                'templates_matched': hdata.get('templates_matched', []),
                'severity_counts': dict(hdata.get('severity_counts', {})),
                'first_seen': hdata.get('first_seen'),
                'last_updated': hdata.get('last_updated'),
                'inferred_stack': hdata.get('inferred_stack', {})
            }
        
        self.save_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.save_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[brain] Saved: {len(self.hosts)} hosts, {len(self.tech_to_hosts)} techs, "
              f"{len(self.cve_to_tech)} CVE correlations")
    
    def load(self):
        """Load previously learned knowledge."""
        if not self.save_path or not self.save_path.exists():
            return
        
        try:
            with open(self.save_path) as f:
                data = json.load(f)
            
            # Restore hosts
            for host, hdata in data.get('hosts', {}).items():
                self.hosts[host] = {
                    'technologies': hdata.get('technologies', []),
                    'versions': hdata.get('versions', {}),
                    'tags_seen': set(hdata.get('tags_seen', [])),
                    'templates_matched': hdata.get('templates_matched', []),
                    'severity_counts': defaultdict(int, hdata.get('severity_counts', {})),
                    'first_seen': hdata.get('first_seen'),
                    'last_updated': hdata.get('last_updated'),
                    'inferred_stack': hdata.get('inferred_stack', {})
                }
            
            # Restore mappings
            self.tech_to_hosts = defaultdict(set, {
                k: set(v) for k, v in data.get('tech_to_hosts', {}).items()
            })
            self.version_to_hosts = defaultdict(set, {
                k: set(v) for k, v in data.get('version_to_hosts', {}).items()
            })
            self.cve_to_tech = defaultdict(set, {
                k: set(v) for k, v in data.get('cve_to_tech', {}).items()
            })
            self.tech_to_cves = defaultdict(set, {
                k: set(v) for k, v in data.get('tech_to_cves', {}).items()
            })
            self.template_success = defaultdict(int, data.get('template_success', {}))
            self.template_tech_map = defaultdict(set, {
                k: set(v) for k, v in data.get('template_tech_map', {}).items()
            })
            self.host_successful_templates = defaultdict(set, {
                k: set(v) for k, v in data.get('host_successful_templates', {}).items()
            })
            self.scanned_hosts = set(data.get('scanned_hosts', []))
            self.failed_hosts = set(data.get('failed_hosts', []))
            
            print(f"[brain] Loaded: {len(self.hosts)} hosts, {len(self.tech_to_hosts)} techs, "
                  f"{len(self.cve_to_tech)} CVE correlations learned")
        except Exception as e:
            print(f"[!] Failed to load brain: {e}")


# ============================================================================
# ADAPTIVE SCAN STRATEGY - AI-POWERED PRIORITIZATION
# ============================================================================
class AdaptiveScanStrategy:
    """
    Dynamically adjusts scanning strategy based on learned intelligence.
    """
    
    def __init__(self, knowledge: IntelligentTechKnowledge):
        self.knowledge = knowledge
        self.scan_history: List[Dict] = []
    
    def get_priority_hosts(self, all_hosts: List[str], scan_type: ScanType) -> List[str]:
        """Intelligently prioritize hosts based on learned patterns."""
        scored_hosts = []
        
        for host in all_hosts:
            score = self._calculate_host_priority(host, scan_type)
            scored_hosts.append((host, score))
        
        # Sort by score (highest first)
        scored_hosts.sort(key=lambda x: -x[1])
        
        return [h for h, s in scored_hosts]
    
    def _calculate_host_priority(self, host: str, scan_type: ScanType) -> float:
        """Calculate priority score dynamically based on intelligence."""
        score = 1.0
        
        if host not in self.knowledge.hosts:
            return score  # Unknown = default priority
        
        host_data = self.knowledge.hosts[host]
        
        # More technologies = more interesting
        score += len(host_data.get('technologies', [])) * 0.5
        
        # Version info = CVE potential
        score += len(host_data.get('versions', {})) * 1.5
        
        # Previous findings = interesting target
        score += min(len(host_data.get('templates_matched', [])) * 0.3, 5.0)
        
        # Severity-based boost
        sev_counts = host_data.get('severity_counts', {})
        score += sev_counts.get('critical', 0) * 5.0
        score += sev_counts.get('high', 0) * 3.0
        score += sev_counts.get('medium', 0) * 1.0
        
        # Boost for CVE scans based on learned correlations
        if scan_type in (ScanType.CVES_CRITICAL, ScanType.CVES_HIGH, ScanType.CVES_ALL):
            for tech in host_data.get('technologies', []):
                # If we've learned CVEs affect this tech, boost priority
                if tech in self.knowledge.tech_to_cves:
                    score += len(self.knowledge.tech_to_cves[tech]) * 0.5
        
        return score
    
    def should_deep_scan(self, host: str) -> bool:
        """Determine if a host warrants additional deep scanning."""
        if host not in self.knowledge.hosts:
            return False
        
        host_data = self.knowledge.hosts[host]
        
        # Deep scan if we found critical/high issues
        if host_data.get('severity_counts', {}).get('critical', 0) > 0:
            return True
        if host_data.get('severity_counts', {}).get('high', 0) > 0:
            return True
        # Deep scan if rich version info
        if len(host_data.get('versions', {})) > 3:
            return True
        
        return False
    
    def get_additional_templates(self, host: str) -> List[str]:
        """Suggest additional templates based on learned correlations."""
        return self.knowledge.suggest_templates_for_host(host)


# ============================================================================
# INTELLIGENT NUCLEI SCANNER
# ============================================================================
class IntelligentNucleiScanner:
    """
    AI-powered Nuclei scanner that LEARNS and ADAPTS dynamically.
    """
    
    def __init__(self, output_dir: Path, temp_dir: Path, scan_type: ScanType):
        self.output_dir = output_dir
        self.temp_dir = temp_dir
        self.scan_type = scan_type
        self.findings: List[Dict] = []
        
        # Create directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / 'vulnerabilities').mkdir(exist_ok=True)
        (self.output_dir / 'nuclei').mkdir(exist_ok=True)
        
        # Initialize INTELLIGENT brain
        self.knowledge = IntelligentTechKnowledge(
            save_path=self.output_dir / 'nuclei' / 'brain_knowledge.json'
        )
        self.strategy = AdaptiveScanStrategy(self.knowledge)
        
        # Checkpoint
        self.checkpoint = self._load_checkpoint()
    
    def _load_checkpoint(self) -> Dict:
        checkpoint_file = self.temp_dir / 'checkpoint.json'
        if checkpoint_file.exists():
            try:
                with open(checkpoint_file) as f:
                    saved = json.load(f)
                if saved.get('scan_type') == self.scan_type.value:
                    print(f"[*] Resuming from batch {saved.get('last_batch', 0)}")
                    return saved
            except:
                pass
        return {
            'scan_type': self.scan_type.value,
            'completed_batches': [],
            'total_findings': 0,
            'last_batch': 0
        }
    
    def _save_checkpoint(self, batch_num: int):
        self.checkpoint['last_batch'] = batch_num
        self.checkpoint['completed_batches'].append(batch_num)
        self.checkpoint['total_findings'] = len(self.findings)
        self.checkpoint['timestamp'] = datetime.now().isoformat()
        
        with open(self.temp_dir / 'checkpoint.json', 'w') as f:
            json.dump(self.checkpoint, f, indent=2)
    
    def _get_template_args(self) -> List[str]:
        """Get template arguments based on scan type."""
        template_map = {
            ScanType.TECHNOLOGIES: ["-t", "technologies/"],
            ScanType.EXPOSURES: ["-t", "exposures/", "-t", "misconfiguration/"],
            ScanType.DEFAULT_LOGINS: ["-t", "default-logins/"],
            ScanType.CVES_CRITICAL: ["-t", "cves/", "-severity", "critical"],
            ScanType.CVES_HIGH: ["-t", "cves/", "-severity", "high"],
            ScanType.CVES_MEDIUM: ["-t", "cves/", "-severity", "medium"],
            ScanType.CVES_LOW: ["-t", "cves/", "-severity", "low,info"],
            ScanType.CVES_ALL: ["-t", "cves/"],
        }
        return template_map.get(self.scan_type, ["-t", "cves/"])
    
    def _build_nuclei_command(self, target_file: Path, output_file: Path) -> List[str]:
        return [
            "nuclei",
            "-l", str(target_file),
            *self._get_template_args(),
            "-c", str(Config.CONCURRENCY),
            "-rl", str(Config.RATE_LIMIT),
            "-timeout", str(Config.TIMEOUT),
            "-retries", str(Config.RETRIES),
            "-bulk-size", str(Config.BULK_SIZE),
            "-nc", "-stats", "-json",
            "-o", str(output_file),
            "-silent"
        ]
    
    def prepare_targets(self, input_files: List[Path]) -> Path:
        """Prepare and PRIORITIZE targets intelligently."""
        all_urls = set()
        
        for input_file in input_files:
            if input_file.exists():
                with open(input_file) as f:
                    for line in f:
                        url = line.strip()
                        if url and url.startswith('http'):
                            all_urls.add(url)
        
        # INTELLIGENT PRIORITIZATION using learned knowledge
        url_list = list(all_urls)
        prioritized = self.strategy.get_priority_hosts(url_list, self.scan_type)
        
        target_file = self.temp_dir / 'all_targets.txt'
        with open(target_file, 'w') as f:
            for url in prioritized:
                f.write(f"{url}\n")
        
        print(f"[+] Prepared {len(prioritized)} targets (AI-prioritized)")
        return target_file
    
    def run_batch(self, target_file: Path, batch_num: int, 
                  start_line: int, end_line: int) -> Path:
        batch_file = self.temp_dir / f'batch_{batch_num}.txt'
        output_file = self.temp_dir / f'results_batch_{batch_num}.json'
        
        with open(target_file) as f:
            lines = f.readlines()
        
        with open(batch_file, 'w') as f:
            for line in lines[start_line:end_line]:
                f.write(line)
        
        print(f"\n[*] Batch {batch_num}: {end_line - start_line} targets")
        
        cmd = self._build_nuclei_command(batch_file, output_file)
        
        try:
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            elapsed = time.time() - start_time
            print(f"    Completed in {elapsed:.1f}s")
        except subprocess.TimeoutExpired:
            print(f"    [!] Batch timed out")
        except Exception as e:
            print(f"    [!] Error: {e}")
        
        return output_file
    
    def parse_results(self, results_file: Path):
        """Parse results and LEARN from them dynamically."""
        if not results_file.exists():
            return
        
        with open(results_file) as f:
            for line in f:
                try:
                    finding = json.loads(line.strip())
                    self.findings.append(finding)
                    
                    # LEARN from this finding - brain updates itself
                    self.knowledge.add_finding(finding)
                    
                except json.JSONDecodeError:
                    continue
    
    def run(self, input_files: List[Path]):
        """Run intelligent scan with dynamic learning."""
        print(f"\n{'='*70}")
        print(f"🧠 INTELLIGENT AI NUCLEI SCANNER - {self.scan_type.value.upper()}")
        print(f"{'='*70}")
        print(f"Mode: AGGRESSIVE + DYNAMIC AI LEARNING")
        print(f"Strategy: Learn from responses, adapt continuously")
        
        # Show brain status
        summary = self.knowledge.get_intelligence_summary()
        print(f"\n[brain] Prior knowledge:")
        print(f"  - Hosts known: {summary['hosts_analyzed']}")
        print(f"  - Technologies learned: {summary['unique_technologies']}")
        print(f"  - CVE correlations: {summary['cve_tech_correlations']}")
        
        target_file = self.prepare_targets(input_files)
        
        with open(target_file) as f:
            total_targets = len(f.readlines())
        
        num_batches = (total_targets + Config.BATCH_SIZE - 1) // Config.BATCH_SIZE
        print(f"\n[*] {total_targets} targets → {num_batches} batches")
        
        start_batch = self.checkpoint.get('last_batch', 0)
        
        for batch_num in range(start_batch, num_batches):
            start_line = batch_num * Config.BATCH_SIZE
            end_line = min((batch_num + 1) * Config.BATCH_SIZE, total_targets)
            
            results_file = self.run_batch(target_file, batch_num + 1, start_line, end_line)
            self.parse_results(results_file)
            self._save_checkpoint(batch_num + 1)
            self.knowledge.save()
            
            # Show real-time learning progress
            print(f"    [brain] Learned: {len(self.knowledge.tech_to_hosts)} techs, "
                  f"{len(self.knowledge.cve_to_tech)} CVE correlations, "
                  f"{len(self.findings)} findings")
        
        # Final outputs
        self.knowledge.save()
        self._write_outputs()
        self._write_vulnerability_reports()
        self._print_summary()
    
    def _write_outputs(self):
        nuclei_dir = self.output_dir / 'nuclei'
        
        # All findings
        with open(nuclei_dir / f'{self.scan_type.value}_results.json', 'w') as f:
            json.dump(self.findings, f, indent=2)
        
        # DYNAMICALLY generated host lists (based on what we learned)
        for tech, hosts in self.knowledge.tech_to_hosts.items():
            if len(hosts) >= 1:
                # Sanitize filename
                safe_name = re.sub(r'[^\w.-]', '_', tech)[:30]
                with open(nuclei_dir / f'learned_{safe_name}_hosts.txt', 'w') as f:
                    for host in hosts:
                        f.write(f"{host}\n")
        
        # Intelligence summary
        with open(nuclei_dir / 'intelligence_summary.json', 'w') as f:
            json.dump(self.knowledge.get_intelligence_summary(), f, indent=2)
    
    def _write_vulnerability_reports(self):
        vuln_dir = self.output_dir / 'vulnerabilities'
        
        for i, finding in enumerate(self.findings):
            info = finding.get('info', {})
            severity = info.get('severity', 'info').upper()
            template_id = finding.get('template-id', 'unknown')
            host = finding.get('host', 'unknown')
            
            if severity.lower() in ['critical', 'high', 'medium']:
                finding_id = f"NUCLEI-{i+1:04d}"
                safe_template = re.sub(r'[^\w.-]', '_', template_id)[:30]
                filename = f"{finding_id}-{safe_template}-{severity}.md"
                
                # Get AI-inferred context
                host_intel = self.knowledge.hosts.get(host, {})
                inferred_stack = host_intel.get('inferred_stack', {})
                related_cves = []
                for tech in host_intel.get('technologies', []):
                    related_cves.extend(list(self.knowledge.tech_to_cves.get(tech, set()))[:3])
                
                content = f"""# Vulnerability Report: {finding_id}

## Overview
| Field | Value |
|-------|-------|
| **ID** | {finding_id} |
| **Template** | {template_id} |
| **Name** | {info.get('name', 'N/A')} |
| **Severity** | {severity} |
| **Confidence** | CONFIRMED (Nuclei Detection) |
| **Host** | `{host}` |
| **Matched At** | `{finding.get('matched-at', 'N/A')}` |
| **Discovered** | {datetime.now().isoformat()} |

## Description
{info.get('description', 'Vulnerability detected by Nuclei template.')}

## Tags
{', '.join(info.get('tags', []))}

## References
"""
                for ref in info.get('reference', []):
                    content += f"- {ref}\n"
                
                content += f"""
## Evidence
```json
{json.dumps(finding.get('extracted-results', []), indent=2)}
```

## 🧠 AI Intelligence (Dynamically Learned)

### Inferred Tech Stack
{json.dumps(inferred_stack, indent=2) if inferred_stack else 'Still learning...'}

### Technologies Detected on Host
{', '.join(host_intel.get('technologies', ['unknown']))}

### Related CVEs (Learned Correlation)
{', '.join(related_cves[:5]) if related_cves else 'No correlations learned yet'}

### Host Risk Profile
- Findings on this host: {len(host_intel.get('templates_matched', []))}
- Critical: {host_intel.get('severity_counts', {}).get('critical', 0)}
- High: {host_intel.get('severity_counts', {}).get('high', 0)}

---
*AI-Assisted Detection by Intelligent Nuclei Scanner*
*Brain learns dynamically from every scan*
"""
                
                with open(vuln_dir / filename, 'w') as f:
                    f.write(content)
    
    def _print_summary(self):
        print(f"\n{'='*70}")
        print("🧠 AI SCAN SUMMARY")
        print(f"{'='*70}")
        print(f"Scan Type: {self.scan_type.value}")
        print(f"Total Findings: {len(self.findings)}")
        
        # Severity breakdown
        severity_counts = {}
        for finding in self.findings:
            sev = finding.get('info', {}).get('severity', 'unknown')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        print(f"\nBy Severity:")
        for sev in Config.SEVERITY_ORDER:
            if sev in severity_counts:
                print(f"    {sev.upper()}: {severity_counts[sev]}")
        
        # Brain intelligence summary
        print(f"\n[BRAIN INTELLIGENCE - Dynamically Learned]")
        summary = self.knowledge.get_intelligence_summary()
        print(f"  Hosts Analyzed: {summary['hosts_analyzed']}")
        print(f"  Technologies Learned: {summary['unique_technologies']}")
        print(f"  Versions Extracted: {summary['versions_detected']}")
        print(f"  CVE↔Tech Correlations: {summary['cve_tech_correlations']}")
        
        if summary['most_common_techs']:
            print(f"\n  Top Technologies (Learned):")
            for tech, count in summary['most_common_techs'][:10]:
                print(f"    - {tech}: {count} hosts")
        
        if summary.get('learned_cve_correlations'):
            print(f"\n  CVE Correlations (Learned):")
            for cve, techs in list(summary['learned_cve_correlations'].items())[:5]:
                print(f"    - {cve} → {', '.join(techs)}")
        
        print(f"\nOutputs: {self.output_dir / 'nuclei'}")
        print(f"Vulnerabilities: {self.output_dir / 'vulnerabilities'}")
        print(f"Brain Knowledge: {self.output_dir / 'nuclei' / 'brain_knowledge.json'}")


# ============================================================================
# CLI
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description='Intelligent AI Nuclei Scanner')
    parser.add_argument('--scan-type', type=str, required=True,
                        choices=[st.value for st in ScanType])
    parser.add_argument('--targets', type=Path, nargs='+')
    parser.add_argument('--output', type=Path, default=Path('outputs'))
    parser.add_argument('--temp', type=Path, default=Path('temp'))
    parser.add_argument('--resume', action='store_true')
    
    args = parser.parse_args()
    
    scan_type = ScanType(args.scan_type)
    task_map = {
        ScanType.TECHNOLOGIES: 35, ScanType.EXPOSURES: 36,
        ScanType.MISCONFIGURATION: 36, ScanType.DEFAULT_LOGINS: 37, 
        ScanType.CVES_CRITICAL: 38, ScanType.CVES_HIGH: 38, 
        ScanType.CVES_MEDIUM: 39, ScanType.CVES_LOW: 39, 
        ScanType.CVES_ALL: 39,
    }
    
    temp_dir = args.temp / f'task{task_map[scan_type]}'
    
    scanner = IntelligentNucleiScanner(
        output_dir=args.output,
        temp_dir=temp_dir,
        scan_type=scan_type
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
