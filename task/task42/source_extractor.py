#!/usr/bin/env python3
"""
Task 42: Source Extraction & Secrets Deep Dive - AI Brain
=========================================================

This is the INTELLIGENT BRAIN for source extraction.
It reads Nuclei findings, decides what to extract, and hunts for secrets.

Author: Jules AI Agent
Mode: AGGRESSIVE - Extract everything found exposed
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
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from urllib.parse import urlparse, urljoin
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
class ExtractionTarget:
    """A target identified for extraction."""
    url: str
    host: str
    exposure_type: str
    tool: str
    severity: str
    nuclei_template: str
    extracted: bool = False
    extraction_path: Optional[str] = None
    secrets_found: List[Dict] = field(default_factory=list)
    error: Optional[str] = None


@dataclass 
class SecretFinding:
    """A secret/credential found during extraction."""
    secret_type: str
    value_redacted: str  # Never store full secret
    value_hash: str  # Hash for dedup
    source_file: str
    source_line: int
    context: str
    commit_sha: Optional[str] = None
    validation_status: str = "pending"


# =============================================================================
# EXTRACTION BRAIN - MAIN INTELLIGENCE
# =============================================================================

class ExtractionBrain:
    """
    The AI brain that learns from Nuclei findings and extracts exposed content.
    
    NOT HARDCODED - Dynamically maps findings to extraction strategies.
    """
    
    # Dynamic mapping - learns from template names
    EXTRACTION_STRATEGIES = {
        # Pattern in template-id/name → (tool, extraction_type)
        'git-config': ('git-dumper', 'git'),
        'git-exposure': ('git-dumper', 'git'),
        'git-head': ('git-dumper', 'git'),
        'gitconfig': ('git-dumper', 'git'),
        'svn-entries': ('dvcs-ripper', 'svn'),
        'svn-wc-db': ('dvcs-ripper', 'svn'),
        'hg-': ('dvcs-ripper', 'hg'),
        'mercurial': ('dvcs-ripper', 'hg'),
        'bzr-': ('dvcs-ripper', 'bzr'),
        'env-file': ('direct-download', 'env'),
        'env-exposure': ('direct-download', 'env'),
        'dotenv': ('direct-download', 'env'),
        'backup': ('direct-download', 'backup'),
        'bak-file': ('direct-download', 'backup'),
        'dump.sql': ('direct-download', 'database'),
        'database-': ('direct-download', 'database'),
        'phpinfo': ('parse-response', 'phpinfo'),
        'server-status': ('parse-response', 'server-status'),
        'server-info': ('parse-response', 'server-info'),
        'htpasswd': ('direct-download', 'htpasswd'),
        'htaccess': ('direct-download', 'htaccess'),
        'config.php': ('direct-download', 'config'),
        'wp-config': ('direct-download', 'config'),
    }
    
    # Secret patterns to search for in extracted content
    SECRET_PATTERNS = {
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret_key': r'[0-9a-zA-Z/+]{40}',
        'github_token': r'ghp_[0-9a-zA-Z]{36}',
        'github_oauth': r'gho_[0-9a-zA-Z]{36}',
        'gitlab_token': r'glpat-[0-9a-zA-Z\-]{20}',
        'slack_token': r'xox[baprs]-[0-9a-zA-Z\-]{10,}',
        'slack_webhook': r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+',
        'stripe_secret': r'sk_live_[0-9a-zA-Z]{24,}',
        'stripe_publishable': r'pk_live_[0-9a-zA-Z]{24,}',
        'google_api': r'AIza[0-9A-Za-z\-_]{35}',
        'google_oauth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        'firebase_url': r'https://[a-z0-9-]+\.firebaseio\.com',
        'heroku_api': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        'mailgun_key': r'key-[0-9a-zA-Z]{32}',
        'mailchimp_key': r'[0-9a-f]{32}-us[0-9]{1,2}',
        'twilio_sid': r'AC[0-9a-fA-F]{32}',
        'twilio_token': r'[0-9a-fA-F]{32}',
        'sendgrid_key': r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
        'jwt_token': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
        'private_key': r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
        'password_assignment': r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{4,}["\']?',
        'api_key_assignment': r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[^\s"\']{8,}["\']?',
        'secret_assignment': r'(?i)(secret|token)\s*[=:]\s*["\']?[^\s"\']{8,}["\']?',
        'connection_string': r'(?i)(mongodb|mysql|postgres|redis)://[^\s"\']+',
        'basic_auth': r'(?i)authorization:\s*basic\s+[a-zA-Z0-9+/=]+',
        'bearer_token': r'(?i)authorization:\s*bearer\s+[a-zA-Z0-9._-]+',
    }
    
    def __init__(self, output_dir: str, temp_dir: str):
        self.output_dir = Path(output_dir)
        self.temp_dir = Path(temp_dir)
        self.extraction_queue: List[ExtractionTarget] = []
        self.extracted_targets: List[ExtractionTarget] = []
        self.all_secrets: List[SecretFinding] = []
        self.secret_hashes: Set[str] = set()  # Dedup
        
        # Create output directories
        self._setup_directories()
        
        # Load checkpoint if exists
        self.checkpoint = self._load_checkpoint()
        
    def _setup_directories(self):
        """Create output directory structure."""
        dirs = [
            self.output_dir / "git_repos",
            self.output_dir / "svn_repos",
            self.output_dir / "hg_repos",
            self.output_dir / "backup_files" / "downloads",
            self.output_dir / "meg_results" / "out",
            self.temp_dir,
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)
            
    def _load_checkpoint(self) -> Dict:
        """Load checkpoint for resume capability."""
        checkpoint_file = self.temp_dir / "checkpoint.json"
        if checkpoint_file.exists():
            try:
                with open(checkpoint_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {"extracted_urls": [], "last_run": None}
    
    def _save_checkpoint(self):
        """Save checkpoint for resume."""
        self.checkpoint["last_run"] = datetime.now().isoformat()
        self.checkpoint["extracted_urls"] = [t.url for t in self.extracted_targets if t.extracted]
        
        checkpoint_file = self.temp_dir / "checkpoint.json"
        with open(checkpoint_file, 'w') as f:
            json.dump(self.checkpoint, f, indent=2)


# =============================================================================
# NUCLEI FINDINGS PARSER
# =============================================================================

class NucleiParser:
    """Parse Nuclei exposure findings and identify extraction targets."""
    
    def __init__(self, brain: ExtractionBrain):
        self.brain = brain
        
    def parse_findings(self, findings_file: str) -> List[ExtractionTarget]:
        """
        Parse Nuclei JSON findings and create extraction targets.
        
        DYNAMIC: Learns from template names, not hardcoded list.
        """
        targets = []
        
        if not os.path.exists(findings_file):
            logger.warning(f"Nuclei findings file not found: {findings_file}")
            return targets
            
        try:
            with open(findings_file, 'r') as f:
                content = f.read().strip()
                
            # Handle JSON lines or array format
            findings = []
            if content.startswith('['):
                findings = json.loads(content)
            else:
                for line in content.split('\n'):
                    if line.strip():
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
                            
            logger.info(f"Parsed {len(findings)} Nuclei findings")
            
            for finding in findings:
                target = self._finding_to_target(finding)
                if target:
                    targets.append(target)
                    
        except Exception as e:
            logger.error(f"Error parsing Nuclei findings: {e}")
            
        return targets
    
    def _finding_to_target(self, finding: Dict) -> Optional[ExtractionTarget]:
        """Convert a Nuclei finding to an extraction target."""
        template_id = finding.get('template-id', '').lower()
        template_name = finding.get('info', {}).get('name', '').lower()
        matched_url = finding.get('matched-at', finding.get('host', ''))
        severity = finding.get('info', {}).get('severity', 'unknown')
        
        if not matched_url:
            return None
            
        # Parse host from URL
        parsed = urlparse(matched_url)
        host = parsed.netloc or parsed.path.split('/')[0]
        
        # DYNAMIC: Find matching extraction strategy
        tool = None
        exposure_type = None
        
        # Check template ID first
        for pattern, (t, e) in self.brain.EXTRACTION_STRATEGIES.items():
            if pattern in template_id or pattern in template_name:
                tool = t
                exposure_type = e
                break
                
        # If no match, try to infer from URL patterns
        if not tool:
            tool, exposure_type = self._infer_from_url(matched_url)
            
        if not tool:
            logger.debug(f"No extraction strategy for: {template_id}")
            return None
            
        # Skip if already extracted
        if matched_url in self.brain.checkpoint.get("extracted_urls", []):
            logger.info(f"Skipping already extracted: {matched_url}")
            return None
            
        return ExtractionTarget(
            url=matched_url,
            host=host,
            exposure_type=exposure_type,
            tool=tool,
            severity=severity,
            nuclei_template=template_id
        )
    
    def _infer_from_url(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """Infer extraction type from URL path."""
        url_lower = url.lower()
        
        if '/.git/' in url_lower:
            return ('git-dumper', 'git')
        elif '/.svn/' in url_lower:
            return ('dvcs-ripper', 'svn')
        elif '/.hg/' in url_lower:
            return ('dvcs-ripper', 'hg')
        elif '.env' in url_lower:
            return ('direct-download', 'env')
        elif any(x in url_lower for x in ['.bak', '.old', '.backup', '.sql']):
            return ('direct-download', 'backup')
        elif 'phpinfo' in url_lower:
            return ('parse-response', 'phpinfo')
        elif 'server-status' in url_lower:
            return ('parse-response', 'server-status')
            
        return (None, None)


# =============================================================================
# EXTRACTORS
# =============================================================================

class GitExtractor:
    """Extract exposed .git repositories."""
    
    def __init__(self, brain: ExtractionBrain):
        self.brain = brain
        
    async def extract(self, target: ExtractionTarget) -> ExtractionTarget:
        """Extract .git repository using git-dumper."""
        logger.info(f"[GIT] Extracting: {target.url}")
        
        # Create output directory for this repo
        safe_host = target.host.replace(':', '_').replace('/', '_')
        repo_dir = self.brain.output_dir / "git_repos" / safe_host
        repo_dir.mkdir(parents=True, exist_ok=True)
        
        # Get base URL (remove /.git/config etc)
        base_url = self._get_git_base_url(target.url)
        
        try:
            # Try git-dumper first
            success = await self._run_git_dumper(base_url, repo_dir)
            
            if not success:
                # Fallback to manual extraction
                success = await self._manual_git_extract(base_url, repo_dir)
                
            if success:
                target.extracted = True
                target.extraction_path = str(repo_dir)
                
                # Search for secrets in extracted content
                secrets = await self._search_for_secrets(repo_dir)
                target.secrets_found = secrets
                
                # Try to checkout files
                await self._checkout_files(repo_dir)
                
                logger.info(f"[GIT] Extracted {target.host}: {len(secrets)} secrets found")
            else:
                target.error = "Extraction failed - repo may be incomplete"
                
        except Exception as e:
            target.error = str(e)
            logger.error(f"[GIT] Error extracting {target.url}: {e}")
            
        return target
    
    def _get_git_base_url(self, url: str) -> str:
        """Get base URL from .git path URL."""
        # Remove /.git/config, /.git/HEAD etc
        for suffix in ['/.git/config', '/.git/HEAD', '/.git/', '/.git']:
            if url.endswith(suffix):
                return url[:-len(suffix)]
        return url
    
    async def _run_git_dumper(self, base_url: str, output_dir: Path) -> bool:
        """Run git-dumper tool."""
        git_url = f"{base_url}/.git/"
        
        try:
            # git-dumper URL output_dir
            proc = await asyncio.create_subprocess_exec(
                'git-dumper', git_url, str(output_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            
            # Check if .git/config exists in output
            if (output_dir / '.git' / 'config').exists():
                return True
                
        except FileNotFoundError:
            logger.warning("git-dumper not found, trying manual extraction")
        except asyncio.TimeoutError:
            logger.warning("git-dumper timed out")
        except Exception as e:
            logger.warning(f"git-dumper error: {e}")
            
        return False
    
    async def _manual_git_extract(self, base_url: str, output_dir: Path) -> bool:
        """Manual git extraction using curl/wget."""
        git_dir = output_dir / '.git'
        git_dir.mkdir(parents=True, exist_ok=True)
        
        # Core git files to fetch
        git_files = [
            'HEAD', 'config', 'description', 'index',
            'packed-refs', 'COMMIT_EDITMSG',
            'info/refs', 'info/exclude',
            'logs/HEAD', 'logs/refs/heads/master', 'logs/refs/heads/main',
            'refs/heads/master', 'refs/heads/main',
            'objects/info/packs',
        ]
        
        downloaded = 0
        for gf in git_files:
            try:
                url = f"{base_url}/.git/{gf}"
                output_file = git_dir / gf
                output_file.parent.mkdir(parents=True, exist_ok=True)
                
                # Use curl
                proc = await asyncio.create_subprocess_exec(
                    'curl', '-s', '-o', str(output_file), url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(proc.communicate(), timeout=30)
                
                if output_file.exists() and output_file.stat().st_size > 0:
                    downloaded += 1
                    
            except Exception as e:
                continue
                
        return downloaded >= 2  # At least HEAD and config
    
    async def _checkout_files(self, repo_dir: Path):
        """Try to checkout source files from .git."""
        try:
            # git checkout .
            proc = await asyncio.create_subprocess_exec(
                'git', '-C', str(repo_dir), 'checkout', '.',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=60)
        except:
            pass  # Best effort
            
    async def _search_for_secrets(self, repo_dir: Path) -> List[Dict]:
        """Search extracted git content for secrets."""
        secrets = []
        
        # Search in all files
        for root, dirs, files in os.walk(repo_dir):
            # Skip .git internal files (except config)
            if '.git' in root and 'config' not in root:
                continue
                
            for filename in files:
                file_path = Path(root) / filename
                try:
                    if file_path.stat().st_size > 10 * 1024 * 1024:  # Skip >10MB
                        continue
                        
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    file_secrets = self._find_secrets_in_content(content, str(file_path))
                    secrets.extend(file_secrets)
                    
                except Exception:
                    continue
                    
        # Also search git log if possible
        try:
            proc = await asyncio.create_subprocess_exec(
                'git', '-C', str(repo_dir), 'log', '-p', '--all',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            
            if stdout:
                log_content = stdout.decode('utf-8', errors='ignore')
                log_secrets = self._find_secrets_in_content(log_content, "git log -p")
                secrets.extend(log_secrets)
                
        except:
            pass  # Best effort
            
        return secrets
    
    def _find_secrets_in_content(self, content: str, source: str) -> List[Dict]:
        """Find secrets in content using patterns."""
        secrets = []
        
        for secret_type, pattern in self.brain.SECRET_PATTERNS.items():
            for match in re.finditer(pattern, content):
                value = match.group()
                value_hash = hashlib.sha256(value.encode()).hexdigest()[:16]
                
                # Skip if duplicate
                if value_hash in self.brain.secret_hashes:
                    continue
                    
                self.brain.secret_hashes.add(value_hash)
                
                # Get context (line around match)
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end].replace('\n', ' ')
                
                # Redact the actual value
                redacted = self._redact_value(value, secret_type)
                
                secrets.append({
                    'type': secret_type,
                    'value_redacted': redacted,
                    'value_hash': value_hash,
                    'source': source,
                    'context': context[:200],
                    'severity': self._get_secret_severity(secret_type)
                })
                
        return secrets
    
    def _redact_value(self, value: str, secret_type: str) -> str:
        """Redact secret value for safe storage."""
        if len(value) <= 8:
            return value[:2] + '*' * (len(value) - 2)
        return value[:4] + '*' * (len(value) - 8) + value[-4:]
    
    def _get_secret_severity(self, secret_type: str) -> str:
        """Determine severity of secret type."""
        critical = ['aws_access_key', 'aws_secret_key', 'private_key', 
                   'connection_string', 'github_token', 'stripe_secret']
        high = ['api_key_assignment', 'password_assignment', 'secret_assignment',
               'bearer_token', 'jwt_token']
        
        if secret_type in critical:
            return 'critical'
        elif secret_type in high:
            return 'high'
        return 'medium'


class DVCSExtractor:
    """Extract SVN/HG/Bazaar repositories."""
    
    def __init__(self, brain: ExtractionBrain):
        self.brain = brain
        
    async def extract(self, target: ExtractionTarget) -> ExtractionTarget:
        """Extract SVN/HG repo using dvcs-ripper or manual methods."""
        logger.info(f"[DVCS] Extracting {target.exposure_type}: {target.url}")
        
        safe_host = target.host.replace(':', '_').replace('/', '_')
        
        if target.exposure_type == 'svn':
            repo_dir = self.brain.output_dir / "svn_repos" / safe_host
            success = await self._extract_svn(target.url, repo_dir)
        elif target.exposure_type == 'hg':
            repo_dir = self.brain.output_dir / "hg_repos" / safe_host
            success = await self._extract_hg(target.url, repo_dir)
        else:
            target.error = f"Unknown DVCS type: {target.exposure_type}"
            return target
            
        repo_dir.mkdir(parents=True, exist_ok=True)
        
        if success:
            target.extracted = True
            target.extraction_path = str(repo_dir)
            # Search for secrets
            secrets = await self._search_for_secrets(repo_dir)
            target.secrets_found = secrets
        else:
            target.error = "DVCS extraction failed"
            
        return target
    
    async def _extract_svn(self, url: str, output_dir: Path) -> bool:
        """Extract SVN repository."""
        # Get base URL
        base_url = url
        for suffix in ['/.svn/entries', '/.svn/wc.db', '/.svn/']:
            if url.endswith(suffix):
                base_url = url[:-len(suffix)]
                break
                
        try:
            # Try rip-svn.pl from dvcs-ripper
            proc = await asyncio.create_subprocess_exec(
                'perl', 'rip-svn.pl', '-v', '-u', f"{base_url}/.svn/",
                cwd=str(output_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=300)
            
            # Check if successful
            if (output_dir / '.svn').exists():
                return True
                
        except FileNotFoundError:
            logger.warning("dvcs-ripper not found")
        except Exception as e:
            logger.warning(f"SVN extraction error: {e}")
            
        # Fallback: download wc.db directly
        try:
            wc_db = output_dir / '.svn' / 'wc.db'
            wc_db.parent.mkdir(parents=True, exist_ok=True)
            
            proc = await asyncio.create_subprocess_exec(
                'curl', '-s', '-o', str(wc_db), f"{base_url}/.svn/wc.db",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=60)
            
            return wc_db.exists() and wc_db.stat().st_size > 0
            
        except:
            return False
    
    async def _extract_hg(self, url: str, output_dir: Path) -> bool:
        """Extract Mercurial repository."""
        base_url = url
        for suffix in ['/.hg/store/00manifest.i', '/.hg/']:
            if url.endswith(suffix):
                base_url = url[:-len(suffix)]
                break
                
        try:
            # Try rip-hg.pl
            proc = await asyncio.create_subprocess_exec(
                'perl', 'rip-hg.pl', '-v', '-u', f"{base_url}/.hg/",
                cwd=str(output_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=300)
            
            return (output_dir / '.hg').exists()
            
        except:
            return False
            
    async def _search_for_secrets(self, repo_dir: Path) -> List[Dict]:
        """Search extracted DVCS content for secrets."""
        secrets = []
        
        for root, dirs, files in os.walk(repo_dir):
            for filename in files:
                file_path = Path(root) / filename
                try:
                    if file_path.stat().st_size > 10 * 1024 * 1024:
                        continue
                        
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    
                    for secret_type, pattern in self.brain.SECRET_PATTERNS.items():
                        for match in re.finditer(pattern, content):
                            value = match.group()
                            value_hash = hashlib.sha256(value.encode()).hexdigest()[:16]
                            
                            if value_hash in self.brain.secret_hashes:
                                continue
                            self.brain.secret_hashes.add(value_hash)
                            
                            secrets.append({
                                'type': secret_type,
                                'value_redacted': value[:4] + '***' + value[-4:] if len(value) > 8 else '***',
                                'value_hash': value_hash,
                                'source': str(file_path),
                                'severity': 'high'
                            })
                            
                except:
                    continue
                    
        return secrets


class DirectDownloader:
    """Download exposed files directly (backup, env, config)."""
    
    def __init__(self, brain: ExtractionBrain):
        self.brain = brain
        
    async def download(self, target: ExtractionTarget) -> ExtractionTarget:
        """Download exposed file directly."""
        logger.info(f"[DOWNLOAD] Fetching: {target.url}")
        
        # Create output path
        parsed = urlparse(target.url)
        safe_host = target.host.replace(':', '_')
        safe_path = parsed.path.replace('/', '_').replace('\\', '_')
        if not safe_path:
            safe_path = 'index'
            
        output_file = self.brain.output_dir / "backup_files" / "downloads" / safe_host / safe_path
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # Download with curl
            proc = await asyncio.create_subprocess_exec(
                'curl', '-s', '-L', '-o', str(output_file), target.url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
            
            if output_file.exists() and output_file.stat().st_size > 0:
                target.extracted = True
                target.extraction_path = str(output_file)
                
                # Parse for secrets
                secrets = await self._parse_for_secrets(output_file, target.exposure_type)
                target.secrets_found = secrets
                
                logger.info(f"[DOWNLOAD] Got {output_file.stat().st_size} bytes, {len(secrets)} secrets")
            else:
                target.error = "Download failed or empty response"
                
        except Exception as e:
            target.error = str(e)
            logger.error(f"[DOWNLOAD] Error: {e}")
            
        return target
    
    async def _parse_for_secrets(self, file_path: Path, exposure_type: str) -> List[Dict]:
        """Parse downloaded file for secrets based on type."""
        secrets = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            if exposure_type == 'env':
                # Parse .env format: KEY=value
                for line in content.split('\n'):
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"\'')
                        
                        # Check if sensitive key
                        sensitive_keys = ['password', 'secret', 'key', 'token', 'api', 
                                        'auth', 'credential', 'private', 'db_', 'database']
                        if any(s in key.lower() for s in sensitive_keys):
                            value_hash = hashlib.sha256(value.encode()).hexdigest()[:16]
                            if value_hash not in self.brain.secret_hashes:
                                self.brain.secret_hashes.add(value_hash)
                                secrets.append({
                                    'type': 'env_variable',
                                    'key': key,
                                    'value_redacted': value[:4] + '***' if len(value) > 4 else '***',
                                    'value_hash': value_hash,
                                    'source': str(file_path),
                                    'severity': 'high'
                                })
                                
            elif exposure_type == 'database':
                # Parse SQL dump for credentials
                patterns = [
                    r"(?i)CREATE USER ['\"]?(\w+)['\"]?.*IDENTIFIED BY ['\"]([^'\"]+)['\"]",
                    r"(?i)GRANT.*TO ['\"]?(\w+)['\"]?.*IDENTIFIED BY ['\"]([^'\"]+)['\"]",
                    r"(?i)INSERT INTO.*users.*VALUES.*['\"]([^'\"]{4,})['\"]",
                ]
                for pattern in patterns:
                    for match in re.finditer(pattern, content):
                        secrets.append({
                            'type': 'database_credential',
                            'value_redacted': match.group()[:50] + '...',
                            'source': str(file_path),
                            'severity': 'critical'
                        })
                        
            else:
                # Generic secret search
                for secret_type, pattern in self.brain.SECRET_PATTERNS.items():
                    for match in re.finditer(pattern, content):
                        value = match.group()
                        value_hash = hashlib.sha256(value.encode()).hexdigest()[:16]
                        if value_hash not in self.brain.secret_hashes:
                            self.brain.secret_hashes.add(value_hash)
                            secrets.append({
                                'type': secret_type,
                                'value_redacted': value[:8] + '***',
                                'value_hash': value_hash,
                                'source': str(file_path),
                                'severity': 'medium'
                            })
                            
        except Exception as e:
            logger.warning(f"Error parsing {file_path}: {e}")
            
        return secrets


class ResponseParser:
    """Parse phpinfo, server-status, etc responses."""
    
    def __init__(self, brain: ExtractionBrain):
        self.brain = brain
        
    async def parse(self, target: ExtractionTarget) -> ExtractionTarget:
        """Fetch and parse response for useful info."""
        logger.info(f"[PARSE] Analyzing: {target.url}")
        
        try:
            # Fetch the page
            proc = await asyncio.create_subprocess_exec(
                'curl', '-s', '-L', target.url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            content = stdout.decode('utf-8', errors='ignore')
            
            if target.exposure_type == 'phpinfo':
                secrets = self._parse_phpinfo(content, target.url)
            elif target.exposure_type == 'server-status':
                secrets = self._parse_server_status(content, target.url)
            else:
                secrets = []
                
            target.extracted = True
            target.secrets_found = secrets
            
        except Exception as e:
            target.error = str(e)
            
        return target
    
    def _parse_phpinfo(self, content: str, source: str) -> List[Dict]:
        """Extract sensitive info from phpinfo output."""
        secrets = []
        
        # Look for sensitive PHP variables
        patterns = [
            (r'DOCUMENT_ROOT.*?</td>\s*<td[^>]*>(.*?)</td>', 'document_root'),
            (r'SERVER_SOFTWARE.*?</td>\s*<td[^>]*>(.*?)</td>', 'server_software'),
            (r'_SERVER\["([^"]*PASS[^"]*)"\].*?</td>\s*<td[^>]*>(.*?)</td>', 'env_password'),
            (r'_SERVER\["([^"]*KEY[^"]*)"\].*?</td>\s*<td[^>]*>(.*?)</td>', 'env_key'),
            (r'_SERVER\["([^"]*SECRET[^"]*)"\].*?</td>\s*<td[^>]*>(.*?)</td>', 'env_secret'),
            (r'_SERVER\["([^"]*TOKEN[^"]*)"\].*?</td>\s*<td[^>]*>(.*?)</td>', 'env_token'),
        ]
        
        for pattern, secret_type in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                value = match.group(1) if match.lastindex == 1 else match.groups()
                secrets.append({
                    'type': f'phpinfo_{secret_type}',
                    'value_redacted': str(value)[:50] + '...',
                    'source': source,
                    'severity': 'high' if 'pass' in secret_type.lower() else 'medium'
                })
                
        return secrets
    
    def _parse_server_status(self, content: str, source: str) -> List[Dict]:
        """Extract info from Apache server-status."""
        secrets = []
        
        # Extract active connections/requests
        request_pattern = r'<td[^>]*>(\w+)</td>\s*<td[^>]*>(https?://[^<]+)</td>'
        for match in re.finditer(request_pattern, content):
            secrets.append({
                'type': 'active_request',
                'method': match.group(1),
                'url': match.group(2),
                'source': source,
                'severity': 'info'
            })
            
        # Look for internal IPs
        internal_ip_pattern = r'(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)'
        for match in re.finditer(internal_ip_pattern, content):
            secrets.append({
                'type': 'internal_ip',
                'value': match.group(1),
                'source': source,
                'severity': 'low'
            })
            
        return secrets


# =============================================================================
# MEG BULK SCANNER
# =============================================================================

class MegScanner:
    """Use meg for bulk endpoint checking."""
    
    SENSITIVE_PATHS = [
        '/.git/config',
        '/.git/HEAD', 
        '/.git/index',
        '/.svn/entries',
        '/.svn/wc.db',
        '/.hg/store/00manifest.i',
        '/.env',
        '/.env.local',
        '/.env.production',
        '/.env.development',
        '/.env.backup',
        '/config.php.bak',
        '/config.php.old',
        '/config.php~',
        '/config.php.swp',
        '/wp-config.php.bak',
        '/wp-config.php.old',
        '/settings.php.bak',
        '/.htpasswd',
        '/.htaccess',
        '/backup.sql',
        '/dump.sql',
        '/database.sql',
        '/db.sql',
        '/data.sql',
        '/backup.tar.gz',
        '/backup.zip',
        '/www.zip',
        '/site.zip',
        '/server-status',
        '/server-info',
        '/_profiler',
        '/debug',
        '/trace',
        '/actuator',
        '/actuator/env',
        '/actuator/heapdump',
        '/actuator/configprops',
        '/phpinfo.php',
        '/info.php',
        '/test.php',
        '/.DS_Store',
        '/Thumbs.db',
        '/crossdomain.xml',
        '/clientaccesspolicy.xml',
        '/.well-known/security.txt',
        '/security.txt',
    ]
    
    def __init__(self, brain: ExtractionBrain):
        self.brain = brain
        self.meg_output_dir = brain.output_dir / "meg_results"
        
    async def scan(self, hosts_file: str) -> List[ExtractionTarget]:
        """Run meg bulk scan against hosts."""
        logger.info(f"[MEG] Starting bulk scan against {hosts_file}")
        
        # Create paths file
        paths_file = self.meg_output_dir / "paths.txt"
        with open(paths_file, 'w') as f:
            f.write('\n'.join(self.SENSITIVE_PATHS))
            
        output_dir = self.meg_output_dir / "out"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # meg -d 100 -c 50 hosts paths output
            proc = await asyncio.create_subprocess_exec(
                'meg', '-d', '100', '-c', '50',
                str(hosts_file), str(paths_file), str(output_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=600)
            
        except FileNotFoundError:
            logger.warning("meg not found, trying ffuf instead")
            return await self._ffuf_fallback(hosts_file)
        except Exception as e:
            logger.error(f"meg error: {e}")
            return []
            
        # Parse meg results
        return await self._parse_meg_results(output_dir)
    
    async def _parse_meg_results(self, output_dir: Path) -> List[ExtractionTarget]:
        """Parse meg output for real findings."""
        targets = []
        
        for host_dir in output_dir.iterdir():
            if not host_dir.is_dir():
                continue
                
            for result_file in host_dir.glob('*'):
                try:
                    content = result_file.read_text(errors='ignore')
                    
                    # meg saves response bodies - check for real content
                    if self._is_real_finding(content, result_file.name):
                        url = f"{host_dir.name}{result_file.name}"
                        exposure_type = self._determine_type(result_file.name)
                        
                        targets.append(ExtractionTarget(
                            url=url,
                            host=host_dir.name,
                            exposure_type=exposure_type,
                            tool='meg-discovery',
                            severity='high',
                            nuclei_template='meg-bulk-scan'
                        ))
                        
                except:
                    continue
                    
        logger.info(f"[MEG] Found {len(targets)} real exposures")
        return targets
    
    def _is_real_finding(self, content: str, path: str) -> bool:
        """Check if meg result is a real finding vs 404/error."""
        # Skip if too small or error page
        if len(content) < 50:
            return False
            
        error_indicators = ['404', 'not found', 'error', 'forbidden', 'denied']
        content_lower = content[:500].lower()
        
        if any(err in content_lower for err in error_indicators):
            return False
            
        # Check for expected content based on path
        if '.git' in path:
            return '[core]' in content or 'ref:' in content
        elif '.env' in path:
            return '=' in content and len(content.split('\n')) > 1
        elif '.sql' in path:
            return any(x in content.upper() for x in ['CREATE', 'INSERT', 'SELECT', 'TABLE'])
        elif 'phpinfo' in path:
            return 'PHP Version' in content or 'phpinfo()' in content
            
        return True
    
    def _determine_type(self, path: str) -> str:
        """Determine exposure type from path."""
        if '.git' in path:
            return 'git'
        elif '.svn' in path:
            return 'svn'
        elif '.hg' in path:
            return 'hg'
        elif '.env' in path:
            return 'env'
        elif '.sql' in path or 'backup' in path:
            return 'backup'
        elif 'phpinfo' in path:
            return 'phpinfo'
        elif 'server-status' in path:
            return 'server-status'
        return 'unknown'
    
    async def _ffuf_fallback(self, hosts_file: str) -> List[ExtractionTarget]:
        """Fallback to ffuf if meg not available."""
        logger.info("[FFUF] Using ffuf as meg fallback")
        
        targets = []
        
        try:
            with open(hosts_file, 'r') as f:
                hosts = [h.strip() for h in f.readlines() if h.strip()]
        except:
            return targets
            
        # Create wordlist
        wordlist = self.meg_output_dir / "backup_wordlist.txt"
        with open(wordlist, 'w') as f:
            f.write('\n'.join(self.SENSITIVE_PATHS))
            
        # Run ffuf per host (batched)
        for host in hosts[:50]:  # Limit to 50 hosts
            try:
                output_file = self.meg_output_dir / f"ffuf_{host.replace('://', '_').replace('/', '_')}.json"
                
                proc = await asyncio.create_subprocess_exec(
                    'ffuf', '-u', f"{host}/FUZZ", '-w', str(wordlist),
                    '-mc', '200,201,301,302', '-o', str(output_file), '-of', 'json',
                    '-t', '50', '-timeout', '10',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(proc.communicate(), timeout=120)
                
                # Parse results
                if output_file.exists():
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        for result in data.get('results', []):
                            targets.append(ExtractionTarget(
                                url=result['url'],
                                host=host,
                                exposure_type=self._determine_type(result['input']['FUZZ']),
                                tool='ffuf-backup-scan',
                                severity='high',
                                nuclei_template='ffuf-backup-wordlist'
                            ))
                            
            except:
                continue
                
        return targets


# =============================================================================
# VULNERABILITY REPORTER
# =============================================================================

class VulnerabilityReporter:
    """Generate vulnerability reports for extracted content."""
    
    def __init__(self, output_dir: str):
        self.vuln_dir = Path(output_dir) / "vulnerabilities"
        self.vuln_dir.mkdir(parents=True, exist_ok=True)
        
    def report_extraction(self, target: ExtractionTarget):
        """Generate vulnerability report for extracted target."""
        if not target.extracted:
            return
            
        # Determine report type and severity
        severity = target.severity.upper()
        if target.secrets_found:
            severity = "CRITICAL"
            
        report_name = f"SOURCE-EXTRACTION-{target.exposure_type}-{target.host.replace('.', '_')}-{severity}.md"
        report_path = self.vuln_dir / report_name
        
        report = f"""# SOURCE CODE/SECRETS LEAK: {target.exposure_type.upper()} Exposed

## Finding Summary
- **Target**: {target.url}
- **Host**: {target.host}
- **Exposure Type**: {target.exposure_type}
- **Severity**: {severity}
- **Detection**: {target.nuclei_template}
- **Extraction Tool**: {target.tool}
- **Extracted To**: {target.extraction_path}

## Evidence

### Extraction Status
- **Successfully Extracted**: Yes
- **Extraction Path**: `{target.extraction_path}`

### Secrets Found: {len(target.secrets_found)}

"""
        
        if target.secrets_found:
            report += "| Type | Value (Redacted) | Severity | Source |\n"
            report += "|------|------------------|----------|--------|\n"
            
            for secret in target.secrets_found[:20]:  # Limit to 20
                report += f"| {secret.get('type', 'unknown')} | "
                report += f"{secret.get('value_redacted', '***')} | "
                report += f"{secret.get('severity', 'unknown')} | "
                report += f"{secret.get('source', 'unknown')[:50]} |\n"
                
            if len(target.secrets_found) > 20:
                report += f"\n*...and {len(target.secrets_found) - 20} more secrets*\n"
                
        report += f"""
## Impact

Exposed {target.exposure_type} allows attacker to:
"""
        
        if target.exposure_type == 'git':
            report += """- Access full source code history
- Extract hardcoded credentials from old commits
- Understand internal application architecture
- Find internal URLs and staging environments
- Review code for security vulnerabilities
"""
        elif target.exposure_type == 'env':
            report += """- Access database credentials
- Access API keys and tokens
- Access third-party service credentials
- Potentially compromise connected services
"""
        elif target.exposure_type == 'backup':
            report += """- Access database contents
- Extract user credentials
- Access application configuration
- Potentially find PII/sensitive data
"""
            
        report += """
## Recommendations

1. **IMMEDIATE**: Remove exposed files from web root
2. **IMMEDIATE**: Rotate ALL credentials found in extraction
3. Add deny rules for sensitive paths:
   - nginx: `location ~ /\\.(git|svn|env) { deny all; }`
   - apache: `<FilesMatch "\\.(git|svn|env)">Require all denied</FilesMatch>`
4. Audit all historical commits for leaked secrets
5. Implement pre-commit hooks to prevent secret commits
6. Use secrets management (Vault, AWS Secrets Manager)

## Timeline
- **Detected**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Extracted**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        with open(report_path, 'w') as f:
            f.write(report)
            
        logger.info(f"[REPORT] Generated: {report_path}")


# =============================================================================
# MAIN ORCHESTRATOR
# =============================================================================

class SourceExtractionOrchestrator:
    """Main orchestrator - coordinates all extraction activities."""
    
    def __init__(self, output_dir: str, temp_dir: str):
        self.brain = ExtractionBrain(output_dir, temp_dir)
        self.nuclei_parser = NucleiParser(self.brain)
        self.git_extractor = GitExtractor(self.brain)
        self.dvcs_extractor = DVCSExtractor(self.brain)
        self.downloader = DirectDownloader(self.brain)
        self.response_parser = ResponseParser(self.brain)
        self.meg_scanner = MegScanner(self.brain)
        self.reporter = VulnerabilityReporter(output_dir)
        
    async def run_auto(self, nuclei_results_file: str):
        """
        AUTO MODE: Parse Nuclei findings and extract everything.
        
        This is the main intelligent workflow.
        """
        logger.info("=" * 60)
        logger.info("TASK 42: SOURCE EXTRACTION - AUTO MODE")
        logger.info("=" * 60)
        
        # Step 1: Parse Nuclei findings
        targets = self.nuclei_parser.parse_findings(nuclei_results_file)
        logger.info(f"Found {len(targets)} extraction targets from Nuclei findings")
        
        if not targets:
            logger.warning("No extraction targets found. Try running meg scan for bulk discovery.")
            return
            
        # Step 2: Group by extraction type
        git_targets = [t for t in targets if t.tool == 'git-dumper']
        dvcs_targets = [t for t in targets if t.tool == 'dvcs-ripper']
        download_targets = [t for t in targets if t.tool == 'direct-download']
        parse_targets = [t for t in targets if t.tool == 'parse-response']
        
        logger.info(f"Targets: {len(git_targets)} git, {len(dvcs_targets)} dvcs, "
                   f"{len(download_targets)} downloads, {len(parse_targets)} parse")
        
        # Step 3: Extract in parallel by type
        results = []
        
        # Git extraction (most valuable)
        for target in git_targets:
            result = await self.git_extractor.extract(target)
            results.append(result)
            self.brain._save_checkpoint()
            
        # DVCS extraction
        for target in dvcs_targets:
            result = await self.dvcs_extractor.extract(target)
            results.append(result)
            self.brain._save_checkpoint()
            
        # Direct downloads (parallel)
        download_tasks = [self.downloader.download(t) for t in download_targets]
        if download_tasks:
            download_results = await asyncio.gather(*download_tasks, return_exceptions=True)
            results.extend([r for r in download_results if isinstance(r, ExtractionTarget)])
            
        # Response parsing (parallel)
        parse_tasks = [self.response_parser.parse(t) for t in parse_targets]
        if parse_tasks:
            parse_results = await asyncio.gather(*parse_tasks, return_exceptions=True)
            results.extend([r for r in parse_results if isinstance(r, ExtractionTarget)])
            
        # Step 4: Generate reports
        for result in results:
            if result.extracted:
                self.reporter.report_extraction(result)
                self.brain.extracted_targets.append(result)
                self.brain.all_secrets.extend(result.secrets_found)
                
        # Step 5: Save summary
        await self._save_summary()
        
        logger.info("=" * 60)
        logger.info(f"EXTRACTION COMPLETE: {len(self.brain.extracted_targets)} extracted, "
                   f"{len(self.brain.all_secrets)} secrets found")
        logger.info("=" * 60)
        
    async def run_meg_scan(self, hosts_file: str):
        """MEG MODE: Bulk endpoint discovery."""
        logger.info("=" * 60)
        logger.info("TASK 42: MEG BULK ENDPOINT SCAN")
        logger.info("=" * 60)
        
        new_targets = await self.meg_scanner.scan(hosts_file)
        
        if new_targets:
            logger.info(f"Found {len(new_targets)} new exposures via meg")
            
            # Extract the findings
            for target in new_targets:
                if target.exposure_type == 'git':
                    result = await self.git_extractor.extract(target)
                elif target.exposure_type in ['svn', 'hg']:
                    result = await self.dvcs_extractor.extract(target)
                else:
                    result = await self.downloader.download(target)
                    
                if result.extracted:
                    self.reporter.report_extraction(result)
                    self.brain.extracted_targets.append(result)
                    
        await self._save_summary()
        
    async def run_git_only(self, targets_file: str):
        """GIT-ONLY MODE: Extract git repos from list."""
        logger.info("=" * 60)
        logger.info("TASK 42: GIT EXTRACTION ONLY")
        logger.info("=" * 60)
        
        try:
            with open(targets_file, 'r') as f:
                urls = [u.strip() for u in f.readlines() if u.strip()]
        except Exception as e:
            logger.error(f"Cannot read targets file: {e}")
            return
            
        for url in urls:
            target = ExtractionTarget(
                url=url,
                host=urlparse(url).netloc,
                exposure_type='git',
                tool='git-dumper',
                severity='high',
                nuclei_template='manual-list'
            )
            
            result = await self.git_extractor.extract(target)
            if result.extracted:
                self.reporter.report_extraction(result)
                self.brain.extracted_targets.append(result)
                
        await self._save_summary()
        
    async def _save_summary(self):
        """Save extraction summary."""
        summary = {
            "extraction_time": datetime.now().isoformat(),
            "total_extracted": len(self.brain.extracted_targets),
            "total_secrets": len(self.brain.all_secrets),
            "by_type": defaultdict(int),
            "targets": [],
            "all_secrets": self.brain.all_secrets[:100]  # Limit for file size
        }
        
        for target in self.brain.extracted_targets:
            summary["by_type"][target.exposure_type] += 1
            summary["targets"].append({
                "url": target.url,
                "host": target.host,
                "type": target.exposure_type,
                "path": target.extraction_path,
                "secrets_count": len(target.secrets_found)
            })
            
        summary["by_type"] = dict(summary["by_type"])
        
        # Save main summary
        summary_file = self.brain.output_dir / "extraction_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
            
        # Save secrets inventory
        secrets_file = self.brain.output_dir / "secrets_found.json"
        with open(secrets_file, 'w') as f:
            json.dump(self.brain.all_secrets, f, indent=2)
            
        logger.info(f"Summary saved to {summary_file}")
        
        # Save internal URLs if found
        internal_urls = []
        for secret in self.brain.all_secrets:
            if secret.get('type') in ['internal_ip', 'active_request']:
                internal_urls.append(secret.get('value', secret.get('url', '')))
                
        if internal_urls:
            urls_file = self.brain.output_dir / "internal_urls_found.txt"
            with open(urls_file, 'w') as f:
                f.write('\n'.join(set(internal_urls)))


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Task 42: Source Extraction & Secrets Deep Dive",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto mode - extract based on Nuclei findings
  python source_extractor.py --mode auto --nuclei-results outputs/nuclei/exposures_results.json

  # Meg bulk scan for new discoveries  
  python source_extractor.py --mode meg-scan --hosts outputs/live_base_urls.txt

  # Git-only extraction from manual list
  python source_extractor.py --mode git-only --targets git_exposed_urls.txt
        """
    )
    
    parser.add_argument('--mode', required=True, 
                       choices=['auto', 'meg-scan', 'git-only', 'backup-hunt'],
                       help='Extraction mode')
    parser.add_argument('--nuclei-results', 
                       help='Path to Nuclei exposures JSON (for auto mode)')
    parser.add_argument('--hosts', 
                       help='Path to hosts file (for meg-scan mode)')
    parser.add_argument('--targets', 
                       help='Path to targets file (for git-only mode)')
    parser.add_argument('--output', default='outputs/extracted',
                       help='Output directory (default: outputs/extracted)')
    parser.add_argument('--temp', default='temp/task42',
                       help='Temp directory (default: temp/task42)')
    
    args = parser.parse_args()
    
    # Validate mode-specific args
    if args.mode == 'auto' and not args.nuclei_results:
        parser.error("--nuclei-results required for auto mode")
    if args.mode == 'meg-scan' and not args.hosts:
        parser.error("--hosts required for meg-scan mode")
    if args.mode == 'git-only' and not args.targets:
        parser.error("--targets required for git-only mode")
        
    # Run orchestrator
    orchestrator = SourceExtractionOrchestrator(args.output, args.temp)
    
    if args.mode == 'auto':
        asyncio.run(orchestrator.run_auto(args.nuclei_results))
    elif args.mode == 'meg-scan':
        asyncio.run(orchestrator.run_meg_scan(args.hosts))
    elif args.mode == 'git-only':
        asyncio.run(orchestrator.run_git_only(args.targets))
    elif args.mode == 'backup-hunt':
        # Same as meg-scan but focuses on backup wordlist
        asyncio.run(orchestrator.run_meg_scan(args.hosts))


if __name__ == "__main__":
    main()
