#!/usr/bin/env python3
"""
Task 33: Role-Diff Access Control Tester
Replays requests with different auth contexts and diffs responses to find BOLA/BFLA.

DYNAMIC PARAMETER DISCOVERY - Does NOT hardcode param names.

USE BRAIN PRINCIPLES:
1. BUILD ACCESS KNOWLEDGE: Learn which roles can access which endpoints
2. PRIORITIZE HIGH-VALUE: Focus on endpoints with user-specific data
3. DETECT ACCESS PATTERNS: Role hierarchy, anomalies between same-role users
4. LEARN FROM RESPONSES: Extract ownership data, detect data leakage
5. FINGERPRINT RESPONSES: Hash structure to detect identical responses
6. CONFIDENCE SCORING: CONFIRMED, LIKELY, POTENTIAL findings
"""

import json
import re
import sys
import time
import hashlib
import argparse
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict, field
from enum import Enum

try:
    import httpx
except ImportError:
    print("ERROR: httpx not installed. Run: pip install httpx")
    sys.exit(1)

try:
    from deepdiff import DeepDiff
except ImportError:
    print("ERROR: deepdiff not installed. Run: pip install deepdiff")
    sys.exit(1)


# ============================================================================
# ENUMS (defined first for type hints)
# ============================================================================
class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(Enum):
    """Confidence level for findings based on evidence quality."""
    CONFIRMED = "CONFIRMED"   # Direct data leakage observed (user2's data in user1's response)
    LIKELY = "LIKELY"         # Strong indicators but needs verification
    POTENTIAL = "POTENTIAL"   # Anomaly detected, manual review needed


class AccessPattern(Enum):
    """Classification of endpoint access patterns."""
    PUBLIC = "PUBLIC"             # Same response for all roles
    AUTH_REQUIRED = "AUTH_REQUIRED"  # 401 for unauth, 200 for authed
    ROLE_RESTRICTED = "ROLE_RESTRICTED"  # Different status per role
    ANOMALY = "ANOMALY"           # Same role, different results (BOLA signal)


# ============================================================================
# ACCESS KNOWLEDGE (THE BRAIN)
# ============================================================================
class AccessKnowledge:
    """
    The 'brain' that learns access patterns and ownership across all tests.
    Persists to disk for continuous learning.
    """
    
    def __init__(self, save_path: Path = None):
        self.save_path = save_path
        
        # Role -> set of endpoints that role can access
        self.role_access: Dict[str, Set[str]] = {}
        
        # Endpoint -> {role -> status_code}
        self.endpoint_access_map: Dict[str, Dict[str, int]] = {}
        
        # Endpoint -> AccessPattern classification
        self.endpoint_patterns: Dict[str, AccessPattern] = {}
        
        # ID -> owner (which user owns this ID)
        self.id_ownership: Dict[str, str] = {}
        
        # User -> [owned IDs]
        self.user_owned_ids: Dict[str, Set[str]] = {}
        
        # Endpoint -> response hash per role (for quick comparison)
        self.response_fingerprints: Dict[str, Dict[str, str]] = {}
        
        # User-specific data fields found (e.g., "email", "name", "phone")
        self.user_data_fields: Set[str] = set()
        
        # Priority scores for endpoints
        self.endpoint_priority: Dict[str, int] = {}
        
        if save_path and save_path.exists():
            self.load()
    
    def record_access(self, endpoint: str, role: str, status_code: int, 
                      response_hash: str = None):
        """Record that a role got a specific status code from an endpoint."""
        if endpoint not in self.endpoint_access_map:
            self.endpoint_access_map[endpoint] = {}
        
        self.endpoint_access_map[endpoint][role] = status_code
        
        # Track which endpoints each role can access
        if status_code == 200:
            if role not in self.role_access:
                self.role_access[role] = set()
            self.role_access[role].add(endpoint)
        
        # Store response fingerprint
        if response_hash:
            if endpoint not in self.response_fingerprints:
                self.response_fingerprints[endpoint] = {}
            self.response_fingerprints[endpoint][role] = response_hash
    
    def add_owned_id(self, user: str, id_value: str):
        """Record that a user owns a specific ID."""
        self.id_ownership[id_value] = user
        
        if user not in self.user_owned_ids:
            self.user_owned_ids[user] = set()
        self.user_owned_ids[user].add(id_value)
    
    def get_id_owner(self, id_value: str) -> Optional[str]:
        """Get the owner of an ID."""
        return self.id_ownership.get(id_value)
    
    def classify_endpoint(self, endpoint: str) -> AccessPattern:
        """Classify an endpoint based on observed access patterns."""
        if endpoint not in self.endpoint_access_map:
            return AccessPattern.PUBLIC
        
        access = self.endpoint_access_map[endpoint]
        statuses = list(access.values())
        roles = list(access.keys())
        
        # Check if all same-role users get same status
        user_statuses = {r: s for r, s in access.items() if r.startswith('user')}
        
        # ANOMALY: Same role type, different results
        if len(set(user_statuses.values())) > 1:
            self.endpoint_patterns[endpoint] = AccessPattern.ANOMALY
            return AccessPattern.ANOMALY
        
        # PUBLIC: All 200
        if all(s == 200 for s in statuses):
            # Check if responses are identical
            fingerprints = self.response_fingerprints.get(endpoint, {})
            if len(set(fingerprints.values())) == 1:
                self.endpoint_patterns[endpoint] = AccessPattern.PUBLIC
                return AccessPattern.PUBLIC
        
        # AUTH_REQUIRED: unauth gets 401, others get 200
        unauth_status = access.get('unauth', 0)
        authed_statuses = [s for r, s in access.items() if r != 'unauth']
        if unauth_status in [401, 403] and all(s == 200 for s in authed_statuses):
            self.endpoint_patterns[endpoint] = AccessPattern.AUTH_REQUIRED
            return AccessPattern.AUTH_REQUIRED
        
        # ROLE_RESTRICTED: Different statuses per role
        self.endpoint_patterns[endpoint] = AccessPattern.ROLE_RESTRICTED
        return AccessPattern.ROLE_RESTRICTED
    
    def calculate_priority(self, endpoint: str, has_id_params: bool = False,
                           method: str = "GET") -> int:
        """Calculate priority score for an endpoint (higher = test first)."""
        priority = 0
        
        # ANOMALY = highest priority
        pattern = self.endpoint_patterns.get(endpoint)
        if pattern == AccessPattern.ANOMALY:
            priority += 100
        elif pattern == AccessPattern.ROLE_RESTRICTED:
            priority += 50
        elif pattern == AccessPattern.AUTH_REQUIRED:
            priority += 30
        elif pattern == AccessPattern.PUBLIC:
            priority += 0  # lowest
        
        # State-changing methods
        if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            priority += 40
        
        # Has object ID parameters
        if has_id_params:
            priority += 30
        
        self.endpoint_priority[endpoint] = priority
        return priority
    
    def detect_cross_user_leakage(self, requesting_user: str, 
                                    response_data: Dict) -> List[Tuple[str, str]]:
        """Check if response contains data belonging to other users."""
        leakages = []
        
        def search_for_ids(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    if isinstance(value, (dict, list)):
                        search_for_ids(value, current_path)
                    else:
                        str_value = str(value)
                        owner = self.get_id_owner(str_value)
                        if owner and owner != requesting_user:
                            leakages.append((str_value, owner))
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    search_for_ids(item, f"{path}[{i}]")
        
        search_for_ids(response_data)
        return leakages
    
    def save(self):
        """Persist knowledge to disk."""
        if not self.save_path:
            return
        
        data = {
            "role_access": {k: list(v) for k, v in self.role_access.items()},
            "endpoint_access_map": self.endpoint_access_map,
            "endpoint_patterns": {k: v.value for k, v in self.endpoint_patterns.items()},
            "id_ownership": self.id_ownership,
            "user_owned_ids": {k: list(v) for k, v in self.user_owned_ids.items()},
            "response_fingerprints": self.response_fingerprints,
            "user_data_fields": list(self.user_data_fields),
            "endpoint_priority": self.endpoint_priority
        }
        
        self.save_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.save_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load(self):
        """Load knowledge from disk."""
        if not self.save_path or not self.save_path.exists():
            return
        
        try:
            with open(self.save_path) as f:
                data = json.load(f)
            
            self.role_access = {k: set(v) for k, v in data.get("role_access", {}).items()}
            self.endpoint_access_map = data.get("endpoint_access_map", {})
            self.endpoint_patterns = {
                k: AccessPattern(v) for k, v in data.get("endpoint_patterns", {}).items()
            }
            self.id_ownership = data.get("id_ownership", {})
            self.user_owned_ids = {k: set(v) for k, v in data.get("user_owned_ids", {}).items()}
            self.response_fingerprints = data.get("response_fingerprints", {})
            self.user_data_fields = set(data.get("user_data_fields", []))
            self.endpoint_priority = data.get("endpoint_priority", {})
        except Exception as e:
            print(f"[!] Failed to load access knowledge: {e}")


class ResponseLearner:
    """Extracts user-specific data and IDs from HTTP responses."""
    
    # Fields that typically contain user-specific data
    USER_DATA_FIELDS = {
        'id', 'user_id', 'userId', 'account_id', 'accountId',
        'email', 'name', 'username', 'phone', 'address',
        'first_name', 'last_name', 'firstName', 'lastName',
        'profile', 'owner', 'owner_id', 'created_by'
    }
    
    # ID field patterns
    ID_FIELD_PATTERNS = [
        r'.*[_-]?id$', r'.*[_-]?Id$', r'.*[_-]?ID$',
        r'^id$', r'^uuid$', r'^guid$'
    ]
    
    @classmethod
    def extract_user_data(cls, response_body: Dict, 
                          user_context: str = None) -> Dict[str, Any]:
        """Extract all user-specific data from a response."""
        user_data = {}
        
        def extract_recursive(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    # Check if this is a user data field
                    if key.lower() in {f.lower() for f in cls.USER_DATA_FIELDS}:
                        user_data[current_path] = value
                    
                    # Recurse
                    if isinstance(value, (dict, list)):
                        extract_recursive(value, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    extract_recursive(item, f"{path}[{i}]")
        
        extract_recursive(response_body)
        return user_data
    
    @classmethod
    def extract_ids(cls, response_body: Dict) -> List[Tuple[str, str]]:
        """Extract all ID values from a response. Returns [(field_path, id_value)]."""
        ids = []
        
        def extract_recursive(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    # Check if this looks like an ID field
                    is_id_field = any(re.match(p, key, re.I) for p in cls.ID_FIELD_PATTERNS)
                    
                    if isinstance(value, (dict, list)):
                        extract_recursive(value, current_path)
                    elif is_id_field and value:
                        ids.append((current_path, str(value)))
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    extract_recursive(item, f"{path}[{i}]")
        
        extract_recursive(response_body)
        return ids
    
    @classmethod
    def fingerprint_response(cls, response_body: Dict, 
                             ignore_fields: List[str] = None) -> str:
        """Generate a structural fingerprint of a response (ignoring dynamic values)."""
        ignore_fields = ignore_fields or []
        ignore_lower = {f.lower() for f in ignore_fields}
        
        def structure_only(obj):
            if isinstance(obj, dict):
                return {
                    k: structure_only(v) 
                    for k, v in sorted(obj.items())
                    if k.lower() not in ignore_lower
                }
            elif isinstance(obj, list):
                if not obj:
                    return []
                # Just get structure of first item
                return [structure_only(obj[0])] if obj else []
            else:
                # Return type name instead of value
                return type(obj).__name__
        
        structure = structure_only(response_body)
        return hashlib.md5(json.dumps(structure, sort_keys=True).encode()).hexdigest()


# ============================================================================
# CONFIGURATION
# ============================================================================
class Config:
    DELAY_MS = 100  # delay between requests
    TIMEOUT_S = 10  # request timeout
    BATCH_SIZE = 50  # endpoints per batch
    CHECKPOINT_INTERVAL = 50  # save checkpoint every N requests
    
    # Fields to ignore in diff (dynamic values)
    IGNORE_FIELDS = [
        "timestamp", "requestId", "request_id", "nonce", "csrf",
        "csrfToken", "_csrf", "date", "Date", "expires", "Expires",
        "set-cookie", "Set-Cookie", "etag", "ETag", "x-request-id"
    ]
    
    # Patterns that indicate object references
    ID_PATTERNS = [
        r'.*[_-]?id$',           # user_id, userId, account-id
        r'.*[_-]?ref$',          # order_ref
        r'.*[_-]?key$',          # api_key
        r'.*[_-]?token$',        # access_token
        r'^uuid$', r'^guid$',
        r'.*account.*', r'.*user.*', r'.*order.*', r'.*profile.*'
    ]


@dataclass
class AuthContext:
    name: str  # e.g., "user1", "user2", "unauth", "admin"
    headers: Dict[str, str]  # Authorization, Cookie, etc.
    user_id: Optional[str] = None  # The user's own ID if known
    owned_ids: List[str] = field(default_factory=list)  # IDs owned by this user
    role: str = "user"  # "admin", "user", "unauth"


@dataclass
class ParsedRequest:
    id: str
    method: str
    url: str
    path: str
    path_params: Dict[str, str]  # extracted from path segments
    query_params: Dict[str, str]
    body_params: Dict[str, Any]
    headers: Dict[str, str]
    body_raw: Optional[str]
    content_type: str
    detected_ids: List[str]  # values that look like object references
    original_auth: str
    source: str  # "har", "kiterunner", "playwright", "corpus"


@dataclass 
class Finding:
    id: str
    severity: Severity
    confidence: Confidence  # NEW: How sure are we?
    type: str  # "BOLA", "AUTH_BYPASS", "PRIV_ESC", "ENUMERATION"
    attack_type: str  # NEW: "cross_user_data", "auth_bypass", "role_escalation"
    endpoint: str
    url: str  # full URL
    method: str
    description: str
    evidence: Dict[str, Any]
    reproduction: List[str]
    poc: Dict[str, str]  # curl_command, raw_request
    impact: str
    remediation: str
    discovered_at: str
    vulnerability_file: str  # path to individual vuln report


# ============================================================================
# PARAMETER DISCOVERY (DYNAMIC)
# ============================================================================
class ParameterDiscovery:
    """Dynamically discover parameters from requests - NO hardcoding."""
    
    # UUID pattern
    UUID_PATTERN = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.I)
    
    # Numeric ID pattern
    NUMERIC_PATTERN = re.compile(r'^\d+$')
    
    # Base64-ish pattern (might be encoded ID)
    BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/=]{8,}$')
    
    @classmethod
    def extract_path_params(cls, path: str) -> Tuple[Dict[str, str], List[str]]:
        """Extract parameters from URL path segments."""
        params = {}
        detected_ids = []
        
        segments = [s for s in path.split('/') if s]
        
        for i, segment in enumerate(segments):
            # Check if this looks like an ID
            if cls.looks_like_id(segment):
                # Try to infer param name from previous segment
                param_name = segments[i-1] if i > 0 else f"path_param_{i}"
                # Singularize: /users/123 → user_id
                if param_name.endswith('s'):
                    param_name = param_name[:-1] + '_id'
                else:
                    param_name = param_name + '_id'
                
                params[param_name] = segment
                detected_ids.append(segment)
        
        return params, detected_ids
    
    @classmethod
    def extract_query_params(cls, url: str) -> Tuple[Dict[str, str], List[str]]:
        """Extract query parameters and detect which look like IDs."""
        parsed = urlparse(url)
        params = {}
        detected_ids = []
        
        query_dict = parse_qs(parsed.query)
        for key, values in query_dict.items():
            value = values[0] if values else ""
            params[key] = value
            
            # Check if this param looks like an ID reference
            if cls.param_name_suggests_id(key) or cls.looks_like_id(value):
                detected_ids.append(value)
        
        return params, detected_ids
    
    @classmethod
    def extract_body_params(cls, body: str, content_type: str) -> Tuple[Dict[str, Any], List[str]]:
        """Extract body parameters based on content type."""
        params = {}
        detected_ids = []
        
        if not body:
            return params, detected_ids
        
        # JSON body
        if 'json' in content_type.lower():
            try:
                data = json.loads(body)
                params, detected_ids = cls._extract_from_json(data)
            except json.JSONDecodeError:
                pass
        
        # Form body
        elif 'form' in content_type.lower():
            try:
                form_dict = parse_qs(body)
                for key, values in form_dict.items():
                    value = values[0] if values else ""
                    params[key] = value
                    if cls.param_name_suggests_id(key) or cls.looks_like_id(value):
                        detected_ids.append(value)
            except:
                pass
        
        return params, detected_ids
    
    @classmethod
    def _extract_from_json(cls, data: Any, prefix: str = "") -> Tuple[Dict[str, Any], List[str]]:
        """Recursively extract params from JSON."""
        params = {}
        detected_ids = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                
                if isinstance(value, (dict, list)):
                    sub_params, sub_ids = cls._extract_from_json(value, full_key)
                    params.update(sub_params)
                    detected_ids.extend(sub_ids)
                else:
                    params[full_key] = value
                    str_value = str(value)
                    if cls.param_name_suggests_id(key) or cls.looks_like_id(str_value):
                        detected_ids.append(str_value)
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                sub_params, sub_ids = cls._extract_from_json(item, f"{prefix}[{i}]")
                params.update(sub_params)
                detected_ids.extend(sub_ids)
        
        return params, detected_ids
    
    @classmethod
    def looks_like_id(cls, value: str) -> bool:
        """Check if a value looks like an object reference/ID."""
        if not value:
            return False
        
        # UUID
        if cls.UUID_PATTERN.match(value):
            return True
        
        # Numeric (but not too short - "0", "1" might be booleans)
        if cls.NUMERIC_PATTERN.match(value) and len(value) >= 2:
            return True
        
        # Alphanumeric that's not too long (might be slug or short ID)
        if re.match(r'^[a-zA-Z0-9_-]{4,36}$', value):
            # Not a common word
            common_words = {'true', 'false', 'null', 'none', 'active', 'inactive', 'pending'}
            if value.lower() not in common_words:
                return True
        
        return False
    
    @classmethod
    def param_name_suggests_id(cls, name: str) -> bool:
        """Check if parameter name suggests it's an object reference."""
        name_lower = name.lower()
        
        for pattern in Config.ID_PATTERNS:
            if re.match(pattern, name_lower):
                return True
        
        return False


# ============================================================================
# REQUEST PARSING
# ============================================================================
class RequestParser:
    """Parse requests from various sources into uniform format."""
    
    @classmethod
    def from_har_entry(cls, entry: Dict, source_auth: str = "unknown") -> ParsedRequest:
        """Parse HAR entry into ParsedRequest."""
        request = entry.get('request', entry)  # Handle both formats
        
        url = request.get('url', '')
        method = request.get('method', 'GET').upper()
        parsed_url = urlparse(url)
        
        # Extract headers
        headers = {}
        for h in request.get('headers', []):
            headers[h['name']] = h['value']
        
        # Get body
        post_data = request.get('postData', {})
        body_raw = post_data.get('text', '')
        content_type = post_data.get('mimeType', headers.get('Content-Type', ''))
        
        # Discover parameters
        path_params, path_ids = ParameterDiscovery.extract_path_params(parsed_url.path)
        query_params, query_ids = ParameterDiscovery.extract_query_params(url)
        body_params, body_ids = ParameterDiscovery.extract_body_params(body_raw, content_type)
        
        # Combine detected IDs
        detected_ids = list(set(path_ids + query_ids + body_ids))
        
        # Generate unique ID
        req_id = hashlib.md5(f"{method}:{url}:{body_raw}".encode()).hexdigest()[:12]
        
        return ParsedRequest(
            id=f"req_{req_id}",
            method=method,
            url=url,
            path=parsed_url.path,
            path_params=path_params,
            query_params=query_params,
            body_params=body_params,
            headers=headers,
            body_raw=body_raw,
            content_type=content_type,
            detected_ids=detected_ids,
            original_auth=source_auth,
            source="har"
        )
    
    @classmethod
    def from_url_line(cls, line: str, source: str = "corpus") -> ParsedRequest:
        """Parse a simple URL line into ParsedRequest."""
        url = line.strip()
        if not url:
            return None
        
        parsed_url = urlparse(url)
        
        # Discover parameters
        path_params, path_ids = ParameterDiscovery.extract_path_params(parsed_url.path)
        query_params, query_ids = ParameterDiscovery.extract_query_params(url)
        
        detected_ids = list(set(path_ids + query_ids))
        
        req_id = hashlib.md5(url.encode()).hexdigest()[:12]
        
        return ParsedRequest(
            id=f"req_{req_id}",
            method="GET",
            url=url,
            path=parsed_url.path,
            path_params=path_params,
            query_params=query_params,
            body_params={},
            headers={},
            body_raw="",
            content_type="",
            detected_ids=detected_ids,
            original_auth="unknown",
            source=source
        )


# ============================================================================
# RESPONSE DIFFING
# ============================================================================
class ResponseDiffer:
    """Compare responses and detect access control issues."""
    
    @classmethod
    def normalize_response(cls, response: Dict) -> Dict:
        """Remove dynamic fields before comparison."""
        normalized = json.loads(json.dumps(response))  # Deep copy
        
        def remove_ignored(obj, path=""):
            if isinstance(obj, dict):
                keys_to_remove = []
                for key in obj:
                    if any(key.lower() == f.lower() for f in Config.IGNORE_FIELDS):
                        keys_to_remove.append(key)
                    else:
                        remove_ignored(obj[key], f"{path}.{key}")
                for key in keys_to_remove:
                    del obj[key]
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    remove_ignored(item, f"{path}[{i}]")
        
        remove_ignored(normalized)
        return normalized
    
    @classmethod
    def diff_responses(cls, resp1: Dict, resp2: Dict, 
                       auth1: str, auth2: str) -> Tuple[str, Dict]:
        """
        Compare two responses and determine if there's an access control issue.
        Returns (severity_or_none, diff_details)
        """
        # Normalize both responses
        norm1 = cls.normalize_response(resp1.get('body', {}))
        norm2 = cls.normalize_response(resp2.get('body', {}))
        
        status1 = resp1.get('status_code', 0)
        status2 = resp2.get('status_code', 0)
        
        diff = DeepDiff(norm1, norm2, ignore_order=True)
        
        details = {
            "status1": status1,
            "status2": status2,
            "auth1": auth1,
            "auth2": auth2,
            "diff": str(diff) if diff else "IDENTICAL",
            "body1_preview": str(norm1)[:500],
            "body2_preview": str(norm2)[:500]
        }
        
        # Analysis logic
        severity = None
        
        # Case 1: Both 200 and identical bodies
        if status1 == 200 and status2 == 200 and not diff:
            # If one is authed and one is not, or different users
            if auth1 != auth2:
                if 'unauth' in [auth1, auth2]:
                    severity = Severity.CRITICAL  # Auth bypass
                    details['issue'] = "Unauthenticated user gets same data as authenticated"
                elif auth1.startswith('user') and auth2.startswith('user'):
                    severity = Severity.CRITICAL  # BOLA
                    details['issue'] = "Different users get identical sensitive data"
                elif 'admin' in [auth1, auth2]:
                    severity = Severity.CRITICAL  # Privilege escalation
                    details['issue'] = "Non-admin can access admin data"
        
        # Case 2: Both 200 but should be 403/401 for one
        elif status1 == 200 and status2 == 200:
            # Might still be issue if responses differ but both succeed
            if 'unauth' in [auth1, auth2]:
                severity = Severity.HIGH
                details['issue'] = "Endpoint returns 200 for unauthenticated request"
        
        # Case 3: 403 vs 404 = enumeration
        elif {status1, status2} == {403, 404}:
            severity = Severity.MEDIUM
            details['issue'] = "Different error codes reveal resource existence (enumeration)"
        
        # Case 4: Unexpected 200 for unauth
        elif 'unauth' in [auth1, auth2]:
            unauth_status = status1 if auth1 == 'unauth' else status2
            if unauth_status == 200:
                severity = Severity.HIGH
                details['issue'] = "Endpoint accessible without authentication"
        
        return severity, details


# ============================================================================
# MAIN TESTER
# ============================================================================
class RoleDiffTester:
    """Main class for role-diff testing with intelligent learning."""
    
    def __init__(self, auth_contexts: List[AuthContext], output_dir: Path):
        self.auth_contexts = {ctx.name: ctx for ctx in auth_contexts}
        self.output_dir = output_dir
        self.temp_dir = output_dir.parent / 'temp' / 'task33'
        self.findings: List[Finding] = []
        self.checkpoint = {"processed": 0, "findings": 0}
        
        # Create directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        (self.temp_dir / 'responses').mkdir(exist_ok=True)
        
        # Initialize the BRAIN
        self.knowledge = AccessKnowledge(
            save_path=self.temp_dir / 'access_knowledge.json'
        )
        
        # Extract owned IDs from auth contexts
        for ctx_name, ctx in self.auth_contexts.items():
            if ctx.user_id:
                self.knowledge.add_owned_id(ctx_name, ctx.user_id)
            for owned_id in ctx.owned_ids:
                self.knowledge.add_owned_id(ctx_name, owned_id)
        
        # HTTP client
        self.client = httpx.Client(timeout=Config.TIMEOUT_S, verify=False)
    
    def load_requests(self, sources: Dict[str, Path]) -> List[ParsedRequest]:
        """Load requests from all sources."""
        requests = []
        seen_urls = set()
        
        # Load HAR endpoints
        if 'har' in sources and sources['har'].exists():
            print(f"[*] Loading HAR: {sources['har']}")
            with open(sources['har']) as f:
                try:
                    data = json.load(f)
                    entries = data if isinstance(data, list) else data.get('entries', [])
                    for entry in entries:
                        req = RequestParser.from_har_entry(entry)
                        if req and req.url not in seen_urls:
                            requests.append(req)
                            seen_urls.add(req.url)
                except json.JSONDecodeError:
                    print(f"[!] Failed to parse HAR JSON")
        
        # Load URL lists
        for source_name in ['kiterunner', 'dynamic', 'sensitive', 'corpus']:
            if source_name in sources and sources[source_name].exists():
                print(f"[*] Loading {source_name}: {sources[source_name]}")
                with open(sources[source_name]) as f:
                    for line in f:
                        url = line.strip()
                        if url and url not in seen_urls:
                            req = RequestParser.from_url_line(url, source_name)
                            if req:
                                requests.append(req)
                                seen_urls.add(url)
        
        print(f"[+] Loaded {len(requests)} unique requests")
        
        # Save parsed requests
        with open(self.temp_dir / 'requests_with_params.json', 'w') as f:
            json.dump([asdict(r) for r in requests], f, indent=2)
        
        return requests
    
    def replay_request(self, req: ParsedRequest, auth: AuthContext) -> Dict:
        """Replay a single request with given auth context."""
        headers = dict(req.headers)
        headers.update(auth.headers)
        
        try:
            if req.method == 'GET':
                resp = self.client.get(req.url, headers=headers)
            elif req.method == 'POST':
                resp = self.client.post(req.url, headers=headers, content=req.body_raw)
            elif req.method == 'PUT':
                resp = self.client.put(req.url, headers=headers, content=req.body_raw)
            elif req.method == 'DELETE':
                resp = self.client.delete(req.url, headers=headers)
            elif req.method == 'PATCH':
                resp = self.client.patch(req.url, headers=headers, content=req.body_raw)
            else:
                resp = self.client.request(req.method, req.url, headers=headers, content=req.body_raw)
            
            # Parse response body
            body = {}
            try:
                body = resp.json()
            except:
                body = {"_raw": resp.text[:2000]}
            
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": body,
                "elapsed_ms": resp.elapsed.total_seconds() * 1000
            }
        
        except Exception as e:
            return {
                "status_code": 0,
                "error": str(e),
                "headers": {},
                "body": {}
            }
    
    def test_request(self, req: ParsedRequest) -> List[Finding]:
        """Test a single request with all auth contexts."""
        findings = []
        responses = {}
        
        # Replay with each auth context
        for auth_name, auth_ctx in self.auth_contexts.items():
            time.sleep(Config.DELAY_MS / 1000)
            responses[auth_name] = self.replay_request(req, auth_ctx)
        
        # Save responses
        resp_dir = self.temp_dir / 'responses' / req.id
        resp_dir.mkdir(exist_ok=True)
        for auth_name, resp in responses.items():
            with open(resp_dir / f'{auth_name}.json', 'w') as f:
                json.dump(resp, f, indent=2)
        
        # Compare all pairs
        auth_names = list(self.auth_contexts.keys())
        for i, auth1 in enumerate(auth_names):
            for auth2 in auth_names[i+1:]:
                severity, details = ResponseDiffer.diff_responses(
                    responses[auth1], responses[auth2], auth1, auth2
                )
                
                if severity:
                    finding_id = f"ACL-{len(self.findings)+len(findings)+1:04d}"
                    finding_type = self._determine_type(auth1, auth2, details)
                    vuln_filename = f"{finding_id}-{finding_type}-{severity.value}.md"
                    
                    # Generate POC
                    poc = self._generate_poc(req, auth2)
                    
                    # Generate impact assessment
                    impact = self._assess_impact(finding_type, req, details)
                    
                    finding = Finding(
                        id=finding_id,
                        severity=severity,
                        confidence=Confidence.POTENTIAL,  # Legacy: no intelligence
                        type=finding_type,
                        attack_type="legacy_detection",
                        endpoint=f"{req.method} {req.path}",
                        url=req.url,
                        method=req.method,
                        description=details.get('issue', 'Access control anomaly detected'),
                        evidence={
                            "request_url": req.url,
                            "detected_ids": req.detected_ids,
                            "auth_context_1": auth1,
                            "auth_context_2": auth2,
                            "response_1_status": responses[auth1].get('status_code'),
                            "response_2_status": responses[auth2].get('status_code'),
                            "response_1_preview": str(responses[auth1].get('body', {}))[:500],
                            "response_2_preview": str(responses[auth2].get('body', {}))[:500],
                            **details
                        },
                        reproduction=[
                            f"1. Obtain authentication token/cookie for {auth2}",
                            f"2. Send {req.method} request to: {req.url}",
                            f"3. Include {auth2}'s auth headers in the request",
                            f"4. Observe that {auth1}'s data is returned (should be denied)",
                            f"5. Compare response with legitimate {auth1} request"
                        ],
                        poc=poc,
                        impact=impact,
                        remediation=self._get_remediation(finding_type),
                        discovered_at=datetime.now().isoformat(),
                        vulnerability_file=f"outputs/vulnerabilities/{vuln_filename}"
                    )
                    findings.append(finding)
        
        return findings
    
    def _generate_poc(self, req: ParsedRequest, attacker_auth: str) -> Dict[str, str]:
        """Generate POC curl command and raw HTTP request."""
        # Get attacker's headers
        attacker_ctx = self.auth_contexts.get(attacker_auth)
        headers = dict(req.headers)
        if attacker_ctx:
            headers.update(attacker_ctx.headers)
        
        # Build curl command
        curl_parts = [f"curl -X {req.method} '{req.url}'"]
        for key, value in headers.items():
            # Mask sensitive values for display
            display_value = value[:20] + "..." if len(value) > 20 else value
            curl_parts.append(f"  -H '{key}: {display_value}'")
        if req.body_raw:
            curl_parts.append(f"  -d '{req.body_raw[:200]}...'")
        curl_command = " \\\n".join(curl_parts)
        
        # Build raw HTTP request
        parsed = urlparse(req.url)
        raw_lines = [f"{req.method} {parsed.path}{'?' + parsed.query if parsed.query else ''} HTTP/1.1"]
        raw_lines.append(f"Host: {parsed.netloc}")
        for key, value in headers.items():
            display_value = value[:50] + "..." if len(value) > 50 else value
            raw_lines.append(f"{key}: {display_value}")
        if req.body_raw:
            raw_lines.append("")
            raw_lines.append(req.body_raw[:500])
        raw_request = "\n".join(raw_lines)
        
        return {
            "curl_command": curl_command,
            "raw_request": raw_request
        }
    
    def _assess_impact(self, finding_type: str, req: ParsedRequest, details: Dict) -> str:
        """Generate impact assessment based on finding type and endpoint."""
        impacts = {
            "BOLA": f"Attacker can access other users' resources at {req.path}. "
                    f"Detected IDs that can be manipulated: {req.detected_ids}. "
                    "This may expose sensitive user data, PII, or allow unauthorized modifications.",
            
            "AUTH_BYPASS": f"Endpoint {req.path} is accessible without authentication. "
                          "Any unauthenticated attacker can access this resource. "
                          "If the endpoint returns sensitive data or allows modifications, impact is severe.",
            
            "PRIV_ESC": f"Non-admin user can access admin-only endpoint {req.path}. "
                       "Attacker can perform privileged operations without proper authorization.",
            
            "ENUMERATION": f"Different error responses at {req.path} allow resource enumeration. "
                          "Attacker can discover valid IDs, usernames, or other resources."
        }
        
        base_impact = impacts.get(finding_type, "Access control vulnerability detected.")
        
        # Add method-specific impact
        if req.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            base_impact += f" As this is a {req.method} request, data modification or deletion may be possible."
        
        return base_impact
    
    def _get_remediation(self, finding_type: str) -> str:
        """Get remediation guidance based on finding type."""
        remediations = {
            "BOLA": """1. Implement object-level authorization checks:
   - Verify the requesting user owns or has access to the requested resource
   - Use the authenticated user's ID from the session, not from request parameters
   - Example: if request.user.id != resource.owner_id: return 403
2. Use indirect object references (UUIDs) instead of sequential IDs
3. Add automated access control tests for all endpoints""",
            
            "AUTH_BYPASS": """1. Add authentication middleware to protect this endpoint
2. Verify authentication token/session is present and valid
3. Return 401 Unauthorized for missing credentials
4. Return 403 Forbidden for invalid/expired credentials
5. Review all endpoints to ensure auth requirements are enforced""",
            
            "PRIV_ESC": """1. Implement role-based access control (RBAC)
2. Verify user has required role/permissions before processing request
3. Separate admin and user endpoints or add role checks
4. Log and alert on unauthorized access attempts
5. Regular audit of privilege assignments""",
            
            "ENUMERATION": """1. Return consistent error responses (always 404 or always 403)
2. Implement rate limiting to slow enumeration attempts
3. Use non-sequential, unpredictable identifiers
4. Add CAPTCHA for repeated failed requests
5. Log and alert on enumeration patterns"""
        }
        return remediations.get(finding_type, "Implement proper authorization checks.")
    
    def _determine_type(self, auth1: str, auth2: str, details: Dict) -> str:
        """Determine the type of access control issue."""
        if 'unauth' in [auth1, auth2]:
            return "AUTH_BYPASS"
        elif 'admin' in [auth1, auth2]:
            return "PRIV_ESC"
        elif details.get('issue', '').find('enumeration') >= 0:
            return "ENUMERATION"
        else:
            return "BOLA"
    
    def quick_probe(self, requests: List[ParsedRequest]):
        """Phase B: Quick probe to learn access patterns before deep testing."""
        print(f"\n[*] PHASE B: Quick probing {len(requests)} endpoints to learn access patterns...")
        
        for i, req in enumerate(requests):
            if (i + 1) % 20 == 0:
                print(f"    [{i+1}/{len(requests)}] probed...")
            
            endpoint_key = f"{req.method} {req.path}"
            
            for auth_name, auth_ctx in self.auth_contexts.items():
                try:
                    time.sleep(Config.DELAY_MS / 1000 / 2)  # Faster for probe
                    
                    headers = dict(req.headers)
                    headers.update(auth_ctx.headers)
                    
                    resp = self.client.get(req.url, headers=headers, timeout=5)
                    
                    # Try to get response body
                    body = {}
                    try:
                        body = resp.json()
                    except:
                        body = {"_raw": resp.text[:500]}
                    
                    # Calculate fingerprint
                    fingerprint = ResponseLearner.fingerprint_response(body, Config.IGNORE_FIELDS)
                    
                    # Record in knowledge
                    self.knowledge.record_access(endpoint_key, auth_name, resp.status_code, fingerprint)
                    
                    # Extract IDs and learn ownership
                    ids_found = ResponseLearner.extract_ids(body)
                    for field_path, id_value in ids_found:
                        # If this is the user's own request, they own these IDs
                        if auth_ctx.user_id and resp.status_code == 200:
                            self.knowledge.add_owned_id(auth_name, id_value)
                    
                except Exception as e:
                    pass  # Silent fail during probe
            
            # Classify this endpoint
            pattern = self.knowledge.classify_endpoint(endpoint_key)
            
            # Calculate priority
            has_id_params = len(req.detected_ids) > 0
            self.knowledge.calculate_priority(endpoint_key, has_id_params, req.method)
        
        # Save learned knowledge
        self.knowledge.save()
        
        # Report what we learned
        patterns = self.knowledge.endpoint_patterns
        print(f"\n[*] PHASE B Complete - Access Patterns Learned:")
        print(f"    PUBLIC endpoints: {sum(1 for p in patterns.values() if p == AccessPattern.PUBLIC)}")
        print(f"    AUTH_REQUIRED endpoints: {sum(1 for p in patterns.values() if p == AccessPattern.AUTH_REQUIRED)}")
        print(f"    ROLE_RESTRICTED endpoints: {sum(1 for p in patterns.values() if p == AccessPattern.ROLE_RESTRICTED)}")
        print(f"    ANOMALY endpoints (BOLA signals!): {sum(1 for p in patterns.values() if p == AccessPattern.ANOMALY)}")
        print(f"    IDs owned by users: {sum(len(ids) for ids in self.knowledge.user_owned_ids.values())}")
    
    def prioritize_requests(self, requests: List[ParsedRequest]) -> List[ParsedRequest]:
        """Sort requests by priority (highest first)."""
        def get_priority(req):
            endpoint_key = f"{req.method} {req.path}"
            return self.knowledge.endpoint_priority.get(endpoint_key, 0)
        
        sorted_requests = sorted(requests, key=get_priority, reverse=True)
        
        # Log top priorities
        print("\n[*] Top 10 Priority Targets:")
        for i, req in enumerate(sorted_requests[:10]):
            endpoint_key = f"{req.method} {req.path}"
            priority = self.knowledge.endpoint_priority.get(endpoint_key, 0)
            pattern = self.knowledge.endpoint_patterns.get(endpoint_key, AccessPattern.PUBLIC)
            print(f"    {i+1}. [{priority}] {pattern.value}: {req.method} {req.path[:50]}")
        
        return sorted_requests
    
    def run(self, requests: List[ParsedRequest], resume_from: int = 0):
        """Run the intelligent test suite with learning."""
        print(f"\n{'='*70}")
        print(f"INTELLIGENT ROLE-DIFF ACCESS CONTROL TESTING")
        print(f"{'='*70}")
        print(f"[*] {len(requests)} requests, {len(self.auth_contexts)} auth contexts")
        print(f"[*] Auth contexts: {list(self.auth_contexts.keys())}")
        print(f"[*] Known owned IDs: {dict(self.knowledge.user_owned_ids)}")
        
        # PHASE B: Quick probe to learn patterns (unless resuming)
        if resume_from == 0:
            self.quick_probe(requests)
        
        # Prioritize based on learned patterns
        prioritized = self.prioritize_requests(requests)
        
        # Skip PUBLIC endpoints (unless they have ID params)
        high_value = []
        skipped = 0
        for req in prioritized:
            endpoint_key = f"{req.method} {req.path}"
            pattern = self.knowledge.endpoint_patterns.get(endpoint_key, AccessPattern.PUBLIC)
            
            if pattern == AccessPattern.PUBLIC and not req.detected_ids:
                skipped += 1
                continue
            high_value.append(req)
        
        print(f"\n[*] Skipping {skipped} PUBLIC endpoints without ID params")
        print(f"[*] Deep testing {len(high_value)} high-value endpoints")
        
        # PHASE C: Deep testing with learning
        print(f"\n[*] PHASE C: Deep testing with role swapping...")
        
        for i, req in enumerate(high_value[resume_from:], start=resume_from):
            print(f"[{i+1}/{len(high_value)}] Testing: {req.method} {req.path[:60]}...")
            
            new_findings = self.test_request_intelligent(req)
            self.findings.extend(new_findings)
            
            if new_findings:
                for f in new_findings:
                    print(f"    [!] {f.confidence.value} {f.type}: {f.description[:50]}...")
            
            # Checkpoint
            if (i + 1) % Config.CHECKPOINT_INTERVAL == 0:
                self.save_checkpoint(i + 1)
                self.knowledge.save()
                print(f"    [checkpoint] Saved progress: {i+1} requests, {len(self.findings)} findings")
        
        # Final save
        self.knowledge.save()
        self.save_results()
        
        # Report summary
        self._print_intelligence_summary()
    
    def test_request_intelligent(self, req: ParsedRequest) -> List[Finding]:
        """Test a single request with intelligent learning."""
        findings = []
        responses = {}
        
        # Replay with each auth context
        for auth_name, auth_ctx in self.auth_contexts.items():
            time.sleep(Config.DELAY_MS / 1000)
            responses[auth_name] = self.replay_request(req, auth_ctx)
            
            # LEARN from response
            body = responses[auth_name].get('body', {})
            if body:
                # Extract and record IDs
                ids_found = ResponseLearner.extract_ids(body)
                for field_path, id_value in ids_found:
                    if auth_ctx.user_id and responses[auth_name].get('status_code') == 200:
                        self.knowledge.add_owned_id(auth_name, id_value)
        
        # Save responses
        resp_dir = self.temp_dir / 'responses' / req.id
        resp_dir.mkdir(exist_ok=True)
        for auth_name, resp in responses.items():
            with open(resp_dir / f'{auth_name}.json', 'w') as f:
                json.dump(resp, f, indent=2)
        
        # Compare all pairs with intelligent analysis
        auth_names = list(self.auth_contexts.keys())
        for i, auth1 in enumerate(auth_names):
            for auth2 in auth_names[i+1:]:
                # Check for cross-user data leakage
                body1 = responses[auth1].get('body', {})
                body2 = responses[auth2].get('body', {})
                
                # Does user2's response contain user1's data?
                leakage_in_resp2 = self.knowledge.detect_cross_user_leakage(auth2, body2)
                leakage_in_resp1 = self.knowledge.detect_cross_user_leakage(auth1, body1)
                
                # Standard diff analysis
                severity, details = ResponseDiffer.diff_responses(
                    responses[auth1], responses[auth2], auth1, auth2
                )
                
                # Determine confidence based on evidence
                confidence = Confidence.POTENTIAL
                attack_type = "access_anomaly"
                
                # CONFIRMED: Direct data leakage
                if leakage_in_resp2:
                    confidence = Confidence.CONFIRMED
                    attack_type = "cross_user_data"
                    details['leaked_ids'] = [f"{lid} (owned by {owner})" for lid, owner in leakage_in_resp2]
                    details['issue'] = f"Response contains data owned by other users: {leakage_in_resp2}"
                    severity = Severity.CRITICAL
                elif leakage_in_resp1:
                    confidence = Confidence.CONFIRMED
                    attack_type = "cross_user_data"
                    details['leaked_ids'] = [f"{lid} (owned by {owner})" for lid, owner in leakage_in_resp1]
                    severity = Severity.CRITICAL
                elif severity == Severity.CRITICAL:
                    confidence = Confidence.LIKELY
                    attack_type = "auth_bypass" if 'unauth' in [auth1, auth2] else "bola"
                elif severity == Severity.HIGH:
                    confidence = Confidence.LIKELY
                    attack_type = "auth_bypass" if 'unauth' in [auth1, auth2] else "access_control"
                elif severity:
                    confidence = Confidence.POTENTIAL
                
                if severity:
                    finding_id = f"ACL-{len(self.findings)+len(findings)+1:04d}"
                    finding_type = self._determine_type(auth1, auth2, details)
                    vuln_filename = f"{finding_id}-{finding_type}-{severity.value}.md"
                    
                    poc = self._generate_poc(req, auth2)
                    impact = self._assess_impact(finding_type, req, details)
                    
                    finding = Finding(
                        id=finding_id,
                        severity=severity,
                        confidence=confidence,
                        type=finding_type,
                        attack_type=attack_type,
                        endpoint=f"{req.method} {req.path}",
                        url=req.url,
                        method=req.method,
                        description=details.get('issue', 'Access control anomaly detected'),
                        evidence={
                            "request_url": req.url,
                            "detected_ids": req.detected_ids,
                            "auth_context_1": auth1,
                            "auth_context_2": auth2,
                            "response_1_status": responses[auth1].get('status_code'),
                            "response_2_status": responses[auth2].get('status_code'),
                            "response_1_preview": str(responses[auth1].get('body', {}))[:500],
                            "response_2_preview": str(responses[auth2].get('body', {}))[:500],
                            **details
                        },
                        reproduction=[
                            f"1. Obtain authentication token/cookie for {auth2}",
                            f"2. Send {req.method} request to: {req.url}",
                            f"3. Include {auth2}'s auth headers in the request",
                            f"4. Observe that {auth1}'s data is returned (should be denied)",
                            f"5. Compare response with legitimate {auth1} request"
                        ],
                        poc=poc,
                        impact=impact,
                        remediation=self._get_remediation(finding_type),
                        discovered_at=datetime.now().isoformat(),
                        vulnerability_file=f"outputs/vulnerabilities/{vuln_filename}"
                    )
                    findings.append(finding)
        
        return findings
    
    def _print_intelligence_summary(self):
        """Print summary of what the brain learned."""
        print(f"\n{'='*70}")
        print("INTELLIGENCE SUMMARY")
        print(f"{'='*70}")
        print(f"Total IDs learned: {len(self.knowledge.id_ownership)}")
        print(f"Users with owned IDs:")
        for user, ids in self.knowledge.user_owned_ids.items():
            print(f"    {user}: {len(ids)} IDs")
        
        # Confidence breakdown
        confirmed = sum(1 for f in self.findings if f.confidence == Confidence.CONFIRMED)
        likely = sum(1 for f in self.findings if f.confidence == Confidence.LIKELY)
        potential = sum(1 for f in self.findings if f.confidence == Confidence.POTENTIAL)
        
        print(f"\nFindings by Confidence:")
        print(f"    CONFIRMED: {confirmed}")
        print(f"    LIKELY: {likely}")
        print(f"    POTENTIAL: {potential}")
        
        print(f"\nKnowledge saved to: {self.knowledge.save_path}")
    
    def run_legacy(self, requests: List[ParsedRequest], resume_from: int = 0):
        """Legacy run method (non-intelligent) for backwards compatibility."""
        print(f"\n[*] Testing {len(requests)} requests with {len(self.auth_contexts)} auth contexts")
        print(f"[*] Auth contexts: {list(self.auth_contexts.keys())}")
        
        for i, req in enumerate(requests[resume_from:], start=resume_from):
            print(f"[{i+1}/{len(requests)}] Testing: {req.method} {req.path[:60]}...")
            
            new_findings = self.test_request(req)
            self.findings.extend(new_findings)
            
            if new_findings:
                print(f"    [!] Found {len(new_findings)} issue(s)")
            
            # Checkpoint
            if (i + 1) % Config.CHECKPOINT_INTERVAL == 0:
                self.save_checkpoint(i + 1)
                print(f"    [checkpoint] Saved progress: {i+1} requests, {len(self.findings)} findings")
        
        # Final save
        self.save_results()
        print(f"\n[+] Complete! {len(self.findings)} findings saved to {self.output_dir}")
    
    def save_checkpoint(self, processed: int):
        """Save checkpoint for resume."""
        checkpoint = {
            "last_processed": processed,
            "findings_count": len(self.findings),
            "timestamp": datetime.now().isoformat()
        }
        with open(self.temp_dir / 'checkpoint.json', 'w') as f:
            json.dump(checkpoint, f, indent=2)
    
    def save_results(self):
        """Save final results."""
        # All findings
        with open(self.output_dir / 'access_control_findings.json', 'w') as f:
            json.dump([asdict(f) for f in self.findings], f, indent=2, default=str)
        
        # BOLA candidates
        bola = [f for f in self.findings if f.type == "BOLA"]
        with open(self.output_dir / 'bola_candidates.txt', 'w') as f:
            for finding in bola:
                f.write(f"{finding.endpoint}\n")
        
        # Auth bypass candidates
        auth_bypass = [f for f in self.findings if f.type == "AUTH_BYPASS"]
        with open(self.output_dir / 'auth_bypass_candidates.txt', 'w') as f:
            for finding in auth_bypass:
                f.write(f"{finding.endpoint}\n")
        
        # Write individual vulnerability files
        self._write_vulnerability_files()
        
        # Summary report
        self._write_summary()
    
    def _write_vulnerability_files(self):
        """Write individual vulnerability markdown files."""
        vuln_dir = self.output_dir / 'vulnerabilities'
        vuln_dir.mkdir(exist_ok=True)
        
        for finding in self.findings:
            vuln_file = vuln_dir / f"{finding.id}-{finding.type}-{finding.severity.name}.md"
            
            # Build reproduction steps
            repro_steps = "\n".join(f"{step}" for step in finding.reproduction)
            
            # Build evidence JSON
            evidence_json = json.dumps(finding.evidence, indent=2, default=str) if finding.evidence else "N/A"
            
            # Get POC components
            poc_curl = finding.poc.get('curl_command', 'N/A') if finding.poc else 'N/A'
            poc_raw = finding.poc.get('raw_request', 'N/A') if finding.poc else 'N/A'
            
            content = f"""# Vulnerability Report: {finding.id}

## Overview

| Field | Value |
|-------|-------|
| **ID** | {finding.id} |
| **Type** | {finding.type} |
| **Severity** | {finding.severity.name} |
| **Confidence** | {finding.confidence.value} |
| **Attack Type** | {finding.attack_type} |
| **Discovered** | {finding.discovered_at} |
| **Endpoint** | `{finding.endpoint}` |
| **URL** | `{finding.url}` |
| **Method** | `{finding.method}` |

## Description

{finding.description}

## Impact

{finding.impact}

## Steps to Reproduce

{repro_steps}

## Proof of Concept (POC)

### cURL Command

```bash
{poc_curl}
```

### Raw HTTP Request

```http
{poc_raw}
```

## Evidence

```json
{evidence_json}
```

## Remediation

{finding.remediation}

---
*Generated by Role-Diff Access Control Tester*
"""
            
            with open(vuln_file, 'w') as f:
                f.write(content)
            
            print(f"    [+] Written: {vuln_file.name}")
    
    def _write_summary(self):
        """Write human-readable summary with intelligence insights."""
        # Sort findings by confidence (CONFIRMED first)
        sorted_findings = sorted(
            self.findings, 
            key=lambda x: (
                {"CONFIRMED": 0, "LIKELY": 1, "POTENTIAL": 2}.get(x.confidence.value, 3),
                x.severity.value
            )
        )
        
        summary = f"""# Role-Diff Access Control Testing Report

**Generated:** {datetime.now().isoformat()}
**Total Requests Tested:** {self.checkpoint.get('last_processed', 'all')}
**Total Findings:** {len(self.findings)}

## Intelligence Summary

| Metric | Value |
|--------|-------|
| Total IDs Learned | {len(self.knowledge.id_ownership)} |
| Endpoints Probed | {len(self.knowledge.endpoint_access_map)} |
| ANOMALY Patterns Found | {sum(1 for p in self.knowledge.endpoint_patterns.values() if p == AccessPattern.ANOMALY)} |

### Users and Owned IDs

"""
        for user, ids in self.knowledge.user_owned_ids.items():
            summary += f"- **{user}**: {len(ids)} IDs\n"
        
        summary += f"""
## Summary by Confidence

| Confidence | Count | Description |
|------------|-------|-------------|
| CONFIRMED | {sum(1 for f in self.findings if f.confidence == Confidence.CONFIRMED)} | Direct data leakage verified |
| LIKELY | {sum(1 for f in self.findings if f.confidence == Confidence.LIKELY)} | Strong indicators, needs verification |
| POTENTIAL | {sum(1 for f in self.findings if f.confidence == Confidence.POTENTIAL)} | Anomaly detected, manual review needed |

## Summary by Severity

| Severity | Count |
|----------|-------|
| CRITICAL | {sum(1 for f in self.findings if f.severity == Severity.CRITICAL)} |
| HIGH     | {sum(1 for f in self.findings if f.severity == Severity.HIGH)} |
| MEDIUM   | {sum(1 for f in self.findings if f.severity == Severity.MEDIUM)} |
| LOW      | {sum(1 for f in self.findings if f.severity == Severity.LOW)} |

## Summary by Type

| Type | Count |
|------|-------|
| BOLA | {sum(1 for f in self.findings if f.type == "BOLA")} |
| AUTH_BYPASS | {sum(1 for f in self.findings if f.type == "AUTH_BYPASS")} |
| PRIV_ESC | {sum(1 for f in self.findings if f.type == "PRIV_ESC")} |
| ENUMERATION | {sum(1 for f in self.findings if f.type == "ENUMERATION")} |

## Summary by Attack Type

| Attack Type | Count |
|-------------|-------|
| cross_user_data | {sum(1 for f in self.findings if f.attack_type == "cross_user_data")} |
| auth_bypass | {sum(1 for f in self.findings if f.attack_type == "auth_bypass")} |
| bola | {sum(1 for f in self.findings if f.attack_type == "bola")} |
| access_control | {sum(1 for f in self.findings if f.attack_type == "access_control")} |

## Confirmed Findings (Highest Priority)

"""
        for f in sorted_findings:
            if f.confidence == Confidence.CONFIRMED:
                summary += f"""### {f.id}: {f.endpoint}

**Type:** {f.type} | **Severity:** {f.severity.name} | **Confidence:** CONFIRMED
**Attack:** {f.attack_type}
**Description:** {f.description}
**Vulnerability Report:** [vulnerabilities/{f.id}-{f.type}-{f.severity.name}.md](vulnerabilities/{f.id}-{f.type}-{f.severity.name}.md)

---

"""
        
        summary += """
## All Vulnerability Files

Individual detailed reports are saved in the `vulnerabilities/` folder.

| ID | Type | Severity | Confidence | Attack Type | File |
|----|------|----------|------------|-------------|------|
"""
        for f in sorted_findings:
            filename = f"{f.id}-{f.type}-{f.severity.name}.md"
            summary += f"| {f.id} | {f.type} | {f.severity.name} | {f.confidence.value} | {f.attack_type} | [{filename}](vulnerabilities/{filename}) |\n"
        
        with open(self.output_dir / 'role_diff_summary.md', 'w') as f:
            f.write(summary)


# ============================================================================
# CLI
# ============================================================================
def load_auth_from_har_accounts(accounts_dir: Path) -> List[AuthContext]:
    """Load auth contexts from outputs/har/accounts/*_auth.json files."""
    auth_contexts = []
    
    if not accounts_dir.exists():
        print(f"[!] Auth accounts directory not found: {accounts_dir}")
        return auth_contexts
    
    for auth_file in accounts_dir.glob("*_auth.json"):
        try:
            with open(auth_file) as f:
                data = json.load(f)
            
            # Extract account name from filename (e.g., "user1_auth.json" -> "user1")
            account_name = auth_file.stem.replace("_auth", "")
            
            # Build headers from auth data
            headers = {}
            
            # Check for Authorization header
            if "authorization" in data:
                headers["Authorization"] = data["authorization"]
            elif "bearer_token" in data:
                headers["Authorization"] = f"Bearer {data['bearer_token']}"
            elif "token" in data:
                headers["Authorization"] = f"Bearer {data['token']}"
            
            # Check for cookies
            if "cookies" in data:
                if isinstance(data["cookies"], dict):
                    cookie_str = "; ".join(f"{k}={v}" for k, v in data["cookies"].items())
                    headers["Cookie"] = cookie_str
                elif isinstance(data["cookies"], str):
                    headers["Cookie"] = data["cookies"]
            elif "cookie" in data:
                headers["Cookie"] = data["cookie"]
            
            # Check for custom headers
            if "headers" in data and isinstance(data["headers"], dict):
                headers.update(data["headers"])
            
            # Extract user ID if present
            user_id = data.get("user_id") or data.get("userId") or data.get("id")
            
            # Extract owned IDs (for intelligent detection)
            owned_ids = []
            if "owned_ids" in data:
                owned_ids = data["owned_ids"]
            elif "account_ids" in data:
                owned_ids = data["account_ids"]
            elif "resource_ids" in data:
                owned_ids = data["resource_ids"]
            
            # Determine role
            role = data.get("role", "user")
            if "admin" in account_name.lower():
                role = "admin"
            elif "unauth" in account_name.lower():
                role = "unauth"
            
            auth_contexts.append(AuthContext(
                name=account_name,
                headers=headers,
                user_id=str(user_id) if user_id else None,
                owned_ids=[str(oid) for oid in owned_ids],
                role=role
            ))
            print(f"[+] Loaded auth context: {account_name} (role={role}, owned_ids={len(owned_ids)})")
            
        except Exception as e:
            print(f"[!] Failed to parse {auth_file}: {e}")
    
    return auth_contexts


def main():
    parser = argparse.ArgumentParser(description='Role-Diff Access Control Tester')
    parser.add_argument('--har-common', type=Path, help='HAR common_data.txt file')
    parser.add_argument('--endpoints', type=Path, help='Kiterunner/API endpoints file')
    parser.add_argument('--dynamic', type=Path, help='Dynamic endpoints file')
    parser.add_argument('--sensitive', type=Path, help='Sensitive files URLs')
    parser.add_argument('--corpus', type=Path, help='URL corpus file')
    parser.add_argument('--auth-config', type=Path, help='Auth contexts JSON file (single file)')
    parser.add_argument('--auth-dir', type=Path, help='Auth accounts directory (outputs/har/accounts/)')
    parser.add_argument('--output', type=Path, default=Path('outputs'), help='Output directory')
    parser.add_argument('--delay', type=int, default=100, help='Delay between requests (ms)')
    parser.add_argument('--resume', type=Path, help='Resume from checkpoint file')
    
    args = parser.parse_args()
    
    Config.DELAY_MS = args.delay
    
    # Load auth contexts
    auth_contexts = []
    
    # Option 1: Load from directory of auth files (preferred)
    if args.auth_dir:
        auth_contexts = load_auth_from_har_accounts(args.auth_dir)
    
    # Option 2: Load from single JSON file
    elif args.auth_config:
        with open(args.auth_config) as f:
            auth_data = json.load(f)
        
        for name, data in auth_data.items():
            auth_contexts.append(AuthContext(
                name=name,
                headers=data.get('headers', {}),
                user_id=data.get('user_id')
            ))
    
    if not auth_contexts:
        print("[!] No auth contexts loaded. Will only test unauthenticated access.")
    
    # Ensure we have unauth context
    if not any(ctx.name == 'unauth' for ctx in auth_contexts):
        auth_contexts.append(AuthContext(name='unauth', headers={}))
    
    # Initialize tester
    tester = RoleDiffTester(auth_contexts, args.output)
    
    # Load requests
    sources = {
        'har': args.har_common,
        'kiterunner': args.endpoints,
        'dynamic': args.dynamic,
        'sensitive': args.sensitive,
        'corpus': args.corpus
    }
    sources = {k: v for k, v in sources.items() if v}
    
    requests = tester.load_requests(sources)
    
    # Resume if checkpoint provided
    resume_from = 0
    if args.resume and args.resume.exists():
        with open(args.resume) as f:
            checkpoint = json.load(f)
            resume_from = checkpoint.get('last_processed', 0)
            print(f"[*] Resuming from request {resume_from}")
    
    # Run tests
    tester.run(requests, resume_from)


if __name__ == '__main__':
    main()
