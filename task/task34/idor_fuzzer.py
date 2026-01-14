#!/usr/bin/env python3
"""
Task 34 — INTELLIGENT IDOR / BOLA Fuzzer
"Use Brain" - Learn from responses, cross-user ID swap, pattern detection.
CLI-only, 9-minute batching, complements Task 33 role-diff.

KEY PRINCIPLES:
1. Cross-user ID swap is highest value (real IDs, real confidence)
2. Learn continuously from every response
3. Detect patterns before blind fuzzing
4. Prioritize by likelihood of success
"""

import argparse
import base64
import hashlib
import json
import re
import sys
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    import httpx
except ImportError:
    print("[!] httpx required: pip install httpx")
    sys.exit(1)

try:
    from deepdiff import DeepDiff
except ImportError:
    print("[!] deepdiff required: pip install deepdiff")
    sys.exit(1)


# ============================================================================
# CONFIGURATION
# ============================================================================
class Config:
    DELAY_MS = 100
    TIMEOUT_S = 10
    MAX_RETRIES = 2
    CHECKPOINT_INTERVAL = 50
    BATCH_TIME_LIMIT = 540  # 9 minutes
    FUZZ_RANGE = 10  # IDs to try around known value
    MAX_FUZZ_PER_ENDPOINT = 20


# ============================================================================
# DATA CLASSES
# ============================================================================
class Severity(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5


class IDType(Enum):
    NUMERIC = "numeric"
    UUID = "uuid"
    SLUG = "slug"
    BASE64 = "base64"
    HEX = "hex"
    PREFIXED = "prefixed"  # e.g., ORD-001, USR-123
    UNKNOWN = "unknown"


class IDPattern(Enum):
    SEQUENTIAL = "sequential"
    RANDOM = "random"
    PREFIXED_SEQ = "prefixed_sequential"
    TIMESTAMP = "timestamp"
    UNKNOWN = "unknown"


@dataclass
class IDLocation:
    """Location of an ID in a request."""
    location: str  # "path", "query", "body", "header"
    field_name: str  # param name or path segment index
    original_value: str
    id_type: IDType
    position: int = 0  # for path: segment index
    owner: Optional[str] = None  # which user owns this ID


@dataclass
class ParsedEndpoint:
    """Parsed endpoint with ID locations."""
    method: str
    url: str
    path: str
    host: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    body_params: Dict[str, Any] = field(default_factory=dict)
    query_params: Dict[str, str] = field(default_factory=dict)
    id_locations: List[IDLocation] = field(default_factory=list)
    pattern: str = ""  # normalized pattern like /api/users/{id}/profile
    source_user: Optional[str] = None  # which user's HAR this came from


@dataclass
class FuzzRequest:
    """A fuzz request to execute."""
    endpoint: ParsedEndpoint
    fuzzed_location: IDLocation
    fuzzed_value: str
    request_id: str
    attack_type: str = "unknown"  # cross_user, sequential, adjacent, random
    target_owner: Optional[str] = None  # whose ID are we trying to access


@dataclass
class AuthContext:
    """Authentication context."""
    name: str
    headers: Dict[str, str]
    user_id: Optional[str] = None
    known_ids: List[str] = field(default_factory=list)


@dataclass
class Finding:
    """IDOR/BOLA finding."""
    id: str
    severity: Severity
    type: str  # BOLA, IDOR, PREDICTABLE_ID, ENUMERATION
    endpoint_pattern: str
    original_url: str
    fuzzed_url: str
    method: str
    id_field: str
    id_type: str
    auth_context: str
    description: str
    evidence: Dict[str, Any]
    reproduction: List[str]
    poc: Dict[str, str]
    impact: str
    remediation: str
    discovered_at: str
    vulnerability_file: str
    confidence: str = "confirmed"  # confirmed, likely, potential
    attack_type: str = "unknown"  # cross_user, sequential, adjacent


# ============================================================================
# INTELLIGENT ID INVENTORY (the "brain")
# ============================================================================
class IDInventory:
    """
    Central knowledge base for IDs.
    Learns from responses, tracks ownership, detects patterns.
    """
    
    def __init__(self):
        # user -> set of IDs they own
        self.user_owned_ids: Dict[str, Set[str]] = defaultdict(set)
        
        # ID -> user who owns it
        self.id_ownership: Dict[str, str] = {}
        
        # endpoint_pattern -> list of observed IDs
        self.endpoint_ids: Dict[str, Set[str]] = defaultdict(set)
        
        # endpoint_pattern -> detected pattern (sequential, random, etc.)
        self.endpoint_patterns: Dict[str, IDPattern] = {}
        
        # All IDs by type for fuzzing
        self.ids_by_type: Dict[str, Set[str]] = defaultdict(set)
        
        # ID -> list of endpoints where it was seen
        self.id_sources: Dict[str, Set[str]] = defaultdict(set)
    
    def add_id(self, id_value: str, owner: str = None, endpoint: str = None, id_type: str = None):
        """Add an ID to the inventory."""
        if not id_value or len(id_value) < 1:
            return
        
        # Track by owner
        if owner:
            self.user_owned_ids[owner].add(id_value)
            self.id_ownership[id_value] = owner
        
        # Track by endpoint
        if endpoint:
            self.endpoint_ids[endpoint].add(id_value)
            self.id_sources[id_value].add(endpoint)
        
        # Track by type
        if id_type:
            self.ids_by_type[id_type].add(id_value)
    
    def get_cross_user_targets(self, attacker: str, endpoint: str) -> List[Tuple[str, str]]:
        """
        Get IDs to try for cross-user attack.
        Returns: [(id_value, owner), ...] where owner != attacker
        """
        targets = []
        
        # Get all IDs seen at this endpoint
        endpoint_ids = self.endpoint_ids.get(endpoint, set())
        
        for id_val in endpoint_ids:
            owner = self.id_ownership.get(id_val)
            if owner and owner != attacker:
                targets.append((id_val, owner))
        
        # Also try IDs from other users that we haven't mapped to this endpoint
        for user, ids in self.user_owned_ids.items():
            if user != attacker:
                for id_val in ids:
                    if (id_val, user) not in targets:
                        targets.append((id_val, user))
        
        return targets[:Config.MAX_FUZZ_PER_ENDPOINT]
    
    def detect_pattern(self, endpoint: str) -> IDPattern:
        """Detect the ID pattern for an endpoint."""
        if endpoint in self.endpoint_patterns:
            return self.endpoint_patterns[endpoint]
        
        ids = list(self.endpoint_ids.get(endpoint, []))
        if len(ids) < 2:
            return IDPattern.UNKNOWN
        
        # Check if numeric and sequential
        try:
            numeric_ids = sorted([int(i) for i in ids if i.isdigit()])
            if len(numeric_ids) >= 2:
                # Check for sequential pattern (gaps <= 10)
                gaps = [numeric_ids[i+1] - numeric_ids[i] for i in range(len(numeric_ids)-1)]
                if all(g <= 10 for g in gaps):
                    self.endpoint_patterns[endpoint] = IDPattern.SEQUENTIAL
                    return IDPattern.SEQUENTIAL
        except:
            pass
        
        # Check for prefixed pattern (e.g., ORD-001, ORD-002)
        prefixed = [i for i in ids if '-' in i and any(c.isdigit() for c in i)]
        if len(prefixed) >= 2:
            prefixes = [i.rsplit('-', 1)[0] for i in prefixed if '-' in i]
            if len(set(prefixes)) == 1:
                self.endpoint_patterns[endpoint] = IDPattern.PREFIXED_SEQ
                return IDPattern.PREFIXED_SEQ
        
        self.endpoint_patterns[endpoint] = IDPattern.RANDOM
        return IDPattern.RANDOM
    
    def get_adjacent_ids(self, id_value: str, id_type: IDType, count: int = 5) -> List[str]:
        """Generate adjacent IDs for sequential patterns."""
        adjacent = []
        
        if id_type == IDType.NUMERIC:
            try:
                num = int(id_value)
                for i in range(-count, count + 1):
                    if i != 0:
                        adjacent.append(str(num + i))
            except:
                pass
        
        elif id_type == IDType.PREFIXED:
            # e.g., ORD-001 -> ORD-000, ORD-002
            if '-' in id_value:
                prefix, suffix = id_value.rsplit('-', 1)
                try:
                    num = int(suffix)
                    for i in range(-count, count + 1):
                        if i != 0:
                            new_suffix = str(num + i).zfill(len(suffix))
                            adjacent.append(f"{prefix}-{new_suffix}")
                except:
                    pass
        
        return adjacent
    
    def save(self, filepath: Path):
        """Save inventory to file."""
        data = {
            "user_owned_ids": {k: list(v) for k, v in self.user_owned_ids.items()},
            "id_ownership": self.id_ownership,
            "endpoint_ids": {k: list(v) for k, v in self.endpoint_ids.items()},
            "endpoint_patterns": {k: v.value for k, v in self.endpoint_patterns.items()},
            "ids_by_type": {k: list(v) for k, v in self.ids_by_type.items()}
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load(self, filepath: Path):
        """Load inventory from file."""
        if not filepath.exists():
            return
        with open(filepath) as f:
            data = json.load(f)
        self.user_owned_ids = defaultdict(set, {k: set(v) for k, v in data.get("user_owned_ids", {}).items()})
        self.id_ownership = data.get("id_ownership", {})
        self.endpoint_ids = defaultdict(set, {k: set(v) for k, v in data.get("endpoint_ids", {}).items()})
        self.endpoint_patterns = {k: IDPattern(v) for k, v in data.get("endpoint_patterns", {}).items()}
        self.ids_by_type = defaultdict(set, {k: set(v) for k, v in data.get("ids_by_type", {}).items()})


# ============================================================================
# RESPONSE ID EXTRACTOR (learns from every response)
# ============================================================================
class ResponseLearner:
    """Extract IDs from HTTP responses to build knowledge."""
    
    # Field names that typically contain IDs
    ID_FIELDS = {
        'id', '_id', 'Id', 'ID', 'uuid', 'guid',
        'userId', 'user_id', 'userID', 'ownerId', 'owner_id', 'createdBy', 'created_by',
        'orderId', 'order_id', 'orderID', 'transactionId', 'transaction_id',
        'accountId', 'account_id', 'customerId', 'customer_id',
        'resourceId', 'resource_id', 'documentId', 'document_id',
        'fileId', 'file_id', 'projectId', 'project_id',
        'teamId', 'team_id', 'orgId', 'org_id', 'organizationId',
        'ref', 'reference', 'key', 'handle', 'slug', 'code'
    }
    
    # URL patterns to extract IDs from
    URL_PATTERN = re.compile(r'/([a-zA-Z0-9_-]+/)?([a-zA-Z0-9_-]{3,})')
    
    @classmethod
    def extract_ids_from_json(cls, data: Any, prefix: str = "") -> Dict[str, str]:
        """
        Recursively extract IDs from JSON response.
        Returns: {field_path: id_value}
        """
        extracted = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                field_path = f"{prefix}.{key}" if prefix else key
                
                # Check if this is an ID field
                if key.lower() in {f.lower() for f in cls.ID_FIELDS}:
                    if isinstance(value, (str, int)) and value:
                        extracted[field_path] = str(value)
                
                # Recurse into nested objects
                if isinstance(value, dict):
                    extracted.update(cls.extract_ids_from_json(value, field_path))
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        extracted.update(cls.extract_ids_from_json(item, f"{field_path}[{i}]"))
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                extracted.update(cls.extract_ids_from_json(item, f"{prefix}[{i}]"))
        
        return extracted
    
    @classmethod
    def extract_ids_from_urls_in_response(cls, data: Any) -> List[str]:
        """Extract IDs from URL strings found in response."""
        ids = []
        
        def find_urls(obj):
            if isinstance(obj, str):
                # Look for URL-like strings
                if '/' in obj and ('http' in obj or obj.startswith('/')):
                    matches = cls.URL_PATTERN.findall(obj)
                    for _, id_part in matches:
                        if len(id_part) >= 3 and not id_part.startswith('api'):
                            ids.append(id_part)
            elif isinstance(obj, dict):
                for v in obj.values():
                    find_urls(v)
            elif isinstance(obj, list):
                for item in obj:
                    find_urls(item)
        
        find_urls(data)
        return ids


# ============================================================================
# ID DETECTION
# ============================================================================
class IDDetector:
    """Detect and classify IDs in requests."""
    
    # Patterns for ID detection
    NUMERIC_PATTERN = re.compile(r'^\d+$')
    UUID_PATTERN = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE
    )
    HEX_PATTERN = re.compile(r'^[0-9a-f]{16,}$', re.IGNORECASE)
    BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]+=*$')
    SLUG_PATTERN = re.compile(r'^[a-z0-9]+(?:-[a-z0-9]+)+$', re.IGNORECASE)
    PREFIXED_PATTERN = re.compile(r'^[A-Z]{2,5}-\d+$')  # e.g., ORD-001, USR-123
    
    # Common ID param names
    ID_PARAM_NAMES = {
        'id', 'uid', 'user_id', 'userid', 'account_id', 'accountid',
        'order_id', 'orderid', 'item_id', 'itemid', 'doc_id', 'docid',
        'file_id', 'fileid', 'ref', 'reference', 'key', 'token',
        'customer_id', 'customerid', 'project_id', 'projectid',
        'org_id', 'orgid', 'team_id', 'teamid', 'resource_id'
    }
    
    @classmethod
    def detect_type(cls, value: str) -> IDType:
        """Detect the type of an ID value."""
        if cls.PREFIXED_PATTERN.match(value):
            return IDType.PREFIXED
        if cls.NUMERIC_PATTERN.match(value):
            return IDType.NUMERIC
        if cls.UUID_PATTERN.match(value):
            return IDType.UUID
        if cls.HEX_PATTERN.match(value) and len(value) >= 16:
            return IDType.HEX
        if cls.SLUG_PATTERN.match(value) and '-' in value:
            return IDType.SLUG
        if cls.BASE64_PATTERN.match(value) and len(value) >= 4:
            try:
                decoded = base64.b64decode(value).decode('utf-8')
                if decoded.isprintable():
                    return IDType.BASE64
            except:
                pass
        return IDType.UNKNOWN
    
    @classmethod
    def detect_type(cls, value: str) -> IDType:
        """Detect the type of an ID value."""
        if cls.NUMERIC_PATTERN.match(value):
            return IDType.NUMERIC
        if cls.UUID_PATTERN.match(value):
            return IDType.UUID
        if cls.HEX_PATTERN.match(value) and len(value) >= 16:
            return IDType.HEX
        if cls.SLUG_PATTERN.match(value) and '-' in value:
            return IDType.SLUG
        if cls.BASE64_PATTERN.match(value) and len(value) >= 4:
            # Try base64 decode
            try:
                import base64
                decoded = base64.b64decode(value).decode('utf-8')
                if decoded.isprintable():
                    return IDType.BASE64
            except:
                pass
        return IDType.UNKNOWN
    
    @classmethod
    def is_likely_id_param(cls, name: str) -> bool:
        """Check if param name suggests it's an ID."""
        name_lower = name.lower()
        return (
            name_lower in cls.ID_PARAM_NAMES or
            name_lower.endswith('_id') or
            name_lower.endswith('id') or
            name_lower.endswith('_ref') or
            name_lower.endswith('_key')
        )
    
    @classmethod
    def extract_ids_from_path(cls, path: str) -> List[IDLocation]:
        """Extract potential IDs from URL path."""
        ids = []
        segments = path.strip('/').split('/')
        
        for i, segment in enumerate(segments):
            if not segment:
                continue
            
            id_type = cls.detect_type(segment)
            
            # Numeric IDs
            if id_type == IDType.NUMERIC and len(segment) <= 10:
                ids.append(IDLocation(
                    location="path",
                    field_name=f"segment_{i}",
                    original_value=segment,
                    id_type=id_type,
                    position=i
                ))
            # UUIDs
            elif id_type == IDType.UUID:
                ids.append(IDLocation(
                    location="path",
                    field_name=f"segment_{i}",
                    original_value=segment,
                    id_type=id_type,
                    position=i
                ))
            # Hex IDs
            elif id_type == IDType.HEX:
                ids.append(IDLocation(
                    location="path",
                    field_name=f"segment_{i}",
                    original_value=segment,
                    id_type=id_type,
                    position=i
                ))
        
        return ids
    
    @classmethod
    def extract_ids_from_query(cls, query_params: Dict[str, str]) -> List[IDLocation]:
        """Extract potential IDs from query parameters."""
        ids = []
        
        for name, value in query_params.items():
            if isinstance(value, list):
                value = value[0] if value else ""
            
            id_type = cls.detect_type(str(value))
            
            # Check if param name or value suggests ID
            if cls.is_likely_id_param(name) or id_type in [IDType.NUMERIC, IDType.UUID]:
                if id_type != IDType.UNKNOWN:
                    ids.append(IDLocation(
                        location="query",
                        field_name=name,
                        original_value=str(value),
                        id_type=id_type
                    ))
        
        return ids
    
    @classmethod
    def extract_ids_from_body(cls, body: Dict[str, Any], prefix: str = "") -> List[IDLocation]:
        """Extract potential IDs from request body."""
        ids = []
        
        for key, value in body.items():
            field_path = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, dict):
                ids.extend(cls.extract_ids_from_body(value, field_path))
            elif isinstance(value, (str, int)):
                str_value = str(value)
                id_type = cls.detect_type(str_value)
                
                if cls.is_likely_id_param(key) or id_type in [IDType.NUMERIC, IDType.UUID]:
                    if id_type != IDType.UNKNOWN:
                        ids.append(IDLocation(
                            location="body",
                            field_name=field_path,
                            original_value=str_value,
                            id_type=id_type
                        ))
        
        return ids


# ============================================================================
# FUZZ VALUE GENERATOR
# ============================================================================
class FuzzGenerator:
    """Generate fuzz values for IDs."""
    
    # Common slugs to try
    COMMON_SLUGS = [
        'admin', 'test', 'default', 'sample', 'demo', 'user',
        'root', 'system', 'guest', 'public', 'private'
    ]
    
    @classmethod
    def generate_numeric_fuzz(cls, original: str, range_size: int = 10) -> List[str]:
        """Generate fuzz values for numeric ID."""
        try:
            orig_int = int(original)
        except ValueError:
            return []
        
        values = []
        
        # Range around original
        for i in range(-range_size, range_size + 1):
            if i != 0:
                values.append(str(orig_int + i))
        
        # Edge cases
        edge_cases = [
            "0", "1", "-1",
            str(orig_int * 2),
            "2147483647",  # MAX_INT
            "9999999999"
        ]
        values.extend(edge_cases)
        
        # Dedupe and limit
        return list(dict.fromkeys(values))[:Config.MAX_FUZZ_PER_ENDPOINT]
    
    @classmethod
    def generate_uuid_fuzz(cls, original: str, known_uuids: List[str] = None) -> List[str]:
        """Generate fuzz values for UUID."""
        values = []
        
        # Null UUID
        values.append("00000000-0000-0000-0000-000000000000")
        
        # Known UUIDs from other users
        if known_uuids:
            values.extend(known_uuids[:10])
        
        # Generate some random UUIDs
        for _ in range(3):
            values.append(str(uuid.uuid4()))
        
        # Variant: change last segment
        if '-' in original:
            parts = original.split('-')
            parts[-1] = 'ffffffffffff'
            values.append('-'.join(parts))
        
        return list(dict.fromkeys(values))[:Config.MAX_FUZZ_PER_ENDPOINT]
    
    @classmethod
    def generate_slug_fuzz(cls, original: str, known_slugs: List[str] = None) -> List[str]:
        """Generate fuzz values for slug."""
        values = list(cls.COMMON_SLUGS)
        
        if known_slugs:
            values.extend(known_slugs[:10])
        
        # Variations of original
        if '-' in original:
            parts = original.split('-')
            if len(parts) >= 2:
                values.append(parts[0])  # First part only
                values.append(f"{parts[0]}-test")
        
        return list(dict.fromkeys(values))[:Config.MAX_FUZZ_PER_ENDPOINT]
    
    @classmethod
    def generate_fuzz_values(
        cls,
        id_location: IDLocation,
        known_ids: Dict[str, List[str]] = None
    ) -> List[str]:
        """Generate fuzz values based on ID type."""
        known_ids = known_ids or {}
        
        if id_location.id_type == IDType.NUMERIC:
            return cls.generate_numeric_fuzz(id_location.original_value)
        
        elif id_location.id_type == IDType.UUID:
            known_uuids = known_ids.get('uuid', [])
            return cls.generate_uuid_fuzz(id_location.original_value, known_uuids)
        
        elif id_location.id_type == IDType.SLUG:
            known_slugs = known_ids.get('slug', [])
            return cls.generate_slug_fuzz(id_location.original_value, known_slugs)
        
        elif id_location.id_type == IDType.HEX:
            # Simple hex manipulation
            values = []
            orig = id_location.original_value
            if len(orig) >= 2:
                values.append('0' * len(orig))
                values.append('f' * len(orig))
                values.append(orig[:-1] + ('0' if orig[-1] != '0' else '1'))
            return values[:Config.MAX_FUZZ_PER_ENDPOINT]
        
        return []


# ============================================================================
# ENDPOINT PARSER
# ============================================================================
class EndpointParser:
    """Parse endpoints and extract ID locations."""
    
    @classmethod
    def parse_url(cls, url: str, method: str = "GET", headers: Dict = None, body: str = None) -> ParsedEndpoint:
        """Parse a URL into ParsedEndpoint with ID locations."""
        parsed = urlparse(url)
        
        # Parse query params
        query_params = {}
        if parsed.query:
            for key, values in parse_qs(parsed.query).items():
                query_params[key] = values[0] if values else ""
        
        # Parse body
        body_params = {}
        if body:
            try:
                body_params = json.loads(body)
            except json.JSONDecodeError:
                pass
        
        endpoint = ParsedEndpoint(
            method=method.upper(),
            url=url,
            path=parsed.path,
            host=parsed.netloc,
            headers=headers or {},
            body=body,
            body_params=body_params,
            query_params=query_params
        )
        
        # Extract IDs
        endpoint.id_locations.extend(IDDetector.extract_ids_from_path(parsed.path))
        endpoint.id_locations.extend(IDDetector.extract_ids_from_query(query_params))
        if body_params:
            endpoint.id_locations.extend(IDDetector.extract_ids_from_body(body_params))
        
        # Generate pattern
        endpoint.pattern = cls._generate_pattern(endpoint)
        
        return endpoint
    
    @classmethod
    def _generate_pattern(cls, endpoint: ParsedEndpoint) -> str:
        """Generate normalized pattern for endpoint."""
        path = endpoint.path
        
        # Replace IDs with placeholders
        for id_loc in endpoint.id_locations:
            if id_loc.location == "path":
                segments = path.strip('/').split('/')
                if id_loc.position < len(segments):
                    segments[id_loc.position] = "{id}"
                    path = '/' + '/'.join(segments)
        
        return f"{endpoint.method} {path}"
    
    @classmethod
    def load_endpoints_from_file(cls, filepath: Path) -> List[ParsedEndpoint]:
        """Load endpoints from various file formats."""
        endpoints = []
        
        if not filepath.exists():
            return endpoints
        
        with open(filepath) as f:
            content = f.read().strip()
        
        # Try JSON first
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and 'url' in item:
                        ep = cls.parse_url(
                            item['url'],
                            item.get('method', 'GET'),
                            item.get('headers', {}),
                            item.get('body')
                        )
                        endpoints.append(ep)
                    elif isinstance(item, str):
                        ep = cls.parse_url(item)
                        endpoints.append(ep)
            return endpoints
        except json.JSONDecodeError:
            pass
        
        # Plain text URLs
        for line in content.split('\n'):
            line = line.strip()
            if line and line.startswith('http'):
                # Check for method prefix
                parts = line.split(' ', 1)
                if len(parts) == 2 and parts[0] in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    ep = cls.parse_url(parts[1], parts[0])
                else:
                    ep = cls.parse_url(line)
                endpoints.append(ep)
        
        return endpoints


# ============================================================================
# INTELLIGENT FUZZER (uses brain)
# ============================================================================
class IDORFuzzer:
    """
    Intelligent IDOR/BOLA fuzzer.
    Uses IDInventory to learn and make smart decisions.
    """
    
    def __init__(
        self,
        auth_contexts: List[AuthContext],
        output_dir: Path,
        temp_dir: Path
    ):
        self.auth_contexts = {ctx.name: ctx for ctx in auth_contexts}
        self.output_dir = output_dir
        self.temp_dir = temp_dir
        self.findings: List[Finding] = []
        self.finding_counter = 0
        self.checkpoint = {}
        
        # THE BRAIN - learns from everything
        self.inventory = IDInventory()
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Load existing inventory if available
        inventory_file = self.temp_dir / 'id_inventory.json'
        if inventory_file.exists():
            self.inventory.load(inventory_file)
            print(f"[*] Loaded existing ID inventory")
        
        self.client = httpx.Client(
            timeout=Config.TIMEOUT_S,
            follow_redirects=True,
            verify=False
        )
    
    def harvest_ids_from_endpoints(self, endpoints: List[ParsedEndpoint]):
        """
        PHASE A: Harvest IDs from all endpoint sources.
        Build initial knowledge before attacking.
        """
        print("\n[*] PHASE A: Harvesting IDs from endpoints...")
        
        for ep in endpoints:
            source_user = ep.source_user or "unknown"
            
            for id_loc in ep.id_locations:
                self.inventory.add_id(
                    id_value=id_loc.original_value,
                    owner=source_user,
                    endpoint=ep.pattern,
                    id_type=id_loc.id_type.value
                )
        
        # Summary
        total_ids = sum(len(ids) for ids in self.inventory.user_owned_ids.values())
        print(f"    [+] Harvested {total_ids} IDs from {len(endpoints)} endpoints")
        for user, ids in self.inventory.user_owned_ids.items():
            print(f"        {user}: {len(ids)} IDs")
    
    def learn_from_response(self, response_body: Any, user: str, endpoint_pattern: str):
        """
        CONTINUOUS LEARNING: Extract IDs from every response.
        This is where the "brain" gets smarter.
        """
        if not response_body:
            return
        
        # Extract IDs from JSON fields
        extracted = ResponseLearner.extract_ids_from_json(response_body)
        for field_path, id_value in extracted.items():
            id_type = IDDetector.detect_type(id_value)
            self.inventory.add_id(
                id_value=id_value,
                owner=user,
                endpoint=endpoint_pattern,
                id_type=id_type.value
            )
        
        # Extract IDs from URLs in response
        url_ids = ResponseLearner.extract_ids_from_urls_in_response(response_body)
        for id_value in url_ids:
            id_type = IDDetector.detect_type(id_value)
            self.inventory.add_id(
                id_value=id_value,
                owner=user,
                endpoint=endpoint_pattern,
                id_type=id_type.value
            )
    
    def build_attack_plan(self, endpoints: List[ParsedEndpoint]) -> List[Tuple[ParsedEndpoint, str, str, str, str]]:
        """
        PHASE B: Build prioritized attack plan.
        Returns: [(endpoint, attacker, target_id, target_owner, attack_type), ...]
        
        Priority:
        1. Cross-user ID swap (highest confidence)
        2. Sequential ID probing
        3. Adjacent ID fuzzing
        """
        plan = []
        
        print("\n[*] PHASE B: Building intelligent attack plan...")
        
        for ep in endpoints:
            if not ep.id_locations:
                continue
            
            pattern = ep.pattern
            
            for attacker_name in self.auth_contexts.keys():
                # PRIORITY 1: Cross-user attacks
                cross_user_targets = self.inventory.get_cross_user_targets(attacker_name, pattern)
                for target_id, owner in cross_user_targets:
                    plan.append((ep, attacker_name, target_id, owner, "cross_user"))
                
                # PRIORITY 2: Sequential/adjacent if pattern detected
                id_pattern = self.inventory.detect_pattern(pattern)
                if id_pattern in [IDPattern.SEQUENTIAL, IDPattern.PREFIXED_SEQ]:
                    for id_loc in ep.id_locations:
                        adjacent = self.inventory.get_adjacent_ids(
                            id_loc.original_value, 
                            id_loc.id_type,
                            count=3
                        )
                        for adj_id in adjacent:
                            # Don't test IDs we know belong to the attacker
                            if adj_id not in self.inventory.user_owned_ids.get(attacker_name, set()):
                                plan.append((ep, attacker_name, adj_id, None, "sequential"))
        
        # Sort by priority: cross_user first, then sequential
        plan.sort(key=lambda x: 0 if x[4] == "cross_user" else 1)
        
        print(f"    [+] Attack plan: {len(plan)} tests")
        cross_user_count = sum(1 for p in plan if p[4] == "cross_user")
        seq_count = sum(1 for p in plan if p[4] == "sequential")
        print(f"        Cross-user attacks: {cross_user_count}")
        print(f"        Sequential probes: {seq_count}")
        
        return plan
    
    def build_fuzzed_url(self, endpoint: ParsedEndpoint, id_loc: IDLocation, new_value: str) -> str:
        """Build URL with fuzzed ID value."""
        parsed = urlparse(endpoint.url)
        
        if id_loc.location == "path":
            segments = parsed.path.strip('/').split('/')
            if id_loc.position < len(segments):
                segments[id_loc.position] = new_value
            new_path = '/' + '/'.join(segments)
            return urlunparse((
                parsed.scheme, parsed.netloc, new_path,
                parsed.params, parsed.query, parsed.fragment
            ))
        
        elif id_loc.location == "query":
            query_params = dict(parse_qs(parsed.query))
            query_params[id_loc.field_name] = [new_value]
            new_query = urlencode({k: v[0] for k, v in query_params.items()})
            return urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
        
        return endpoint.url
    
    def build_fuzzed_body(self, endpoint: ParsedEndpoint, id_loc: IDLocation, new_value: str) -> str:
        """Build request body with fuzzed ID value."""
        if not endpoint.body_params or id_loc.location != "body":
            return endpoint.body
        
        body = dict(endpoint.body_params)
        
        # Handle nested paths like "user.id"
        parts = id_loc.field_name.split('.')
        current = body
        for part in parts[:-1]:
            if part in current:
                current = current[part]
        
        if parts[-1] in current:
            current[parts[-1]] = new_value
        
        return json.dumps(body)
    
    def send_request(
        self,
        method: str,
        url: str,
        auth_ctx: AuthContext,
        body: str = None
    ) -> Tuple[int, Dict, str]:
        """Send HTTP request and return status, headers, body."""
        headers = dict(auth_ctx.headers)
        
        if body:
            headers['Content-Type'] = 'application/json'
        
        try:
            response = self.client.request(
                method,
                url,
                headers=headers,
                content=body,
            )
            
            body_text = response.text
            
            # Try to parse as JSON
            try:
                body_json = response.json()
            except:
                body_json = {"raw": body_text[:1000]}
            
            return response.status_code, dict(response.headers), body_json
            
        except Exception as e:
            return 0, {}, {"error": str(e)}
    
    def compare_responses(
        self,
        baseline: Tuple[int, Dict, Any],
        fuzzed: Tuple[int, Dict, Any],
        endpoint: ParsedEndpoint,
        id_loc: IDLocation
    ) -> Optional[Dict]:
        """Compare baseline and fuzzed responses to detect IDOR."""
        b_status, b_headers, b_body = baseline
        f_status, f_headers, f_body = fuzzed
        
        # Error responses - no issue
        if f_status in [401, 403, 404, 500, 0]:
            return None
        
        # Success on fuzzed ID
        if f_status in [200, 201] and b_status in [200, 201]:
            # Check if responses are identical (bad - accessing other user's data)
            if isinstance(b_body, dict) and isinstance(f_body, dict):
                diff = DeepDiff(b_body, f_body, ignore_order=True)
                
                # If very similar but some values changed - potential IDOR
                if diff:
                    changed_values = diff.get('values_changed', {})
                    # Data changed = different resource accessed
                    if changed_values:
                        return {
                            "issue": "different_data_accessed",
                            "original_status": b_status,
                            "fuzzed_status": f_status,
                            "diff_summary": str(diff)[:500],
                            "data_fields_changed": list(changed_values.keys())[:10]
                        }
                else:
                    # Identical response for different IDs - might be public or cached
                    pass
            
            # Different status but both success - potential issue
            if b_status != f_status:
                return {
                    "issue": "status_difference",
                    "original_status": b_status,
                    "fuzzed_status": f_status
                }
        
        # Enumeration: different error codes reveal existence
        if b_status == 200 and f_status == 404:
            return {
                "issue": "enumeration_possible",
                "original_status": b_status,
                "fuzzed_status": f_status,
                "note": "Status difference reveals resource existence"
            }
        
        return None
    
    def test_endpoint(self, endpoint: ParsedEndpoint, auth_name: str) -> List[Finding]:
        """Test a single endpoint for IDOR vulnerabilities."""
        findings = []
        auth_ctx = self.auth_contexts.get(auth_name)
        
        if not auth_ctx or not endpoint.id_locations:
            return findings
        
        for id_loc in endpoint.id_locations:
            # Get baseline response
            time.sleep(Config.DELAY_MS / 1000)
            baseline = self.send_request(
                endpoint.method,
                endpoint.url,
                auth_ctx,
                endpoint.body
            )
            
            # Generate fuzz values
            fuzz_values = FuzzGenerator.generate_fuzz_values(id_loc, self.known_ids)
            
            for fuzz_val in fuzz_values:
                time.sleep(Config.DELAY_MS / 1000)
                
                # Build fuzzed request
                fuzzed_url = self.build_fuzzed_url(endpoint, id_loc, fuzz_val)
                fuzzed_body = self.build_fuzzed_body(endpoint, id_loc, fuzz_val)
                
                # Send fuzzed request
                fuzzed_response = self.send_request(
                    endpoint.method,
                    fuzzed_url,
                    auth_ctx,
                    fuzzed_body
                )
                
                # Compare
                issue = self.compare_responses(baseline, fuzzed_response, endpoint, id_loc)
                
                if issue:
                    self.finding_counter += 1
                    finding_id = f"IDOR-{self.finding_counter:04d}"
                    finding_type = self._classify_finding(issue)
                    severity = self._assess_severity(finding_type, endpoint, issue)
                    
                    vuln_filename = f"{finding_id}-{finding_type}-{severity.name}.md"
                    
                    poc = self._generate_poc(endpoint.method, fuzzed_url, auth_ctx, fuzzed_body)
                    impact = self._assess_impact(finding_type, endpoint, id_loc)
                    
                    finding = Finding(
                        id=finding_id,
                        severity=severity,
                        type=finding_type,
                        endpoint_pattern=endpoint.pattern,
                        original_url=endpoint.url,
                        fuzzed_url=fuzzed_url,
                        method=endpoint.method,
                        id_field=f"{id_loc.location}:{id_loc.field_name}",
                        id_type=id_loc.id_type.value,
                        auth_context=auth_name,
                        description=f"IDOR detected: {auth_name} can access resource by changing {id_loc.field_name} from {id_loc.original_value} to {fuzz_val}",
                        evidence={
                            "original_id": id_loc.original_value,
                            "fuzzed_id": fuzz_val,
                            "original_status": issue.get("original_status"),
                            "fuzzed_status": issue.get("fuzzed_status"),
                            "issue_type": issue.get("issue"),
                            "diff_summary": issue.get("diff_summary", "")[:500]
                        },
                        reproduction=[
                            f"1. Authenticate as {auth_name}",
                            f"2. Note original request: {endpoint.method} {endpoint.url}",
                            f"3. Change {id_loc.field_name} from '{id_loc.original_value}' to '{fuzz_val}'",
                            f"4. Send modified request: {endpoint.method} {fuzzed_url}",
                            f"5. Observe response returns data for different resource"
                        ],
                        poc=poc,
                        impact=impact,
                        remediation=self._get_remediation(finding_type),
                        discovered_at=datetime.now().isoformat(),
                        vulnerability_file=f"outputs/vulnerabilities/{vuln_filename}"
                    )
                    findings.append(finding)
        
        return findings
    
    def _classify_finding(self, issue: Dict) -> str:
        """Classify the finding type."""
        issue_type = issue.get("issue", "")
        
        if issue_type == "different_data_accessed":
            return "BOLA"
        elif issue_type == "enumeration_possible":
            return "ENUMERATION"
        elif issue_type == "status_difference":
            return "IDOR"
        else:
            return "IDOR"
    
    def _assess_severity(self, finding_type: str, endpoint: ParsedEndpoint, issue: Dict) -> Severity:
        """Assess severity based on finding type and context."""
        # State-changing methods are more severe
        if endpoint.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            if finding_type == "BOLA":
                return Severity.CRITICAL
            return Severity.HIGH
        
        # GET requests
        if finding_type == "BOLA":
            return Severity.HIGH
        elif finding_type == "ENUMERATION":
            return Severity.MEDIUM
        
        return Severity.MEDIUM
    
    def _generate_poc(self, method: str, url: str, auth_ctx: AuthContext, body: str = None) -> Dict[str, str]:
        """Generate POC curl command and raw request."""
        curl_parts = [f"curl -X {method} '{url}'"]
        for key, value in auth_ctx.headers.items():
            display_value = value[:30] + "..." if len(value) > 30 else value
            curl_parts.append(f"  -H '{key}: {display_value}'")
        if body:
            curl_parts.append(f"  -d '{body[:200]}...'")
        
        parsed = urlparse(url)
        raw_lines = [f"{method} {parsed.path}{'?' + parsed.query if parsed.query else ''} HTTP/1.1"]
        raw_lines.append(f"Host: {parsed.netloc}")
        for key, value in auth_ctx.headers.items():
            display_value = value[:50] + "..." if len(value) > 50 else value
            raw_lines.append(f"{key}: {display_value}")
        if body:
            raw_lines.append("")
            raw_lines.append(body[:500])
        
        return {
            "curl_command": " \\\n".join(curl_parts),
            "raw_request": "\n".join(raw_lines)
        }
    
    def _assess_impact(self, finding_type: str, endpoint: ParsedEndpoint, id_loc: IDLocation) -> str:
        """Generate impact assessment."""
        impacts = {
            "BOLA": f"Attacker can access other users' resources at {endpoint.path}. "
                    f"By manipulating {id_loc.field_name}, any authenticated user can access "
                    f"data belonging to other users, potentially exposing PII or sensitive information.",
            
            "IDOR": f"Insecure direct object reference at {endpoint.path}. "
                    f"Object IDs are exposed and can be manipulated to access unauthorized resources.",
            
            "ENUMERATION": f"Resource enumeration possible at {endpoint.path}. "
                          f"Different responses for valid/invalid IDs allow attackers to discover valid resources."
        }
        
        base_impact = impacts.get(finding_type, "Access control vulnerability detected.")
        
        if endpoint.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            base_impact += f" This is a {endpoint.method} endpoint, so data modification or deletion may be possible."
        
        return base_impact
    
    def _get_remediation(self, finding_type: str) -> str:
        """Get remediation guidance."""
        remediations = {
            "BOLA": """1. Implement object-level authorization:
   - Verify the authenticated user has access to the requested resource
   - Use session/token user ID, not request parameter
   - Example: if resource.owner_id != current_user.id: return 403
2. Use indirect references (UUIDs) instead of sequential IDs
3. Add authorization middleware to all data-access endpoints
4. Log and monitor for IDOR attempts""",
            
            "IDOR": """1. Validate user authorization for every object access
2. Use cryptographically random identifiers instead of sequential IDs
3. Implement proper access control lists (ACLs)
4. Add rate limiting to prevent enumeration
5. Return consistent error responses (always 404 or always 403)""",
            
            "ENUMERATION": """1. Return identical responses for non-existent and unauthorized resources
2. Use UUIDs instead of sequential identifiers
3. Implement rate limiting on endpoints
4. Add CAPTCHA for repeated failed requests
5. Monitor for enumeration patterns in logs"""
        }
        return remediations.get(finding_type, "Implement proper authorization checks.")
    
    def run(self, endpoints: List[ParsedEndpoint], resume_from: int = 0):
        """
        INTELLIGENT RUN - Uses brain, not brute force.
        
        1. Harvest IDs from all sources
        2. Build smart attack plan (cross-user first)
        3. Execute attacks, learning from each response
        4. Save findings with full context
        """
        print("\n" + "="*60)
        print("INTELLIGENT IDOR/BOLA FUZZER")
        print("="*60)
        
        # Filter to endpoints with IDs
        endpoints_with_ids = [ep for ep in endpoints if ep.id_locations]
        print(f"[*] Found {len(endpoints_with_ids)} endpoints with potential IDs")
        print(f"[*] Auth contexts: {list(self.auth_contexts.keys())}")
        
        # PHASE A: Harvest IDs
        self.harvest_ids_from_endpoints(endpoints_with_ids)
        
        # PHASE B: Build intelligent attack plan
        attack_plan = self.build_attack_plan(endpoints_with_ids)
        
        if not attack_plan:
            print("[!] No attacks to execute. Need more ID ownership data.")
            print("    Hint: Ensure HAR data contains user-specific IDs")
            return
        
        # PHASE C: Execute attacks
        print(f"\n[*] PHASE C: Executing {len(attack_plan)} smart attacks...")
        start_time = time.time()
        
        for i, (endpoint, attacker, target_id, target_owner, attack_type) in enumerate(attack_plan[resume_from:], start=resume_from):
            # Check batch time limit
            elapsed = time.time() - start_time
            if elapsed > Config.BATCH_TIME_LIMIT:
                print(f"\n[!] Batch time limit reached. Checkpointing at {i}...")
                self.save_checkpoint(i)
                break
            
            time.sleep(Config.DELAY_MS / 1000)
            
            auth_ctx = self.auth_contexts[attacker]
            
            # Build attack request
            if endpoint.id_locations:
                id_loc = endpoint.id_locations[0]  # Use first ID location
                fuzzed_url = self.build_fuzzed_url(endpoint, id_loc, target_id)
                fuzzed_body = self.build_fuzzed_body(endpoint, id_loc, target_id)
            else:
                continue
            
            # Send attack request
            status, headers, body = self.send_request(
                endpoint.method,
                fuzzed_url,
                auth_ctx,
                fuzzed_body
            )
            
            # LEARN from response (continuous learning)
            if status == 200 and isinstance(body, dict):
                self.learn_from_response(body, attacker, endpoint.pattern)
            
            # Analyze result
            confidence = "potential"
            finding_type = "IDOR"
            
            if status == 200:
                # Check if we got someone else's data
                if attack_type == "cross_user" and target_owner:
                    # This is a CONFIRMED IDOR - we know whose data it should be
                    confidence = "confirmed"
                    finding_type = "BOLA"
                    severity = Severity.CRITICAL if endpoint.method in ['POST', 'PUT', 'DELETE'] else Severity.HIGH
                    
                    print(f"    [!!!] CONFIRMED BOLA: {attacker} accessed {target_owner}'s resource!")
                    
                    self.finding_counter += 1
                    finding_id = f"IDOR-{self.finding_counter:04d}"
                    vuln_filename = f"{finding_id}-{finding_type}-{severity.name}.md"
                    
                    finding = Finding(
                        id=finding_id,
                        severity=severity,
                        type=finding_type,
                        endpoint_pattern=endpoint.pattern,
                        original_url=endpoint.url,
                        fuzzed_url=fuzzed_url,
                        method=endpoint.method,
                        id_field=f"{id_loc.location}:{id_loc.field_name}",
                        id_type=id_loc.id_type.value,
                        auth_context=attacker,
                        description=f"CONFIRMED BOLA: {attacker} can access {target_owner}'s resource by using their ID ({target_id})",
                        evidence={
                            "attack_type": attack_type,
                            "attacker": attacker,
                            "target_owner": target_owner,
                            "target_id": target_id,
                            "response_status": status,
                            "response_sample": str(body)[:500] if body else ""
                        },
                        reproduction=[
                            f"1. Authenticate as {attacker}",
                            f"2. Note that {target_owner} owns resource ID: {target_id}",
                            f"3. Send request as {attacker}: {endpoint.method} {fuzzed_url}",
                            f"4. Observe that {target_owner}'s data is returned",
                            f"5. This proves {attacker} can access {target_owner}'s resources"
                        ],
                        poc=self._generate_poc(endpoint.method, fuzzed_url, auth_ctx, fuzzed_body),
                        impact=f"Any user can access any other user's data at {endpoint.path} by knowing/guessing their resource IDs. "
                               f"This was confirmed by {attacker} accessing {target_owner}'s resource.",
                        remediation=self._get_remediation(finding_type),
                        discovered_at=datetime.now().isoformat(),
                        vulnerability_file=f"outputs/vulnerabilities/{vuln_filename}",
                        confidence=confidence,
                        attack_type=attack_type
                    )
                    self.findings.append(finding)
                
                elif attack_type == "sequential":
                    # Sequential probe found something - likely IDOR but need to verify
                    confidence = "likely"
                    print(f"    [!] Likely IDOR at {endpoint.path} (sequential ID {target_id})")
            
            # Progress
            if (i + 1) % 20 == 0:
                print(f"[{i+1}/{len(attack_plan)}] Progress... {len(self.findings)} findings so far")
            
            # Checkpoint
            if (i + 1) % Config.CHECKPOINT_INTERVAL == 0:
                self.save_checkpoint(i + 1)
                self.inventory.save(self.temp_dir / 'id_inventory.json')
        
        # Save everything
        self.inventory.save(self.temp_dir / 'id_inventory.json')
        self.save_results()
        
        print(f"\n[+] Complete!")
        print(f"    Findings: {len(self.findings)}")
        print(f"    Confirmed BOLA: {sum(1 for f in self.findings if f.confidence == 'confirmed')}")
        print(f"    IDs learned: {sum(len(ids) for ids in self.inventory.user_owned_ids.values())}")
    
    def save_checkpoint(self, processed: int):
        """Save checkpoint for resume."""
        checkpoint = {
            "last_processed": processed,
            "findings_count": len(self.findings),
            "finding_counter": self.finding_counter,
            "timestamp": datetime.now().isoformat()
        }
        with open(self.temp_dir / 'checkpoint.json', 'w') as f:
            json.dump(checkpoint, f, indent=2)
    
    def save_results(self):
        """Save all results."""
        # All findings JSON
        with open(self.output_dir / 'idor_findings.json', 'w') as f:
            json.dump([asdict(f) for f in self.findings], f, indent=2, default=str)
        
        # Confirmed endpoints
        with open(self.output_dir / 'idor_confirmed_endpoints.txt', 'w') as f:
            for finding in self.findings:
                f.write(f"{finding.fuzzed_url}\n")
        
        # Write vulnerability files
        self._write_vulnerability_files()
        
        # Summary report
        self._write_summary()
    
    def _write_vulnerability_files(self):
        """Write individual vulnerability files."""
        vuln_dir = self.output_dir / 'vulnerabilities'
        vuln_dir.mkdir(exist_ok=True)
        
        for finding in self.findings:
            filename = f"{finding.id}-{finding.type}-{finding.severity.name}.md"
            vuln_file = vuln_dir / filename
            
            repro_steps = "\n".join(finding.reproduction)
            evidence_json = json.dumps(finding.evidence, indent=2, default=str)
            poc_curl = finding.poc.get('curl_command', 'N/A')
            poc_raw = finding.poc.get('raw_request', 'N/A')
            
            content = f"""# Vulnerability Report: {finding.id}

## Overview

| Field | Value |
|-------|-------|
| **ID** | {finding.id} |
| **Type** | {finding.type} |
| **Severity** | {finding.severity.name} |
| **Confidence** | {finding.confidence.upper()} |
| **Attack Type** | {finding.attack_type} |
| **Discovered** | {finding.discovered_at} |
| **Endpoint Pattern** | `{finding.endpoint_pattern}` |
| **Original URL** | `{finding.original_url}` |
| **Fuzzed URL** | `{finding.fuzzed_url}` |
| **Method** | `{finding.method}` |
| **ID Field** | `{finding.id_field}` |
| **ID Type** | `{finding.id_type}` |
| **Auth Context** | `{finding.auth_context}` |

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
*Generated by IDOR/BOLA Fuzzer (Task 34)*
"""
            
            with open(vuln_file, 'w') as f:
                f.write(content)
            
            print(f"    [+] Written: {filename}")
    
    def _write_summary(self):
        """Write summary report."""
        summary = f"""# IDOR/BOLA Intelligent Fuzzing Report

**Generated:** {datetime.now().isoformat()}
**Total Attacks Executed:** {self.checkpoint.get('last_processed', 'all')}
**Total Findings:** {len(self.findings)}

## Intelligence Summary

| Metric | Value |
|--------|-------|
| **IDs Learned** | {sum(len(ids) for ids in self.inventory.user_owned_ids.values())} |
| **Confirmed BOLA** | {sum(1 for f in self.findings if f.confidence == 'confirmed')} |
| **Likely Findings** | {sum(1 for f in self.findings if f.confidence == 'likely')} |
| **Potential Findings** | {sum(1 for f in self.findings if f.confidence == 'potential')} |

## Summary by Confidence

| Confidence | Count | Description |
|------------|-------|-------------|
| CONFIRMED | {sum(1 for f in self.findings if f.confidence == 'confirmed')} | Cross-user ID swap succeeded - verified IDOR |
| LIKELY | {sum(1 for f in self.findings if f.confidence == 'likely')} | Sequential probe found other data |
| POTENTIAL | {sum(1 for f in self.findings if f.confidence == 'potential')} | Needs manual verification |

## Summary by Severity

| Severity | Count |
|----------|-------|
| CRITICAL | {sum(1 for f in self.findings if f.severity == Severity.CRITICAL)} |
| HIGH     | {sum(1 for f in self.findings if f.severity == Severity.HIGH)} |
| MEDIUM   | {sum(1 for f in self.findings if f.severity == Severity.MEDIUM)} |
| LOW      | {sum(1 for f in self.findings if f.severity == Severity.LOW)} |

## Summary by Attack Type

| Attack Type | Count |
|-------------|-------|
| Cross-User Swap | {sum(1 for f in self.findings if f.attack_type == 'cross_user')} |
| Sequential Probe | {sum(1 for f in self.findings if f.attack_type == 'sequential')} |

## Critical & High Findings

"""
        for f in self.findings:
            if f.severity in [Severity.CRITICAL, Severity.HIGH]:
                summary += f"""### {f.id}: {f.endpoint_pattern}

**Type:** {f.type} | **Severity:** {f.severity.name} | **Confidence:** {f.confidence.upper()}
**Attack:** {f.attack_type}
**Description:** {f.description}
**Vulnerability Report:** [vulnerabilities/{f.id}-{f.type}-{f.severity.name}.md](vulnerabilities/{f.id}-{f.type}-{f.severity.name}.md)

---

"""
        
        summary += """
## All Vulnerability Files

| ID | Type | Severity | Confidence | File |
|----|------|----------|------------|------|
"""
        for f in sorted(self.findings, key=lambda x: (x.severity.value, x.confidence != 'confirmed', x.type)):
            filename = f"{f.id}-{f.type}-{f.severity.name}.md"
            summary += f"| {f.id} | {f.type} | {f.severity.name} | {f.confidence} | [{filename}](vulnerabilities/{filename}) |\n"
        
        with open(self.output_dir / 'idor_summary.md', 'w') as f:
            f.write(summary)


# ============================================================================
# CLI
# ============================================================================
def load_auth_from_directory(accounts_dir: Path) -> List[AuthContext]:
    """Load auth contexts from accounts directory."""
    auth_contexts = []
    
    if not accounts_dir.exists():
        print(f"[!] Auth directory not found: {accounts_dir}")
        return auth_contexts
    
    for auth_file in accounts_dir.glob("*_auth.json"):
        try:
            with open(auth_file) as f:
                data = json.load(f)
            
            account_name = auth_file.stem.replace("_auth", "")
            headers = {}
            
            if "authorization" in data:
                headers["Authorization"] = data["authorization"]
            elif "bearer_token" in data:
                headers["Authorization"] = f"Bearer {data['bearer_token']}"
            elif "token" in data:
                headers["Authorization"] = f"Bearer {data['token']}"
            
            if "cookies" in data:
                if isinstance(data["cookies"], dict):
                    headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in data["cookies"].items())
                else:
                    headers["Cookie"] = data["cookies"]
            
            if "headers" in data:
                headers.update(data["headers"])
            
            user_id = data.get("user_id") or data.get("userId") or data.get("id")
            known_ids = data.get("known_ids", [])
            
            auth_contexts.append(AuthContext(
                name=account_name,
                headers=headers,
                user_id=str(user_id) if user_id else None,
                known_ids=known_ids
            ))
            print(f"[+] Loaded auth: {account_name}")
            
        except Exception as e:
            print(f"[!] Failed to load {auth_file}: {e}")
    
    return auth_contexts


def main():
    parser = argparse.ArgumentParser(description='IDOR/BOLA Fuzzer - Task 34')
    parser.add_argument('--api-endpoints', type=Path, help='Kiterunner API endpoints')
    parser.add_argument('--dynamic-urls', type=Path, help='Dynamic URLs with params')
    parser.add_argument('--har-data', type=Path, help='HAR common data file')
    parser.add_argument('--corpus', type=Path, help='URL corpus file')
    parser.add_argument('--url', type=str, help='Single URL to test')
    parser.add_argument('--auth-dir', type=Path, help='Auth accounts directory')
    parser.add_argument('--output', type=Path, default=Path('outputs'), help='Output directory')
    parser.add_argument('--temp', type=Path, default=Path('temp/task34'), help='Temp directory')
    parser.add_argument('--delay', type=int, default=100, help='Delay between requests (ms)')
    parser.add_argument('--fuzz-range', type=int, default=10, help='Range for numeric fuzzing')
    parser.add_argument('--resume', type=Path, help='Resume from checkpoint')
    
    args = parser.parse_args()
    
    Config.DELAY_MS = args.delay
    Config.FUZZ_RANGE = args.fuzz_range
    
    # Load auth contexts
    auth_contexts = []
    if args.auth_dir:
        auth_contexts = load_auth_from_directory(args.auth_dir)
    
    if not auth_contexts:
        print("[!] No auth contexts loaded. Add --auth-dir")
        sys.exit(1)
    
    # Load endpoints
    endpoints = []
    
    if args.url:
        endpoints.append(EndpointParser.parse_url(args.url))
    else:
        for source in [args.api_endpoints, args.dynamic_urls, args.har_data, args.corpus]:
            if source and source.exists():
                loaded = EndpointParser.load_endpoints_from_file(source)
                endpoints.extend(loaded)
                print(f"[+] Loaded {len(loaded)} endpoints from {source}")
    
    if not endpoints:
        print("[!] No endpoints to test")
        sys.exit(1)
    
    # Dedupe by URL
    seen = set()
    unique_endpoints = []
    for ep in endpoints:
        if ep.url not in seen:
            seen.add(ep.url)
            unique_endpoints.append(ep)
    
    print(f"[*] Total unique endpoints: {len(unique_endpoints)}")
    
    # Create fuzzer and run
    fuzzer = IDORFuzzer(
        auth_contexts=auth_contexts,
        output_dir=args.output,
        temp_dir=args.temp
    )
    
    resume_from = 0
    if args.resume and args.resume.exists():
        with open(args.resume) as f:
            checkpoint = json.load(f)
        resume_from = checkpoint.get('last_processed', 0)
        fuzzer.finding_counter = checkpoint.get('finding_counter', 0)
        print(f"[*] Resuming from request {resume_from}")
    
    fuzzer.run(unique_endpoints, resume_from)


if __name__ == "__main__":
    main()
