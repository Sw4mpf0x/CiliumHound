"""
Policy Parser: Parses Cilium Network Policy YAML files

This module handles parsing and extracting information from CiliumNetworkPolicy
YAML files, including namespaces, policy names, ports, and keys.
"""

import os
import yaml
from typing import Dict, List, Set, Any, Optional, Tuple


class PolicyParser:
    """Parser for Cilium Network Policy YAML files"""
    
    NAMESPACE_LABEL_KEY = 'k8s:io.kubernetes.pod.namespace'
    
    def __init__(self, debug: bool = False):
        """Initialize the parser with optional debug mode"""
        self.debug = debug
    
    def _add_key(self, key: str, keys: Set[str], prefix: str = "") -> None:
        """Helper method to add a key with optional debug output"""
        keys.add(key)
        if self.debug and prefix:
            print(f"      [DEBUG] {prefix} Adding key: {key}")
    
    def _add_cidr_keys(self, cidr_list: List[Any], keys: Set[str], key_prefix: str) -> None:
        """Extract and add CIDR keys from a list"""
        if self.debug:
            print(f"    [DEBUG] Found {key_prefix}: {cidr_list}")
        for cidr_item in cidr_list:
            if isinstance(cidr_item, dict):
                cidr = cidr_item.get('cidr', cidr_item)
            else:
                cidr = cidr_item
            key = f"{key_prefix}:{cidr}"
            self._add_key(key, keys)
    
    def _add_entity_keys(self, entity_list: List[str], keys: Set[str], key_prefix: str) -> None:
        """Extract and add entity keys from a list"""
        if self.debug:
            print(f"    [DEBUG] Found {key_prefix}: {entity_list}")
        for entity in entity_list:
            key = f"{key_prefix}:{entity}"
            self._add_key(key, keys)
    
    def _process_labels(self, labels: Dict[str, str], keys: Set[str], 
                        and_edges: Set[Tuple[str, ...]], 
                        namespace_key_format: str = "namespace:{value} (byLabel)") -> None:
        """Process matchLabels and extract keys, handling AND relationships"""
        if self.debug:
            print(f"      [DEBUG] Processing labels: {labels}")
        
        and_edges_list = []
        for k, v in labels.items():
            if k == self.NAMESPACE_LABEL_KEY:
                key = namespace_key_format.format(value=labels[k])
            else:
                key = f"label:{k}={v}"
            and_edges_list.append(key)
            self._add_key(key, keys, prefix="")
            
        if len(and_edges_list) > 1:
            and_edges.add(tuple(and_edges_list))
    
    def _process_from_endpoint_labels(self, labels: Dict[str, str], keys: Set[str]) -> None:
        """Process fromEndpoint labels (special handling for namespace)"""
        if self.debug:
            print(f"      [DEBUG] Processing fromEndpoint labels: {labels}")
        
        # Add namespace key if present
        if self.NAMESPACE_LABEL_KEY in labels:
            key = f"namespace:{labels[self.NAMESPACE_LABEL_KEY]}"
            self._add_key(key, keys, prefix="")
        
        # Add all label keys
        for k, v in labels.items():
            key = f"label:{k}={v}"
            self._add_key(key, keys, prefix="")
    
    def extract_namespace_from_filename(self, filename: str) -> Optional[str]:
        """Extract namespace from filename format: [namespace]_[policy_name].yaml"""
        basename = os.path.basename(filename)
        if '_' in basename:
            parts = basename.rsplit('.', 1)[0].split('_', 1)
            if len(parts) >= 1:
                return parts[0]
        return None

    def extract_namespace_from_policy(self, policy: Dict[str, Any]) -> Optional[str]:
        """Extract namespace from policy metadata"""
        if 'metadata' in policy:
            if 'namespace' in policy['metadata']:
                return policy['metadata']['namespace']
        return None

    def extract_policy_name_from_filename(self, filename: str) -> Optional[str]:
        """Extract policy name from filename format: [namespace]_[policy_name].yaml"""
        basename = os.path.basename(filename)
        if '_' in basename:
            parts = basename.rsplit('.', 1)[0].split('_', 1)
            if len(parts) >= 2:
                return parts[1]
        return None

    def extract_policy_name_from_policy(self, policy: Dict[str, Any]) -> Optional[str]:
        """Extract policy name from policy metadata"""
        if 'metadata' in policy:
            if 'name' in policy['metadata']:
                return policy['metadata']['name']
        return None

    def extract_port_info_from_toPorts(self, toPorts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract port information from toPorts"""
        ports_info = []
        dns_rules_from_ports = []

        for port_rule in toPorts:
            # Extract ports
            if 'ports' in port_rule:
                for port_entry in port_rule['ports']:
                    port = port_entry.get('port', '')
                    protocol = port_entry.get('protocol', '')
                    ports_info.append({'port': port, 'protocol': protocol})
                    if self.debug:
                        print(f"      [DEBUG] Found port: {port}/{protocol}")
            
            # Extract DNS rules from toPorts
            if 'rules' in port_rule and 'dns' in port_rule['rules']:
                for dns_rule in port_rule['rules']['dns']:
                    if 'matchName' in dns_rule:
                        dns_rules_from_ports.append(dns_rule['matchName'])
                        if self.debug:
                            print(f"      [DEBUG] Found DNS matchName in toPorts: {dns_rule['matchName']}")
        return {"ports": ports_info, "dns_rules": dns_rules_from_ports}

    def _extract_fqdns(self, spec: Dict[str, Any], keys: Set[str]) -> None:
        """Extract FQDN keys from spec"""
        if 'toFQDNs' not in spec:
            return
        
        if self.debug:
            print(f"    [DEBUG] Found toFQDNs: {spec['toFQDNs']}")
        for fqdn_rule in spec['toFQDNs']:
            if 'matchName' in fqdn_rule:
                key = f"fqdn:{fqdn_rule['matchName']}"
                self._add_key(key, keys)
            if 'matchPattern' in fqdn_rule:
                key = f"fqdn-pattern:{fqdn_rule['matchPattern']}"
                self._add_key(key, keys)

    def _extract_to_cidrs(self, spec: Dict[str, Any], keys: Set[str]) -> None:
        """Extract toCIDR and toCIDRSet keys from spec"""
        if 'toCIDR' in spec:
            self._add_cidr_keys(spec['toCIDR'], keys, "cidr")
        
        if 'toCIDRSet' in spec:
            if self.debug:
                print(f"    [DEBUG] Found toCIDRSet: {spec['toCIDRSet']}")
            for cidr_rule in spec['toCIDRSet']:
                cidr = cidr_rule.get('cidr', cidr_rule) if isinstance(cidr_rule, dict) else cidr_rule
                key = f"cidrSet:{cidr}"
                self._add_key(key, keys)

    def _extract_from_cidrs(self, spec: Dict[str, Any], keys: Set[str]) -> None:
        """Extract fromCIDRs keys from spec"""
        if 'fromCIDRs' in spec:
            self._add_cidr_keys(spec['fromCIDRs'], keys, "cidr")

    def _extract_to_endpoints(self, spec: Dict[str, Any], keys: Set[str], 
                              and_edges: Set[Tuple[str, ...]]) -> None:
        """Extract toEndpoints keys from spec"""
        if 'toEndpoints' not in spec:
            return
        
        if self.debug:
            print(f"    [DEBUG] Found toEndpoints: {spec['toEndpoints']}")
        for endpoint in spec['toEndpoints']:
            if 'matchLabels' in endpoint:
                self._process_labels(endpoint['matchLabels'], keys, and_edges)
            if 'matchExpressions' in endpoint:
                self._process_match_expressions(endpoint['matchExpressions'], keys, and_edges)

    def _extract_from_endpoints(self, spec: Dict[str, Any], keys: Set[str], and_edges: Set[Tuple[str, ...]]) -> None:
        """Extract fromEndpoints keys from spec"""
        if 'fromEndpoints' not in spec:
            return
        
        if self.debug:
            print(f"    [DEBUG] Found fromEndpoints: {spec['fromEndpoints']}")
        for endpoint in spec['fromEndpoints']:
            if 'matchLabels' in endpoint:
                self._process_labels(endpoint['matchLabels'], keys, and_edges)
            if 'matchExpressions' in endpoint:
                self._process_match_expressions(endpoint['matchExpressions'], keys, and_edges)

    def _process_match_expressions(self, match_expressions: List[Dict[str, Any]], keys: Set[str], and_edges: Set[Tuple[str, ...]]) -> None:
        """Process matchExpressions and extract keys"""
        if self.debug:
            print(f"      [DEBUG] Processing matchExpressions: {match_expressions}")
        and_edges_list = []
        for match_expression in match_expressions:
            key = f"label:expr:\"{match_expression['key']}\"-({match_expression['operator']})"
            if match_expression.get('values'):
                key += f"-{str(match_expression.get('values'))}"
            self._add_key(key, keys)
            and_edges_list.append(key)
        if len(and_edges_list) > 1:
            and_edges.add(tuple(and_edges_list))

    def _extract_services(self, spec: Dict[str, Any], keys: Set[str]) -> None:
        """Extract toServices keys from spec"""
        if 'toServices' not in spec:
            return
        
        if self.debug:
            print(f"    [DEBUG] Found toServices: {spec['toServices']}")
        for service in spec['toServices']:
            if 'k8sService' in service:
                svc = service['k8sService']
                service_name = svc.get('serviceName', '')
                namespace = svc.get('namespace', '')
                if service_name:
                    key = f"service:{namespace}/{service_name}" if namespace else f"service:{service_name}"
                    self._add_key(key, keys)
            if 'serviceSelector' in service:
                selector = service['serviceSelector']
                if 'matchLabels' in selector:
                    labels = selector['matchLabels']
                    if self.debug:
                        print(f"      [DEBUG] Processing serviceSelector labels: {labels}")
                    for k, v in labels.items():
                        key = f"label:{k}={v}"
                        self._add_key(key, keys)

    def _extract_to_entities(self, spec: Dict[str, Any], keys: Set[str]) -> None:
        """Extract toEntities keys from spec"""
        if 'toEntities' in spec:
            self._add_entity_keys(spec['toEntities'], keys, "entity")

    def _extract_from_entities(self, spec: Dict[str, Any], keys: Set[str]) -> None:
        """Extract fromEntities keys from spec"""
        if 'fromEntities' in spec:
            self._add_entity_keys(spec['fromEntities'], keys, "entity")

    def extract_keys_from_spec(self, spec: Dict[str, Any], direction: str) -> Tuple[Dict[str, Dict[str, Any]], Set[Tuple[str, ...]]]:
        """
        Extract all keys (FQDNs, endpoints, CIDRs, etc.) from ingress/egress spec
        Returns: (key_metadata, and_edges) where:
            - key_metadata: maps key -> {ports, dns_rules, etc.}
            - and_edges: set of tuples representing AND relationships between labels
        """
        keys: Set[str] = set()
        key_metadata: Dict[str, Dict[str, Any]] = {}
        and_edges: Set[Tuple[str, ...]] = set()

        if not spec:
            if self.debug:
                print(f"  [DEBUG] Empty spec for {direction}")
            return key_metadata, and_edges
        
        if self.debug:
            print(f"  [DEBUG] Processing {direction} spec with keys: {list(spec.keys())}")
        
        # Extract all key types
        self._extract_fqdns(spec, keys)
        self._extract_to_cidrs(spec, keys)
        self._extract_to_endpoints(spec, keys, and_edges)
        self._extract_services(spec, keys)
        self._extract_to_entities(spec, keys)
        self._extract_from_endpoints(spec, keys)
        self._extract_from_cidrs(spec, keys)
        self._extract_from_entities(spec, keys)
        
        # Populate key metadata
        for key in keys:
            key_metadata[key] = {}
        
        # Add port info if available
        if 'toPorts' in spec:
            if self.debug:
                print(f"    [DEBUG] Found toPorts: {spec['toPorts']}")
            port_info = self.extract_port_info_from_toPorts(spec['toPorts'])
            for key in key_metadata.keys():
                if not key.startswith("namespace:"):
                    key_metadata[key] = port_info

        if self.debug:
            print(f"  [DEBUG] Total keys extracted from {direction} spec: {len(keys)}")
            if key_metadata:
                print(f"  [DEBUG] Key metadata collected for {len(key_metadata)} keys")
                for key, meta in key_metadata.items():
                    if meta.get('ports') or meta.get('dns_rules'):
                        print(f"    [DEBUG]   {key}: ports={meta.get('ports')}, dns_rules={meta.get('dns_rules')}")
        
        return key_metadata, and_edges

    def parse_policy_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Parse a CiliumNetworkPolicy YAML file"""
        print(f"Parsing file: {filepath}")
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                # Try to parse as standard YAML
                try:
                    policy = yaml.safe_load(content)
                    if policy and isinstance(policy, dict):
                        if self.debug:
                            print(f"  [DEBUG] Successfully parsed YAML. Keys: {list(policy.keys())}")
                        return policy
                except yaml.YAMLError as e:
                    # If it fails, it might be in kubectl describe format
                    # For now, we'll skip those or try to parse them differently
                    if self.debug:
                        print(f"  [DEBUG] YAML parse error: {e}")
                    pass
        except Exception as e:
            print(f"Warning: Could not parse {filepath}: {e}")
            if self.debug:
                print(f"  [DEBUG] Exception details: {type(e).__name__}: {e}")
        return None


# Module-level functions for backward compatibility
_default_parser = PolicyParser(debug=False)

def extract_namespace_from_filename(filename: str) -> Optional[str]:
    """Extract namespace from filename format: [namespace]_[policy_name].yaml"""
    return _default_parser.extract_namespace_from_filename(filename)


def extract_namespace_from_policy(policy: Dict[str, Any]) -> Optional[str]:
    """Extract namespace from policy metadata"""
    return _default_parser.extract_namespace_from_policy(policy)


def extract_policy_name_from_filename(filename: str) -> Optional[str]:
    """Extract policy name from filename format: [namespace]_[policy_name].yaml"""
    return _default_parser.extract_policy_name_from_filename(filename)


def extract_policy_name_from_policy(policy: Dict[str, Any]) -> Optional[str]:
    """Extract policy name from policy metadata"""
    return _default_parser.extract_policy_name_from_policy(policy)


def extract_port_info_from_toPorts(toPorts: List[Dict[str, Any]], debug: bool = False) -> Dict[str, Any]:
    """Extract port information from toPorts"""
    parser = PolicyParser(debug=debug)
    return parser.extract_port_info_from_toPorts(toPorts)


def extract_keys_from_spec(spec: Dict[str, Any], direction: str, debug: bool = False) -> Tuple[Dict[str, Dict[str, Any]], Set[Tuple[str, ...]]]:
    """
    Extract all keys (FQDNs, endpoints, CIDRs, etc.) from ingress/egress spec
    Returns: (key_metadata, and_edges) where:
        - key_metadata: maps key -> {ports, dns_rules, etc.}
        - and_edges: set of tuples representing AND relationships between labels
    """
    parser = PolicyParser(debug=debug)
    return parser.extract_keys_from_spec(spec, direction)


def parse_policy_file(filepath: str, debug: bool = False) -> Optional[Dict[str, Any]]:
    """Parse a CiliumNetworkPolicy YAML file"""
    parser = PolicyParser(debug=debug)
    return parser.parse_policy_file(filepath)
