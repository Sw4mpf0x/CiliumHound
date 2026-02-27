"""
Policy Parser: Parses Cilium Network Policy YAML files

This module handles parsing and extracting information from CiliumNetworkPolicy
YAML files, including namespaces, policy names, ports, and keys.
"""

import os
import yaml
from typing import Dict, List, Set, Any, Optional, Tuple


def extract_namespace_from_filename(filename: str) -> Optional[str]:
    """Extract namespace from filename format: [namespace]_[policy_name].yaml"""
    basename = os.path.basename(filename)
    if '_' in basename:
        parts = basename.rsplit('.', 1)[0].split('_', 1)
        if len(parts) >= 1:
            return parts[0]
    return None


def extract_namespace_from_policy(policy: Dict[str, Any]) -> Optional[str]:
    """Extract namespace from policy metadata"""
    if 'metadata' in policy:
        if 'namespace' in policy['metadata']:
            return policy['metadata']['namespace']
    return None


def extract_policy_name_from_filename(filename: str) -> Optional[str]:
    """Extract policy name from filename format: [namespace]_[policy_name].yaml"""
    basename = os.path.basename(filename)
    if '_' in basename:
        parts = basename.rsplit('.', 1)[0].split('_', 1)
        if len(parts) >= 2:
            return parts[1]
    return None


def extract_policy_name_from_policy(policy: Dict[str, Any]) -> Optional[str]:
    """Extract policy name from policy metadata"""
    if 'metadata' in policy:
        if 'name' in policy['metadata']:
            return policy['metadata']['name']
    return None


def extract_port_info_from_toPorts(toPorts: List[Dict[str, Any]], debug: bool = False) -> Dict[str, Any]:
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
                if debug:
                    print(f"      [DEBUG] Found port: {port}/{protocol}")
        
        # Extract DNS rules from toPorts
        if 'rules' in port_rule and 'dns' in port_rule['rules']:
            for dns_rule in port_rule['rules']['dns']:
                if 'matchName' in dns_rule:
                    dns_rules_from_ports.append(dns_rule['matchName'])
                    if debug:
                        print(f"      [DEBUG] Found DNS matchName in toPorts: {dns_rule['matchName']}")
    return {"ports": ports_info, "dns_rules": dns_rules_from_ports}


def extract_keys_from_spec(spec: Dict[str, Any], direction: str, debug: bool = False) -> Tuple[Set[str], Dict[str, Dict[str, Any]], Set[Tuple[str, ...]]]:
    """
    Extract all keys (FQDNs, endpoints, CIDRs, etc.) from ingress/egress spec
    Returns: (keys, key_metadata, and_edges) where:
        - keys: set of extracted key strings
        - key_metadata: maps key -> {ports, dns_rules, etc.}
        - and_edges: set of tuples representing AND relationships between labels
    """
    keys = set()
    key_metadata: Dict[str, Dict[str, Any]] = {}
    and_edges = set()

    if not spec:
        if debug:
            print(f"  [DEBUG] Empty spec for {direction}")
        return keys, key_metadata, and_edges
    
    if debug:
        print(f"  [DEBUG] Processing {direction} spec with keys: {list(spec.keys())}")
    
    # Extract FQDNs
    if 'toFQDNs' in spec:
        if debug:
            print(f"    [DEBUG] Found toFQDNs: {spec['toFQDNs']}")
        for fqdn_rule in spec['toFQDNs']:
            if 'matchName' in fqdn_rule:
                key = f"fqdn:{fqdn_rule['matchName']}"
                keys.add(key)
                if debug:
                    print(f"      [DEBUG] Adding key: {key}")
            if 'matchPattern' in fqdn_rule:
                key = f"fqdn-pattern:{fqdn_rule['matchPattern']}"
                keys.add(key)
                if debug:
                    print(f"      [DEBUG] Adding key: {key}")
    
    # Extract CIDR
    if 'toCIDR' in spec:
        if debug:
            print(f"    [DEBUG] Found toCIDR: {spec['toCIDR']}")
        for cidr in spec['toCIDR']:
            key = f"cidr:{cidr}"
            keys.add(key)
            if debug:
                print(f"      [DEBUG] Adding key: {key}")

    # Extract CIDRSets
    if 'toCIDRSet' in spec:
        if debug:
            print(f"    [DEBUG] Found toCIDRSet: {spec['toCIDRSet']}")
        for cidr_rule in spec['toCIDRSet']:
            cidr = cidr_rule.get('cidr', cidr_rule) if isinstance(cidr_rule, dict) else cidr_rule
            key = f"cidrSet:{cidr}"
            keys.add(key)
            if debug:
                print(f"      [DEBUG] Adding key: {key}")
    
    # Extract Endpoints (namespaces from match labels)
    if 'toEndpoints' in spec:
        if debug:
            print(f"    [DEBUG] Found toEndpoints: {spec['toEndpoints']}")
        for endpoint in spec['toEndpoints']:
            if 'matchLabels' in endpoint:
                labels = endpoint['matchLabels']
                if debug:
                    print(f"      [DEBUG] Processing endpoint labels: {labels}")
                # Extract namespace from labels
                namespace_key = 'k8s:io.kubernetes.pod.namespace'
                # Add all label combinations as keys
                and_edges_list = []
                for k, v in labels.items():
                    if k == namespace_key:
                        key = f"namespace:{labels[k]} (byLabel)"
                    else:
                        key = f"label:{k}={v}"
                    and_edges_list.append(key)
                    keys.add(key)
                    if debug:
                        print(f"        [DEBUG] Adding key: {key}")

                if len(and_edges_list) > 1:
                    and_edges.add(tuple(and_edges_list))
    
    # Extract Services
    if 'toServices' in spec:
        if debug:
            print(f"    [DEBUG] Found toServices: {spec['toServices']}")
        for service in spec['toServices']:
            if 'k8sService' in service:
                svc = service['k8sService']
                service_name = svc.get('serviceName', '')
                namespace = svc.get('namespace', '')
                if service_name:
                    key = f"service:{namespace}/{service_name}" if namespace else f"service:{service_name}"
                    keys.add(key)
                    if debug:
                        print(f"      [DEBUG] Adding key: {key}")
            if 'serviceSelector' in service:
                selector = service['serviceSelector']
                if 'matchLabels' in selector:
                    labels = selector['matchLabels']
                    if debug:
                        print(f"      [DEBUG] Processing serviceSelector labels: {labels}")
                    for k, v in labels.items():
                        key = f"label:{k}={v}"
                        keys.add(key)
    
    # Extract Entities
    if 'toEntities' in spec:
        if debug:
            print(f"    [DEBUG] Found toEntities: {spec['toEntities']}")
        for entity in spec['toEntities']:
            key = f"entity:{entity}"
            keys.add(key)
            if debug:
                print(f"      [DEBUG] Adding key: {key}")
    
    # Extract fromEndpoints for ingress
    if 'fromEndpoints' in spec:
        if debug:
            print(f"    [DEBUG] Found fromEndpoints: {spec['fromEndpoints']}")
        for endpoint in spec['fromEndpoints']:
            if 'matchLabels' in endpoint:
                labels = endpoint['matchLabels']
                if debug:
                    print(f"      [DEBUG] Processing fromEndpoint labels: {labels}")
                namespace_key = 'k8s:io.kubernetes.pod.namespace'
                if namespace_key in labels:
                    key = f"namespace:{labels[namespace_key]}"
                    keys.add(key)
                    if debug:
                        print(f"        [DEBUG] Adding key: {key}")
                for k, v in labels.items():
                    key = f"label:{k}={v}"
                    keys.add(key)
                    if debug:
                        print(f"        [DEBUG] Adding key: {key}")
    
    # Extract fromCIDRs for ingress
    if 'fromCIDRs' in spec:
        if debug:
            print(f"    [DEBUG] Found fromCIDRs: {spec['fromCIDRs']}")
        for cidr in spec['fromCIDRs']:
            key = f"cidr:{cidr}"
            keys.add(key)
            if debug:
                print(f"      [DEBUG] Adding key: {key}")
    
    # Extract fromEntities for ingress
    if 'fromEntities' in spec:
        if debug:
            print(f"    [DEBUG] Found fromEntities: {spec['fromEntities']}")
        for entity in spec['fromEntities']:
            key = f"entity:{entity}"
            keys.add(key)
            if debug:
                print(f"      [DEBUG] Adding key: {key}")
    
    # Populate key metadata
    for key in keys:
        key_metadata[key] = {}
    # Add port info if available
    if 'toPorts' in spec:
        if debug:
            print(f"    [DEBUG] Found toPorts: {spec['toPorts']}")
        port_info = extract_port_info_from_toPorts(spec['toPorts'], debug=debug)
        for key, _ in key_metadata.items():
            if not key.startswith("namespace:"):
                key_metadata[key] = port_info

    if debug:
        print(f"  [DEBUG] Total keys extracted from {direction} spec: {len(keys)}")
        if key_metadata:
            print(f"  [DEBUG] Key metadata collected for {len(key_metadata)} keys")
            for key, meta in key_metadata.items():
                if meta.get('ports') or meta.get('dns_rules'):
                    print(f"    [DEBUG]   {key}: ports={meta.get('ports')}, dns_rules={meta.get('dns_rules')}")
    
    return key_metadata, and_edges


def parse_policy_file(filepath: str, debug: bool = False) -> Optional[Dict[str, Any]]:
    """Parse a CiliumNetworkPolicy YAML file"""
    print(f"Parsing file: {filepath}")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            # Try to parse as standard YAML
            try:
                policy = yaml.safe_load(content)
                if policy and isinstance(policy, dict):
                    if debug:
                        print(f"  [DEBUG] Successfully parsed YAML. Keys: {list(policy.keys())}")
                    return policy
            except yaml.YAMLError as e:
                # If it fails, it might be in kubectl describe format
                # For now, we'll skip those or try to parse them differently
                if debug:
                    print(f"  [DEBUG] YAML parse error: {e}")
                pass
    except Exception as e:
        print(f"Warning: Could not parse {filepath}: {e}")
        if debug:
            print(f"  [DEBUG] Exception details: {type(e).__name__}: {e}")
    return None
