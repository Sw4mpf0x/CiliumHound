#!/usr/bin/env python3
"""
CiliumHound: Convert Cilium Network Policies to BloodHound OpenGraph

This script processes CiliumNetworkPolicy YAML files and converts them
into a BloodHound OpenGraph JSON file for visualization.
"""

import os
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Tuple
from collections import defaultdict

from graph_builder import create_bloodhound_graph
from policy_parser import (
    parse_policy_file,
    extract_namespace_from_filename,
    extract_namespace_from_policy,
    extract_policy_name_from_filename,
    extract_policy_name_from_policy,
    extract_keys_from_spec
)


def process_policies(folder_path: str, debug: bool = False) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]], Dict[str, Dict[str, Any]], Set[Tuple[str, ...]]]:
    """
    Process all YAML files in the folder and extract relationships.
    Returns: (namespace_egress_keys, namespace_ingress_keys, key_metadata, and_edges)
    where key_metadata maps key -> {ports, dns_rules, etc.}
    and and_edges is a set of tuples representing AND relationships
    """
    namespace_egress_keys: Dict[str, Set[str]] = defaultdict(set)
    namespace_ingress_keys: Dict[str, Set[str]] = defaultdict(set)
    key_egress_namespaces: Dict[str, Set[str]] = defaultdict(set)
    key_ingress_namespaces: Dict[str, Set[str]] = defaultdict(set)
    key_metadata: Dict[str, Dict[str, Any]] = defaultdict(lambda: {'ports': [], 'dns_rules': []})
    and_edges: set() = set()
    folder = Path(folder_path)
    yaml_files = list(folder.glob("*.yaml")) + list(folder.glob("*.yml"))
    
    print(f"Found {len(yaml_files)} YAML files in {folder_path}")
    if debug:
        for yf in yaml_files:
            print(f"  [DEBUG]   - {yf}")
    
    if not yaml_files:
        print(f"Warning: No YAML files found in {folder_path}")
        return namespace_egress_keys, namespace_ingress_keys, dict(key_metadata), and_edges
    
    for yaml_file in yaml_files:
        print(f"\nProcessing file: {yaml_file}")
        
        policy = parse_policy_file(str(yaml_file), debug=debug)
        if not policy:
            if debug:
                print(f"  [DEBUG] Skipping file (could not parse)")
            continue
        
        # Determine namespace
        namespace = extract_namespace_from_policy(policy)
        if debug:
            print(f"  [DEBUG] Namespace from policy metadata: {namespace}")
        if not namespace:
            namespace = extract_namespace_from_filename(str(yaml_file))
            if debug:
                print(f"  [DEBUG] Namespace from filename: {namespace}")
        
        policy_name = extract_policy_name_from_filename(str(yaml_file))
        if debug:
            print(f"  [DEBUG] Policy name from filename: {policy_name}")
        if not policy_name:
            policy_name = extract_policy_name_from_policy(policy)
            if debug:
                print(f"  [DEBUG] Policy name from policy metadata: {policy_name}")
        
        if not namespace:
            print(f"Warning: Could not determine namespace for {yaml_file}")
            continue
        
        if debug:
            print(f"  [DEBUG] Using namespace: {namespace}")
        
        # Check for specs
        specs = []
        if 'specs' in policy:
            specs = policy.get('specs')
        if 'spec' in policy:
            specs.append(policy.get('spec'))
        
        if debug:
            print(f"  [DEBUG] Found {len(specs)} spec(s)")

        if not specs:
            print(f"Warning: No specs found in {yaml_file}")
            continue
        
        # Process spec
        for spec in specs:
            # Process Egress
            if 'egress' in spec:
                if debug:
                    print(f"  [DEBUG] Processing Egress rules...")
                egress_rules = spec['egress'] if isinstance(spec['egress'], list) else [spec['egress']]
                if debug:
                    print(f"    [DEBUG] Found {len(egress_rules)} egress rule(s)")
                for idx, egress in enumerate(egress_rules):
                    if debug:
                        print(f"    [DEBUG] Processing egress rule {idx + 1}")
                    keys, metadata, new_and_edges = extract_keys_from_spec(egress, 'egress', debug=debug)
                    and_edges.update(new_and_edges)
                    if debug:
                        print(f"    [DEBUG] Extracted {len(keys)} keys from egress rule {idx + 1}: {keys}")
                    namespace_egress_keys[namespace].update(keys)
                    for key in keys:
                        key_egress_namespaces[key].add(namespace)
                    # Merge metadata
                    for key, meta in metadata.items():
                        if key in key_metadata and 'ports' in key_metadata[key]:
                            # Add namespace and policy name to key metadata
                            key_metadata[key]['namespace'] += f",{namespace}"
                            key_metadata[key]['policy_name'] += f",{policy_name}"
                            # Merge ports and dns_rules lists
                            key_metadata[key]['ports'].extend(meta.get('ports', []))
                            key_metadata[key]['dns_rules'].extend(meta.get('dns_rules', []))
                        else:
                            meta['namespace'] = namespace
                            meta['policy_name'] = policy_name
                            key_metadata[key] = meta.copy()
            
            # Process Ingress
            if 'ingress' in spec:
                if debug:
                    print(f"  [DEBUG] Processing Ingress rules...")
                ingress_rules = spec['ingress'] if isinstance(spec['ingress'], list) else [spec['ingress']]
                if debug:
                    print(f"    [DEBUG] Found {len(ingress_rules)} ingress rule(s)")
                for idx, ingress in enumerate(ingress_rules):
                    if debug:
                        print(f"    [DEBUG] Processing ingress rule {idx + 1}")
                    keys, metadata, new_and_edges = extract_keys_from_spec(ingress, 'ingress', debug=debug)
                    and_edges.update(new_and_edges)
                    if debug:
                        print(f"    [DEBUG] Extracted {len(keys)} keys from ingress rule {idx + 1}: {keys}")
                    namespace_ingress_keys[namespace].update(keys)
                    for key in keys:
                        key_ingress_namespaces[key].add(namespace)
                    # Merge metadata
                    for key, meta in metadata.items():
                        if key in key_metadata and 'ports' in key_metadata[key]:
                            # Add namespace and policy name to key metadata if not already present
                            if policy_name not in key_metadata[key]['policy_name']:
                                key_metadata[key]['policy_name'] += f",{policy_name}"
                            if namespace not in key_metadata[key]['namespace']:
                                key_metadata[key]['namespace'] += f",{namespace}"
                            # Merge ports and dns_rules lists
                            key_metadata[key]['ports'].extend(meta.get('ports', []))
                            key_metadata[key]['dns_rules'].extend(meta.get('dns_rules', []))
                        else:
                            meta['namespace'] = namespace
                            meta['policy_name'] = policy_name
                            key_metadata[key] = meta.copy()
    
    print(f"\nSummary:")
    print(f"  Namespaces with egress: {len(namespace_egress_keys)}")
    for ns, keys in namespace_egress_keys.items():
        print(f"    {ns}: {len(keys)} keys")
    print(f"  Namespaces with ingress: {len(namespace_ingress_keys)}")
    for ns, keys in namespace_ingress_keys.items():
        print(f"    {ns}: {len(keys)} keys")
    print(f"  Keys with metadata: {len([k for k, v in key_metadata.items() if v.get('ports') or v.get('dns_rules')])}")
    
    return namespace_egress_keys, namespace_ingress_keys, dict(key_metadata), and_edges



def main():
    parser = argparse.ArgumentParser(
        description="Convert Cilium Network Policies to BloodHound OpenGraph JSON"
    )
    parser.add_argument(
        "folder",
        help="Folder containing CiliumNetworkPolicy YAML files"
    )
    parser.add_argument(
        "-o", "--output",
        default="cilium_opengraph.json",
        help="Output JSON file path (default: cilium_opengraph.json)"
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Enable debug mode with verbose output"
    )
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.folder):
        print(f"Error: {args.folder} is not a valid directory")
        sys.exit(1)
    
    if args.debug:
        print("=" * 60)
        print("DEBUG MODE ENABLED")
        print("=" * 60)
    
    print(f"Processing Cilium policies from: {args.folder}")
    
    # Process all policies
    namespace_egress_keys, namespace_ingress_keys, key_metadata, and_edges = process_policies(args.folder, debug=args.debug)
    
    if not namespace_egress_keys and not namespace_ingress_keys:
        print("Error: No valid policies found or no relationships extracted")
        sys.exit(1)
    
    print(f"Found {len(set(namespace_egress_keys.keys()) | set(namespace_ingress_keys.keys()))} namespaces")
    total_keys = set()
    for keys in namespace_egress_keys.values():
        total_keys.update(keys)
    for keys in namespace_ingress_keys.values():
        total_keys.update(keys)
    print(f"Found {len(total_keys)} unique keys")
    
    if args.debug:
        print(f"\n[DEBUG] All unique keys found:")
        for key in sorted(total_keys):
            print(f"  [DEBUG]   - {key}")
    
    # Create BloodHound graph
    print("Creating BloodHound OpenGraph...")
    graph = create_bloodhound_graph(namespace_egress_keys, namespace_ingress_keys, key_metadata, and_edges, debug=args.debug)
    
    # Export to file
    print(f"Exporting to {args.output}...")
    graph.export_to_file(args.output)
    
    print(f"Success! Created {args.output} with {len(graph.nodes)} nodes and {len(graph.edges)} edges")


if __name__ == "__main__":
    main()
