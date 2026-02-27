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


def process_policy_file(yaml_file: Path, namespace_egress_keys: Dict[str, Set[str]], 
                        namespace_ingress_keys: Dict[str, Set[str]], 
                        key_metadata: Dict[str, Dict[str, Any]], 
                        and_edges: Set[Tuple[str, ...]], 
                        debug: bool = False) -> None:
    """
    Process a single YAML policy file and update the relationship dictionaries.
    """
    print(f"\nProcessing file: {yaml_file}")
    
    policy = parse_policy_file(str(yaml_file), debug=debug)
    if not policy:
        if debug:
            print(f"  [DEBUG] Skipping file (could not parse)")
        return
    
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
        return
    
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
        return
    
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
                metadata, new_and_edges = extract_keys_from_spec(egress, 'egress', debug=debug)
                and_edges.update(new_and_edges)
                if debug:
                    print(f"    [DEBUG] Extracted {len(metadata)} keys from egress rule {idx + 1}: {list(metadata.keys())}")
                namespace_egress_keys[namespace].update(metadata.keys())

                # Merge metadata
                for key, meta in metadata.items():
                    if key in key_metadata:
                        # Add namespace and policy name to key metadata if not already present
                        if 'policy_name' in key_metadata[key]:
                            if policy_name and policy_name not in key_metadata[key]['policy_name']:
                                key_metadata[key]['policy_name'] += f",{policy_name}"
                        else:
                            key_metadata[key]['policy_name'] = policy_name or ""
                        if 'namespace' in key_metadata[key]:
                            if namespace not in key_metadata[key]['namespace']:
                                key_metadata[key]['namespace'] += f",{namespace}"
                        else:
                            key_metadata[key]['namespace'] = namespace
                        if 'ports' in key_metadata[key]:
                            # Merge ports and dns_rules lists
                            # TODO: Make these map to policies
                            key_metadata[key]['ports'].extend(meta.get('ports', []))
                            # Add only unique 'dns_rules' to avoid duplicates
                            new_dns_rules = meta.get('dns_rules', [])
                            for rule in new_dns_rules:
                                if rule not in key_metadata[key]['dns_rules']:
                                    key_metadata[key]['dns_rules'].append(rule)
                    else:
                        meta['namespace'] = namespace
                        meta['policy_name'] = policy_name or ""
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
                metadata, new_and_edges = extract_keys_from_spec(ingress, 'ingress', debug=debug)
                and_edges.update(new_and_edges)
                if debug:
                    print(f"    [DEBUG] Extracted {len(metadata)} keys from ingress rule {idx + 1}: {list(metadata.keys())}")
                namespace_ingress_keys[namespace].update(metadata.keys())

                # Merge metadata
                for key, meta in metadata.items():
                    if key in key_metadata:
                        # Add namespace and policy name to key metadata if not already present
                        if 'policy_name' in key_metadata[key]:
                            if policy_name and policy_name not in key_metadata[key]['policy_name']:
                                key_metadata[key]['policy_name'] += f",{policy_name}"
                        else:
                            key_metadata[key]['policy_name'] = policy_name or ""
                        if 'namespace' in key_metadata[key]:
                            if namespace not in key_metadata[key]['namespace']:
                                key_metadata[key]['namespace'] += f",{namespace}"
                        else:
                            key_metadata[key]['namespace'] = namespace
                        if 'ports' in key_metadata[key]:
                            # Merge ports and dns_rules lists
                            # TODO: Make these map to policies
                            key_metadata[key]['ports'].extend(meta.get('ports', []))
                            # Add only unique 'dns_rules' to avoid duplicates
                            new_dns_rules = meta.get('dns_rules', [])
                            for rule in new_dns_rules:
                                if rule not in key_metadata[key]['dns_rules']:
                                    key_metadata[key]['dns_rules'].append(rule)
                    else:
                        meta['namespace'] = namespace
                        meta['policy_name'] = policy_name or ""
                        key_metadata[key] = meta.copy()


def process_policies(path: str, debug: bool = False) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]], Dict[str, Dict[str, Any]], Set[Tuple[str, ...]]]:
    """
    Process YAML files from a folder or a single file and extract relationships.
    Returns: (namespace_egress_keys, namespace_ingress_keys, key_metadata, and_edges)
    where key_metadata maps key -> {ports, dns_rules, etc.}
    and and_edges is a set of tuples representing AND relationships
    """
    namespace_egress_keys: Dict[str, Set[str]] = defaultdict(set)
    namespace_ingress_keys: Dict[str, Set[str]] = defaultdict(set)
    key_metadata: Dict[str, Dict[str, Any]] = defaultdict(lambda: {'ports': [], 'dns_rules': []})
    and_edges: Set[Tuple[str, ...]] = set()
    
    path_obj = Path(path)
    
    # Determine if path is a file or directory
    if path_obj.is_file():
        # Single file
        if path_obj.suffix.lower() not in ['.yaml', '.yml']:
            print(f"Warning: {path} is not a YAML file (.yaml or .yml)")
            return namespace_egress_keys, namespace_ingress_keys, dict(key_metadata), and_edges
        yaml_files = [path_obj]
        print(f"Processing single policy file: {path}")
    elif path_obj.is_dir():
        # Directory - get all YAML files
        yaml_files = list(path_obj.glob("*.yaml")) + list(path_obj.glob("*.yml"))
        print(f"Found {len(yaml_files)} YAML files in {path}")
        if debug:
            for yf in yaml_files:
                print(f"  [DEBUG]   - {yf}")
    else:
        print(f"Error: {path} is not a valid file or directory")
        return namespace_egress_keys, namespace_ingress_keys, dict(key_metadata), and_edges
    
    if not yaml_files:
        print(f"Warning: No YAML files found in {path}")
        return namespace_egress_keys, namespace_ingress_keys, dict(key_metadata), and_edges
    
    # Process each file
    for yaml_file in yaml_files:
        process_policy_file(yaml_file, namespace_egress_keys, namespace_ingress_keys, 
                          key_metadata, and_edges, debug=debug)
    
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
        "path",
        help="Path to a folder containing CiliumNetworkPolicy YAML files or a single YAML policy file"
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
    
    path_obj = Path(args.path)
    if not path_obj.exists():
        print(f"Error: {args.path} does not exist")
        sys.exit(1)
    
    if not (path_obj.is_file() or path_obj.is_dir()):
        print(f"Error: {args.path} is not a valid file or directory")
        sys.exit(1)
    
    if args.debug:
        print("=" * 60)
        print("DEBUG MODE ENABLED")
        print("=" * 60)
    
    if path_obj.is_file():
        print(f"Processing Cilium policy file: {args.path}")
    else:
        print(f"Processing Cilium policies from folder: {args.path}")
    
    # Process policies (handles both file and folder)
    namespace_egress_keys, namespace_ingress_keys, key_metadata, and_edges = process_policies(args.path, debug=args.debug)
    
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
