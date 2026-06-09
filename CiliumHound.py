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
from typing import Dict

from graph_builder import create_bloodhound_graph
from models import Rule
from policy_parser import (
    PolicyParser,
    parse_policy_file,
    extract_namespace_from_filename,
    extract_namespace_from_policy,
    extract_policy_name_from_filename,
    extract_policy_name_from_policy
)


def process_policy_file(yaml_file: Path, rules: Dict[str, Rule], debug: bool = False) -> None:
    """
    Process a single YAML policy file and update the rules dictionary.
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
        print(f"  [DEBUG] Processing policy: {policy_name} in namespace: {namespace}")
    
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
        parser = PolicyParser(debug=debug)
        parser.process_spec(spec, namespace, policy_name, rules)
    
    print(f"Found this many rules: {len(rules)}")
    for rule in rules.values():
        rule.print()


def process_policies(path: str, debug: bool = False) -> Dict[str, Rule]:
    """
    Process YAML files from a folder or a single file and extract rules.
    Returns: Dict mapping rule key -> Rule
    """
    rules: Dict[str, Rule] = {}
    
    path_obj = Path(path)
    
    # Determine if path is a file or directory
    if path_obj.is_file():
        # Single file
        if path_obj.suffix.lower() not in ['.yaml', '.yml']:
            print(f"Warning: {path} is not a YAML file (.yaml or .yml)")
            return rules
        yaml_files = [path_obj]
        print(f"Processing single policy file: {path}")
    elif path_obj.is_dir():
        # Directory - get all YAML files
        yaml_files = list(path_obj.glob("*.yaml")) + list(path_obj.glob("*.yml"))
        print(f"Found {len(yaml_files)} YAML files in {path}")
        if debug:
            for yf in yaml_files:
                print(f"  [DEBUG]  File Found: {yf}")
    else:
        print(f"Error: {path} is not a valid file or directory")
        return rules
    
    if not yaml_files:
        print(f"Warning: No YAML files found in {path}")
        return rules
    
    # Process each file
    for yaml_file in yaml_files:
        if debug:
            print(f"  [DEBUG] Processing policy file: {yaml_file}")
        process_policy_file(yaml_file, rules, debug=debug)

    return rules



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
    rules = process_policies(args.path, debug=args.debug)
    namespaces = set(rule.namespace for rule in rules.values())
    namespaces.update(rule.tgt_namespace for rule in rules.values() if rule.tgt_namespace)
    print(rules)
    if not rules:
        print("Error: No valid policies found or no rules extracted")
        sys.exit(1)
    
    if args.debug:
        print(f"\n[DEBUG] All rules found:")
        for key in sorted(rules.keys()):
            rules[key].print()
    
    # Create BloodHound graph
    print("Creating BloodHound OpenGraph...")
    graph = create_bloodhound_graph(rules, namespaces, debug=args.debug)
    
    # Export to file
    print(f"Exporting to {args.output}...")
    graph.export_to_file(args.output)
    
    print(f"Success! Created {args.output} with {len(graph.nodes)} nodes and {len(graph.edges)} edges")


if __name__ == "__main__":
    main()
