#!/usr/bin/env python3
"""
CiliumHound: Convert Cilium Network Policies to BloodHound OpenGraph

This script processes CiliumNetworkPolicy YAML and JSON files and converts them
into a BloodHound OpenGraph JSON file for visualization.
"""

import os
import sys
import argparse
from pathlib import Path
from typing import Any, Dict, List, Tuple

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


SUPPORTED_POLICY_EXTENSIONS: Tuple[str, ...] = ('.yaml', '.yml', '.json')
JSON_POLICY_EXTENSION = '.json'
CILIUM_POLICY_KIND = 'CiliumNetworkPolicy'

def parse_bool(value: str) -> bool:
    normalized_value = value.lower()
    if normalized_value in ("true", "1", "yes", "y"):
        return True
    if normalized_value in ("false", "0", "no", "n"):
        return False
    raise argparse.ArgumentTypeError("Expected true or false")


def extract_policies_from_file(policy: Dict[str, Any], policy_file: Path, debug: bool) -> List[Dict[str, Any]]:
    """
    Extract policy documents from a parsed file.
    """
    if policy_file.suffix.lower() != JSON_POLICY_EXTENSION:
        return [policy]

    policy_items = policy.get('items')
    if not isinstance(policy_items, list):
        print(f"Warning: JSON policy file {policy_file} does not contain an items array")
        return []

    policies: List[Dict[str, Any]] = []
    for item_index, policy_item in enumerate(policy_items):
        if not isinstance(policy_item, dict):
            print(f"Warning: JSON policy file {policy_file} item {item_index} is not a policy object")
            continue
        policy_kind = policy_item.get('kind')
        if policy_kind != CILIUM_POLICY_KIND:
            print(f"Warning: JSON policy file {policy_file} item {item_index} is not a {CILIUM_POLICY_KIND}: kind={policy_kind!r}")
            continue
        policies.append(policy_item)

    if debug:
        print(f"  [DEBUG] Found {len(policies)} policy item(s) in JSON list")

    return policies


def process_policy(policy: Dict[str, Any], policy_file: Path, rules: Dict[str, Rule], debug: bool) -> None:
    """
    Process a single parsed policy document and update the rules dictionary.
    """
    # Determine namespace
    namespace = extract_namespace_from_policy(policy)
    if not namespace:
        print(f"Warning: Could not determine namespace for {policy_file}")
        return

    policy_name = extract_policy_name_from_policy(policy)
    if not policy_name:
        print(f"Warning: Could not determine policy name for {policy_file}")
        return

    if debug:
        print(f"  [DEBUG] Namespace from policy metadata: {namespace}")
        print(f"  [DEBUG] Policy name from policy metadata: {policy_name}")
        print(f"  [DEBUG] Processing policy: {policy_name} in namespace: {namespace}")
    
    # Check for specs
    specs: List[Dict[str, Any]] = []
    if 'specs' in policy:
        policy_specs = policy.get('specs')
        if isinstance(policy_specs, list):
            specs.extend(policy_specs)
    if 'spec' in policy:
        policy_spec = policy.get('spec')
        if isinstance(policy_spec, dict):
            specs.append(policy_spec)
    
    if debug:
        print(f"  [DEBUG] Found {len(specs)} spec(s)")

    if not specs:
        print(f"Warning: No specs found in {policy_file}")
        return
    
    # Process spec
    for spec in specs:
        # Process Egress
        parser = PolicyParser(debug=debug)
        parser.process_spec(spec, namespace, policy_name, rules)


def process_policy_file(policy_file: Path, rules: Dict[str, Rule], debug: bool = False) -> None:
    """
    Process a single policy file and update the rules dictionary.
    """
    print(f"\nProcessing file: {policy_file}")
    
    parsed_policy = parse_policy_file(str(policy_file), debug=debug)
    if not parsed_policy:
        if debug:
            print(f"  [DEBUG] Skipping file (could not parse)")
        return

    policies = extract_policies_from_file(parsed_policy, policy_file, debug)
    if not policies:
        return

    for policy in policies:
        process_policy(policy, policy_file, rules, debug)

    print(f"Found this many rules: {len(rules)}")

def process_policies(path: str, debug: bool = False) -> Dict[str, Rule]:
    """
    Process YAML and JSON policy files from a folder or a single file and extract rules.
    Returns: Dict mapping rule key -> Rule
    """
    rules: Dict[str, Rule] = {}
    policy_files: List[Path] = []
    
    path_obj = Path(path)
    
    # Determine if path is a file or directory
    if path_obj.is_file():
        # Single file
        if path_obj.suffix.lower() not in SUPPORTED_POLICY_EXTENSIONS:
            print(f"Warning: {path} is not a supported policy file (.yaml, .yml, or .json)")
            return rules
        policy_files = [path_obj]
        print(f"Processing single policy file: {path}")
    elif path_obj.is_dir():
        # Directory - get all supported policy files
        policy_files = sorted(
            policy_file
            for policy_file in path_obj.iterdir()
            if policy_file.is_file() and policy_file.suffix.lower() in SUPPORTED_POLICY_EXTENSIONS
        )
        print(f"Found {len(policy_files)} policy files in {path}")
        if debug:
            for policy_file in policy_files:
                print(f"  [DEBUG]  File Found: {policy_file}")
    else:
        print(f"Error: {path} is not a valid file or directory")
        return rules
    
    if not policy_files:
        print(f"Warning: No policy files found in {path}")
        return rules
    
    # Process each file
    for policy_file in policy_files:
        if debug:
            print(f"  [DEBUG] Processing policy file: {policy_file}")
        process_policy_file(policy_file, rules, debug=debug)

    return rules

def main():
    parser = argparse.ArgumentParser(
        description="Convert Cilium Network Policies to BloodHound OpenGraph JSON"
    )
    parser.add_argument(
        "path",
        help="Path to a folder containing CiliumNetworkPolicy YAML/JSON files or a single policy file"
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
    parser.add_argument(
        "--any-namespace",
        default=False,
        type=parse_bool,
        metavar="true|false",
        help="Create ANY namespace node and fallback namespace edges (default: false)"
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
    endpoint_selector_keys = []
    for rule in rules.values():
        if rule.rule_type == "endpointSelector":
            endpoint_selector_keys.append(rule.key)
    endpoint_selectors = []
    for esk in endpoint_selector_keys:
        endpoint_selectors.append(rules.pop(esk))
    
    if not rules:
        print("Error: No valid policies found or no rules extracted")
        sys.exit(1)
    
    if args.debug:
        print(f"\n[DEBUG] All rules found:")
        for key in sorted(rules.keys()):
            rules[key].print()
    
    # Create BloodHound graph
    print("Creating BloodHound OpenGraph...")
    graph = create_bloodhound_graph(
        rules,
        namespaces,
        endpoint_selectors,
        debug=args.debug,
        any_namespace=args.any_namespace
    )
    
    # Export to file
    print(f"Exporting to {args.output}...")
    graph.export_to_file(args.output)
    
    print(f"Success! Created {args.output} with {len(graph.nodes)} nodes and {len(graph.edges)} edges")


if __name__ == "__main__":
    main()
