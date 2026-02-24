"""
Graph Builder: Creates BloodHound OpenGraph from extracted Cilium policy data

This module handles the creation of BloodHound OpenGraph structures
from processed Cilium network policy data.
"""

from typing import Dict, Set, Any, Tuple
from bhopengraph.OpenGraph import OpenGraph
from bhopengraph.Node import Node
from bhopengraph.Edge import Edge
from bhopengraph.Properties import Properties


def create_metadata_string(metadata: Dict[str, Any]) -> Tuple[str, str]:
    """Create readable strings from metadata for ports and DNS rules"""
    port_string, dns_string = "", ""
    if metadata.get('ports'):
        ports = metadata.get('ports')
        # Create a readable port string
        port_string = ",".join([f"{p.get('port', '')}/{p.get('protocol', '')}" for p in ports if p.get('port') or p.get('protocol')])
    if metadata.get('dns_rules'):
        dns_string += f" [dns: {metadata['dns_rules']}]"
    return port_string, dns_string


def create_bloodhound_graph(
    namespace_egress_keys: Dict[str, Set[str]],
    namespace_ingress_keys: Dict[str, Set[str]],
    key_metadata: Dict[str, Dict[str, Any]] = None,
    and_edges: set = None,
    debug: bool = False
) -> OpenGraph:
    """Create a BloodHound OpenGraph from the extracted relationships"""
    print(f"\nCreating BloodHound graph...")
    
    graph = OpenGraph(source_kind="CiliumNetworkPolicy")
    
    # Collect all unique namespaces and keys
    all_namespaces = set(namespace_egress_keys.keys()) | set(namespace_ingress_keys.keys())
    all_keys = set()
    for keys in namespace_egress_keys.values():
        all_keys.update(keys)
    for keys in namespace_ingress_keys.values():
        all_keys.update(keys)
    
    print(f"  Total unique namespaces: {len(all_namespaces)}")
    print(f"  Total unique keys: {len(all_keys)}")
    if key_metadata:
        print(f"  Keys with metadata: {len([k for k in all_keys if k in key_metadata and (key_metadata[k].get('ports') or key_metadata[k].get('dns_rules'))])}")
    
    if key_metadata is None:
        key_metadata = {}
    
    if and_edges is None:
        and_edges = set()
    
    # Create namespace nodes
    namespace_nodes = {}
    if debug:
        print(f"  [DEBUG] Creating namespace nodes...")
    for namespace in all_namespaces:
        node_id = f"namespace:{namespace}"
        node = Node(
            id=node_id,
            kinds=["Namespace", "Base"],
            properties=Properties(
                displayname=namespace,
                name=namespace,
                objectid=node_id,
                namespace=namespace
            )
        )
        graph.add_node(node)
        namespace_nodes[namespace] = node_id
        if debug:
            print(f"    [DEBUG] Created namespace node: {node_id}")
    
    # Create key nodes (FQDNs, CIDRs, endpoints, etc.)
    key_nodes = {}
    if debug:
        print(f"  [DEBUG] Creating key nodes...")
    for key in all_keys:
        node_id = f"key:{key}"
        # Determine key type and name
        if key.startswith("fqdn:"):
            key_type = "FQDN"
            key_name = key[5:]
        elif key.startswith("fqdn-pattern:"):
            key_type = "FQDN-Pattern"
            key_name = key[13:]
        elif key.startswith("cidr:"):
            key_type = "CIDR"
            key_name = key[5:]
        elif key.startswith("cidrSet:"):
            key_type = "CIDRSet"
            key_name = key[8:]
        elif key.startswith("namespace:"):
            key_type = "Namespace"
            key_name = key[10:]
        elif key.startswith("service:"):
            key_type = "Service"
            key_name = key[8:]
        elif key.startswith("app:"):
            key_type = "App"
            key_name = key[4:]
        elif key.startswith("label:"):
            key_type = "Label"
            key_name = key[6:]
        elif key.startswith("entity:"):
            key_type = "Entity"
            key_name = key[7:]
        else:
            key_type = "Key"
            key_name = key
        
        # Build properties with metadata
        props_dict = {
            'displayname': key_name,
            'name': key_name,
            'objectid': node_id,
            'key_type': key_type,
            'full_key': key
        }
        
        # Add port information if available
        meta = key_metadata.get(key, {})
        
        if meta:
            port_string, dns_string = create_metadata_string(meta)
            props_dict['ports'] = port_string
            props_dict['dns_rules'] = dns_string
            props_dict['namespace'] = meta.get('namespace', '')
            props_dict['policy_name'] = meta.get('policy_name', '')
            if dns_string:
                props_dict['name'] += f" (DNS Rules)"
        
        node = Node(
            id=node_id,
            kinds=[key_type, "Base"],
            properties=Properties(**props_dict)
        )
        graph.add_node(node)
        key_nodes[key] = node_id

        ports = meta.get('ports', [])
        if ports:
            for port in ports:
                port_node = Node(
                    id=f"Key:{port['port']}/{port['protocol']}",
                    kinds=["Port", "Base"],
                    properties=Properties(
                        displayname=f"{port['port']}/{port['protocol']}",
                        name=f"{port['port']}/{port['protocol']}",
                        objectid=f"Key:{port['port']}/{port['protocol']}"
                    )
                )
                # Add port node to key nodes
                key_nodes[f"{port['port']}/{port['protocol']}"] = port_node.id
                graph.add_node(port_node)
                edge = Edge(
                    start_node=node_id,
                    end_node=port_node.id,
                    kind="ToPorts"
                )
                graph.add_edge(edge)
        if debug:
            print(f"    [DEBUG] Created key node: {node_id} (type: {key_type}, name: {key_name})")
    
    # Create Egress edges: namespace -> key
    if debug:
        print(f"  [DEBUG] Creating Egress edges...")
    egress_count = 0
    for namespace, keys in namespace_egress_keys.items():
        namespace_id = namespace_nodes[namespace]
        for key in keys:
            key_id = key_nodes[key]
            edge = Edge(
                start_node=namespace_id,
                end_node=key_id,
                kind="Egress"
            )
            graph.add_edge(edge)
            egress_count += 1
            if debug:
                print(f"    [DEBUG] Created Egress edge: {namespace_id} -> {key_id}")
    if debug:
        print(f"  [DEBUG] Created {egress_count} Egress edges")
    
    # Create Ingress edges: key -> namespace
    if debug:
        print(f"  [DEBUG] Creating Ingress edges...")
    ingress_count = 0
    for namespace, keys in namespace_ingress_keys.items():
        namespace_id = namespace_nodes[namespace]
        for key in keys:
            key_id = key_nodes[key]
            edge = Edge(
                start_node=key_id,
                end_node=namespace_id,
                kind="Ingress"
            )
            graph.add_edge(edge)
            ingress_count += 1
            if debug:
                print(f"    [DEBUG] Created Ingress edge: {key_id} -> {namespace_id}")
    if debug:
        print(f"  [DEBUG] Created {ingress_count} Ingress edges")

    # Create And edges
    if debug:
        print(f"  [DEBUG] Creating And edges...")
    
    and_count = 0
    for and_edge in and_edges:
        if debug:
            print(f"    [DEBUG] Processing And edge tuple: {and_edge}")
        for idx, key in enumerate(and_edge):
            if idx < len(and_edge) - 1:
                if key in key_nodes and and_edge[idx + 1] in key_nodes:
                    start_node = key_nodes[key]
                    end_node = key_nodes[and_edge[idx + 1]]
                    edge = Edge(start_node=start_node, end_node=end_node, kind="And")
                    graph.add_edge(edge)
                    and_count += 1
                    if debug:
                        print(f"      [DEBUG] Created And edge: {start_node} -> {end_node}")
                elif debug:
                    print(f"      [DEBUG] Skipping And edge - key not found: {key} or {and_edge[idx + 1]}")
    if debug:
        print(f"  [DEBUG] Created {and_count} And edges")
    
    return graph
