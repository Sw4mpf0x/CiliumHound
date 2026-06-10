"""
Graph Builder: Creates BloodHound OpenGraph from extracted Cilium policy data

This module handles the creation of BloodHound OpenGraph structures
from processed Cilium network policy data.
"""

from typing import Dict, Set, Any, Tuple, List
from bhopengraph.OpenGraph import OpenGraph
from bhopengraph.Node import Node
from bhopengraph.Edge import Edge
from bhopengraph.Properties import Properties
from models import Rule, Ports

def get_endpoint_selector(metadata: Dict[str, Any]) -> str:
    """Get the endpointSelector from a key"""
    return metadata.get('endpointSelector', None)

def remove_node_egress_edge(graph: OpenGraph, node_id: str, policy_name: str) -> None:
    """Remove all Egress edges from a node"""
    edge_to_remove = ""
    print(f"    [DEBUG] Locating Egress edge: {node_id} -> {policy_name}")
    for key, edge in graph.edges.items():
        if edge.end_node == node_id and edge.kind == "Egress":
            # If the policy name is exactly the same, remove the edge
            if edge.get_property('policy_name') == policy_name:

                edge_to_remove = key
            # If the policy name is a substring, remove the policy name from the edge property
            elif policy_name in edge.get_property('policy_name'):
                print(f"    [DEBUG] Removing policy name from edge property: {edge.get_property('policy_name')}")
                new_policy_name = edge.get_property('policy_name').replace(policy_name, '').strip(",").replace(",,", ",")
                edge.set_property('policy_name', new_policy_name)
                break
    if edge_to_remove:
        print(f"    [DEBUG] Removing Egress edge: {key} -> {policy_name}")
        del graph.edges[edge_to_remove]

def remove_node_ingress_edge(graph: OpenGraph, node_id: str, policy_name: str) -> None:
    """Remove all Ingress edges from a node"""
    edge_to_remove = ""
    print(f"    [DEBUG] Locating Ingress edge: {node_id} -> {policy_name}")
    for key, edge in graph.edges.items():
        if edge.start_node == node_id and edge.kind == "Ingress":
            # If the policy name is exactly the same, remove the edge
            if edge.get_property('policy_name') == policy_name:

                edge_to_remove = key
            # If the policy name is a substring, remove the policy name from the edge property
            elif policy_name in edge.get_property('policy_name'):
                print(f"    [DEBUG] Removing policy name from edge property: {edge.get_property('policy_name')}")
                new_policy_name = edge.get_property('policy_name').replace(policy_name, '').strip(",").replace(",,", ",")
                edge.set_property('policy_name', new_policy_name)
                break
    if edge_to_remove:
        print(f"    [DEBUG] Removing Ingress edge: {key} -> {policy_name}")
        del graph.edges[edge_to_remove]

def create_metadata_string(ports: Ports) -> Tuple[str, str]:
    """Create readable strings from metadata for ports and DNS rules"""
    port_string, dns_string = "", ""
    if ports.ports:
        # Create a readable port string
        port_string = ",".join([f"{p.get('port', '')}/{p.get('protocol', '')}" for p in ports.ports if p.get('port') or p.get('protocol')])
    if ports.dns_rules:
        dns_string += f" [dns: {ports.dns_rules}]"
    return port_string, dns_string


def strip_identifier_suffix(key_name: str) -> str:
    return key_name[:-9] if len(key_name) > 9 else key_name


def add_node_with_endpoint_selector(
    graph: OpenGraph,
    rule: Rule,
    namespace_id: str,
    debug: bool = False,
) -> bool:
    """
    Ensure the endpoint selector node exists and add Egress (selector -> key)
    and EndpointsWithSelector (namespace -> selector) edges.

    Returns False if the endpoint selector node could not be added; the caller
    should skip the rest of processing for this rule.
    """

    if debug:
        print(f"    [DEBUG] Creating {rule.direction.capitalize()} edge from endpointSelector: {rule.endpoint_selector} to {rule.key}")
    if rule.direction == "ingress":
        start_node = rule.key
        end_node = rule.endpoint_selector
    else:
        start_node = rule.endpoint_selector
        end_node = rule.key
    endpoint_selector_edge = Edge(
        start_node=start_node,
        end_node=end_node,
        kind=rule.direction.capitalize(),
        properties=Properties(
            policy_name=rule.policy_name,
            namespace=rule.namespace
        )
    )
    if not graph.add_edge(endpoint_selector_edge):
        print(f"    [ERROR] Failed to add {rule.direction.capitalize()} edge: {rule.endpoint_selector} -> {rule.key}")
    namespace_edge = Edge(
        start_node=namespace_id,
        end_node=rule.endpoint_selector,
        kind="EndpointsWithSelector",
        properties=Properties(
            policy_name=rule.policy_name,
            namespace=rule.namespace
        )
    )
    if not graph.add_edge(namespace_edge):
        print(f"    [ERROR] Failed to add EndpointsWithSelector edge: {namespace_id} -> {rule.endpoint_selector}")
    return True


def create_bloodhound_graph(
    rules: Dict[str, Rule],
    namespaces: Set[str],
    endpoint_selectors: List[Rule],
    debug: bool = False
) -> OpenGraph:
    """Create a BloodHound OpenGraph from the extracted relationships"""
    print(f"\nCreating BloodHound graph...")
    
    graph = OpenGraph(source_kind="CiliumNetworkPolicy")
    
    print(f"  Total rules: {len(rules.keys())}")
    print(f"  Total namespaces: {len(namespaces)}")
    
    # Create namespace nodes
    namespace_nodes = {}
    if debug:
        print(f"  [DEBUG] Creating namespace nodes...")
    for namespace in namespaces:
        if namespace.startswith("namespace:"):
            node_id = namespace
            ns_displayname = namespace[10:]
        else:
            node_id = f"namespace:{namespace}"
            ns_displayname = namespace
        node = Node(
            id=node_id,
            kinds=["Namespace"],
            properties=Properties(
                displayname=ns_displayname,
                name=ns_displayname,
                namespace=ns_displayname
            )
        )
        if not graph.add_node(node):
            print(f"    [ERROR] Failed to add namespace node: {node_id}")
        namespace_nodes[namespace] = node_id
        if debug:
            print(f"    [DEBUG] Created namespace node: {node_id}")
    
    # Create endpoint selectors
    if debug:
        print(f"  [DEBUG] Creating endpointSelector nodes...")
    for es in endpoint_selectors:
        props_dict = dict(es.properties)
        props_dict["displayname"] = es.name
        props_dict["name"] = es.name
        props_dict["namespace"] = es.namespace
        node = Node(
            id=es.key,
            kinds=["EndpointSelector"],
            properties=Properties(**props_dict)
        )
        if not graph.add_node(node):
            print(f"    [ERROR] Failed to add endpointSelector node: {es.key}")
        if debug:
            print(f"    [DEBUG] Created endpointSelector node: {es.key}")
        
    # Create rule nodes (FQDNs, CIDRs, endpoints, etc.)
    rule_nodes = {}
    if debug:
        print(f"  [DEBUG] Creating rule nodes...")
    for rule in rules.values():
        node_id = f"{rule.key}"
        # Determine key type and name
        if rule.key.startswith("fqdn:"):
            key_type = "FQDN"
            key_name = rule.key[5:]
        elif rule.key.startswith("fqdn-pattern:"):
            key_type = "FQDN-Pattern"
            key_name = rule.key[13:]
        elif rule.key.startswith("cidr:"):
            key_type = "CIDR"
            key_name = rule.key[5:]
        elif rule.key.startswith("cidrSet:"):
            key_type = "CIDRSet"
            key_name = rule.key[8:]
        elif rule.key.startswith("namespace:"):
            key_type = "Namespace"
            key_name = rule.key[10:]
        elif rule.key.startswith("service:"):
            key_type = "Service"
            key_name = rule.key[8:]
        elif rule.key.startswith("app:"):
            key_type = "App"
            key_name = rule.key[4:]
        elif rule.key.startswith("label:"):
            key_type = "Label"
            key_name = rule.key[6:]
        elif rule.key.startswith("entity:"):
            key_type = "Entity"
            key_name = rule.key[7:]
        elif rule.key.startswith("endpointSelector:"):
            key_type = "EndpointSelector"
            key_name = rule.key[17:]
        else:
            key_type = "Key"
            key_name = rule.key
        display_key_name = strip_identifier_suffix(key_name)
        
        # Build properties with metadata
        props_dict = {
            'displayname': display_key_name,
            'name': display_key_name,
            'key_type': key_type,
            'full_key': rule.key,
            'namespace': rule.namespace,
            'policy_name': rule.policy_name
        }
        
        # Add port information if available
        if rule.to_ports:
            port_string, dns_string = create_metadata_string(rule.to_ports)
            props_dict['ports'] = port_string
            props_dict['dns_rules'] = dns_string
            if dns_string:
                props_dict['name'] += f" (DNS Rules)"

        if rule.properties.get('rules'):
            props_dict['rules'] = rule.properties.get('rules')

        node = Node(
            id=node_id,
            kinds=[key_type],
            properties=Properties(**props_dict)
        )
        if not graph.add_node(node):
            print(f"    [ERROR] Failed to add rule node: {node_id}")
        rule_nodes[rule.key] = node_id

        # If ports exist, create port nodes and edges
        to_ports_ids = []
        if rule.to_ports:
            ports = rule.to_ports.ports
            if ports and len(ports) > 0:
                for port in ports:
                    port_node = Node(
                        id=f"Key:{port['port']}/{port['protocol']}",
                        kinds=["Port"],
                        properties=Properties(
                            displayname=f"{port['port']}/{port['protocol']}",
                            name=f"{port['port']}/{port['protocol']}"
                        )
                    )
                    # Add port node to rule nodes
                    rule_nodes[f"{port['port']}/{port['protocol']}"] = port_node.id
                    graph.add_node(port_node)
                    to_ports_ids.append(port_node.id)
                    edge = Edge(
                        start_node=node_id,
                        end_node=port_node.id,
                        kind="ToPorts"
                    )
                    if not graph.add_edge(edge):
                        print(f"    [ERROR] Failed to add edge: {node_id} -> {port_node.id}")

        if rule.tgt_namespace:
            tgt_namespace_id = namespace_nodes[rule.tgt_namespace]
            if rule.direction == "ingress":
                start_node = tgt_namespace_id
                end_node = node_id
                kind = "FromNamespace"
            else:
                start_node = node_id
                end_node = tgt_namespace_id
                kind="ToNamespace"
            edge = Edge(
                start_node=start_node,
                end_node=end_node,
                kind=kind
            )
            if not graph.add_edge(edge):
                print(f"    [ERROR] Failed to add edge: {node_id} -> {tgt_namespace_id}")
        if debug:
            print(f"    [DEBUG] Created rule node: {node_id} (type: {key_type}, name: {display_key_name})")
    
        if rule.direction == "egress":
            # Create Egress edges: namespace -> key or endpointSelector -> key
            if debug:
                print(f"  [DEBUG] Creating Egress edge from namespace: {rule.namespace} to {rule.key}")

            namespace_id = namespace_nodes[rule.namespace]

            if rule.endpoint_selector:
                add_node_with_endpoint_selector(graph, rule, namespace_id, debug=debug)
            else:
                if debug:
                    print(f"    [DEBUG] Creating Egress edge from namespace: {namespace_id} to {rule.key}")
                namespace_edge = Edge(
                    start_node=namespace_id,
                    end_node=rule.key,
                    kind="Egress",
                    properties=Properties(
                        policy_name=rule.policy_name,
                        namespace=rule.namespace
                    )
                )
                if not graph.add_edge(namespace_edge):
                    print(f"    [ERROR] Failed to add Egress edge: {namespace_id} -> {rule.key}")
            if debug:
                print(f"    [DEBUG] Created Egress edge: {namespace_id} -> {rule.key}")

        if rule.direction == "ingress":
            # Create Ingress edges: key -> namespace
            if debug:
                print(f"    [DEBUG] Creating Ingress edge from key: {rule.key} to namespace: {rule.namespace}")
            namespace_id = namespace_nodes[rule.namespace]

            if rule.endpoint_selector:
                add_node_with_endpoint_selector(graph, rule, namespace_id, debug=debug)
            else:
                edge = Edge(
                    start_node=rule.key,
                    end_node=namespace_id,
                    kind="Ingress",
                    properties=Properties(
                        policy_name=rule.policy_name,
                        namespace=rule.namespace
                    )
                )
                if not graph.add_edge(edge):
                    print(f"    [ERROR] Failed to add Ingress edge: {rule.key} -> {namespace_id}")
            if debug:
                print(f"    [DEBUG] Created Ingress edge: {rule.key} -> {namespace_id}")

        # Create Egress Deny edges: namespace -> key
        if rule.direction == "egressDeny":
            if debug:
                print(f"  [DEBUG] Creating Egress Deny edge from namespace: {namespace_id} to {rule.key}")
            namespace_id = namespace_nodes[rule.namespace]

            if rule.endpoint_selector:
                add_node_with_endpoint_selector(graph, rule, namespace_id, debug=debug)
            else:
                edge = Edge(
                    start_node=namespace_id,
                    end_node=rule.key,
                    kind="EgressDeny",
                    properties=Properties(
                        policy_name=rule.policy_name,
                        namespace=rule.namespace
                    )
                )
                if not graph.add_edge(edge):
                    print(f"    [ERROR] Failed to add Egress Deny edge: {namespace_id} -> {rule.key}")
            if debug:
                print(f"    [DEBUG] Created Egress Deny edge: {namespace_id} -> {rule.key}")

        # Create Ingress Deny edges: key -> namespace
        if rule.direction == "ingressDeny":
            if debug:
                print(f"  [DEBUG] Creating Ingress Deny edge from key: {rule.key} to namespace: {rule.namespace}")

            namespace_id = namespace_nodes[rule.namespace]

            if rule.endpoint_selector:
                add_node_with_endpoint_selector(graph, rule, namespace_id, debug=debug)
            else:
                edge = Edge(
                    start_node=rule.key,
                        end_node=namespace_id,
                        kind="IngressDeny",
                        properties=Properties(
                            policy_name=rule.policy_name,
                            namespace=rule.namespace
                        )
                )
                if not graph.add_edge(edge):
                    print(f"    [ERROR] Failed to add Ingress Deny edge: {rule.key} -> {namespace_id}")
            if debug:
                print(f"    [DEBUG] Created Ingress Deny edge: {rule.key} -> {namespace_id}")
    
    return graph
