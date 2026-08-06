"""
Graph Builder: Creates BloodHound OpenGraph from extracted Cilium policy data

This module handles the creation of BloodHound OpenGraph structures
from processed Cilium network policy data.
"""

from typing import Dict, Set, Any, Tuple, List, Optional
import hashlib
import yaml
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
    """Create readable strings from metadata for ports"""
    port_string = ""
    if ports.ports:
        # Create a readable port string
        port_string = ",".join([f"{p.get('port', '')}/{p.get('protocol', '')}" for p in ports.ports if p.get('port') or p.get('protocol')])
    return port_string


def create_port_rules_lines(port_rules: Dict[str, Any]) -> List[str]:
    return yaml.safe_dump(port_rules, sort_keys=False).strip().splitlines()


def create_port_rules_node_id(
    source_node_id: str,
    port: Dict[str, Any],
    rule_protocol: str,
    protocol_rules: Any,
    policy_name: Any
) -> str:
    """Generate a port key containing a unique ID based on port information"""
    hash_input = yaml.safe_dump(
        {
            "source": source_node_id,
            "port": port.get("port"),
            "protocol": port.get("protocol"),
            "rule_protocol": rule_protocol,
            "policy_name": policy_name,
            "rules": protocol_rules,
        },
        sort_keys=True,
    )
    key_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()[-8:]
    return f"PortRules:{rule_protocol}:{key_hash}"


def strip_identifier_suffix(key_name: str) -> str:
    return key_name[:-9] if len(key_name) > 9 else key_name


def normalize_policy_names(policy_name: object) -> List[str]:
    if isinstance(policy_name, list):
        policy_names: List[str] = []
        for item in policy_name:
            if not isinstance(item, str):
                raise TypeError(f"Expected policy_name list values to be strings, got {type(item).__name__}")
            if item and item not in policy_names:
                policy_names.append(item)
        return policy_names
    if isinstance(policy_name, str):
        if policy_name:
            return [policy_name]
        return []
    if policy_name is None:
        return []
    raise TypeError(f"Expected policy_name to be a string or list of strings, got {type(policy_name).__name__}")


def get_rule_policy_names(rule: Rule) -> List[str]:
    if rule.policy_names:
        return list(rule.policy_names)
    return normalize_policy_names(rule.policy_name)


def merge_policy_names(existing_policy_names: List[str], incoming_policy_names: List[str]) -> List[str]:
    merged_policy_names = list(existing_policy_names)
    for policy_name in incoming_policy_names:
        if policy_name not in merged_policy_names:
            merged_policy_names.append(policy_name)
    return merged_policy_names


def get_existing_edge(graph: OpenGraph, start_node: str, end_node: str, kind: str) -> Optional[Tuple[str, Edge]]:
    for edge_key, edge in graph.edges.items():
        if edge.start_node == start_node and edge.end_node == end_node and edge.kind == kind:
            return edge_key, edge
    return None


def create_edge(graph: OpenGraph, start_node: str, end_node: str, kind: str, properties: Properties) -> Edge:
    existing_edge = get_existing_edge(graph, start_node, end_node, kind)
    if existing_edge:
        edge_key, edge = existing_edge
        existing_policy_names = normalize_policy_names(edge.get_property("policy_name"))
        incoming_policy_names = normalize_policy_names(properties.get_property("policy_name"))
        edge.set_property("policy_name", merge_policy_names(existing_policy_names, incoming_policy_names))
        del graph.edges[edge_key]
        return edge

    return Edge(
        start_node=start_node,
        end_node=end_node,
        kind=kind,
        properties=properties
    )


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

    endpoint_selector_edge = create_edge(
        graph,
        start_node,
        end_node,
        rule.direction.capitalize(),
        Properties(
            policy_name=get_rule_policy_names(rule),
            namespace=rule.namespace
        )
    )
    if not graph.add_edge(endpoint_selector_edge):
        print(f"    [ERROR] Failed to add {rule.direction.capitalize()} edge: {rule.endpoint_selector} -> {rule.key}")

    namespace_edge = create_edge(
        graph,
        namespace_id,
        rule.endpoint_selector,
        "EndpointsWithSelector",
        Properties(
            policy_name=get_rule_policy_names(rule),
            namespace=rule.namespace
        )
    )
    if not graph.add_edge(namespace_edge) and debug:
        print(f"    [WARNING] Failed to add EndpointsWithSelector edge: {namespace_id} -> {rule.endpoint_selector}")
    return True


def create_bloodhound_graph(
    rules: Dict[str, Rule],
    namespaces: Set[str],
    endpoint_selectors: List[Rule],
    debug: bool = False,
    any_namespace: bool = True
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

    if any_namespace:
        any_namespace_id = "namespace:ANY"
        if any_namespace_id not in namespace_nodes.values():
            node = Node(
                id=any_namespace_id,
                kinds=["Namespace"],
                properties=Properties(
                    displayname="ANY",
                    name="ANY",
                    namespace="ANY"
                )
            )
            if not graph.add_node(node):
                print(f"    [ERROR] Failed to add namespace node: {any_namespace_id}")
            if debug:
                print(f"    [DEBUG] Created namespace node: {any_namespace_id}")
        namespace_nodes["ANY"] = any_namespace_id
    
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
        
        # Build properties with metadata
        props_dict = {
            'displayname': rule.name,
            'name': rule.name,
            'key_type': key_type,
            'full_key': rule.key,
            'namespace': rule.namespace,
            'policy_name': get_rule_policy_names(rule)
        }
        
        # Add port information if available
        if rule.to_ports:
            port_string = create_metadata_string(rule.to_ports)
            props_dict['ports'] = port_string

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
                    port_rules = port.get('rules')
                    port_policy_names = normalize_policy_names(port.get('policy_name', get_rule_policy_names(rule)))
                    port_policy_name = ",".join(port_policy_names)
                    if port_rules:
                        port_rule_items = port_rules.items() if isinstance(port_rules, dict) else [("rules", port_rules)]
                        # Handle cases where more than one protocol are present
                        for rule_protocol, protocol_rules in port_rule_items:
                            protocol_port_rules = {rule_protocol: protocol_rules}
                            port_rules_node_id = create_port_rules_node_id(
                                node_id,
                                port,
                                rule_protocol,
                                protocol_rules,
                                port_policy_name
                            )
                            port_rules_node = Node(
                                id=port_rules_node_id,
                                kinds=["PortRules"],
                                properties=Properties(
                                    displayname=f"{rule_protocol} rules",
                                    name=f"{rule_protocol} rules",
                                    port=f"{port['port']}/{port['protocol']}",
                                    rules=create_port_rules_lines(protocol_port_rules),
                                    policy_name=port_policy_names,
                                    namespace=rule.namespace
                                )
                            )
                            graph.add_node(port_rules_node)

                            edge = create_edge(
                                graph,
                                node_id,
                                port_rules_node_id,
                                "WithPortRules",
                                Properties(
                                    policy_name=port_policy_names,
                                    namespace=rule.namespace
                                )
                            )
                            if not graph.add_edge(edge):
                                print(f"    [ERROR] Failed to add edge: {node_id} -> {port_rules_node_id}")

                            edge = create_edge(
                                graph,
                                port_rules_node_id,
                                port_node.id,
                                "ToPorts",
                                Properties(
                                    policy_name=port_policy_names,
                                    namespace=rule.namespace
                                )
                            )
                            if not graph.add_edge(edge):
                                print(f"    [ERROR] Failed to add edge: {port_rules_node_id} -> {port_node.id}")
                    else:
                        edge = create_edge(
                            graph,
                            node_id,
                            port_node.id,
                            "ToPorts",
                            Properties(
                                policy_name=port_policy_names,
                                namespace=rule.namespace
                            )
                        )
                        if not graph.add_edge(edge):
                            print(f"    [ERROR] Failed to add edge: {node_id} -> {port_node.id}")

        if rule.tgt_namespace or any_namespace:
            tgt_namespace_id = namespace_nodes[rule.tgt_namespace] if rule.tgt_namespace else any_namespace_id
            if rule.direction.startswith("ingress"):
                start_node = tgt_namespace_id
                end_node = node_id
                kind = "FromNamespace"
            else:
                start_node = node_id
                end_node = tgt_namespace_id
                kind = "ToNamespace"

            edge = create_edge(
                graph,
                start_node,
                end_node,
                kind,
                Properties(
                    policy_name=get_rule_policy_names(rule),
                    namespace=rule.namespace
                )
            )
            if not graph.add_edge(edge):
                print(f"    [ERROR] Failed to add edge: {start_node} -> {end_node}")
        if debug:
            print(f"    [DEBUG] Created rule node: {node_id} (type: {key_type}, name: {rule.name})")
    
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

                namespace_edge = create_edge(
                    graph,
                    namespace_id,
                    rule.key,
                    "Egress",
                    Properties(
                        policy_name=get_rule_policy_names(rule),
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
                edge = create_edge(
                    graph,
                    rule.key,
                    namespace_id,
                    "Ingress",
                    Properties(
                        policy_name=get_rule_policy_names(rule),
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
                edge = create_edge(
                    graph,
                    namespace_id,
                    rule.key,
                    "EgressDeny",
                    Properties(
                        policy_name=get_rule_policy_names(rule),
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
                edge = create_edge(
                    graph,
                    rule.key,
                    namespace_id,
                    "IngressDeny",
                    Properties(
                        policy_name=get_rule_policy_names(rule),
                        namespace=rule.namespace
                    )
                )
                if not graph.add_edge(edge):
                    print(f"    [ERROR] Failed to add Ingress Deny edge: {rule.key} -> {namespace_id}")
            if debug:
                print(f"    [DEBUG] Created Ingress Deny edge: {rule.key} -> {namespace_id}")
    
    return graph
