import hashlib
from typing import List
from enum import Enum
from typing import Dict, Any, Optional

class Properties(Enum):
    ENDPOINT_SELECTOR = "endpointSelector"
    TO_PORTS = "toPorts"
    tgt_namespace = "toNamespace"

class EdgeType(Enum):
    EGRESS = 1
    INGRESS = 2
    EGRESS_DENY = 3
    INGRESS_DENY = 4
    TO_PORTS = 5
    IN_NAMESPACE = 6
    FROM_ENDPOINT = 7

class Ports:
    ports: List[Dict[str, Any]]

    def __init__(self, ports: List[Dict[str, Any]]):
        self.ports = ports

    def print(self):
        print(f"Ports: {self.ports}")

def append_key_hash_id(key: str, namespace: str, direction: str, endpoint_selector: str, rules: str = None) -> str:
    if rules:
        hash_input = f"{namespace}:{direction}:{endpoint_selector}:{rules}"
    else:
        hash_input = f"{namespace}:{direction}:{endpoint_selector}"

    key_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()[-8:]
    return f"{key}-{key_hash}"

class Rule:
    direction: str
    namespace: str
    identifier_set: bool = False
    key: str = None
    name: str
    policy_name: str
    policy_names: List[str]
    rule_type: str
    edge_type: EdgeType = None
    endpoint_selector: str = ""
    to_ports: Ports = None
    tgt_namespace: str = None
    properties: Dict[str, Any]

    def __init__(self, direction: str, namespace: str, key: str, rule_type: str, endpoint_selector: str, properties: Optional[Dict[str, Any]] = None, edge_type: EdgeType = None):
        self.direction = direction
        self.namespace = namespace
        self.rule_type = rule_type
        self.properties = dict(properties) if properties else {}
        self.edge_type = edge_type
        self.endpoint_selector = endpoint_selector
        self.key = key
        self.policy_name = ""
        self.policy_names = []
        self.name = key.split(":", 1)[1]
        self.generate_key_identifier()
        print("---------" + key + "---------")

    def generate_key_identifier(self):
        # If this is just a namespace rule, we don't want include the ID suffix
        if self.rule_type in "namespace":
            return
        if self.identifier_set:
            self.key = self.key[:-9]
        if self.properties.get("rules"):
            self.key = append_key_hash_id(self.key, self.namespace, self.direction, self.endpoint_selector, rules=self.properties.get("rules"))
            self.identifier_set = True
        else:
            self.key = append_key_hash_id(self.key, self.namespace, self.direction, self.endpoint_selector)
            self.identifier_set = True

    def print(self):
        print("-" * 80)
        print(f"Direction: {self.direction}")
        print(f"Namespace: {self.namespace}")
        print(f"Key: {self.key}")
        print(f"Name: {self.name}")
        print(f"Edge Type: {self.edge_type}")
        print(f"Endpoint Selector: {self.endpoint_selector}")
        if self.to_ports:
            self.to_ports.print()
        print(f"Rule Type: {self.rule_type}")
        print(f"To Namespace: {self.tgt_namespace}")
        print(f"Properties: {self.properties}")
        print("-" * 80)
    
