"""
Policy Parser: Parses Cilium Network Policy YAML files

This module handles parsing and extracting information from CiliumNetworkPolicy
YAML files, including namespaces, policy names, ports, and keys.
"""

import os
import yaml
import random
import string
from enum import Enum
from typing import Dict, List, Set, Any, Optional, Tuple
from models import Rule, Ports, append_key_hash_id

class PolicyParser:
    """Parser for Cilium Network Policy YAML files"""
    
    NAMESPACE_LABEL_KEY = 'k8s:io.kubernetes.pod.namespace'
    namespace = ""
    debug = False
    EDGE_TYPE = {}
    
    def __init__(self, debug: bool = False):
        """Initialize the parser with optional debug mode"""
        self.debug = debug
    
    def _add_key(self, key: str, keys: Set[str], prefix: str = "") -> None:
        """Helper method to add a key with optional debug output"""
        keys.add(key)
        if self.debug and prefix:
            print(f"      [DEBUG] {prefix} Adding key: {key}")
    
    def _add_cidr_keys(self, cidr_list: List[Any], rules: Dict[str, Rule], direction: str) -> None:
        """Extract and add CIDR keys from a list"""
        if self.debug:
            print(f"    [DEBUG] Found CIDRs: {cidr_list}")
        for cidr_item in cidr_list:
            if isinstance(cidr_item, dict):
                cidr = cidr_item.get('cidr', cidr_item)
            else:
                cidr = cidr_item
            key = f"cidr:{cidr}"
            rule = Rule(direction, self.namespace, key, 'cidr')
            rules[rule.key] = rule
    
    def _add_entity_keys(self, entity_list: List[str], rules: Dict[str, Rule], direction: str) -> None:
        """Extract and add entity keys from a list"""
        if self.debug:
            print(f"    [DEBUG] Found entity: {entity_list}")
        for entity in entity_list:
            key = f"entity:{entity}"
            rule = Rule(direction, self.namespace, key, 'entity')
            rules[rule.key] = rule
    
    def _process_labels(self, labels: Dict[str, str], rules: Dict[str, Rule], direction: str, header: str = "label", namespace_key_format: str = "namespace:{value} (byLabel)") -> str:
        """Process matchLabels and extract keys, handling AND relationships"""
        if self.debug:
            print(f"      [DEBUG] Processing labels: {labels}")
        
        # TODO: This doesn't account for situations where multiple labels are in a single matchLabels entry equating to an AND situation. Right now they all appear as OR with their own node.
        tgt_namespace = ""
        first_key = ""
        other_keys = ""
        label_rules = []
        for k, v in labels.items():
            # If a namespace label is found, set the tgt_namespace and continue to the next label. Namespace nodes will be generated separately
            if k == self.NAMESPACE_LABEL_KEY:
                tgt_namespace = namespace_key_format.format(value=labels[k])
                continue
            
            # Otherwise, create a label rule for the label
            if not first_key:
                first_key = f"{header}:{k}={v}"
            elif not other_keys:
                other_keys = f"{k}={v}"
            else:
                other_keys += f" && {k}={v}"

        if not first_key:
            if tgt_namespace:
                first_key = f"{tgt_namespace}"
            else:
                first_key = "empty"
        rule_key = first_key
        if other_keys:
            rule_key += f" (+ OTHER RULES)"
        new_rule = Rule(direction, self.namespace, rule_key, rule_key.split(":")[0])
        if other_keys:
            new_rule.properties["rules"] = other_keys
            new_rule.generate_key_identifier()
        if tgt_namespace:
            new_rule.tgt_namespace = tgt_namespace
        rules[new_rule.key] = new_rule

        return new_rule.key

    
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
        return Ports(ports_info, dns_rules_from_ports)

    def _extract_fqdns(self, spec: Dict[str, Any], rules: Dict[str, Rule], direction: str) -> None:
        """Extract FQDN keys from spec"""
        if 'toFQDNs' not in spec:
            return
        
        if self.debug:
            print(f"    [DEBUG] Found toFQDNs: {spec['toFQDNs']}")
        for fqdn_rule in spec['toFQDNs']:
            if 'matchName' in fqdn_rule:
                key = f"fqdn:{fqdn_rule['matchName']}"
            elif 'matchPattern' in fqdn_rule:
                key = f"fqdn-pattern:{fqdn_rule['matchPattern']}"
            else:
                return
            
            rule = Rule(direction, self.namespace, key, 'fqdn')
            rules[rule.key] = rule

    def _extract_to_cidrs(self, spec: Dict[str, Any], rules: Dict[str, Rule], direction: str) -> None:
        """Extract toCIDR and toCIDRSet keys from spec"""
        if 'toCIDR' in spec:
            self._add_cidr_keys(spec['toCIDR'], rules, direction)
        
        if 'toCIDRSet' in spec:
            if self.debug:
                print(f"    [DEBUG] Found toCIDRSet: {spec['toCIDRSet']}")
            for cidr_rule in spec['toCIDRSet']:
                cidr = cidr_rule.get('cidr', cidr_rule) if isinstance(cidr_rule, dict) else cidr_rule
                key = f"cidrSet:{cidr}"
                rule = Rule(direction, self.namespace, key, 'cidrSet')
                rules[rule.key] = rule

    def _extract_from_cidrs(self, spec: Dict[str, Any], rules: Dict[str, Rule], direction: str) -> None:
        """Extract fromCIDRs rules from spec"""
        if 'fromCIDRs' in spec:
            self._add_cidr_keys(spec['fromCIDRs'], rules, direction)

    def _extract_to_endpoints(self, spec: Dict[str, Any], rules: Dict[str, Rule], direction: str) -> str:
        """Extract toEndpoints rules from spec"""
        if 'toEndpoints' not in spec:
            return
        
        if self.debug:
            print(f"    [DEBUG] Found toEndpoints: {spec['toEndpoints']}")
        match_label_key = ""
        for endpoint in spec['toEndpoints']:
            if 'matchLabels' in endpoint:
                match_label_key = self._process_labels(endpoint['matchLabels'], rules, direction)
            if 'matchExpressions' in endpoint:
                match_label_key = self._process_match_expressions(endpoint['matchExpressions'], match_label_key, rules, direction)
        return match_label_key

    def _extract_from_endpoints(self, spec: Dict[str, Any], rules: Dict[str, Rule], direction: str) -> str:
        """Extract fromEndpoints rules from spec"""
        if 'fromEndpoints' not in spec:
            return
        
        if self.debug:
            print(f"    [DEBUG] Found fromEndpoints: {spec['fromEndpoints']}")
        match_label_key = ""
        for endpoint in spec['fromEndpoints']:
            if 'matchLabels' in endpoint:
                match_label_key = self._process_labels(endpoint['matchLabels'], rules, direction)
            if 'matchExpressions' in endpoint:
                match_label_key = self._process_match_expressions(endpoint['matchExpressions'], match_label_key, rules, direction)
        return match_label_key

    def _process_match_expressions(self, match_expressions: List[Dict[str, Any]], match_label_key: str, rules: Dict[str, Rule], direction: str, header: str = "label:expr", namespace_key_format: str = "namespace:{value} (byLabel)") -> str:
        """Process matchExpressions and extract keys"""
        if self.debug:
            if match_label_key:
                print(f"      [DEBUG] Match label key found: {match_label_key}")
            print(f"      [DEBUG] Processing matchExpressions: {match_expressions}")
        tgt_namespace = ""
        match_expression_rules = []
        first_key = ""
        other_keys = ""
        for match_expression in match_expressions:
            # If a namespace label is found, set the tgt_namespace and continue to the next match expression. Namespace nodes will be generated separately
            if match_expression['key'] == self.NAMESPACE_LABEL_KEY:
                tgt_namespace = namespace_key_format.format(value=match_expression['values'][0])
                continue
            
            # Otherwise, create a label rule for the match expression
            key = f"\"{match_expression['key']}\"-({match_expression['operator']})"
            if match_expression.get('values'):
                key += f"-{str(match_expression.get('values'))}"
            if not first_key:
                first_key = f"{header}:{key}"
            elif not other_keys:
                first_key += f" (+ OTHER RULES)"
                other_keys = key
            else:
                other_keys += f" && {key}"
        
        # If a matchLabel key is present in this peer rule, add the new match expression to the existing rule
        if match_label_key and match_label_key in rules:
            if self.debug:
                print(f"      [DEBUG] Adding match expression to existing rule: {match_label_key}")
            # If the only label was a namespace, replace it with a new rule object
            if rules[match_label_key].rule_type == "namespace":
                namespace_rule = rules.pop(match_label_key)
                properties = {}
                if other_keys:
                    properties["rules"] = f"{other_keys}"
                new_rule = Rule(direction, namespace_rule.namespace, first_key, 'label', properties=properties)
                new_rule.tgt_namespace = namespace_rule.key
                rules[new_rule.key] = new_rule
                return new_rule.key
            # otherwise, update existing and generate a new identifier
            elif "rules" in rules[match_label_key].properties:
                rules[match_label_key].properties["rules"] += f" && {first_key} && {other_keys}"
            else:
                rules[match_label_key].properties["rules"] = f"{first_key} && {other_keys}"
            rules[match_label_key].generate_key_identifier()
            return rules[match_label_key].key
        # Otherwise, create a new rule for the match expression
        else:
            rule_key = first_key
            if other_keys:
                rule_key += f" (+ OTHER RULES)"
                new_rule = Rule(direction, self.namespace, rule_key, rule_key.split(":")[0], properties={"rules": other_keys})
            else:
                new_rule = Rule(direction, self.namespace, rule_key, rule_key.split(":")[0])

            if tgt_namespace:
                new_rule.tgt_namespace = tgt_namespace
            rules[new_rule.key] = new_rule
            return new_rule.key

    def _extract_services(self, spec: Dict[str, Any], rules: Dict[str, Rule], direction: str) -> None:
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
                    # TODO: Check if this makes sense in the graph once encountered
                    key = f"service:{namespace}/{service_name}" if namespace else f"service:{service_name}"
                    rule = Rule(direction, self.namespace, key, 'service')
                    rules[rule.key] = rule
            if 'serviceSelector' in service:
                selector = service['serviceSelector']
                if 'matchLabels' in selector:
                    labels = selector['matchLabels']
                    if self.debug:
                        print(f"      [DEBUG] Processing serviceSelector labels: {labels}")
                    # TODO: Check if this makes sense in the graph once encountered
                    self._process_labels(labels, rules, direction)

    def _extract_to_entities(self, spec: Dict[str, Any], rules: Dict[str, Rule], direction: str) -> None:
        """Extract toEntities rules from spec"""
        if 'toEntities' in spec:
            self._add_entity_keys(spec['toEntities'], rules, direction)

    def _extract_from_entities(self, spec: Dict[str, Any], rules: Dict[str, Rule], direction: str) -> None:
        """Extract fromEntities rules from spec"""
        if 'fromEntities' in spec:
            self._add_entity_keys(spec['fromEntities'], rules, direction)

    def _extract_endpoint_selector(self, policy_rule: Dict[str, Any], rules: Dict[str, Rule]) -> str:
        """Extract endpointSelector keys from spec"""
        if self.debug:
            print(f"    [DEBUG] Found endpointSelector: {policy_rule.get('endpointSelector')}")
        endpoint_selector = policy_rule.get('endpointSelector')
        # endpoint_selector_id = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        # endpoint_selector_key = f"endpointSelector:{endpoint_selector_id}"
        
        endpoint_selector_id = ""
        if endpoint_selector.get('matchLabels'):
            endpoint_selector_id = self._process_labels(endpoint_selector.get('matchLabels'), rules, "FromPods", header="endpointSelector")
        if endpoint_selector.get('matchExpressions'):
            endpoint_selector_id = self._process_match_expressions(endpoint_selector.get('matchExpressions'), endpoint_selector_id, rules, "FromPods", header="endpointSelector")
        
        return endpoint_selector_id


    def extract_rules_from_spec(self, spec: Dict[str, Any], direction: str) -> Dict[str, Rule]:
        """
        Extract all rules (FQDNs, endpoints, CIDRs, etc.) from ingress/egress spec
        Returns: Dict mapping rule key -> Rule
        """
        rules: Dict[str, Rule] = {}

        if not spec:
            if self.debug:
                print(f"  [DEBUG] Empty spec for {direction}")
            return rules
        
        if self.debug:
            print(f"  [DEBUG] Processing {direction} spec with keys: {list(spec.keys())}")
        
        # Extract all rule types
        self._extract_fqdns(spec, rules, direction)
        self._extract_to_cidrs(spec, rules, direction)
        self._extract_to_endpoints(spec, rules, direction)
        self._extract_services(spec, rules, direction)
        self._extract_to_entities(spec, rules, direction)
        self._extract_from_endpoints(spec, rules, direction)
        self._extract_from_cidrs(spec, rules, direction)
        self._extract_from_entities(spec, rules, direction)
        
        # Add port info if available
        if 'toPorts' in spec:
            if self.debug:
                print(f"    [DEBUG] Found toPorts: {spec['toPorts']}")
            port_info = self.extract_port_info_from_toPorts(spec['toPorts'])
            for rule in rules.values():
                rule.to_ports = port_info

        if self.debug:
            print(f"  [DEBUG] Total rules extracted from {direction} spec: {len(rules)}")
            for rule in rules.values():
                if rule.to_ports:
                    print(f"    [DEBUG]   {rule.key}: {rule.to_ports}")
        
        return rules

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

    def process_rules(self, policy_rules: List[Dict[str, Any]], direction: str, rules: Dict[str, Rule]) -> None:
        """
        Process a list of rules (egress/ingress/egressDeny/ingressDeny) and merge into rules dict.
        
        Args:
            policy_rules: List of policy rule dictionaries
            direction: Direction of the rule ('egress', 'ingress', 'egressDeny', 'ingressDeny')
            rules: Dict keyed by rule key, updated in place
        """
        if self.debug:
            print(f"    [DEBUG] Found {len(policy_rules)} {direction} rule(s)")
        
        for idx, rule in enumerate(policy_rules):
            if self.debug:
                print(f"    [DEBUG] Processing {direction} rule {idx + 1}")
            
            new_rules = self.extract_rules_from_spec(rule, direction)
            
            if self.debug:
                print(f"    [DEBUG] Extracted {len(new_rules)} rules from {direction} rule {idx + 1}: {list(new_rules.keys())}")    

            # Set the policy name for each rule
            for new_rule in new_rules.values():
                new_rule.direction = direction
            rules.update(new_rules)


    def process_spec(self, spec: Dict[str, Any], namespace: str, policy_name: str, rules: Dict[str, Rule]) -> None:
        if self.debug:
            print(f"  [DEBUG] Spec keys: {spec.keys()}")
        self.namespace = namespace

        new_rules: Dict[str, Rule] = {}

        endpoint_selector = None
        if 'endpointSelector' in spec:
            endpoint_selector = self._extract_endpoint_selector(spec, new_rules)

        if 'egress' in spec:
            if self.debug:
                print(f"  [DEBUG] Processing Egress rules...")
            egress_policy_rules = spec['egress'] if isinstance(spec['egress'], list) else [spec['egress']]
            self.process_rules(egress_policy_rules, 'egress', new_rules)
        
        # Process Ingress
        if 'ingress' in spec:
            if self.debug:
                print(f"  [DEBUG] Processing Ingress rules...")
            ingress_policy_rules = spec['ingress'] if isinstance(spec['ingress'], list) else [spec['ingress']]
            self.process_rules(ingress_policy_rules, 'ingress', new_rules)

        # Process Egress Deny
        if 'egressDeny' in spec:
            if self.debug:
                print(f"  [DEBUG] Processing Egress Deny rules...")
            egress_deny_policy_rules = spec['egressDeny'] if isinstance(spec['egressDeny'], list) else [spec['egressDeny']]
            self.process_rules(egress_deny_policy_rules, 'egressDeny', new_rules)

        # Process Ingress Deny
        if 'ingressDeny' in spec:
            if self.debug:
                print(f"  [DEBUG] Processing Ingress Deny rules...")
            ingress_deny_policy_rules = spec['ingressDeny'] if isinstance(spec['ingressDeny'], list) else [spec['ingressDeny']]
            self.process_rules(ingress_deny_policy_rules, 'ingressDeny', new_rules)

        
        for new_rule in new_rules.values():
            if endpoint_selector:
                new_rule.endpoint_selector = endpoint_selector
            new_rule.namespace = namespace
            new_rule.policy_name = policy_name
        rules.update(new_rules)



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


def extract_port_info_from_toPorts(toPorts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract port information from toPorts"""
    parser = PolicyParser()
    return parser.extract_port_info_from_toPorts(toPorts)


def parse_policy_file(filepath: str, debug: bool = False) -> Optional[Dict[str, Any]]:
    """Parse a CiliumNetworkPolicy YAML file"""
    parser = PolicyParser(debug=debug)
    return parser.parse_policy_file(filepath)

