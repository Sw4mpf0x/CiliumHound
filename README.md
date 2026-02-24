# CiliumHound

Convert Kubernetes Cilium Network Policies to OpenGraph JSON BloodHound ingestion.

## Installation

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python cilium_to_bloodhound.py <folder_path> [-o output.json] [-d]
```

### Arguments

- `folder_path`: Path to the folder containing CiliumNetworkPolicy YAML files
- `-o, --output`: Output JSON file path (default: `cilium_opengraph.json`)
- `-d, --debug`: Enable debug mode with verbose output showing each key being added and processing details

### Examples

```bash
# Basic usage
python cilium_to_bloodhound.py ./policies -o cilium_graph.json

# With debug mode
python cilium_to_bloodhound.py ./policies -o cilium_graph.json --debug
```

## File Naming Convention

The script expects YAML files to be named in the format:
```
[namespace]_[policy_name].yaml
```

For example: `production_web-policy.yaml`

If the namespace cannot be extracted from the filename, the script will attempt to extract it from the policy's metadata.

## Output

The script generates a BloodHound OpenGraph JSON file that can be imported into BloodHound for visualization. The graph includes:

- **Nodes**:
  - Namespaces (from policy metadata or filenames)
  - Keys extracted from ingress/egress rules:
    - FQDNs (from `toFQDNs` and `matchName`)
    - FQDN Patterns (from `toFQDNs` and `matchPattern`)
    - CIDRs (from `toCIDR`, `toCIDRs`, `toCIDRSet`, and `fromCIDRs`)
    - Services (from `toServices`)
    - Endpoints (from `toEndpoints` and `fromEndpoints` match labels)
    - Entities (from `toEntities` and `fromEntities`)
    - Labels (from endpoint match labels)

- **Edges**:
  - `Egress`: Namespace → Key (for egress rules)
  - `Ingress`: Key → Namespace (for ingress rules)

## Supported Cilium Policy Fields

The script extracts relationships from the following CiliumNetworkPolicy spec fields:

- `egress.toFQDNs` (matchName and matchPattern)
- `egress.toCIDR`
- `egress.toCIDRs`
- `egress.toCIDRSet`
- `egress.toEndpoints`
- `egress.toServices`
- `egress.toEntities`
- `ingress.fromEndpoints`
- `ingress.fromCIDRs`
- `ingress.fromEntities`

## Debug Mode

When using the `-d` or `--debug` flag, the script will output detailed information including:

- Each file being processed
- Namespace extraction attempts
- Each key being extracted from policies
- Spec structure details
- Node and edge creation details
- Summary statistics

This is useful for troubleshooting and understanding how policies are being parsed.

## References

- [bhopengraph Library](https://github.com/p0dalirius/bhopengraph)
- [BloodHound OpenGraph Schema](https://bloodhound.specterops.io/opengraph/schema)
