# CiliumHound

Convert Kubernetes Cilium Network Policies to OpenGraph JSON BloodHound ingestion.

## Installation

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python CiliumHound.py <policy_path> [-o output.json] [-d]
```

### Arguments

- `policy_path`: Path to a folder containing CiliumNetworkPolicy YAML/JSON files, or a single YAML/JSON policy file
- JSON policy files are expected to be Kubernetes `List` objects, with `CiliumNetworkPolicy` resources inside the top-level `items` array
- `-o, --output`: Output JSON file path (default: `cilium_opengraph.json`)
- `-d, --debug`: Enable debug mode with verbose output showing each key being added and processing details

### Examples

```bash
# Basic usage
python CiliumHound.py ./policies -o cilium_graph.json

# With debug mode
python CiliumHound.py ./policies -o cilium_graph.json --debug
```

## Output

The script generates a BloodHound OpenGraph JSON file that can be imported into BloodHound for visualization.

Edges store policy_name as an array containing every policy whose spec creates that edge.

## Graph Node And Edge Types

### Node Types

| Node kind | Created from | Key format | Common properties |
|-----------|--------------|------------|-------------------|
| `Namespace` | Policy namespaces, namespace label selectors, and optional fallback namespace | `namespace:<name>` or `namespace:ANY` | `displayname`, `name`, `namespace` |
| `EndpointSelector` | Top-level `endpointSelector.matchLabels` and `endpointSelector.matchExpressions` | `endpointSelector:<selector>` | Selector labels, `displayname`, `name`, `namespace`, optional `rules` |
| `FQDN` | `toFQDNs.matchName` | `fqdn:<name>` | `displayname`, `name`, `key_type`, `full_key`, `namespace`, `policy_name`, optional `ports`, `rules` |
| `FQDN-Pattern` | `toFQDNs.matchPattern` | `fqdn-pattern:<pattern>` | `displayname`, `name`, `key_type`, `full_key`, `namespace`, `policy_name`, optional `ports`, `rules` |
| `CIDR` | `toCIDR`, `fromCIDRs` | `cidr:<cidr>` | `displayname`, `name`, `key_type`, `full_key`, `namespace`, `policy_name`, optional `ports`, `rules` |
| `CIDRSet` | `toCIDRSet` | `cidrSet:<cidr>` | `displayname`, `name`, `key_type`, `full_key`, `namespace`, `policy_name`, optional `ports`, `rules` |
| `Service` | `toServices.k8sService` | `service:<namespace>/<name>` or `service:<name>` | `displayname`, `name`, `key_type`, `full_key`, `namespace`, `policy_name`, optional `ports` |
| `Label` | `toEndpoints`, `fromEndpoints`, service selectors, and match expressions | `label:<key>=<value>` or `label:expr:<expression>` | `displayname`, `name`, `key_type`, `full_key`, `namespace`, `policy_name`, optional `rules` as an array |
| `Entity` | `toEntities`, `fromEntities` | `entity:<name>` | `displayname`, `name`, `key_type`, `full_key`, `namespace`, `policy_name`, optional `ports` |
| `Port` | `toPorts.ports` | `Key:<port>/<protocol>` | `displayname`, `name` |
| `PortRules` | Per-protocol `toPorts.rules` blocks | `PortRules:<protocol>:<hash>` | `displayname`, `name`, `port`, `rules` as an array, `policy_name`, `namespace` |
| `Key` | Fallback for unclassified rule keys | Original rule key | `displayname`, `name`, `key_type`, `full_key`, `namespace`, `policy_name` |

### Edge Types

| Edge kind | Direction | Created when | Common properties |
|-----------|-----------|--------------|-------------------|
| `Egress` | `Namespace` or `EndpointSelector` -> rule node | An egress rule allows traffic to the rule target | `policy_name`, `namespace` |
| `Ingress` | Rule node -> `Namespace` or `EndpointSelector` | An ingress rule allows traffic from the rule source | `policy_name`, `namespace` |
| `EgressDeny` | `Namespace` -> rule node or `EndpointSelector` -> rule node | An egress deny rule may or may not scoped by an endpoint selector | `policy_name`, `namespace` |
| `IngressDeny` | Rule node -> `Namespace` or Rule node -> `EndpointSelector` | An ingress deny rule may or may scoped by an endpoint selector | `policy_name`, `namespace` |
| `EndpointsWithSelector` | `Namespace` -> `EndpointSelector` | A policy has an endpoint selector | `policy_name`, `namespace` |
| `ToNamespace` | Rule node -> `Namespace` | A rule targets a namespace, or no target namespace exists and `--any-namespace true` is used | none |
| `FromNamespace` | `Namespace` -> rule node | An ingress rule has a source namespace, or no source namespace exists and `--any-namespace true` is used | none |
| `ToPorts` | Rule node -> `Port`, or `PortRules` -> `Port` | A rule has a port without protocol rules, or a `PortRules` node points to its port | `policy_name`, `namespace` |
| `WithPortRules` | Rule node -> `PortRules` | A port has protocol-specific rules such as `dns` or `http` | `policy_name`, `namespace` |

## BloodHound CE helper (`helper-scripts/`)

The script [`helper-scripts/bloodhound_helper.py`](helper-scripts/bloodhound_helper.py) talks to BloodHound Community Edition over the HTTP API: upload collection JSON for ingest, clear data, sync saved Cypher queries, upload an OpenGraph extension schema, and push custom node icons.

### Installing helper dependencies

```bash
pip install -r helper-scripts/requirements.txt
```

### Authentication

Credentials are read in this order: command-line flags, `.env` file (via `python-dotenv`), then process environment.

| Variable | Purpose |
|----------|---------|
| `BLOODHOUND_URL` | Base URL (for example `https://bloodhound.example`) |
| `BLOODHOUND_USERNAME` | Login username |
| `BLOODHOUND_SECRET` | API secret / password |

Every subcommand accepts `--url`, `--username`, and `--secret` if you prefer not to use a `.env` file. Use `--insecure` only when you must disable TLS verification (not recommended for production).

### Subcommands

| Command | What it does |
|---------|----------------|
| `ingest` | Upload one or more collection `.json` files, end the upload job, and poll until ingest finishes (or fails). |
| `clear-database` | `POST /api/v2/clear-database` with configurable delete flags. Use `--source-kind-name` (for example `TS_Base`) or `--source-kind-id` when you need to clear a specific graph source kind. |
| `upload-queries` | Deletes your **owned** saved queries, then uploads every `*.json` from a folder (default folder name: `saved-queries`). Each file must be a JSON object with at least `name` and `query`. |
| `upload-schema` | `PUT` an OpenGraph extension payload to `/api/v2/extensions` (default file: `schema.json`). |
| `push-icons` | Registers Font Awesome custom node icons used by this project; optional repeatable `--icon TYPE NAME COLOR` adds more. |

Run `python helper-scripts/bloodhound_helper.py --help` or `python helper-scripts/bloodhound_helper.py <subcommand> --help` for all flags.

### Examples

```bash
# Ingest the graph produced by CiliumHound.py
python helper-scripts/bloodhound_helper.py ingest cilium_opengraph.json --verbose

# Clear CE data for a named source kind (matches older Tailscale-focused helpers)
python helper-scripts/bloodhound_helper.py clear-database --source-kind-name TS_Base

# Replace your saved queries from a directory of JSON definitions
python helper-scripts/bloodhound_helper.py upload-queries --folder ./saved-queries

# Upload extension schema (path relative to your current working directory)
python helper-scripts/bloodhound_helper.py upload-schema --file ./schema.json

# Push default CiliumHound icons (add --insecure if you use plain HTTP to localhost)
python helper-scripts/bloodhound_helper.py push-icons
```

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
