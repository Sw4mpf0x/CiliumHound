# CiliumHound

Convert Kubernetes Cilium Network Policies to OpenGraph JSON BloodHound ingestion.

## Installation

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python CiliumHound.py <folder_path> [-o output.json] [-d]
```

### Arguments

- `folder_path`: Path to the folder containing CiliumNetworkPolicy YAML files
- `-o, --output`: Output JSON file path (default: `cilium_opengraph.json`)
- `-d, --debug`: Enable debug mode with verbose output showing each key being added and processing details

### Examples

```bash
# Basic usage
python CiliumHound.py ./policies -o cilium_graph.json

# With debug mode
python CiliumHound.py ./policies -o cilium_graph.json --debug
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
