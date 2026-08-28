# CiliumHound Example Policies

This folder contains synthetic CiliumNetworkPolicy examples for CiliumHound graph ingestion. The policies model three namespaces:

- `payments`: isolated application namespace.
- `records`: isolated data namespace.
- `management`: operations namespace with controlled access into the isolated namespaces.

Run CiliumHound from its project folder or by absolute path, for example:

```powershell
python ./CiliumHound.py ./ExamplePolicies -o /tmp/ciliumhound-example-output.json
```

## Intentional Findings

1. Full egress from `payments` to `uploads.backup-vendor.example.com`.
   - File: `payments_vendor-full-egress.yaml`
   - Signal: `endpointSelector: {}` and `toFQDNs` without `toPorts`, creating broad egress to a specific external FQDN.

2. Isolated namespace bridge from `payments` to `records`.
   - Files: `payments_to-records-audit-bridge.yaml`, `records_from-payments-audit-bridge.yaml`
   - Signal: access only appears when the source and destination share `access.int.example.com/bridge=finance-review` plus the expected app and environment labels.

3. Isolated namespace access to a specific management pod.
   - Files: `payments_to-management-breakglass.yaml`, `management_breakglass-ingress-from-isolated.yaml`
   - Signal: `payments` workload `fraud-worker` can reach `management` pod label `statefulset.kubernetes.io/pod-name=breakglass-console-0` on `2222/TCP`.

4. Management namespace administrative reach into isolated workloads.
   - Files: `management_admin-egress-to-isolated.yaml`, `payments_management-ingress.yaml`, `records_management-ingress.yaml`
   - Signal: `management` workloads with privileged administration labels can access selected pods in both isolated namespaces.
