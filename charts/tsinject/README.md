# tsinject chart

Installs the tsinject operator: the pod admission webhook (annotation-driven
Tailscale sidecar injection with scheduling-gate deferral), the
TailscaleCredential controller (per-workload OAuth clients minted via the
Tailscale API, revoked on deletion), the pod gate controller, and
self-managed webhook TLS. See the repository README for the architecture
and the pod annotation contract.

```sh
helm upgrade --install tsinject oci://ghcr.io/davefinster/charts/tsinject \
  --namespace tsinject-system --create-namespace
kubectl -n tsinject-system create secret generic tailscale-oauth \
  --from-file=secret.json=/path/to/secret.json
```

Or hand the chart the OAuth client inline (`tailscale.oauth.existingSecret=""`,
`tailscale.oauth.clientId=...`, `tailscale.oauth.clientSecret=...`) if your
values handling is already secret-safe.

For multiple tailnets (the Tailnets API), set `tailscale.tailnets` — one
entry per tailnet, each with its own admin OAuth client, plus
`tailscale.defaultTailnet` nominating the default — or keep
`existingSecret` and write the multi-tailnet `secret.json` yourself (see
the repository README for the file shape). Workloads pick a tailnet with
the `tailscale-tailnet` annotation.

The `TailscaleCredential` CRD ships in `crds/` — Helm installs it on first
install but does **not** upgrade it; apply the file manually when a chart
release notes a CRD change.

Notable values (see `values.yaml` for the full set):

| Value | Default | Meaning |
| --- | --- | --- |
| `operator.image.tag` | `v12` | Promoted operator image (`promote` workflow mints these). |
| `operator.replicas` | `1` | >1 enables leader election automatically. |
| `tailscale.tailnet` | `-` | Tailnet to attach workloads to (single-client setup; ignored with `tailnets`). |
| `tailscale.oauth.existingSecret` | `tailscale-oauth` | Secret with `secret.json`; empty switches to inline `clientId`/`clientSecret` or `tailnets`. |
| `tailscale.tailnets` | `{}` | Named tailnets, each `{tailnet, clientId, clientSecret}`; workloads select one via the `tailscale-tailnet` annotation. |
| `tailscale.defaultTailnet` | `""` | Which `tailnets` entry unnamed workloads land on; required with more than one entry. |
| `tailscale.injectedImage` | `ghcr.io/tailscale/tailscale:latest` | Sidecar image the webhook injects. |
| `tailscale.kataTunResource` | `""` | Extended resource a Kata pod's sidecar requests for `/dev/net/tun` (e.g. `squat.ai/tun`); empty requests nothing. |
| `webhook.enabled` | `true` | Serve admission + create the webhook configuration. |
| `webhook.createCertSecret` | `true` | Ship the placeholder cert Secret (disable when it pre-exists). |

Fixed object names (`tsinject-webhook`, `tsinject-mutating`,
`tsinject-webhook-cert`) match constants in the operator binary — one
release per cluster.
