# tsinject

A Kubernetes operator that joins annotated workloads to a Tailscale tailnet.
Label a pod `inject-tailscale: "true"`, optionally tune it with
`tailscale-*` annotations, and the operator injects a tailscale sidecar and
provisions a dedicated Tailscale OAuth client for the workload.

One binary, built on controller-runtime, runs four parts:

- **Pod admission webhook** (opt-in via the `inject-tailscale: "true"`
  label): injects the sidecar machinery driven by the pod's `tailscale-*`
  annotations. Admission performs **no writes and no Tailscale API calls**
  (`sideEffects: None`). If the workload's credential is not provisioned
  yet — or is provisioned for other tags, another tailnet or another
  ephemeral setting than the pod's annotations ask for, or its `Ready`
  predates its current spec — the pod is admitted with the
  `tsinject.dmf.zone/awaiting-credential` **scheduling gate** and sits
  visibly `SchedulingGated`. The webhook's `failurePolicy` is `Fail`: while
  the operator is down, creating a labeled pod is rejected rather than
  started off-tailnet. Unlabeled pods never reach the webhook.
- **TailscaleCredential controller**: reconciles the namespaced
  `TailscaleCredential` CRD — mints an OAuth client via the Tailscale API,
  delivers it as the `<name>-ts-credential` Secret, updates tags in place on
  spec drift, adopts an existing Secret of that name that already holds a
  client, and **revokes the OAuth client via a finalizer** when the credential is
  deleted.
- **Pod gate controller**: the asynchronous half of admission. For each
  gated pod it materializes what the annotations demand — the
  `TailscaleCredential` itself (created on first use, ownerReferenced to
  the owning Deployment; an existing one has its tags, tailnet and
  ephemeral flag synced to the pod's), the serve/config ConfigMaps, the
  tailscaled state-secret RBAC — and lifts the scheduling gate once the
  credential is `Ready` for the spec it now has. The scheduler takes over
  from there.
- **Cert rotator** (the Gatekeeper pattern, via
  `open-policy-agent/cert-controller`): the webhook CA and serving cert are
  self-managed in a Secret and the CA bundle is patched into the webhook
  configuration. No cert-manager, no hand-rolled certificates.

## Flow

```
pod CREATE (label inject-tailscale=true)
  └─ webhook: inject sidecar + stamp tsinject.dmf.zone/credential=<identity>
       ├─ credential Ready and matching the pod, configs in place → admitted, schedules immediately
       └─ otherwise → admitted with scheduling gate
            └─ pod gate controller: ensure TailscaleCredential/ConfigMaps/RBAC
                 └─ credential controller: mint OAuth client → deliver Secret → Ready
                      └─ pod gate controller: remove gate → pod schedules
```

The workload identity (= name of the `TailscaleCredential`, its Secret and
ConfigMaps) is the `tailscale-shared-name` annotation, else the owning
Deployment's name, else the pod's own name — so all replicas of a
Deployment share one OAuth client. A persistent pod's tailscaled state
Secret and its RBAC are named after it too.

## Install

Via the Helm chart (released to GHCR as an OCI artifact):

```sh
helm upgrade --install tsinject oci://ghcr.io/davefinster/charts/tsinject \
  --namespace tsinject-system --create-namespace
kubectl -n tsinject-system create secret generic tailscale-oauth \
  --from-file=secret.json=/path/to/secret.json
```

Or with plain manifests:

```sh
kubectl apply -f config/tsinject.dmf.zone_tailscalecredentials.yaml
kubectl apply -f config/install.yaml
kubectl -n tsinject-system create secret generic tailscale-oauth \
  --from-file=secret.json=/path/to/secret.json
```

`secret.json` is the operator's own OAuth client (needs scope to create
auth keys / OAuth clients): `{"client_id": "...", "client_secret": "..."}`.
The chart can also create this Secret from values (`tailscale.oauth.clientId`/
`clientSecret`), and exposes the tailnet, injected image, Kata tun device,
replica count and webhook toggles — see `charts/tsinject/values.yaml`. Set `TAILNET` if the
credential can address more than its own tailnet (default `-`).

For multiple tailnets, `secret.json` instead maps named tailnets to their
credentials — see below.

See `config/samples/` for a minimal injected Deployment and a hand-authored
`TailscaleCredential`.

## Pod annotations

| Annotation | Effect |
| --- | --- |
| `tailscale-tags` | Comma-separated tags (no `tag:` prefix); `tag:injected` always added. Sets the OAuth client's tags and `--advertise-tags`. |
| `tailscale-ephemeral` | `"true"`/`"false"` — appends `?ephemeral=…` to the OAuth secret and switches the sidecar to in-memory state. |
| `tailscale-tailnet` | Named operator-configured tailnet the workload's OAuth client is minted in; absent means the nominated default. Unknown names are denied at admission. |
| `tailscale-custom-image` | Overrides the injected tailscale image. |
| `tailscale-privileged` | `"true"` runs the sidecar privileged. |
| `tailscale-shared-name` | Shared identity override (must be a valid object name). |
| `tailscale-env` | Newline-separated `NAME=VALUE` merged into the sidecar env; existing names get the value appended (space-separated). |
| `tailscale-serve-config` | serve.json content, materialized as the `<identity>-serve-config` ConfigMap and wired via `TS_SERVE_CONFIG` (in a federated tailnet, projected straight from the annotation instead). |
| `tailscale-config-json` | tailscaled config.json content, materialized as `<identity>-json-config` and passed via `--config` (federated: projected from the annotation). |
| `tailscale-shared-socket-mount` | Author-defined volume to share the tailscaled socket through. |
| `tailscale-advertise-services` | Comma-separated Tailscale services advertised by a helper container. |
| `tailscale-advertise-services-skip-advertise-container` | `"true"` suppresses the helper container. |
| `tailscale-client-id` | Federated tailnets only, and required there: the workload's Tailscale federated identity (its client ID, no `?` attributes — `tailscale-ephemeral` decides those). |
| `tailscale-audience` | Federated tailnets only, and required there: that identity's audience, which the projected service-account token is issued for. |
| `tailscale-resources` | JSON `ResourceRequirements` for the sidecar, e.g. `{"limits":{"memory":"2Gi"}}`. Replaces whichever of `requests`/`limits` it names, whole — so naming only memory in `limits` leaves the CPU **uncapped**, and `"limits":{}` removes both. A document that does not parse, carries an unknown field, or holds a bad or negative quantity is denied at admission. |

The sidecar's defaults are `25m`/`96Mi` requested and `1` CPU/`1Gi` limited:
requests sized to an ordinary tunnel (median 35Mi and p90 90Mi of memory,
measured across several hundred sidecars over two weeks), a ceiling for a
busy one. A pod that moves data should request what it uses through
`tailscale-resources`.
Raising, or removing, the CPU limit is what a pod moving data at line rate
needs: the tunnel's encryption is the sidecar's own CPU, so its ceiling is a
throughput ceiling. In one measurement on a 149 ms path, the sidecar spent
~290m at 8.6 MB/s and ~450m at 13.9 MB/s, and its cgroup was throttled in
10–15 of every 550 scheduling periods at those rates.

### Kata Containers

A pod under a Kata runtime class (any `runtimeClassName` starting with
`kata`) runs in a VM whose guest does not get the host's `/dev/net/tun`,
which tailscaled needs for kernel networking. If a device plugin on your
Kata nodes advertises the device as an extended resource — for example
`squat.ai/tun` from
[squat's generic-device-plugin](https://github.com/squat/generic-device-plugin)
— set `tailscale.kataTunResource` in the chart (`KATA_TUN_RESOURCE` for the
operator) to that name, and the sidecar of every Kata pod requests one. It
is off by default, because a request no node advertises leaves the pod
`Pending`.

## The TailscaleCredential CRD

```sh
kubectl get tscred                # Ready state, client ID, secret per identity
kubectl delete tscred web        # revokes the OAuth client, GCs the Secret
```

Normally created on demand by the operator; author one directly to
pre-provision, pin custom tags or secret names, or share an identity across
workloads. Credentials created for a Deployment carry an ownerReference to
it: **deleting the Deployment revokes the workload's OAuth client and
deletes its Secret**.

## Multiple tailnets

With the [Tailnets API](https://tailscale.com/docs/features/tailnets-api)
one account holds several tailnets, and each API-only tailnet is
administered only by its own scoped OAuth client — the org-level client
that created it cannot. The operator therefore takes a *set* of tailnets,
each a (name, API path segment, admin OAuth client) triple, with one
nominated as the default, via the multi-tailnet `secret.json` shape:

```json
{
  "default": "homelab",
  "tailnets": {
    "homelab": {"tailnet": "-", "client_id": "...", "client_secret": "..."},
    "global-infrastructure": {"tailnet": "<tailnet-id>", "client_id": "...", "client_secret": "..."}
  }
}
```

`tailnet` is what the entry's admin client addresses the tailnet as in API
paths — a tailnet ID from the Tailnets API, or `-` (the default when
omitted) for the client's own tailnet. `default` may be omitted only when
exactly one tailnet is configured. The single-client shape also works and
registers its tailnet under the name `default`. The chart
renders this file from `tailscale.tailnets`/`tailscale.defaultTailnet`.

Workloads pick a tailnet with the `tailscale-tailnet` annotation (or
`spec.tailnet` on a hand-authored credential); their per-workload OAuth
client is minted inside that tailnet, so the injected sidecar still
addresses its own tailnet as `-` and is none the wiser. `status.tailnet`
records where a client actually lives — revocations go there, and an empty
`spec.tailnet` stays pinned to it, so re-nominating the default never
re-homes existing clients. Setting `spec.tailnet` to a different name
revokes the client and mints a replacement in the new tailnet (the
delivered Secret changes; running pods keep their session until restart).
A credential naming an unconfigured tailnet goes `Ready=False` with reason
`UnknownTailnet`, and pods annotated with one are denied at admission.

### Federated credential mode

A tailnet entry with `"credential_mode": "federated"` stops minting
per-workload OAuth clients. Its pods join as a [Tailscale federated
identity](https://tailscale.com/kb/1581/workload-identity-federation) of
their own, declared outside the operator (typically one per workload,
trusting the cluster's public service-account issuer), and named
on the pod by `tailscale-client-id` and `tailscale-audience`. The webhook:

- mounts a projected service-account token for the audience at
  `/var/run/secrets/tailscale/token` and sets `TS_CLIENT_ID` and
  `TS_ID_TOKEN=file:…` — there is no `TS_CLIENT_SECRET` and no OAuth Secret;
- appends `?ephemeral=false` to the client ID for `tailscale-ephemeral: "false"`
  (a federated client ID otherwise registers ephemeral nodes);
- projects `tailscale-serve-config` / `tailscale-config-json` from the pod's
  own annotations (downward API), so no ConfigMap is needed;
- creates no TailscaleCredential and gates a pod only while a persistent
  pod's state-Secret RBAC is missing (provisioned by the gate controller,
  owned by the Deployment);
- denies admission when either annotation is missing.

The entry's admin client becomes optional: keep it while TailscaleCredentials
from before the switch still need revoking, then drop it.

```json
"config-plane": {"tailnet": "<tailnet-id>", "credential_mode": "federated"}
```

Undo by setting the mode back to `oauth` (with the admin client): pods
admitted afterwards get OAuth clients again.

## Releases

Everything ships from the `build` workflow on pushes to `main`:

- **Operator image** — `ghcr.io/davefinster/tsinject:main` (moving) and
  `:sha-<short>` (immutable) on every push. Versioned tags (`v1`, `v2`, …)
  — what the chart and `config/install.yaml` reference — are minted by the
  manual **promote** workflow, which re-tags an already-built image by
  digest (no rebuild) and anchors a matching `vN` git tag.
- **Helm chart** — `oci://ghcr.io/davefinster/charts/tsinject`. Versions
  are immutable and source-controlled: bump `version` in
  `charts/tsinject/Chart.yaml` and merge — CI lints the chart, checks the
  `crds/` copy against `config/`, server-side dry-runs the rendered
  manifests on a throwaway kind cluster, and publishes only versions not
  yet in the registry.

Typical release: run **promote** → update `operator.image.tag` in
`charts/tsinject/values.yaml` (and `config/install.yaml`) → bump the chart
version → merge.

## Development

```sh
go test ./...
helm lint charts/tsinject
./build-push.sh          # manual image escape hatch (defaults to :dev)
```
