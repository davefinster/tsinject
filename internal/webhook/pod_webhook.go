// Package webhook implements the pod admission handler: opt-in pods (label
// inject-tailscale=true via objectSelector) get the tailscale sidecar
// machinery injected, bound to their workload's TailscaleCredential -- or,
// in a tailnet in federated credential mode, to the federated identity the
// pod names, which it joins as with its own service-account token.
//
// Unlike the pre-operator injector, admission performs no writes and no
// Tailscale API calls (sideEffects: None): it only shapes the pod. Whenever
// the cluster state the pod depends on is not in place yet — the credential
// Secret, the serve/config ConfigMaps, the state-secret RBAC — the pod is
// admitted WITH a scheduling gate and sits visibly SchedulingGated until
// the gate controller has provisioned everything and lifts the gate.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	tsv1alpha1 "github.com/davefinster/tsinject/api/v1alpha1"
	"github.com/davefinster/tsinject/internal/controller"
)

const (
	// SidecarName is the injected container's name; its presence marks a
	// pod as already mutated (reinvocation idempotency).
	SidecarName = "tailscale"
	// AdvertiseContainerName advertises Tailscale services next to the
	// sidecar when the pod asks for it.
	AdvertiseContainerName = "tailscale-service-advertise"

	oauthVolume       = "oauth"
	serveConfigVolume = "serve-config"
	jsonConfigVolume  = "json-config"
	socketVolume      = "socket-volume"

	socketPath = "/socket/run/tailscale/tailscaled.sock"

	// The projected service-account token a federated pod presents to
	// Tailscale, issued for its identity's audience. An hour is the
	// kubelet's usual lifetime; the sidecar only reads it when it logs in.
	idTokenVolume  = "tailscale-id-token"
	idTokenDir     = "/var/run/secrets/tailscale"
	idTokenFile    = "token"
	idTokenSeconds = int64(3600)
)

const advertiseScript = `
ALL_ADVERTISED=0
while [ $ALL_ADVERTISED -eq 0 ]
do
  echo Sleeping;
  sleep 15;
  ALL_ADVERTISED=1
  for i in $SERVICES
  do
      echo "$i";
      if tailscale --socket $TS_SOCKET serve advertise $i; then
        echo Advertised $i
      else
        echo Failed to advertise $i
        ALL_ADVERTISED=0
      fi
  done
done
sleep infinity;
`

// serviceHostProbeScript is the sidecar's liveness check when the pod advertises Tailscale Services. It fails while
// the node is Running and, for a Service it advertises, either
//   - control has not made it the host: the Service is missing from the self node's service-host capability
//     ("svc:name": [addresses]), which control grants after asking the node, over c2n, GET /vip-services. When that
//     call never comes the Service stays hostless for good; after node rolls, Services have sat that way for most of
//     a day;
//   - or control made it the host but routes it nothing: an address service-host lists is missing from the self
//     node's AllowedIPs, which is where clients route the Service from. Seen when a node's only /vip-services call
//     came a second BEFORE containerboot advertised the Service and no second call came: for 15 minutes it held the
//     capability while every client had no route to it.
//
// Each was fixed by restarting the sidecar; failing here makes the kubelet do that restart. It passes while the node
// is not Running (logging in) and when the local API cannot be asked, so it never fights a login. The Services come
// from the serve config containerboot advertises (TS_SERVE_CONFIG's Services keys) and the advertise annotation.
const serviceHostProbeScript = `
svcs=""
[ -n "${TS_SERVE_CONFIG:-}" ] && [ -r "$TS_SERVE_CONFIG" ] && svcs=$(grep -o '"svc:[A-Za-z0-9-]*"' "$TS_SERVE_CONFIG" | tr -d '"')
for s in $(echo "${TSINJECT_ADVERTISE_SERVICES:-}" | tr ',' ' '); do svcs="$svcs $s"; done
[ -n "$(echo $svcs)" ] || exit 0
st=$(tailscale ${TS_SOCKET:+--socket=$TS_SOCKET} status --json 2>/dev/null) || exit 0
echo "$st" | grep -q '"BackendState": *"Running"' || exit 0
self=$(echo "$st" | awk '/^  "Self": \{/{s=1} s{print} s && /^  \},?$/{exit}')
for s in $svcs; do
  addrs=$(echo "$self" | awk -v k="\"$s\": [" 'index($0,k){f=1;next} f&&/\]/{exit} f{gsub(/[",[:space:]]/,""); if($0!="")print}')
  [ -n "$addrs" ] || { echo "advertising $s, but control has not made this node its host"; exit 1; }
  for a in $addrs; do
    echo "$self" | grep -q "\"$a/" || { echo "the host of $s, but its address $a is not routed to this node"; exit 1; }
  done
done
exit 0
`

// serviceHostProbe gives the sidecar of a pod that advertises Tailscale Services the liveness check above: after a
// two-minute start, six failures 30 s apart -- three minutes advertising without being the host -- restart it.
func serviceHostProbe(pod *corev1.Pod, container *corev1.Container) {
	_, serve := pod.Annotations[tsv1alpha1.ServeConfigAnnotation]
	advertised, advertise := pod.Annotations[tsv1alpha1.AdvertiseServicesAnnotation]
	if (!serve && !advertise) || pod.Annotations[tsv1alpha1.ServiceHostProbeAnnotation] == "false" {
		return
	}
	if advertise {
		container.Env = append(container.Env, corev1.EnvVar{Name: "TSINJECT_ADVERTISE_SERVICES", Value: advertised})
	}
	container.LivenessProbe = &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{Command: []string{"sh", "-c", serviceHostProbeScript}},
		},
		InitialDelaySeconds: 120,
		PeriodSeconds:       30,
		TimeoutSeconds:      15,
		FailureThreshold:    6,
	}
}

// PodMutator injects the tailscale machinery into opt-in pods.
type PodMutator struct {
	Client         client.Client // manager cache: TailscaleCredential lookups
	APIReader      client.Reader // uncached: owner chains and gate checks
	Decoder        admission.Decoder
	TailscaleImage string // image injected unless tailscale-custom-image overrides
	// KataTunResource is the extended resource the sidecar of a pod under a
	// Kata runtime class requests, so that a device plugin hands /dev/net/tun
	// into the guest VM (which does not get the host's) and tailscaled can
	// use kernel networking there. Empty requests nothing.
	KataTunResource corev1.ResourceName
	// Tailnets validates the tailscale-tailnet annotation at admission so a
	// typo fails fast instead of gating the pod forever. Nil skips the check.
	Tailnets *controller.TailnetRegistry
}

func (m *PodMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	pod := &corev1.Pod{}
	if err := m.Decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	for _, c := range pod.Spec.Containers {
		if c.Name == SidecarName {
			return admission.Allowed("tailscale sidecar already present")
		}
	}

	if tailnet := controller.TailnetForPod(pod); tailnet != "" && m.Tailnets != nil && !m.Tailnets.Has(tailnet) {
		return admission.Denied(fmt.Sprintf("unknown tailnet %q; configured tailnets: %s",
			tailnet, strings.Join(m.Tailnets.Names(), ", ")))
	}

	if _, err := resolveResources(pod); err != nil {
		// A resource hint the author got wrong is worth saying out loud:
		// ignored, the pod would run with the defaults and the mistake
		// would only show up as a throughput ceiling months later.
		return admission.Denied(err.Error())
	}

	identifier, _, err := controller.ResolveWorkloadIdentity(ctx, m.APIReader, req.Namespace, pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	if identifier == "" {
		return admission.Denied("cannot derive a workload identity for this pod; set the tailscale-shared-name annotation")
	}

	if m.Tailnets != nil && m.Tailnets.Federated(controller.TailnetForPod(pod)) {
		return m.handleFederated(ctx, req, pod, identifier)
	}

	cred := &tsv1alpha1.TailscaleCredential{}
	if err := m.Client.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: identifier}, cred); err != nil {
		cred = nil // treated as "not provisioned yet" — the pod gets gated
	}
	secretName := controller.CredentialSecretName(identifier)
	if cred != nil {
		secretName = controller.DefaultedCredentialSpec(cred).SecretName
	}

	mutated := pod.DeepCopy()
	mutatePod(mutated, mutateInput{
		identifier:      identifier,
		secretName:      secretName,
		defaultImage:    m.TailscaleImage,
		kataTunResource: m.KataTunResource,
	})
	if m.needsGate(ctx, req.Namespace, pod, identifier, cred) {
		addGate(mutated)
	}
	return patched(req, mutated)
}

// handleFederated injects a pod of a federated tailnet: it joins as the
// federated identity its annotations name, presenting a projected token of
// its own service account, so there is no credential to wait for. The only
// gate left is the state Secret's RBAC, for a persistent pod that keeps its
// tailscaled state in one.
func (m *PodMutator) handleFederated(ctx context.Context, req admission.Request, pod *corev1.Pod, identifier string) admission.Response {
	clientID := strings.TrimSpace(pod.Annotations[tsv1alpha1.ClientIDAnnotation])
	audience := strings.TrimSpace(pod.Annotations[tsv1alpha1.AudienceAnnotation])
	tailnet := controller.TailnetForPod(pod)
	if tailnet == "" {
		tailnet = m.Tailnets.DefaultName()
	}
	if clientID == "" || audience == "" {
		return admission.Denied(fmt.Sprintf("tailnet %q joins workloads as federated identities: the pod needs %s (the identity's client ID) and %s (its audience)",
			tailnet, tsv1alpha1.ClientIDAnnotation, tsv1alpha1.AudienceAnnotation))
	}
	if strings.Contains(clientID, "?") {
		return admission.Denied(fmt.Sprintf("%s %q carries attributes; ephemerality comes from %s",
			tsv1alpha1.ClientIDAnnotation, clientID, tsv1alpha1.EphemeralAnnotation))
	}
	mutated := pod.DeepCopy()
	mutatePod(mutated, mutateInput{
		identifier:      identifier,
		defaultImage:    m.TailscaleImage,
		kataTunResource: m.KataTunResource,
		federated:       true,
		clientID:        clientID,
		audience:        audience,
	})
	if controller.NeedsStateSecret(pod) && !m.stateRBACReady(ctx, req.Namespace, pod, identifier) {
		addGate(mutated)
	}
	return patched(req, mutated)
}

func patched(req admission.Request, mutated *corev1.Pod) admission.Response {
	raw, err := json.Marshal(mutated)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	resp := admission.PatchResponseFromRaw(req.Object.Raw, raw)
	if resp.AuditAnnotations == nil {
		resp.AuditAnnotations = map[string]string{}
	}
	resp.AuditAnnotations["tsinject.dmf.zone/injected"] = "true"
	return resp
}

// needsGate decides whether the pod must wait for the gate controller: the
// bound credential is not Ready for its current spec, its spec is not what
// the pod's annotations demand, or any pod-demanded companion object is
// missing or stale. Lookups that fail gate conservatively — the controller
// converges the same state and lifts the gate.
func (m *PodMutator) needsGate(ctx context.Context, namespace string, pod *corev1.Pod, identifier string, cred *tsv1alpha1.TailscaleCredential) bool {
	if cred == nil || !controller.CredentialReady(cred) {
		return true
	}
	// Only the gate controller syncs a credential to its pods, and only gated
	// pods reach it: admitted ungated, a pod whose tags or tailnet changed
	// starts against the old OAuth client and is refused its tags.
	if !controller.CredentialMatchesPod(pod, cred) {
		return true
	}
	if want, ok := pod.Annotations[tsv1alpha1.ServeConfigAnnotation]; ok {
		if !m.configMapCurrent(ctx, namespace, controller.ServeConfigMapName(identifier), "serve.json", want) {
			return true
		}
	}
	if want, ok := pod.Annotations[tsv1alpha1.ConfigJSONAnnotation]; ok {
		if !m.configMapCurrent(ctx, namespace, controller.JSONConfigMapName(identifier), "config.json", want) {
			return true
		}
	}
	if controller.NeedsStateSecret(pod) && !m.stateRBACReady(ctx, namespace, pod, identifier) {
		return true
	}
	return false
}

func (m *PodMutator) configMapCurrent(ctx context.Context, namespace, name, key, want string) bool {
	cm := &corev1.ConfigMap{}
	if err := m.APIReader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, cm); err != nil {
		return false
	}
	return cm.Data[key] == want
}

func (m *PodMutator) stateRBACReady(ctx context.Context, namespace string, pod *corev1.Pod, identifier string) bool {
	role := &rbacv1.Role{}
	if err := m.APIReader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: controller.StateRoleName(identifier)}, role); err != nil {
		return false
	}
	binding := &rbacv1.RoleBinding{}
	if err := m.APIReader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: controller.StateRoleBindingName(identifier)}, binding); err != nil {
		return false
	}
	for _, subject := range binding.Subjects {
		if subject.Kind == rbacv1.ServiceAccountKind && subject.Name == pod.Spec.ServiceAccountName {
			return true
		}
	}
	return false
}

type mutateInput struct {
	identifier      string
	secretName      string
	defaultImage    string
	kataTunResource corev1.ResourceName

	// federated: join as the federated identity clientID, with a projected
	// token for audience, instead of the OAuth client in secretName.
	federated bool
	clientID  string
	audience  string
}

// mutatePod applies the full injection in place. Pure with respect to the
// cluster (no API access) so tests can assert on the result directly. The
// assembly order — volumes, env layering, container placement — matches the
// pre-operator injector so existing workloads see byte-identical specs.
func mutatePod(pod *corev1.Pod, in mutateInput) {
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[tsv1alpha1.CredentialAnnotation] = in.identifier

	var mount corev1.VolumeMount
	var credEnv []corev1.EnvVar
	if in.federated {
		expiry := idTokenSeconds
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: idTokenVolume,
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{
					ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
						Audience: in.audience, ExpirationSeconds: &expiry, Path: idTokenFile,
					},
				}}},
			},
		})
		mount = corev1.VolumeMount{Name: idTokenVolume, ReadOnly: true, MountPath: idTokenDir}
		clientID := in.clientID
		// A federated client ID registers ephemeral nodes unless told otherwise.
		if eph := controller.EphemeralForPod(pod); eph != nil && !*eph {
			clientID += "?ephemeral=false"
		}
		credEnv = []corev1.EnvVar{
			{Name: "TS_CLIENT_ID", Value: clientID},
			{Name: "TS_ID_TOKEN", Value: "file:" + idTokenDir + "/" + idTokenFile},
		}
	} else {
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: oauthVolume,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: in.secretName},
			},
		})
		mount = corev1.VolumeMount{Name: oauthVolume, ReadOnly: true, MountPath: "/tailscale-secrets"}
		credEnv = []corev1.EnvVar{
			{Name: "TS_CLIENT_ID", Value: "file:/tailscale-secrets/oauth.id"},
			{Name: "TS_CLIENT_SECRET", Value: "file:/tailscale-secrets/oauth.secret"},
		}
	}

	container := tailscaleContainer(pod, in.defaultImage, in.kataTunResource, mount, credEnv)
	applyStateEnv(pod, in.identifier, container)
	container.Env = mergeAnnotationEnv(pod, container.Env)
	// A federated pod has no credential to own ConfigMaps, so its serve and
	// config documents come straight from its annotations (downward API).
	attachServeConfig(pod, in.identifier, container, in.federated)
	attachConfigJSON(pod, in.identifier, container, in.federated)
	attachSharedSocket(pod, container)
	serviceHostProbe(pod, container)
	if advertise := advertiseContainer(pod, container, in.defaultImage); advertise != nil {
		pod.Spec.Containers = append(pod.Spec.Containers, *advertise)
	}
	pod.Spec.Containers = append(pod.Spec.Containers, *container)
}

func addGate(pod *corev1.Pod) {
	for _, gate := range pod.Spec.SchedulingGates {
		if gate.Name == tsv1alpha1.PodGateName {
			return
		}
	}
	pod.Spec.SchedulingGates = append(pod.Spec.SchedulingGates, corev1.PodSchedulingGate{Name: tsv1alpha1.PodGateName})
}

// defaultSidecarResources is what the sidecar gets without the
// ResourcesAnnotation: requests sized to what a tunnel carrying ordinary
// traffic uses, with a ceiling that keeps a busy node's other pods out of
// trouble. Measured over two weeks across several hundred sidecars: median
// 35Mi and p90 90Mi of memory, a few millicores of CPU at p95. Earlier
// defaults of 500m/512Mi reserved about fifty times the CPU and twelve times
// the memory tunnels used, and left nodes' CPU requests near full while they
// sat idle. A pod that moves data raises its own through the
// ResourcesAnnotation.
func defaultSidecarResources() corev1.ResourceRequirements {
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("25m"),
			corev1.ResourceMemory: resource.MustParse("96Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("1"),
			corev1.ResourceMemory: resource.MustParse("1024Mi"),
		},
	}
}

// resolveResources returns the sidecar's resources for a pod: the defaults, or
// the ResourcesAnnotation's document where it carries one. Requests and limits
// are replaced whole, never merged, so the annotation can drop a default as
// well as raise it.
//
// Both maps are always non-nil -- a key the document names decodes to a map,
// and one it leaves out keeps the default -- which matters because a Kata pod
// has its tun device added to the limits afterwards. "limits":{} is how a pod
// asks for no limits at all.
func resolveResources(pod *corev1.Pod) (corev1.ResourceRequirements, error) {
	out := defaultSidecarResources()
	raw, ok := pod.Annotations[tsv1alpha1.ResourcesAnnotation]
	if !ok {
		return out, nil
	}
	var want corev1.ResourceRequirements
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&want); err != nil {
		return out, fmt.Errorf("%s: %w", tsv1alpha1.ResourcesAnnotation, err)
	}
	if want.Requests != nil {
		out.Requests = want.Requests
	}
	if want.Limits != nil {
		out.Limits = want.Limits
	}
	for _, side := range []struct {
		name string
		list corev1.ResourceList
	}{{"requests", out.Requests}, {"limits", out.Limits}} {
		for key, qty := range side.list {
			if qty.Sign() < 0 {
				return out, fmt.Errorf("%s: %s %s is negative", tsv1alpha1.ResourcesAnnotation, side.name, key)
			}
		}
	}
	return out, nil
}

func resolveImage(pod *corev1.Pod, defaultImage string) string {
	if image, ok := pod.Annotations[tsv1alpha1.CustomImageAnnotation]; ok {
		return image
	}
	return defaultImage
}

// usesKataRuntime reports whether the pod runs under a Kata runtime class
// (kata-qemu, kata-fc, ...), where the guest kernel needs a tun device
// handed in by a device plugin.
func usesKataRuntime(pod *corev1.Pod) bool {
	return pod.Spec.RuntimeClassName != nil && strings.HasPrefix(*pod.Spec.RuntimeClassName, "kata")
}

// tailscaleContainer builds the sidecar; mount and credEnv carry its
// credential: the OAuth Secret, or the federated identity and its token.
// A Kata pod's sidecar also requests one kataTun device, when that is set.
func tailscaleContainer(pod *corev1.Pod, defaultImage string, kataTun corev1.ResourceName, mount corev1.VolumeMount, credEnv []corev1.EnvVar) *corev1.Container {
	nonRoot := false
	rootUser := int64(0)
	privileged := pod.Annotations[tsv1alpha1.PrivilegedAnnotation] == "true"
	// An unparseable document is refused at admission (checkAnnotations), so
	// by here the error can only mean "keep the defaults".
	resources, _ := resolveResources(pod)
	container := &corev1.Container{
		SecurityContext: &corev1.SecurityContext{
			Privileged: &privileged,
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"NET_ADMIN"},
			},
			RunAsNonRoot: &nonRoot,
			RunAsGroup:   &rootUser,
			RunAsUser:    &rootUser,
		},
		ImagePullPolicy: corev1.PullAlways,
		Name:            SidecarName,
		Image:           resolveImage(pod, defaultImage),
		VolumeMounts:    []corev1.VolumeMount{mount},
		Resources:       resources,
		Env: append(credEnv, []corev1.EnvVar{
			{
				Name:  "TS_EXTRA_ARGS",
				Value: fmt.Sprintf("--advertise-tags=%s", strings.Join(controller.TagsForPod(pod), ",")),
			},
			{
				Name: "POD_NAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"},
				},
			},
			{
				Name: "POD_UID",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"},
				},
			},
		}...),
	}
	if kataTun != "" && usesKataRuntime(pod) {
		container.Resources.Limits[kataTun] = resource.MustParse("1")
	}
	return container
}

// applyStateEnv wires tailscaled state persistence: a kube Secret for
// non-ephemeral pods running as a dedicated ServiceAccount (the gate
// controller provisions the matching RBAC), in-memory state for ephemeral
// ones, and nothing for non-ephemeral pods on the default ServiceAccount.
func applyStateEnv(pod *corev1.Pod, identifier string, container *corev1.Container) {
	if controller.NeedsStateSecret(pod) {
		container.Env = append(container.Env, corev1.EnvVar{
			Name:  "TS_KUBE_SECRET",
			Value: controller.StateSecretName(identifier),
		})
		return
	}
	if eph := controller.EphemeralForPod(pod); eph != nil && *eph {
		container.Env = append(container.Env,
			corev1.EnvVar{Name: "TS_KUBE_SECRET", Value: ""},
			corev1.EnvVar{Name: "TS_STATE_DIR", Value: "/tmp"},
		)
	}
}

// mergeAnnotationEnv folds the tailscale-env annotation (newline-separated
// NAME=VALUE) into the container env. A name that already exists gets the
// new value appended space-separated (the documented way to extend
// TS_EXTRA_ARGS); the result is name-sorted. ValueFrom entries pass through
// untouched.
func mergeAnnotationEnv(pod *corev1.Pod, baseEnv []corev1.EnvVar) []corev1.EnvVar {
	valueByName := map[string]string{}
	var vars []corev1.EnvVar
	for _, env := range baseEnv {
		if env.ValueFrom != nil {
			vars = append(vars, env)
			continue
		}
		valueByName[env.Name] = env.Value
	}
	if annotation, ok := pod.Annotations[tsv1alpha1.EnvAnnotation]; ok {
		for line := range strings.SplitSeq(annotation, "\n") {
			name, value, found := strings.Cut(strings.TrimSpace(line), "=")
			if !found || name == "" {
				continue
			}
			if existing, ok := valueByName[name]; ok {
				valueByName[name] = existing + " " + value
			} else {
				valueByName[name] = value
			}
		}
	}
	for name, value := range valueByName {
		vars = append(vars, corev1.EnvVar{Name: name, Value: value})
	}
	sort.Slice(vars, func(i, j int) bool { return vars[i].Name < vars[j].Name })
	return vars
}

// annotationFile projects one of the pod's own annotations into a file.
func annotationFile(annotation, path string) corev1.VolumeSource {
	return corev1.VolumeSource{DownwardAPI: &corev1.DownwardAPIVolumeSource{Items: []corev1.DownwardAPIVolumeFile{{
		Path:     path,
		FieldRef: &corev1.ObjectFieldSelector{FieldPath: fmt.Sprintf("metadata.annotations['%s']", annotation)},
	}}}}
}

func attachServeConfig(pod *corev1.Pod, identifier string, container *corev1.Container, fromAnnotation bool) {
	if _, ok := pod.Annotations[tsv1alpha1.ServeConfigAnnotation]; !ok {
		return
	}
	source := corev1.VolumeSource{
		ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{
				Name: controller.ServeConfigMapName(identifier),
			},
		},
	}
	if fromAnnotation {
		source = annotationFile(tsv1alpha1.ServeConfigAnnotation, "serve.json")
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: serveConfigVolume, VolumeSource: source})
	container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
		Name:      serveConfigVolume,
		MountPath: "/ts-serve",
		ReadOnly:  true,
	})
	container.Env = append(container.Env, corev1.EnvVar{
		Name:  "TS_SERVE_CONFIG",
		Value: "/ts-serve/serve.json",
	})
}

func attachConfigJSON(pod *corev1.Pod, identifier string, container *corev1.Container, fromAnnotation bool) {
	if _, ok := pod.Annotations[tsv1alpha1.ConfigJSONAnnotation]; !ok {
		return
	}
	source := corev1.VolumeSource{
		ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{
				Name: controller.JSONConfigMapName(identifier),
			},
		},
	}
	if fromAnnotation {
		source = annotationFile(tsv1alpha1.ConfigJSONAnnotation, "config.json")
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: jsonConfigVolume, VolumeSource: source})
	container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
		Name:      jsonConfigVolume,
		MountPath: "/ts-config",
		ReadOnly:  true,
	})
	container.Env = append(container.Env, corev1.EnvVar{
		Name:  "TS_TAILSCALED_EXTRA_ARGS",
		Value: "--config=/ts-config/config.json",
	})
}

func attachSharedSocket(pod *corev1.Pod, container *corev1.Container) {
	mountName, ok := pod.Annotations[tsv1alpha1.SharedSocketMountAnnotation]
	if !ok {
		return
	}
	container.Env = append(container.Env, corev1.EnvVar{
		Name:  "TS_SOCKET",
		Value: socketPath,
	})
	container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
		Name:      mountName,
		MountPath: "/socket",
	})
}

// advertiseContainer builds the service-advertise helper when the pod asks
// for it. Without a shared socket mount it also wires a fresh emptyDir
// socket volume into the pod and the tailscale container.
func advertiseContainer(pod *corev1.Pod, tailscale *corev1.Container, defaultImage string) *corev1.Container {
	raw, ok := pod.Annotations[tsv1alpha1.AdvertiseServicesAnnotation]
	if !ok {
		return nil
	}
	if pod.Annotations[tsv1alpha1.SkipAdvertiseContainerAnnotation] == "true" {
		return nil
	}
	var services []string
	for service := range strings.SplitSeq(raw, ",") {
		if clean := strings.TrimSpace(service); clean != "" {
			services = append(services, clean)
		}
	}
	if len(services) == 0 {
		return nil
	}

	socketVolumeName := pod.Annotations[tsv1alpha1.SharedSocketMountAnnotation]
	if socketVolumeName == "" {
		socketVolumeName = socketVolume
		sizeLimit := resource.MustParse("1Gi")
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: socketVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &sizeLimit},
			},
		})
		tailscale.Env = append(tailscale.Env, corev1.EnvVar{
			Name:  "TS_SOCKET",
			Value: socketPath,
		})
		tailscale.VolumeMounts = append(tailscale.VolumeMounts, corev1.VolumeMount{
			Name:      socketVolumeName,
			MountPath: "/socket",
		})
	}

	nonRoot := false
	rootUser := int64(0)
	restart := corev1.ContainerRestartPolicyOnFailure
	return &corev1.Container{
		SecurityContext: &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{"NET_ADMIN"},
			},
			RunAsNonRoot: &nonRoot,
			RunAsGroup:   &rootUser,
			RunAsUser:    &rootUser,
		},
		RestartPolicy:   &restart,
		ImagePullPolicy: corev1.PullAlways,
		Name:            AdvertiseContainerName,
		Image:           resolveImage(pod, defaultImage),
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("125m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("125m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
		},
		Command: []string{"sh", "-c", advertiseScript},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      socketVolumeName,
				MountPath: "/socket",
			},
		},
		Env: []corev1.EnvVar{
			{
				Name:  "SERVICES",
				Value: strings.Join(services, " "),
			},
			{
				Name:  "TS_SOCKET",
				Value: socketPath,
			},
		},
	}
}
