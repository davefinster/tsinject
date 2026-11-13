package webhook

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	tsv1alpha1 "github.com/davefinster/tsinject/api/v1alpha1"
	"github.com/davefinster/tsinject/internal/controller"
)

const testImage = "ghcr.io/tailscale/tailscale:latest"

// testTunResource stands in for whatever a cluster's device plugin
// advertises /dev/net/tun as.
const testTunResource corev1.ResourceName = "example.com/tun"

func webhookScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := tsv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func newMutator(t *testing.T, objs ...client.Object) *PodMutator {
	t.Helper()
	s := webhookScheme(t)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
	// The mutator only checks names against the registry, never calls the
	// API — nil clients suffice.
	tailnets, err := controller.NewTailnetRegistry("default", map[string]controller.TailscaleAPI{
		"default": nil,
		"global":  nil,
	}, map[string]bool{"fed": true})
	if err != nil {
		t.Fatal(err)
	}
	return &PodMutator{
		Client:         c,
		APIReader:      c,
		Decoder:        admission.NewDecoder(s),
		TailscaleImage: testImage,
		Tailnets:       tailnets,
	}
}

func TestUnknownTailnetAnnotationDenied(t *testing.T) {
	m := newMutator(t)
	resp := m.Handle(context.Background(), podRequest(t, "team-a", basicPod(map[string]string{
		tsv1alpha1.TailnetAnnotation: "typo",
	})))
	if resp.Allowed {
		t.Fatal("a pod naming an unconfigured tailnet must be denied at admission")
	}
	if !strings.Contains(resp.Result.Message, "typo") || !strings.Contains(resp.Result.Message, "global") {
		t.Errorf("denial should name the offender and the configured tailnets: %q", resp.Result.Message)
	}

	resp = m.Handle(context.Background(), podRequest(t, "team-a", basicPod(map[string]string{
		tsv1alpha1.TailnetAnnotation: "global",
	})))
	if !resp.Allowed {
		t.Errorf("a configured tailnet must admit: %v", resp.Result)
	}
}

func readyCredential(ns, name string) *tsv1alpha1.TailscaleCredential {
	cred := &tsv1alpha1.TailscaleCredential{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
	}
	meta.SetStatusCondition(&cred.Status.Conditions, metav1.Condition{
		Type: tsv1alpha1.ReadyCondition, Status: metav1.ConditionTrue, Reason: "Provisioned",
	})
	return cred
}

func podRequest(t *testing.T, ns string, pod *corev1.Pod) admission.Request {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Namespace: ns,
		Operation: admissionv1.Create,
		Object:    runtime.RawExtension{Raw: raw},
	}}
}

func basicPod(annotations map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "app",
			Labels:      map[string]string{tsv1alpha1.InjectLabel: tsv1alpha1.InjectLabelValue},
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "alpine"}},
		},
	}
}

// mutatedFromResponse applies the response's actual RFC 6902 patches to the
// original object — asserting on what the API server would really persist.
func mutatedFromResponse(t *testing.T, req admission.Request, resp admission.Response) *corev1.Pod {
	t.Helper()
	if !resp.Allowed {
		t.Fatalf("expected allowed, got denied: %+v", resp.Result)
	}
	patchJSON, err := json.Marshal(resp.Patches)
	if err != nil {
		t.Fatal(err)
	}
	patch, err := jsonpatch.DecodePatch(patchJSON)
	if err != nil {
		t.Fatal(err)
	}
	patched, err := patch.Apply(req.Object.Raw)
	if err != nil {
		t.Fatal(err)
	}
	out := &corev1.Pod{}
	if err := json.Unmarshal(patched, out); err != nil {
		t.Fatal(err)
	}
	return out
}

func findContainer(pod *corev1.Pod, name string) *corev1.Container {
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == name {
			return &pod.Spec.Containers[i]
		}
	}
	return nil
}

func envValue(c *corev1.Container, name string) (string, bool) {
	for _, env := range c.Env {
		if env.Name == name {
			return env.Value, true
		}
	}
	return "", false
}

func findVolume(pod *corev1.Pod, name string) *corev1.Volume {
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == name {
			return &pod.Spec.Volumes[i]
		}
	}
	return nil
}

func TestInjectsAndGatesWhenCredentialMissing(t *testing.T) {
	m := newMutator(t)
	req := podRequest(t, "team-a", basicPod(map[string]string{tsv1alpha1.TagsAnnotation: "web"}))
	pod := mutatedFromResponse(t, req, m.Handle(context.Background(), req))

	ts := findContainer(pod, SidecarName)
	if ts == nil {
		t.Fatalf("tailscale container not injected: %+v", pod.Spec.Containers)
	}
	if ts.Image != testImage {
		t.Errorf("image = %q", ts.Image)
	}
	if got, _ := envValue(ts, "TS_EXTRA_ARGS"); got != "--advertise-tags=tag:injected,tag:web" {
		t.Errorf("TS_EXTRA_ARGS = %q", got)
	}
	if got, _ := envValue(ts, "TS_CLIENT_SECRET"); got != "file:/tailscale-secrets/oauth.secret" {
		t.Errorf("TS_CLIENT_SECRET = %q", got)
	}
	hasPodName := false
	for _, env := range ts.Env {
		if env.Name == "POD_NAME" && env.ValueFrom != nil && env.ValueFrom.FieldRef != nil {
			hasPodName = true
		}
	}
	if !hasPodName {
		t.Error("POD_NAME fieldRef env must survive the env merge")
	}
	oauth := findVolume(pod, oauthVolume)
	if oauth == nil || oauth.Secret == nil || oauth.Secret.SecretName != "app-ts-credential" {
		t.Errorf("oauth volume = %+v", oauth)
	}
	if pod.Annotations[tsv1alpha1.CredentialAnnotation] != "app" {
		t.Errorf("credential annotation = %q", pod.Annotations[tsv1alpha1.CredentialAnnotation])
	}
	if len(pod.Spec.SchedulingGates) != 1 || pod.Spec.SchedulingGates[0].Name != tsv1alpha1.PodGateName {
		t.Errorf("pod must be gated while the credential does not exist: %+v", pod.Spec.SchedulingGates)
	}
}

func TestNoGateWhenCredentialReady(t *testing.T) {
	m := newMutator(t, readyCredential("team-a", "app"))
	req := podRequest(t, "team-a", basicPod(nil))
	pod := mutatedFromResponse(t, req, m.Handle(context.Background(), req))

	if len(pod.Spec.SchedulingGates) != 0 {
		t.Errorf("ready credential must not gate scheduling: %+v", pod.Spec.SchedulingGates)
	}
	if findContainer(pod, SidecarName) == nil {
		t.Error("tailscale container must still be injected")
	}
}

func TestGatesWhenCredentialDriftsFromPod(t *testing.T) {
	// A workload changed its annotations while its credential stayed Ready
	// for the old ones. Admitted ungated, the sidecar asks the old OAuth
	// client for tags it does not hold and is refused, and the gate
	// controller, which only sees gated pods, never syncs the credential.
	cred := readyCredential("team-a", "app")
	cred.Spec.Tags = []string{"tag:infrastructure"}

	for name, annotations := range map[string]map[string]string{
		"tags":      {tsv1alpha1.TagsAnnotation: "flyconnector"},
		"tailnet":   {tsv1alpha1.TagsAnnotation: "infrastructure", tsv1alpha1.TailnetAnnotation: "global"},
		"ephemeral": {tsv1alpha1.TagsAnnotation: "infrastructure", tsv1alpha1.EphemeralAnnotation: "true"},
	} {
		t.Run(name, func(t *testing.T) {
			m := newMutator(t, cred.DeepCopy())
			req := podRequest(t, "team-a", basicPod(annotations))
			pod := mutatedFromResponse(t, req, m.Handle(context.Background(), req))
			if len(pod.Spec.SchedulingGates) != 1 || pod.Spec.SchedulingGates[0].Name != tsv1alpha1.PodGateName {
				t.Errorf("pod must be gated while the credential's spec differs from its annotations: %+v", pod.Spec.SchedulingGates)
			}
		})
	}

	m := newMutator(t, cred.DeepCopy())
	req := podRequest(t, "team-a", basicPod(map[string]string{tsv1alpha1.TagsAnnotation: "infrastructure"}))
	pod := mutatedFromResponse(t, req, m.Handle(context.Background(), req))
	if len(pod.Spec.SchedulingGates) != 0 {
		t.Errorf("a pod matching its Ready credential must not be gated: %+v", pod.Spec.SchedulingGates)
	}
}

func TestGatesOnReadyFromEarlierGeneration(t *testing.T) {
	// The spec was just updated and the credential controller has not caught
	// up: Ready=True describes the previous generation's OAuth client.
	cred := readyCredential("team-a", "app")
	cred.Generation = 2
	cred.Status.Conditions[0].ObservedGeneration = 1
	m := newMutator(t, cred)
	req := podRequest(t, "team-a", basicPod(nil))
	pod := mutatedFromResponse(t, req, m.Handle(context.Background(), req))

	if len(pod.Spec.SchedulingGates) != 1 {
		t.Errorf("Ready from an earlier generation must gate: %+v", pod.Spec.SchedulingGates)
	}
}

func TestMountsCustomSecretName(t *testing.T) {
	cred := readyCredential("team-a", "app")
	cred.Spec.SecretName = "custom-oauth"
	m := newMutator(t, cred)
	req := podRequest(t, "team-a", basicPod(nil))
	pod := mutatedFromResponse(t, req, m.Handle(context.Background(), req))

	oauth := findVolume(pod, oauthVolume)
	if oauth == nil || oauth.Secret == nil || oauth.Secret.SecretName != "custom-oauth" {
		t.Errorf("oauth volume must mount spec.secretName: %+v", oauth)
	}
}

func TestSharedNameGroupsPods(t *testing.T) {
	m := newMutator(t)
	req := podRequest(t, "team-a", basicPod(map[string]string{tsv1alpha1.SharedNameAnnotation: "shared"}))
	pod := mutatedFromResponse(t, req, m.Handle(context.Background(), req))

	if pod.Annotations[tsv1alpha1.CredentialAnnotation] != "shared" {
		t.Errorf("credential annotation = %q, want shared", pod.Annotations[tsv1alpha1.CredentialAnnotation])
	}
	if oauth := findVolume(pod, oauthVolume); oauth.Secret.SecretName != "shared-ts-credential" {
		t.Errorf("secret name = %q", oauth.Secret.SecretName)
	}
}

func TestEnvAnnotationMergesAndAppends(t *testing.T) {
	m := newMutator(t)
	req := podRequest(t, "team-a", basicPod(map[string]string{
		tsv1alpha1.EnvAnnotation: "TS_EXTRA_ARGS=--hostname=web\nCUSTOM=1",
	}))
	pod := mutatedFromResponse(t, req, m.Handle(context.Background(), req))
	ts := findContainer(pod, SidecarName)

	if got, _ := envValue(ts, "TS_EXTRA_ARGS"); got != "--advertise-tags=tag:injected --hostname=web" {
		t.Errorf("TS_EXTRA_ARGS = %q, want the annotation value appended", got)
	}
	if got, _ := envValue(ts, "CUSTOM"); got != "1" {
		t.Errorf("CUSTOM = %q", got)
	}
}

func TestEphemeralStateEnv(t *testing.T) {
	m := newMutator(t)
	req := podRequest(t, "team-a", basicPod(map[string]string{tsv1alpha1.EphemeralAnnotation: "true"}))
	pod := mutatedFromResponse(t, req, m.Handle(context.Background(), req))
	ts := findContainer(pod, SidecarName)

	if got, ok := envValue(ts, "TS_KUBE_SECRET"); !ok || got != "" {
		t.Errorf("TS_KUBE_SECRET = %q,%v — want present and empty", got, ok)
	}
	if got, _ := envValue(ts, "TS_STATE_DIR"); got != "/tmp" {
		t.Errorf("TS_STATE_DIR = %q", got)
	}
}

func TestStateSecretEnvAndRBACGate(t *testing.T) {
	base := func() *corev1.Pod {
		pod := basicPod(nil)
		pod.Spec.ServiceAccountName = "app-sa"
		return pod
	}

	// Ready credential but no RBAC yet: env is wired, pod is gated.
	m := newMutator(t, readyCredential("team-a", "app"))
	req := podRequest(t, "team-a", base())
	pod := mutatedFromResponse(t, req, m.Handle(context.Background(), req))
	ts := findContainer(pod, SidecarName)
	if got, _ := envValue(ts, "TS_KUBE_SECRET"); got != "app-state-secret" {
		t.Errorf("TS_KUBE_SECRET = %q", got)
	}
	if len(pod.Spec.SchedulingGates) != 1 {
		t.Errorf("missing state RBAC must gate the pod: %+v", pod.Spec.SchedulingGates)
	}

	// With Role and RoleBinding in place: no gate.
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: controller.StateRoleName("app")}}
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: controller.StateRoleBindingName("app")},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "app-sa", Namespace: "team-a"}},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: controller.StateRoleName("app")},
	}
	m = newMutator(t, readyCredential("team-a", "app"), role, binding)
	req = podRequest(t, "team-a", base())
	pod = mutatedFromResponse(t, req, m.Handle(context.Background(), req))
	if len(pod.Spec.SchedulingGates) != 0 {
		t.Errorf("state RBAC in place must not gate: %+v", pod.Spec.SchedulingGates)
	}
}

func TestServeConfigMountAndGate(t *testing.T) {
	serveJSON := `{"TCP":{}}`
	annotations := map[string]string{tsv1alpha1.ServeConfigAnnotation: serveJSON}

	// Ready credential but no ConfigMap yet: mounts wired, pod gated.
	m := newMutator(t, readyCredential("team-a", "app"))
	req := podRequest(t, "team-a", basicPod(annotations))
	pod := mutatedFromResponse(t, req, m.Handle(context.Background(), req))
	ts := findContainer(pod, SidecarName)
	if got, _ := envValue(ts, "TS_SERVE_CONFIG"); got != "/ts-serve/serve.json" {
		t.Errorf("TS_SERVE_CONFIG = %q", got)
	}
	vol := findVolume(pod, serveConfigVolume)
	if vol == nil || vol.ConfigMap == nil || vol.ConfigMap.Name != "app-serve-config" {
		t.Errorf("serve-config volume = %+v", vol)
	}
	if len(pod.Spec.SchedulingGates) != 1 {
		t.Error("missing serve ConfigMap must gate the pod")
	}

	// Matching ConfigMap: no gate. Stale content: gated again.
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "app-serve-config"},
		Data:       map[string]string{"serve.json": serveJSON},
	}
	m = newMutator(t, readyCredential("team-a", "app"), cm)
	pod = mutatedFromResponse(t, req, m.Handle(context.Background(), req))
	if len(pod.Spec.SchedulingGates) != 0 {
		t.Error("current serve ConfigMap must not gate")
	}

	stale := podRequest(t, "team-a", basicPod(map[string]string{tsv1alpha1.ServeConfigAnnotation: `{"TCP":{"443":{}}}`}))
	pod = mutatedFromResponse(t, stale, m.Handle(context.Background(), stale))
	if len(pod.Spec.SchedulingGates) != 1 {
		t.Error("stale serve ConfigMap must gate until the controller updates it")
	}
}

func TestAdvertiseContainer(t *testing.T) {
	m := newMutator(t)
	req := podRequest(t, "team-a", basicPod(map[string]string{
		tsv1alpha1.AdvertiseServicesAnnotation: "svc-a, svc-b",
	}))
	pod := mutatedFromResponse(t, req, m.Handle(context.Background(), req))

	adv := findContainer(pod, AdvertiseContainerName)
	if adv == nil {
		t.Fatalf("advertise container not injected: %+v", pod.Spec.Containers)
	}
	if got, _ := envValue(adv, "SERVICES"); got != "svc-a svc-b" {
		t.Errorf("SERVICES = %q", got)
	}
	if vol := findVolume(pod, socketVolume); vol == nil || vol.EmptyDir == nil {
		t.Errorf("socket emptyDir volume missing: %+v", pod.Spec.Volumes)
	}
	ts := findContainer(pod, SidecarName)
	if got, _ := envValue(ts, "TS_SOCKET"); got != socketPath {
		t.Errorf("tailscale TS_SOCKET = %q", got)
	}
	// The advertise container must come before the tailscale container
	// (matching the pre-operator injector's append order).
	names := []string{}
	for _, c := range pod.Spec.Containers {
		names = append(names, c.Name)
	}
	want := []string{"app", AdvertiseContainerName, SidecarName}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("container order = %v, want %v", names, want)
	}
}

func TestAdvertiseSkipAndSharedSocket(t *testing.T) {
	m := newMutator(t)
	req := podRequest(t, "team-a", basicPod(map[string]string{
		tsv1alpha1.AdvertiseServicesAnnotation:      "svc-a",
		tsv1alpha1.SkipAdvertiseContainerAnnotation: "true",
	}))
	pod := mutatedFromResponse(t, req, m.Handle(context.Background(), req))
	if findContainer(pod, AdvertiseContainerName) != nil {
		t.Error("skip annotation must suppress the advertise container")
	}
	if findVolume(pod, socketVolume) != nil {
		t.Error("no socket volume without the advertise container")
	}

	req = podRequest(t, "team-a", basicPod(map[string]string{
		tsv1alpha1.AdvertiseServicesAnnotation: "svc-a",
		tsv1alpha1.SharedSocketMountAnnotation: "my-socket",
	}))
	pod = mutatedFromResponse(t, req, m.Handle(context.Background(), req))
	if findVolume(pod, socketVolume) != nil {
		t.Error("shared socket mount must suppress the injected emptyDir")
	}
	adv := findContainer(pod, AdvertiseContainerName)
	if adv == nil || adv.VolumeMounts[0].Name != "my-socket" {
		t.Errorf("advertise container must mount the shared socket volume: %+v", adv)
	}
	ts := findContainer(pod, SidecarName)
	mountsShared := false
	for _, vm := range ts.VolumeMounts {
		if vm.Name == "my-socket" && vm.MountPath == "/socket" {
			mountsShared = true
		}
	}
	if !mountsShared {
		t.Errorf("tailscale container must mount the shared socket volume: %+v", ts.VolumeMounts)
	}
}

func TestCustomImageAndPrivileged(t *testing.T) {
	m := newMutator(t)
	req := podRequest(t, "team-a", basicPod(map[string]string{
		tsv1alpha1.CustomImageAnnotation: "example.com/custom-ts:v1",
		tsv1alpha1.PrivilegedAnnotation:  "true",
	}))
	pod := mutatedFromResponse(t, req, m.Handle(context.Background(), req))
	ts := findContainer(pod, SidecarName)
	if ts.Image != "example.com/custom-ts:v1" {
		t.Errorf("image = %q", ts.Image)
	}
	if ts.SecurityContext.Privileged == nil || !*ts.SecurityContext.Privileged {
		t.Error("privileged annotation must be honored")
	}
}

func TestKataRuntimeGetsTunDevice(t *testing.T) {
	for _, rc := range []string{"kata-qemu", "kata-fc"} {
		m := newMutator(t)
		m.KataTunResource = testTunResource
		src := basicPod(nil)
		src.Spec.RuntimeClassName = &rc
		req := podRequest(t, "team-a", src)
		pod := mutatedFromResponse(t, req, m.Handle(context.Background(), req))
		ts := findContainer(pod, SidecarName)
		if qty, ok := ts.Resources.Limits[testTunResource]; !ok || qty.Value() != 1 {
			t.Errorf("%s: sidecar must request one %s device, limits = %+v", rc, testTunResource, ts.Resources.Limits)
		}
	}

	// No runtime class → no device request.
	m := newMutator(t)
	m.KataTunResource = testTunResource
	req := podRequest(t, "team-a", basicPod(nil))
	pod := mutatedFromResponse(t, req, m.Handle(context.Background(), req))
	ts := findContainer(pod, SidecarName)
	if _, ok := ts.Resources.Limits[testTunResource]; ok {
		t.Errorf("non-kata pod must not request %s", testTunResource)
	}
}

// With no resource configured, a Kata pod's sidecar requests no device: not
// every cluster runs a device plugin for /dev/net/tun, and a request no node
// advertises would leave the pod Pending.
func TestKataTunDeviceIsOptIn(t *testing.T) {
	rc := "kata-qemu"
	m := newMutator(t)
	src := basicPod(nil)
	src.Spec.RuntimeClassName = &rc
	req := podRequest(t, "team-a", src)
	ts := findContainer(mutatedFromResponse(t, req, m.Handle(context.Background(), req)), SidecarName)
	if want := defaultSidecarResources().Limits; len(ts.Resources.Limits) != len(want) {
		t.Errorf("limits = %+v; want only the defaults %+v", ts.Resources.Limits, want)
	}
}

func TestIdempotentOnReinvocation(t *testing.T) {
	m := newMutator(t)
	pod := basicPod(nil)
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: SidecarName, Image: testImage})
	resp := m.Handle(context.Background(), podRequest(t, "team-a", pod))
	if !resp.Allowed {
		t.Fatalf("expected allowed: %+v", resp.Result)
	}
	if len(resp.Patches) != 0 {
		t.Errorf("reinvocation must not re-mutate: %+v", resp.Patches)
	}
}

func TestSidecarResourcesDefaultAndOverride(t *testing.T) {
	// Default: the tunnel gets a ceiling that keeps a busy node's other pods
	// out of trouble.
	m := newMutator(t)
	req := podRequest(t, "team-a", basicPod(nil))
	ts := findContainer(mutatedFromResponse(t, req, m.Handle(context.Background(), req)), SidecarName)
	if cpu := ts.Resources.Limits.Cpu(); cpu.String() != "1" {
		t.Errorf("default CPU limit = %s; want 1", cpu)
	}
	if cpu := ts.Resources.Requests.Cpu(); cpu.String() != "25m" {
		t.Errorf("default CPU request = %s; want 25m", cpu)
	}
	if mem := ts.Resources.Requests.Memory(); mem.String() != "96Mi" {
		t.Errorf("default memory request = %s; want 96Mi", mem)
	}
	if mem := ts.Resources.Limits.Memory(); mem.String() != "1Gi" {
		t.Errorf("default memory limit = %s; want 1Gi", mem)
	}

	// Override: a pod moving data at line rate drops the CPU ceiling, because
	// the tunnel's encryption is this container's CPU. Memory stays capped,
	// and requests are left at the default by naming only limits.
	m = newMutator(t)
	src := basicPod(map[string]string{
		tsv1alpha1.ResourcesAnnotation: `{"limits":{"memory":"2Gi"}}`,
	})
	req = podRequest(t, "team-a", src)
	ts = findContainer(mutatedFromResponse(t, req, m.Handle(context.Background(), req)), SidecarName)
	if _, ok := ts.Resources.Limits[corev1.ResourceCPU]; ok {
		t.Errorf("limits = %+v; naming only memory must leave the CPU uncapped", ts.Resources.Limits)
	}
	if mem := ts.Resources.Limits.Memory(); mem.String() != "2Gi" {
		t.Errorf("memory limit = %s; want 2Gi", mem)
	}
	if cpu := ts.Resources.Requests.Cpu(); cpu.String() != "25m" {
		t.Errorf("CPU request = %s; a document naming only limits leaves requests alone", cpu)
	}

	// Both sides named: each replaces its default whole.
	m = newMutator(t)
	src = basicPod(map[string]string{
		tsv1alpha1.ResourcesAnnotation: `{"requests":{"cpu":"1","memory":"256Mi"},"limits":{"cpu":"4","memory":"2Gi"}}`,
	})
	req = podRequest(t, "team-a", src)
	ts = findContainer(mutatedFromResponse(t, req, m.Handle(context.Background(), req)), SidecarName)
	if cpu := ts.Resources.Limits.Cpu(); cpu.String() != "4" {
		t.Errorf("CPU limit = %s; want 4", cpu)
	}
	if mem := ts.Resources.Requests.Memory(); mem.String() != "256Mi" {
		t.Errorf("memory request = %s; want 256Mi", mem)
	}
}

func TestSidecarResourcesRefusesNonsense(t *testing.T) {
	// Ignored, a mistake here would only surface as a throughput ceiling
	// months later, so the pod is refused instead.
	for name, value := range map[string]string{
		"not json":      `cpu=2`,
		"bad quantity":  `{"limits":{"cpu":"two"}}`,
		"unknown field": `{"limit":{"cpu":"2"}}`,
		"negative":      `{"limits":{"cpu":"-1"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			m := newMutator(t)
			req := podRequest(t, "team-a", basicPod(map[string]string{
				tsv1alpha1.ResourcesAnnotation: value,
			}))
			resp := m.Handle(context.Background(), req)
			if resp.Allowed {
				t.Fatalf("%q was admitted; want it refused", value)
			}
			if msg := resp.Result.Message; !strings.Contains(msg, tsv1alpha1.ResourcesAnnotation) {
				t.Errorf("message = %q; want it to name the annotation", msg)
			}
		})
	}
}

func TestKataTunDeviceSurvivesAResourcesOverride(t *testing.T) {
	// The device goes into limits, which the annotation may have replaced.
	rc := "kata-fc"
	m := newMutator(t)
	m.KataTunResource = testTunResource
	src := basicPod(map[string]string{
		tsv1alpha1.ResourcesAnnotation: `{"limits":{"memory":"2Gi"}}`,
	})
	src.Spec.RuntimeClassName = &rc
	req := podRequest(t, "team-a", src)
	ts := findContainer(mutatedFromResponse(t, req, m.Handle(context.Background(), req)), SidecarName)
	if qty, ok := ts.Resources.Limits[testTunResource]; !ok || qty.Value() != 1 {
		t.Errorf("limits = %+v; want the tun device alongside the override", ts.Resources.Limits)
	}
}

// fedPod is a pod of the federated test tailnet naming its identity.
func fedPod(extra map[string]string) *corev1.Pod {
	annotations := map[string]string{
		tsv1alpha1.TailnetAnnotation:  "fed",
		tsv1alpha1.TagsAnnotation:     "web",
		tsv1alpha1.ClientIDAnnotation: "TFED-kAbc123CNTRL",
		tsv1alpha1.AudienceAnnotation: "api.tailscale.com/TFED-kAbc123CNTRL",
	}
	for k, v := range extra {
		annotations[k] = v
	}
	return basicPod(annotations)
}

// A pod of a federated tailnet joins as its identity with a projected token
// of its own: no OAuth Secret, no TailscaleCredential to wait for, no gate,
// and its serve config straight from its annotation.
func TestFederatedPodJoinsWithItsOwnToken(t *testing.T) {
	m := newMutator(t) // no TailscaleCredential exists, and none is needed
	serveJSON := `{"TCP":{"443":{"HTTPS":true}}}`
	req := podRequest(t, "team-a", fedPod(map[string]string{tsv1alpha1.ServeConfigAnnotation: serveJSON}))
	pod := mutatedFromResponse(t, req, m.Handle(context.Background(), req))

	if len(pod.Spec.SchedulingGates) != 0 {
		t.Errorf("a federated pod has nothing to wait for: %+v", pod.Spec.SchedulingGates)
	}
	ts := findContainer(pod, SidecarName)
	if ts == nil {
		t.Fatal("tailscale container not injected")
	}
	if got, _ := envValue(ts, "TS_CLIENT_ID"); got != "TFED-kAbc123CNTRL" {
		t.Errorf("TS_CLIENT_ID = %q (ephemeral is the federated default; no attribute)", got)
	}
	if got, _ := envValue(ts, "TS_ID_TOKEN"); got != "file:/var/run/secrets/tailscale/token" {
		t.Errorf("TS_ID_TOKEN = %q", got)
	}
	if _, ok := envValue(ts, "TS_CLIENT_SECRET"); ok {
		t.Error("a federated pod carries no client secret")
	}
	if got, _ := envValue(ts, "TS_EXTRA_ARGS"); got != "--advertise-tags=tag:injected,tag:web" {
		t.Errorf("TS_EXTRA_ARGS = %q", got)
	}
	if findVolume(pod, oauthVolume) != nil {
		t.Error("no OAuth Secret volume for a federated pod")
	}
	tok := findVolume(pod, idTokenVolume)
	if tok == nil || tok.Projected == nil || len(tok.Projected.Sources) != 1 || tok.Projected.Sources[0].ServiceAccountToken == nil {
		t.Fatalf("token volume = %+v", tok)
	}
	sat := tok.Projected.Sources[0].ServiceAccountToken
	if sat.Audience != "api.tailscale.com/TFED-kAbc123CNTRL" || sat.Path != "token" || sat.ExpirationSeconds == nil || *sat.ExpirationSeconds != 3600 {
		t.Errorf("token projection = %+v", sat)
	}
	mounted := false
	for _, vm := range ts.VolumeMounts {
		if vm.Name == idTokenVolume && vm.MountPath == "/var/run/secrets/tailscale" && vm.ReadOnly {
			mounted = true
		}
	}
	if !mounted {
		t.Errorf("token not mounted read-only at /var/run/secrets/tailscale: %+v", ts.VolumeMounts)
	}
	serve := findVolume(pod, serveConfigVolume)
	if serve == nil || serve.DownwardAPI == nil || serve.ConfigMap != nil || len(serve.DownwardAPI.Items) != 1 ||
		serve.DownwardAPI.Items[0].Path != "serve.json" ||
		serve.DownwardAPI.Items[0].FieldRef.FieldPath != "metadata.annotations['tailscale-serve-config']" {
		t.Errorf("serve config should come from the annotation: %+v", serve)
	}
	if got, _ := envValue(ts, "TS_SERVE_CONFIG"); got != "/ts-serve/serve.json" {
		t.Errorf("TS_SERVE_CONFIG = %q", got)
	}
}

// A persistent federated pod asks for a persistent node, keeps its state in
// a Secret, and waits only for that Secret's RBAC.
func TestFederatedPersistentPod(t *testing.T) {
	base := func() *corev1.Pod {
		pod := fedPod(map[string]string{tsv1alpha1.EphemeralAnnotation: "false"})
		pod.Spec.ServiceAccountName = "app-sa"
		return pod
	}
	m := newMutator(t)
	req := podRequest(t, "team-a", base())
	pod := mutatedFromResponse(t, req, m.Handle(context.Background(), req))
	ts := findContainer(pod, SidecarName)
	if got, _ := envValue(ts, "TS_CLIENT_ID"); got != "TFED-kAbc123CNTRL?ephemeral=false" {
		t.Errorf("TS_CLIENT_ID = %q", got)
	}
	if got, _ := envValue(ts, "TS_KUBE_SECRET"); got != "app-state-secret" {
		t.Errorf("TS_KUBE_SECRET = %q", got)
	}
	if len(pod.Spec.SchedulingGates) != 1 {
		t.Errorf("missing state RBAC must gate a persistent federated pod: %+v", pod.Spec.SchedulingGates)
	}

	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: controller.StateRoleName("app")}}
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: controller.StateRoleBindingName("app")},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "app-sa", Namespace: "team-a"}},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: controller.StateRoleName("app")},
	}
	m = newMutator(t, role, binding)
	req = podRequest(t, "team-a", base())
	pod = mutatedFromResponse(t, req, m.Handle(context.Background(), req))
	if len(pod.Spec.SchedulingGates) != 0 {
		t.Errorf("state RBAC in place must not gate: %+v", pod.Spec.SchedulingGates)
	}
}

// A federated pod must name its identity; there is nothing to fall back to.
func TestFederatedPodNeedsItsIdentity(t *testing.T) {
	m := newMutator(t)
	for name, pod := range map[string]*corev1.Pod{
		"no client id": fedPod(map[string]string{tsv1alpha1.ClientIDAnnotation: ""}),
		"no audience":  fedPod(map[string]string{tsv1alpha1.AudienceAnnotation: ""}),
		"attributes":   fedPod(map[string]string{tsv1alpha1.ClientIDAnnotation: "TFED-kAbc123CNTRL?ephemeral=false"}),
	} {
		resp := m.Handle(context.Background(), podRequest(t, "team-a", pod))
		if resp.Allowed {
			t.Errorf("%s: admitted", name)
			continue
		}
		if !strings.Contains(resp.Result.Message, "tailscale-client-id") {
			t.Errorf("%s: the denial should name the annotation: %q", name, resp.Result.Message)
		}
	}
	// The OAuth tailnets are untouched: a pod without the annotations is admitted there.
	if resp := m.Handle(context.Background(), podRequest(t, "team-a", basicPod(nil))); !resp.Allowed {
		t.Errorf("an oauth tailnet's pod was refused: %v", resp.Result)
	}
}

// A pod that advertises Tailscale Services gets the service-host liveness probe on its sidecar; one that advertises
// nothing, or opts out, does not.
func TestServiceHostProbe(t *testing.T) {
	m := newMutator(t, readyCredential("team-a", "app"))
	sidecar := func(annotations map[string]string) *corev1.Container {
		req := podRequest(t, "team-a", basicPod(annotations))
		return findContainer(mutatedFromResponse(t, req, m.Handle(context.Background(), req)), SidecarName)
	}
	serve := `{"Services":{"svc:app":{"TCP":{"443":{"TCPForward":"127.0.0.1:8443"}}}}}`
	ts := sidecar(map[string]string{tsv1alpha1.ServeConfigAnnotation: serve})
	if ts.LivenessProbe == nil || ts.LivenessProbe.Exec == nil || ts.LivenessProbe.FailureThreshold != 6 || ts.LivenessProbe.PeriodSeconds != 30 {
		t.Fatalf("serve config: probe %+v", ts.LivenessProbe)
	}
	ts = sidecar(map[string]string{tsv1alpha1.AdvertiseServicesAnnotation: "svc:app,svc:other", tsv1alpha1.SkipAdvertiseContainerAnnotation: "true"})
	if ts.LivenessProbe == nil {
		t.Error("advertise annotation: no probe")
	}
	if got, _ := envValue(ts, "TSINJECT_ADVERTISE_SERVICES"); got != "svc:app,svc:other" {
		t.Errorf("TSINJECT_ADVERTISE_SERVICES = %q", got)
	}
	if ts := sidecar(map[string]string{tsv1alpha1.ServeConfigAnnotation: serve, tsv1alpha1.ServiceHostProbeAnnotation: "false"}); ts.LivenessProbe != nil {
		t.Error("opted out, still probed")
	}
	if ts := sidecar(nil); ts.LivenessProbe != nil {
		t.Error("a pod advertising nothing got the probe")
	}
}

// The probe script itself, against a stub tailscale CLI: it fails only while the node is Running and a Service it
// advertises is missing from its service-host capability.
func TestServiceHostProbeScript(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	serve := filepath.Join(dir, "serve.json")
	os.WriteFile(serve, []byte(`{"Services":{"svc:app":{"TCP":{"443":{}},"Web":{"svc:app:443":{}}}}}`), 0o644)
	status := filepath.Join(dir, "status.json")
	os.WriteFile(filepath.Join(dir, "tailscale"), []byte("#!/bin/sh\n[ -f "+filepath.Join(dir, "down")+" ] && exit 1\ncat "+status+"\n"), 0o755)
	host := `{
  "BackendState": "Running",
  "Self": {
    "AllowedIPs": [
      "100.69.0.2/32",
      "100.64.0.1/32"
    ],
    "CapMap": {
      "service-host": [
        {
          "svc:app": [
            "100.64.0.1"
          ]
        }
      ],
      "services/app": [
        {
          "Name": "svc:app"
        }
      ]
    }
  }
}`
	notHost := strings.Replace(host, `"svc:app": [`, `"svc:else": [`, 1)
	run := func(statusJSON string, env ...string) (int, string) {
		os.WriteFile(status, []byte(statusJSON), 0o644)
		cmd := exec.Command("sh", "-c", serviceHostProbeScript)
		cmd.Env = append([]string{"PATH=" + dir + ":/usr/bin:/bin", "TS_SERVE_CONFIG=" + serve}, env...)
		out, _ := cmd.CombinedOutput()
		return cmd.ProcessState.ExitCode(), string(out)
	}
	if code, out := run(host); code != 0 {
		t.Errorf("the host: exit %d %s", code, out)
	}
	if code, out := run(notHost); code != 1 || !strings.Contains(out, "svc:app") {
		t.Errorf("advertising but not the host: exit %d %s", code, out)
	}
	// The host, but its address is not routed to it: the VIP missing from its own AllowedIPs.
	unrouted := strings.Replace(host, `"100.64.0.1/32"`, `"100.69.0.3/32"`, 1)
	if code, out := run(unrouted); code != 1 || !strings.Contains(out, "100.64.0.1 is not routed") {
		t.Errorf("granted but not routed: exit %d %s", code, out)
	}
	// Another host of the same Service listed among the peers must not count for this one.
	peerRoutes := strings.Replace(unrouted, "\n}", ",\n  \"Peer\": {\n    \"x\": {\n      \"AllowedIPs\": [\n        \"100.64.0.1/32\"\n      ]\n    }\n  }\n}", 1)
	if code, _ := run(peerRoutes); code != 1 {
		t.Errorf("another host's route counted for this node: exit %d", code)
	}
	if code, _ := run(strings.Replace(notHost, `"Running"`, `"Starting"`, 1)); code != 0 {
		t.Errorf("not Running yet: exit %d", code)
	}
	if code, _ := run(host, "TSINJECT_ADVERTISE_SERVICES=svc:app,svc:second"); code != 1 {
		t.Errorf("an advertised Service missing: exit %d", code)
	}
	os.WriteFile(filepath.Join(dir, "down"), nil, 0o644)
	if code, _ := run(notHost); code != 0 {
		t.Errorf("local API unreachable: exit %d", code)
	}
	os.Remove(filepath.Join(dir, "down"))
	if code, _ := run(notHost, "TS_SERVE_CONFIG="); code != 0 {
		t.Errorf("no Services at all: exit %d", code)
	}
}
