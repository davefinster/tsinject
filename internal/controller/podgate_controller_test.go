package controller

import (
	"context"
	"slices"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	tsv1alpha1 "github.com/davefinster/tsinject/api/v1alpha1"
)

func newGateReconciler(t *testing.T, objs ...client.Object) (*PodGateReconciler, client.Client) {
	t.Helper()
	c := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithStatusSubresource(&tsv1alpha1.TailscaleCredential{}).
		WithObjects(objs...).
		WithInterceptorFuncs(interceptor.Funcs{Update: bumpCredentialGeneration}).
		Build()
	return &PodGateReconciler{Client: c, APIReader: c}, c
}

// bumpCredentialGeneration does what the API server does and the fake client
// does not: a spec update advances metadata.generation. Without it a Ready
// condition from before the update looks current, which is how the gate
// releasing pods onto a superseded OAuth client went unnoticed.
func bumpCredentialGeneration(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
	if cred, ok := obj.(*tsv1alpha1.TailscaleCredential); ok {
		live := &tsv1alpha1.TailscaleCredential{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(cred), live); err == nil && !equality.Semantic.DeepEqual(live.Spec, cred.Spec) {
			cred.Generation = live.Generation + 1
		}
	}
	return c.Update(ctx, obj, opts...)
}

// catchUpCredential plays the credential controller finishing a reconcile:
// Ready for the credential's current generation.
func catchUpCredential(t *testing.T, c client.Client, ns, name string) {
	t.Helper()
	ctx := context.Background()
	cred := &tsv1alpha1.TailscaleCredential{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, cred); err != nil {
		t.Fatal(err)
	}
	meta.SetStatusCondition(&cred.Status.Conditions, metav1.Condition{
		Type: tsv1alpha1.ReadyCondition, Status: metav1.ConditionTrue, Reason: "test",
		ObservedGeneration: cred.Generation,
	})
	if err := c.Status().Update(ctx, cred); err != nil {
		t.Fatal(err)
	}
}

func gatedPod(ns, name string, annotations map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   ns,
			Name:        name,
			Labels:      map[string]string{tsv1alpha1.InjectLabel: tsv1alpha1.InjectLabelValue},
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			SchedulingGates: []corev1.PodSchedulingGate{{Name: tsv1alpha1.PodGateName}},
			Containers:      []corev1.Container{{Name: "app", Image: "alpine"}},
		},
	}
}

func readyCredential(ns, name string, ready bool) *tsv1alpha1.TailscaleCredential {
	cred := &tsv1alpha1.TailscaleCredential{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
	}
	status := metav1.ConditionFalse
	if ready {
		status = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&cred.Status.Conditions, metav1.Condition{
		Type: tsv1alpha1.ReadyCondition, Status: status, Reason: "test",
	})
	return cred
}

func podReq(ns, name string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}
}

func TestCreatesCredentialFromPodAnnotations(t *testing.T) {
	ctx := context.Background()
	pod := gatedPod("team-a", "app-1", map[string]string{
		tsv1alpha1.CredentialAnnotation: "web",
		tsv1alpha1.TagsAnnotation:       "web, db",
		tsv1alpha1.EphemeralAnnotation:  "true",
		tsv1alpha1.TailnetAnnotation:    "global-infrastructure",
	})
	r, c := newGateReconciler(t, pod)

	if _, err := r.Reconcile(ctx, podReq("team-a", "app-1")); err != nil {
		t.Fatal(err)
	}

	cred := &tsv1alpha1.TailscaleCredential{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "team-a", Name: "web"}, cred); err != nil {
		t.Fatalf("credential must be created on demand: %v", err)
	}
	wantTags := []string{"tag:db", "tag:injected", "tag:web"}
	if !slices.Equal(cred.Spec.Tags, wantTags) {
		t.Errorf("spec.tags = %v, want %v", cred.Spec.Tags, wantTags)
	}
	if cred.Spec.Ephemeral == nil || !*cred.Spec.Ephemeral {
		t.Errorf("spec.ephemeral = %v, want true", cred.Spec.Ephemeral)
	}
	if cred.Spec.Tailnet != "global-infrastructure" {
		t.Errorf("spec.tailnet = %q, want the annotation's tailnet", cred.Spec.Tailnet)
	}

	got := &corev1.Pod{}
	if err := c.Get(ctx, podReq("team-a", "app-1").NamespacedName, got); err != nil {
		t.Fatal(err)
	}
	if !hasTailscaleGate(got) {
		t.Error("gate must stay until the credential is Ready")
	}
}

func TestDerivesIdentityFromDeployment(t *testing.T) {
	// No stamped annotation: the controller re-derives pod → ReplicaSet →
	// Deployment and ties the credential's lifecycle to the Deployment.
	ctx := context.Background()
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "web", UID: "dep-uid"}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Namespace:       "team-a",
		Name:            "web-abc123",
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", UID: "dep-uid"}},
	}}
	pod := gatedPod("team-a", "web-abc123-xyz", nil)
	pod.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-abc123", UID: "rs-uid"}}
	r, c := newGateReconciler(t, dep, rs, pod)

	if _, err := r.Reconcile(ctx, podReq("team-a", "web-abc123-xyz")); err != nil {
		t.Fatal(err)
	}
	cred := &tsv1alpha1.TailscaleCredential{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "team-a", Name: "web"}, cred); err != nil {
		t.Fatalf("credential must be named after the Deployment: %v", err)
	}
	if len(cred.OwnerReferences) != 1 || cred.OwnerReferences[0].Name != "web" || cred.OwnerReferences[0].Kind != "Deployment" {
		t.Errorf("credential must be owned by the Deployment: %+v", cred.OwnerReferences)
	}
}

func TestReleasesGateOnReady(t *testing.T) {
	ctx := context.Background()
	pod := gatedPod("team-a", "app-1", map[string]string{tsv1alpha1.CredentialAnnotation: "web"})
	r, c := newGateReconciler(t, pod, readyCredential("team-a", "web", false))
	req := podReq("team-a", "app-1")

	// Not ready: gate stays.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	got := &corev1.Pod{}
	if err := c.Get(ctx, req.NamespacedName, got); err != nil {
		t.Fatal(err)
	}
	if !hasTailscaleGate(got) {
		t.Fatal("gate must stay while the credential is not Ready")
	}

	// Flip to ready: gate released.
	cred := &tsv1alpha1.TailscaleCredential{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "team-a", Name: "web"}, cred); err != nil {
		t.Fatal(err)
	}
	meta.SetStatusCondition(&cred.Status.Conditions, metav1.Condition{
		Type: tsv1alpha1.ReadyCondition, Status: metav1.ConditionTrue, Reason: "Provisioned",
	})
	if err := c.Status().Update(ctx, cred); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, req.NamespacedName, got); err != nil {
		t.Fatal(err)
	}
	if hasTailscaleGate(got) {
		t.Errorf("gate should be released once Ready: %+v", got.Spec.SchedulingGates)
	}
}

func TestEnsuresConfigMapsAndStateRBAC(t *testing.T) {
	ctx := context.Background()
	pod := gatedPod("team-a", "app-1", map[string]string{
		tsv1alpha1.CredentialAnnotation:  "web",
		tsv1alpha1.ServeConfigAnnotation: `{"TCP":{}}`,
		tsv1alpha1.ConfigJSONAnnotation:  `{"Hostname":"web"}`,
	})
	pod.Spec.ServiceAccountName = "web-sa"
	r, c := newGateReconciler(t, pod, readyCredential("team-a", "web", true))

	if _, err := r.Reconcile(ctx, podReq("team-a", "app-1")); err != nil {
		t.Fatal(err)
	}

	serve := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "team-a", Name: "web-serve-config"}, serve); err != nil {
		t.Fatal(err)
	}
	if serve.Data["serve.json"] != `{"TCP":{}}` {
		t.Errorf("serve.json = %q", serve.Data["serve.json"])
	}
	if len(serve.OwnerReferences) != 1 || serve.OwnerReferences[0].Name != "web" {
		t.Errorf("serve ConfigMap must be owned by the credential: %+v", serve.OwnerReferences)
	}
	jsonCM := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "team-a", Name: "web-json-config"}, jsonCM); err != nil {
		t.Fatal(err)
	}
	if jsonCM.Data["config.json"] != `{"Hostname":"web"}` {
		t.Errorf("config.json = %q", jsonCM.Data["config.json"])
	}

	role := &rbacv1.Role{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "team-a", Name: "web-state-secret-interaction-role"}, role); err != nil {
		t.Fatal(err)
	}
	// The by-name rule must target the state Secret (the pre-operator
	// injector's update path wrongly scoped it to the Role's own name).
	var byName *rbacv1.PolicyRule
	for i := range role.Rules {
		if len(role.Rules[i].ResourceNames) > 0 {
			byName = &role.Rules[i]
		}
	}
	if byName == nil || !slices.Contains(byName.ResourceNames, "web-state-secret") {
		t.Errorf("role must scope access to the state secret: %+v", role.Rules)
	}
	binding := &rbacv1.RoleBinding{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "team-a", Name: "web-state-secret-interaction-role-binding"}, binding); err != nil {
		t.Fatal(err)
	}
	if len(binding.Subjects) != 1 || binding.Subjects[0].Name != "web-sa" || binding.Subjects[0].Kind != rbacv1.ServiceAccountKind {
		t.Errorf("binding subjects = %+v", binding.Subjects)
	}
	if binding.RoleRef.APIGroup != rbacv1.GroupName || binding.RoleRef.Name != role.Name {
		t.Errorf("binding roleRef = %+v", binding.RoleRef)
	}

	// Everything in place and the credential Ready: gate released in the
	// same pass.
	got := &corev1.Pod{}
	if err := c.Get(ctx, podReq("team-a", "app-1").NamespacedName, got); err != nil {
		t.Fatal(err)
	}
	if hasTailscaleGate(got) {
		t.Error("gate should be released once everything is materialized")
	}
}

func TestConfigMapContentFollowsAnnotation(t *testing.T) {
	ctx := context.Background()
	pod := gatedPod("team-a", "app-1", map[string]string{
		tsv1alpha1.CredentialAnnotation:  "web",
		tsv1alpha1.ServeConfigAnnotation: `{"v":2}`,
	})
	stale := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "web-serve-config"},
		Data:       map[string]string{"serve.json": `{"v":1}`},
	}
	r, c := newGateReconciler(t, pod, stale, readyCredential("team-a", "web", false))

	if _, err := r.Reconcile(ctx, podReq("team-a", "app-1")); err != nil {
		t.Fatal(err)
	}
	cm := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "team-a", Name: "web-serve-config"}, cm); err != nil {
		t.Fatal(err)
	}
	if cm.Data["serve.json"] != `{"v":2}` {
		t.Errorf("serve.json = %q, want the annotation's value", cm.Data["serve.json"])
	}
}

func TestMapCredentialToGatedPods(t *testing.T) {
	r, _ := newGateReconciler(t,
		gatedPod("team-a", "gated-1", map[string]string{tsv1alpha1.CredentialAnnotation: "web"}),
		gatedPod("team-a", "gated-other", map[string]string{tsv1alpha1.CredentialAnnotation: "other"}),
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "ungated"},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "a", Image: "x"}}}},
	)
	reqs := r.mapCredentialToGatedPods(context.Background(), readyCredential("team-a", "web", true))
	if len(reqs) != 1 || reqs[0].Name != "gated-1" {
		t.Errorf("expected only the bound gated pod, got %v", reqs)
	}
}

func TestSyncsCredentialSpecOnAnnotationChange(t *testing.T) {
	// The migration case: a workload changes its tailscale-tailnet (and
	// tags), rolls a new gated pod, and the existing Ready credential must
	// follow the annotations rather than ungate the pod onto the old tailnet.
	ctx := context.Background()
	pod := gatedPod("team-a", "app-1", map[string]string{
		tsv1alpha1.CredentialAnnotation: "web",
		tsv1alpha1.TailnetAnnotation:    "global-infrastructure",
		tsv1alpha1.TagsAnnotation:       "media",
	})
	cred := readyCredential("team-a", "web", true)
	cred.Spec.Tailnet = "" // provisioned in the default tailnet
	cred.Spec.Tags = []string{"tag:injected"}
	r, c := newGateReconciler(t, pod, cred)
	req := podReq("team-a", "app-1")

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}

	got := &tsv1alpha1.TailscaleCredential{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "team-a", Name: "web"}, got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.Tailnet != "global-infrastructure" {
		t.Errorf("spec.tailnet = %q, want the pod's annotation", got.Spec.Tailnet)
	}
	wantTags := []string{"tag:injected", "tag:media"}
	if !slices.Equal(got.Spec.Tags, wantTags) {
		t.Errorf("spec.tags = %v, want %v", got.Spec.Tags, wantTags)
	}

	// The stale-but-Ready credential must NOT have released the gate on the
	// sync pass: Ready has to be earned against the new spec first.
	gotPod := &corev1.Pod{}
	if err := c.Get(ctx, req.NamespacedName, gotPod); err != nil {
		t.Fatal(err)
	}
	if !hasTailscaleGate(gotPod) {
		t.Error("gate must stay until the credential is Ready for the new spec")
	}

	// The sync's own update event re-enqueues the pod before the credential
	// controller has acted on it: no drift is left, but Ready is still the
	// one the old spec earned, and releasing on it would start the pod
	// against the OAuth client of the old tailnet and tags.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, req.NamespacedName, gotPod); err != nil {
		t.Fatal(err)
	}
	if !hasTailscaleGate(gotPod) {
		t.Error("gate must stay while Ready describes an earlier generation of the spec")
	}

	// Once the credential controller has provisioned the new spec, the gate
	// releases.
	catchUpCredential(t, c, "team-a", "web")
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, req.NamespacedName, gotPod); err != nil {
		t.Fatal(err)
	}
	if hasTailscaleGate(gotPod) {
		t.Error("gate should release once Ready holds for the synced spec")
	}
}

// A gated pod of a federated tailnet gets its state RBAC, owned by its
// Deployment, and is released -- and no TailscaleCredential is ever created.
func TestFederatedPodGetsRBACAndNoCredential(t *testing.T) {
	ctx := context.Background()
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "web", UID: "dep-uid"}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Namespace:       "team-a",
		Name:            "web-abc123",
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", UID: "dep-uid"}},
	}}
	pod := gatedPod("team-a", "web-abc123-xyz", map[string]string{
		tsv1alpha1.CredentialAnnotation: "web",
		tsv1alpha1.TailnetAnnotation:    "config-plane",
		tsv1alpha1.EphemeralAnnotation:  "false",
		tsv1alpha1.ClientIDAnnotation:   "TFED-kAbc123CNTRL",
	})
	pod.Spec.ServiceAccountName = "web-sa"
	pod.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-abc123", UID: "rs-uid"}}
	r, c := newGateReconciler(t, dep, rs, pod)
	reg, err := NewTailnetRegistry("homelab", map[string]TailscaleAPI{"homelab": &fakeTailscale{}}, map[string]bool{"config-plane": true})
	if err != nil {
		t.Fatal(err)
	}
	r.Tailnets = reg

	if _, err := r.Reconcile(ctx, podReq("team-a", "web-abc123-xyz")); err != nil {
		t.Fatal(err)
	}
	creds := &tsv1alpha1.TailscaleCredentialList{}
	if err := c.List(ctx, creds); err != nil {
		t.Fatal(err)
	}
	if len(creds.Items) != 0 {
		t.Errorf("a federated pod must not get a TailscaleCredential: %+v", creds.Items)
	}
	role := &rbacv1.Role{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "team-a", Name: StateRoleName("web")}, role); err != nil {
		t.Fatalf("state Role: %v", err)
	}
	if len(role.OwnerReferences) != 1 || role.OwnerReferences[0].Kind != "Deployment" || role.OwnerReferences[0].Name != "web" {
		t.Errorf("state Role must be owned by the Deployment: %+v", role.OwnerReferences)
	}
	binding := &rbacv1.RoleBinding{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "team-a", Name: StateRoleBindingName("web")}, binding); err != nil {
		t.Fatalf("state RoleBinding: %v", err)
	}
	if len(binding.Subjects) != 1 || binding.Subjects[0].Name != "web-sa" {
		t.Errorf("binding subjects = %+v", binding.Subjects)
	}
	got := &corev1.Pod{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "team-a", Name: "web-abc123-xyz"}, got); err != nil {
		t.Fatal(err)
	}
	if hasTailscaleGate(got) {
		t.Error("the gate must be released once the RBAC exists")
	}
}
