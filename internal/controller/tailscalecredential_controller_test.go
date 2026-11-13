package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	tailscale "tailscale.com/client/tailscale/v2"

	tsv1alpha1 "github.com/davefinster/tsinject/api/v1alpha1"
)

func testScheme(t *testing.T) *runtime.Scheme {
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

// fakeTailscale records API traffic and mints deterministic keys.
type fakeTailscale struct {
	created []tailscale.CreateOAuthClientRequest
	set     map[string]tailscale.SetOAuthClientRequest
	deleted []string
	nextID  int
}

func (f *fakeTailscale) CreateOAuthClient(_ context.Context, req tailscale.CreateOAuthClientRequest) (*tailscale.Key, error) {
	f.created = append(f.created, req)
	f.nextID++
	return &tailscale.Key{
		ID:  fmt.Sprintf("k%d", f.nextID),
		Key: fmt.Sprintf("tskey-client-%d", f.nextID),
	}, nil
}

func (f *fakeTailscale) SetOAuthClient(_ context.Context, id string, req tailscale.SetOAuthClientRequest) (*tailscale.Key, error) {
	if f.set == nil {
		f.set = map[string]tailscale.SetOAuthClientRequest{}
	}
	f.set[id] = req
	return &tailscale.Key{ID: id}, nil
}

func (f *fakeTailscale) DeleteKey(_ context.Context, id string) error {
	f.deleted = append(f.deleted, id)
	return nil
}

// testRegistry builds a registry from name → fake pairs; the first name is
// the default.
func testRegistry(t *testing.T, defaultName string, apis map[string]TailscaleAPI) *TailnetRegistry {
	t.Helper()
	reg, err := NewTailnetRegistry(defaultName, apis, nil)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func newCredReconciler(t *testing.T, objs ...client.Object) (*TailscaleCredentialReconciler, client.Client, *fakeTailscale) {
	t.Helper()
	c := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithStatusSubresource(&tsv1alpha1.TailscaleCredential{}).
		WithObjects(objs...).
		Build()
	ts := &fakeTailscale{}
	reg := testRegistry(t, "default", map[string]TailscaleAPI{"default": ts})
	return &TailscaleCredentialReconciler{Client: c, APIReader: c, Tailnets: reg}, c, ts
}

func credReq(ns, name string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}
}

func getCred(t *testing.T, c client.Client, ns, name string) *tsv1alpha1.TailscaleCredential {
	t.Helper()
	cred := &tsv1alpha1.TailscaleCredential{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, cred); err != nil {
		t.Fatal(err)
	}
	return cred
}

func getSecret(t *testing.T, c client.Client, ns, name string) *corev1.Secret {
	t.Helper()
	sec := &corev1.Secret{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, sec); err != nil {
		t.Fatal(err)
	}
	return sec
}

func TestProvisionMintsClientAndSecret(t *testing.T) {
	ctx := context.Background()
	cred := &tsv1alpha1.TailscaleCredential{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "web"},
		Spec:       tsv1alpha1.TailscaleCredentialSpec{Tags: []string{"tag:web"}},
	}
	r, c, ts := newCredReconciler(t, cred)

	if _, err := r.Reconcile(ctx, credReq("team-a", "web")); err != nil {
		t.Fatal(err)
	}

	if len(ts.created) != 1 {
		t.Fatalf("expected one OAuth client creation, got %d", len(ts.created))
	}
	wantTags := []string{"tag:injected", "tag:web"}
	if !slices.Equal(ts.created[0].Tags, wantTags) {
		t.Errorf("tags = %v, want %v (sorted, default included)", ts.created[0].Tags, wantTags)
	}
	if !slices.Equal(ts.created[0].Scopes, oauthClientScopes) {
		t.Errorf("scopes = %v, want %v", ts.created[0].Scopes, oauthClientScopes)
	}

	sec := getSecret(t, c, "team-a", "web-ts-credential")
	if got := string(sec.Data[oauthIDKey]); got != "k1" {
		t.Errorf("oauth.id = %q, want k1", got)
	}
	if got := string(sec.Data[oauthSecretKey]); got != "tskey-client-1" {
		t.Errorf("oauth.secret = %q, want plain key without suffix", got)
	}
	if sec.Labels[managedByLabel] != managedByValue || sec.Labels[credentialLabel] != "web" {
		t.Errorf("secret labels missing: %v", sec.Labels)
	}
	if sec.Labels[tsv1alpha1.WatchedSecretLabel] != tsv1alpha1.WatchedSecretLabelValue {
		t.Errorf("secret must carry the watched label the scoped informer selects on: %v", sec.Labels)
	}
	if len(sec.OwnerReferences) != 1 || sec.OwnerReferences[0].Name != "web" {
		t.Errorf("secret must be owned by the credential: %+v", sec.OwnerReferences)
	}

	got := getCred(t, c, "team-a", "web")
	if !meta.IsStatusConditionTrue(got.Status.Conditions, tsv1alpha1.ReadyCondition) {
		t.Error("credential must be Ready after provisioning")
	}
	if got.Status.OAuthClientID != "k1" || got.Status.SecretName != "web-ts-credential" {
		t.Errorf("status = %+v", got.Status)
	}
	if !slices.Contains(got.Finalizers, finalizerName) {
		t.Error("finalizer must be added")
	}
}

func TestProvisionEphemeralSuffix(t *testing.T) {
	ephemeral := true
	cred := &tsv1alpha1.TailscaleCredential{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "web"},
		Spec:       tsv1alpha1.TailscaleCredentialSpec{Ephemeral: &ephemeral},
	}
	r, c, _ := newCredReconciler(t, cred)
	if _, err := r.Reconcile(context.Background(), credReq("team-a", "web")); err != nil {
		t.Fatal(err)
	}
	sec := getSecret(t, c, "team-a", "web-ts-credential")
	if got := string(sec.Data[oauthSecretKey]); got != "tskey-client-1?ephemeral=true" {
		t.Errorf("oauth.secret = %q, want ?ephemeral=true suffix", got)
	}
}

func TestAdoptsPreOperatorSecret(t *testing.T) {
	// The pre-operator injector wrote Secrets at admission time; the
	// reconciler must adopt them instead of minting a replacement client.
	ephemeral := true
	cred := &tsv1alpha1.TailscaleCredential{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "web"},
		Spec:       tsv1alpha1.TailscaleCredentialSpec{Ephemeral: &ephemeral},
	}
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "web-ts-credential"},
		Data: map[string][]byte{
			oauthIDKey:     []byte("legacy-id"),
			oauthSecretKey: []byte("legacy-key?ephemeral=true"),
		},
	}
	r, c, ts := newCredReconciler(t, cred, existing)

	if _, err := r.Reconcile(context.Background(), credReq("team-a", "web")); err != nil {
		t.Fatal(err)
	}
	if len(ts.created) != 0 || len(ts.deleted) != 0 {
		t.Fatalf("adoption must not touch the Tailscale API: created=%v deleted=%v", ts.created, ts.deleted)
	}
	sec := getSecret(t, c, "team-a", "web-ts-credential")
	if got := string(sec.Data[oauthSecretKey]); got != "legacy-key?ephemeral=true" {
		t.Errorf("oauth.secret = %q, adopted key must be preserved", got)
	}
	if len(sec.OwnerReferences) != 1 {
		t.Errorf("adopted secret must gain an ownerReference: %+v", sec.OwnerReferences)
	}
	got := getCred(t, c, "team-a", "web")
	if got.Status.OAuthClientID != "legacy-id" {
		t.Errorf("status.oauthClientID = %q, want legacy-id", got.Status.OAuthClientID)
	}
	ready := meta.FindStatusCondition(got.Status.Conditions, tsv1alpha1.ReadyCondition)
	if ready == nil || ready.Reason != "Adopted" {
		t.Errorf("Ready reason = %+v, want Adopted", ready)
	}
}

func provisionedCred(tags []string) *tsv1alpha1.TailscaleCredential {
	return &tsv1alpha1.TailscaleCredential{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "team-a",
			Name:       "web",
			Finalizers: []string{finalizerName},
		},
		Spec: tsv1alpha1.TailscaleCredentialSpec{Tags: tags},
		Status: tsv1alpha1.TailscaleCredentialStatus{
			OAuthClientID:   "old-id",
			SecretName:      "web-ts-credential",
			ProvisionedTags: []string{"tag:injected"},
		},
	}
}

func provisionedSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "team-a",
			Name:      "web-ts-credential",
			Labels: map[string]string{
				managedByLabel:                managedByValue,
				credentialLabel:               "web",
				tsv1alpha1.WatchedSecretLabel: tsv1alpha1.WatchedSecretLabelValue,
			},
		},
		Data: map[string][]byte{
			oauthIDKey:     []byte("old-id"),
			oauthSecretKey: []byte("old-key"),
		},
	}
}

func TestTagDriftUpdatesClientInPlace(t *testing.T) {
	r, c, ts := newCredReconciler(t, provisionedCred([]string{"tag:web"}), provisionedSecret())

	if _, err := r.Reconcile(context.Background(), credReq("team-a", "web")); err != nil {
		t.Fatal(err)
	}
	if len(ts.created) != 0 || len(ts.deleted) != 0 {
		t.Fatalf("tag drift must not rotate the client: created=%v deleted=%v", ts.created, ts.deleted)
	}
	want := []string{"tag:injected", "tag:web"}
	if got, ok := ts.set["old-id"]; !ok || !slices.Equal(got.Tags, want) {
		t.Errorf("SetOAuthClient(old-id) tags = %v, want %v", got.Tags, want)
	}
	sec := getSecret(t, c, "team-a", "web-ts-credential")
	if got := string(sec.Data[oauthSecretKey]); got != "old-key" {
		t.Errorf("oauth.secret = %q, secret must be untouched by tag updates", got)
	}
	got := getCred(t, c, "team-a", "web")
	if !slices.Equal(got.Status.ProvisionedTags, want) {
		t.Errorf("status.provisionedTags = %v, want %v", got.Status.ProvisionedTags, want)
	}
}

func TestLostSecretRotatesClient(t *testing.T) {
	// The plaintext OAuth secret only exists in the delivered Secret; when
	// it is gone the old client must be revoked and a new one minted.
	r, c, ts := newCredReconciler(t, provisionedCred(nil))

	if _, err := r.Reconcile(context.Background(), credReq("team-a", "web")); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(ts.deleted, "old-id") {
		t.Errorf("old client must be revoked, deleted=%v", ts.deleted)
	}
	if len(ts.created) != 1 {
		t.Fatalf("expected re-mint, created=%v", ts.created)
	}
	sec := getSecret(t, c, "team-a", "web-ts-credential")
	if got := string(sec.Data[oauthIDKey]); got != "k1" {
		t.Errorf("oauth.id = %q, want the re-minted k1", got)
	}
	got := getCred(t, c, "team-a", "web")
	if got.Status.OAuthClientID != "k1" {
		t.Errorf("status.oauthClientID = %q, want k1", got.Status.OAuthClientID)
	}
}

func TestFinalizeRevokesClient(t *testing.T) {
	ctx := context.Background()
	r, c, ts := newCredReconciler(t, provisionedCred(nil), provisionedSecret())

	cred := getCred(t, c, "team-a", "web")
	if err := c.Delete(ctx, cred); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, credReq("team-a", "web")); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(ts.deleted, "old-id") {
		t.Errorf("finalizer must revoke the OAuth client, deleted=%v", ts.deleted)
	}
	err := c.Get(ctx, types.NamespacedName{Namespace: "team-a", Name: "web"}, &tsv1alpha1.TailscaleCredential{})
	if err == nil {
		t.Error("credential must be gone once the finalizer is removed")
	}
}

func TestSteadyStateIsNoOp(t *testing.T) {
	cred := provisionedCred([]string{"tag:injected"})
	meta.SetStatusCondition(&cred.Status.Conditions, metav1.Condition{
		Type: tsv1alpha1.ReadyCondition, Status: metav1.ConditionTrue, Reason: "Provisioned",
	})
	converged := provisionedSecret()
	controller := true
	converged.OwnerReferences = []metav1.OwnerReference{{
		APIVersion:         tsv1alpha1.GroupVersion.String(),
		Kind:               "TailscaleCredential",
		Name:               "web",
		Controller:         &controller,
		BlockOwnerDeletion: &controller,
	}}
	r, c, ts := newCredReconciler(t, cred, converged)

	before := getSecret(t, c, "team-a", "web-ts-credential").ResourceVersion
	if _, err := r.Reconcile(context.Background(), credReq("team-a", "web")); err != nil {
		t.Fatal(err)
	}
	if len(ts.created)+len(ts.deleted)+len(ts.set) != 0 {
		t.Errorf("steady state must not call the API: %+v", ts)
	}
	if after := getSecret(t, c, "team-a", "web-ts-credential").ResourceVersion; after != before {
		t.Error("steady state must not rewrite the secret (Owns watch feedback)")
	}
}

// newMultiReconciler wires two tailnets — "default" (nominated) and "global"
// — each backed by its own fake, mirroring the one-admin-client-per-tailnet
// reality of API-only tailnets.
func newMultiReconciler(t *testing.T, objs ...client.Object) (*TailscaleCredentialReconciler, client.Client, *fakeTailscale, *fakeTailscale) {
	t.Helper()
	c := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithStatusSubresource(&tsv1alpha1.TailscaleCredential{}).
		WithObjects(objs...).
		Build()
	def, global := &fakeTailscale{}, &fakeTailscale{}
	reg := testRegistry(t, "default", map[string]TailscaleAPI{"default": def, "global": global})
	return &TailscaleCredentialReconciler{Client: c, APIReader: c, Tailnets: reg}, c, def, global
}

func TestProvisionInNamedTailnet(t *testing.T) {
	cred := &tsv1alpha1.TailscaleCredential{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "web"},
		Spec:       tsv1alpha1.TailscaleCredentialSpec{Tailnet: "global"},
	}
	r, c, def, global := newMultiReconciler(t, cred)

	if _, err := r.Reconcile(context.Background(), credReq("team-a", "web")); err != nil {
		t.Fatal(err)
	}
	if len(def.created) != 0 {
		t.Errorf("default tailnet must not be touched: %+v", def.created)
	}
	if len(global.created) != 1 {
		t.Fatalf("client must be minted in the named tailnet, created=%v", global.created)
	}
	got := getCred(t, c, "team-a", "web")
	if got.Status.Tailnet != "global" {
		t.Errorf("status.tailnet = %q, want global", got.Status.Tailnet)
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, tsv1alpha1.ReadyCondition) {
		t.Error("credential must be Ready")
	}
}

func TestUnknownTailnetNotReady(t *testing.T) {
	cred := &tsv1alpha1.TailscaleCredential{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "web"},
		Spec:       tsv1alpha1.TailscaleCredentialSpec{Tailnet: "nope"},
	}
	r, c, ts := newCredReconciler(t, cred)

	if _, err := r.Reconcile(context.Background(), credReq("team-a", "web")); err != nil {
		t.Fatal(err)
	}
	if len(ts.created)+len(ts.deleted) != 0 {
		t.Errorf("unknown tailnet must not reach the API: %+v", ts)
	}
	got := getCred(t, c, "team-a", "web")
	ready := meta.FindStatusCondition(got.Status.Conditions, tsv1alpha1.ReadyCondition)
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != "UnknownTailnet" {
		t.Errorf("Ready = %+v, want False/UnknownTailnet", ready)
	}
}

func TestTailnetMoveRevokesAndRemints(t *testing.T) {
	// An OAuth client lives in exactly one tailnet: pointing the spec at
	// another one must revoke the old client where it was minted and mint a
	// replacement in the new tailnet.
	cred := provisionedCred(nil)
	cred.Spec.Tailnet = "global"
	cred.Status.Tailnet = "default"
	r, c, def, global := newMultiReconciler(t, cred, provisionedSecret())

	if _, err := r.Reconcile(context.Background(), credReq("team-a", "web")); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(def.deleted, "old-id") {
		t.Errorf("old client must be revoked in its own tailnet, deleted=%v", def.deleted)
	}
	if len(global.created) != 1 {
		t.Fatalf("replacement must be minted in the new tailnet, created=%v", global.created)
	}
	sec := getSecret(t, c, "team-a", "web-ts-credential")
	if got := string(sec.Data[oauthIDKey]); got != "k1" {
		t.Errorf("oauth.id = %q, want the re-minted k1", got)
	}
	got := getCred(t, c, "team-a", "web")
	if got.Status.Tailnet != "global" {
		t.Errorf("status.tailnet = %q, want global", got.Status.Tailnet)
	}
}

func TestDefaultChangeDoesNotRehomeCredentials(t *testing.T) {
	// spec.tailnet empty sticks to the tailnet status records: re-nominating
	// the default must never revoke and re-mint existing clients.
	cred := provisionedCred([]string{"tag:injected"})
	cred.Status.Tailnet = "global" // provisioned back when "global" was the default
	meta.SetStatusCondition(&cred.Status.Conditions, metav1.Condition{
		Type: tsv1alpha1.ReadyCondition, Status: metav1.ConditionTrue, Reason: "Provisioned",
	})
	r, _, def, global := newMultiReconciler(t, cred, provisionedSecret())

	if _, err := r.Reconcile(context.Background(), credReq("team-a", "web")); err != nil {
		t.Fatal(err)
	}
	if len(def.created)+len(def.deleted)+len(global.created)+len(global.deleted) != 0 {
		t.Errorf("no client may move on a default change: default=%+v global=%+v", def, global)
	}
}

func TestFinalizeRevokesInProvisionedTailnet(t *testing.T) {
	ctx := context.Background()
	cred := provisionedCred(nil)
	cred.Status.Tailnet = "global"
	r, c, def, global := newMultiReconciler(t, cred, provisionedSecret())

	if err := c.Delete(ctx, getCred(t, c, "team-a", "web")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, credReq("team-a", "web")); err != nil {
		t.Fatal(err)
	}
	if len(def.deleted) != 0 {
		t.Errorf("revocation must not hit the default tailnet: %v", def.deleted)
	}
	if !slices.Contains(global.deleted, "old-id") {
		t.Errorf("finalizer must revoke in the provisioned tailnet, deleted=%v", global.deleted)
	}
}

// A credential whose deletion has started but is not in the cache yet, with
// its owned Secret already gone: the reconcile must finalize, not mint a
// client the finalizer will never revoke.
func TestNoMintForACredentialBeingDeleted(t *testing.T) {
	ctx := context.Background()
	stale := &tsv1alpha1.TailscaleCredential{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "web", Finalizers: []string{finalizerName}},
		Spec:       tsv1alpha1.TailscaleCredentialSpec{Tags: []string{"tag:web"}},
		Status:     tsv1alpha1.TailscaleCredentialStatus{OAuthClientID: "k-old", Tailnet: "default"},
	}
	deleting := stale.DeepCopy()
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	// One store, as the API server; reads through the cache do not see the
	// deletion yet, and writes go to the store, as the operator's do.
	live := fake.NewClientBuilder().WithScheme(testScheme(t)).WithStatusSubresource(&tsv1alpha1.TailscaleCredential{}).WithObjects(deleting).Build()
	cache := interceptor.NewClient(live, interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		if err := c.Get(ctx, key, obj, opts...); err != nil {
			return err
		}
		if cr, ok := obj.(*tsv1alpha1.TailscaleCredential); ok {
			cr.DeletionTimestamp = nil
		}
		return nil
	}})
	ts := &fakeTailscale{}
	r := &TailscaleCredentialReconciler{Client: cache, APIReader: live, Tailnets: testRegistry(t, "default", map[string]TailscaleAPI{"default": ts})}

	if _, err := r.Reconcile(ctx, credReq("team-a", "web")); err != nil {
		t.Fatal(err)
	}
	if len(ts.created) != 0 {
		t.Errorf("minted %d OAuth client(s) for a credential being deleted", len(ts.created))
	}
	if !slices.Equal(ts.deleted, []string{"k-old"}) {
		t.Errorf("revoked %v, want the recorded client once", ts.deleted)
	}
}

// A client minted whose ID cannot be recorded is revoked at once.
func TestRevokesAClientItCannotRecord(t *testing.T) {
	ctx := context.Background()
	cred := &tsv1alpha1.TailscaleCredential{
		ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "web"},
		Spec:       tsv1alpha1.TailscaleCredentialSpec{Tags: []string{"tag:web"}},
	}
	failed := false
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithStatusSubresource(&tsv1alpha1.TailscaleCredential{}).WithObjects(cred).
		WithInterceptorFuncs(interceptor.Funcs{SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			if !failed {
				failed = true
				return apierrors.NewConflict(schema.GroupResource{Group: "tsinject.dmf.zone", Resource: "tailscalecredentials"}, obj.GetName(), errors.New("modified"))
			}
			return c.SubResource(sub).Update(ctx, obj, opts...)
		}}).Build()
	ts := &fakeTailscale{}
	r := &TailscaleCredentialReconciler{Client: c, APIReader: c, Tailnets: testRegistry(t, "default", map[string]TailscaleAPI{"default": ts})}

	if _, err := r.Reconcile(ctx, credReq("team-a", "web")); err == nil {
		t.Fatal("the failed status write must be returned for a retry")
	}
	if len(ts.created) != 1 || !slices.Equal(ts.deleted, []string{"k1"}) {
		t.Errorf("created %d, revoked %v: the unrecorded client must be revoked", len(ts.created), ts.deleted)
	}
}
