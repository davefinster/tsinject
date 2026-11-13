// Package controller reconciles TailscaleCredential objects into their
// dependency chain: an OAuth client minted via the Tailscale API, delivered
// as a namespace-local Secret in the shape the injected sidecar expects
// (oauth.id / oauth.secret) — plus the pod gate controller, which provisions
// credentials on demand for gated pods and releases them once Ready.
package controller

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	tailscale "tailscale.com/client/tailscale/v2"

	tsv1alpha1 "github.com/davefinster/tsinject/api/v1alpha1"
)

const (
	finalizerName   = "tsinject.dmf.zone/oauth-client-cleanup"
	credentialLabel = "tsinject.dmf.zone/credential" // name of the owning TailscaleCredential
	managedByLabel  = "app.kubernetes.io/managed-by"
	managedByValue  = "tsinject-operator"

	oauthIDKey     = "oauth.id"
	oauthSecretKey = "oauth.secret"

	// DefaultTag marks every injected node; always present on minted OAuth
	// clients and in the advertised tag set.
	DefaultTag = "tag:injected"

	condReady   = tsv1alpha1.ReadyCondition
	waitRequeue = 30 * time.Second
)

// oauthClientScopes are the scopes of the per-workload OAuth clients this
// operator mints — just enough for containerboot to self-issue auth keys.
var oauthClientScopes = []string{"all:read", "auth_keys"}

// TailscaleAPI is the slice of the Tailscale admin API the reconciler
// needs; narrowed to an interface so tests can fake it.
type TailscaleAPI interface {
	CreateOAuthClient(ctx context.Context, req tailscale.CreateOAuthClientRequest) (*tailscale.Key, error)
	SetOAuthClient(ctx context.Context, id string, req tailscale.SetOAuthClientRequest) (*tailscale.Key, error)
	DeleteKey(ctx context.Context, id string) error
}

// KeysAPI adapts *tailscale.Client to TailscaleAPI.
type KeysAPI struct {
	Client *tailscale.Client
}

func (k KeysAPI) CreateOAuthClient(ctx context.Context, req tailscale.CreateOAuthClientRequest) (*tailscale.Key, error) {
	return k.Client.Keys().CreateOAuthClient(ctx, req)
}

func (k KeysAPI) SetOAuthClient(ctx context.Context, id string, req tailscale.SetOAuthClientRequest) (*tailscale.Key, error) {
	return k.Client.Keys().SetOAuthClient(ctx, id, req)
}

func (k KeysAPI) DeleteKey(ctx context.Context, id string) error {
	return k.Client.Keys().Delete(ctx, id)
}

// Names of the per-identifier objects. These preserve the pre-operator
// injector's naming so existing Secrets, ConfigMaps and mounts keep lining
// up across the migration.

// CredentialSecretName is the delivered Secret's default name.
func CredentialSecretName(identifier string) string { return identifier + "-ts-credential" }

// StateSecretName is the tailscaled state Secret containerboot writes.
func StateSecretName(identifier string) string { return identifier + "-state-secret" }

// StateRoleName is the Role granting the workload's ServiceAccount access
// to its state Secret.
func StateRoleName(identifier string) string {
	return StateSecretName(identifier) + "-interaction-role"
}

// StateRoleBindingName is the RoleBinding for StateRoleName.
func StateRoleBindingName(identifier string) string { return StateRoleName(identifier) + "-binding" }

// ServeConfigMapName holds the serve.json from the tailscale-serve-config
// annotation.
func ServeConfigMapName(identifier string) string { return identifier + "-serve-config" }

// JSONConfigMapName holds the config.json from the tailscale-config-json
// annotation.
func JSONConfigMapName(identifier string) string { return identifier + "-json-config" }

// normalizeTags dedupes, guarantees DefaultTag, and sorts — tag sets are
// compared for drift, so the representation must be canonical.
func normalizeTags(tags []string) []string {
	set := map[string]bool{DefaultTag: true}
	for _, tag := range tags {
		if clean := strings.TrimSpace(tag); clean != "" {
			set[clean] = true
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// TagsForPod resolves the legacy tailscale-tags annotation (comma-separated,
// unprefixed) into the canonical tag set.
func TagsForPod(pod *corev1.Pod) []string {
	var tags []string
	for tag := range strings.SplitSeq(pod.Annotations[tsv1alpha1.TagsAnnotation], ",") {
		if clean := strings.TrimSpace(tag); clean != "" {
			tags = append(tags, "tag:"+clean)
		}
	}
	return normalizeTags(tags)
}

// TailnetForPod resolves the tailscale-tailnet annotation: the name of the
// operator-configured tailnet the workload's OAuth client is minted in;
// empty means the nominated default.
func TailnetForPod(pod *corev1.Pod) string {
	return strings.TrimSpace(pod.Annotations[tsv1alpha1.TailnetAnnotation])
}

// EphemeralForPod resolves the legacy tailscale-ephemeral annotation: absent
// means unset, "false" means explicitly persistent, anything else means
// ephemeral (matching the old injector's checks).
func EphemeralForPod(pod *corev1.Pod) *bool {
	value, ok := pod.Annotations[tsv1alpha1.EphemeralAnnotation]
	if !ok {
		return nil
	}
	ephemeral := value != "false"
	return &ephemeral
}

// NeedsStateSecret reports whether a pod gets tailscaled state persisted to
// a kube Secret: non-ephemeral pods running as a dedicated ServiceAccount
// (the default ServiceAccount is never granted Secret access).
func NeedsStateSecret(pod *corev1.Pod) bool {
	if eph := EphemeralForPod(pod); eph != nil && *eph {
		return false
	}
	sa := pod.Spec.ServiceAccountName
	return sa != "" && sa != "default"
}

// DefaultedCredentialSpec mirrors the CRD defaults for in-memory use, with
// tags canonicalized.
func DefaultedCredentialSpec(cred *tsv1alpha1.TailscaleCredential) tsv1alpha1.TailscaleCredentialSpec {
	spec := *cred.Spec.DeepCopy()
	spec.Tags = normalizeTags(spec.Tags)
	if spec.SecretName == "" {
		spec.SecretName = CredentialSecretName(cred.Name)
	}
	if spec.Description == "" {
		spec.Description = cred.Name
	}
	return spec
}

// TailscaleCredentialReconciler reconciles TailscaleCredential objects.
type TailscaleCredentialReconciler struct {
	client.Client
	// APIReader reads live: re-provisioning is destructive (it revokes the
	// OAuth client), so the decision must never fire on informer lag.
	APIReader client.Reader
	// Tailnets holds one admin API client per configured tailnet; each
	// credential's calls go to the tailnet it names (or the default).
	Tailnets *TailnetRegistry
}

// +kubebuilder:rbac:groups=tsinject.dmf.zone,resources=tailscalecredentials,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=tsinject.dmf.zone,resources=tailscalecredentials/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=tsinject.dmf.zone,resources=tailscalecredentials/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch

// Reconcile converges one TailscaleCredential: ensure finalizer → ensure
// the OAuth client exists (minting, adopting a pre-operator Secret, or
// updating tags in place) → ensure the delivered Secret → status.
func (r *TailscaleCredentialReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)

	cred := &tsv1alpha1.TailscaleCredential{}
	if err := r.Get(ctx, req.NamespacedName, cred); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !cred.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, cred)
	}

	if !controllerutil.ContainsFinalizer(cred, finalizerName) {
		controllerutil.AddFinalizer(cred, finalizerName)
		if err := r.Update(ctx, cred); err != nil {
			return ctrl.Result{}, err
		}
	}

	spec := DefaultedCredentialSpec(cred)

	// Which tailnet the client should live in: the spec names one
	// explicitly; otherwise stick with whatever status records, so
	// re-nominating the default never silently re-homes existing clients; a
	// fresh credential lands on the current default.
	desired := spec.Tailnet
	if desired == "" {
		desired = cred.Status.Tailnet
	}
	api, tailnetName, err := r.Tailnets.API(desired)
	if err != nil {
		return r.setNotReady(ctx, cred, "UnknownTailnet", err.Error())
	}
	// Revocations must go to the tailnet the client was actually minted in,
	// which differs from the desired one mid-move. Empty status (pre-multi-
	// tailnet credentials) resolves to the default, where the then-single
	// admin client minted them.
	provisionedAPI, provisionedName, err := r.Tailnets.API(cred.Status.Tailnet)
	if err != nil {
		return r.setNotReady(ctx, cred, "UnknownTailnet",
			fmt.Sprintf("cannot revoke OAuth client %s: %v", cred.Status.OAuthClientID, err))
	}

	secret := &corev1.Secret{}
	secretFound := true
	if err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: cred.Namespace, Name: spec.SecretName}, secret); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		secretFound = false
	}

	clientID := cred.Status.OAuthClientID
	// The plaintext OAuth secret is only ever returned at creation; in
	// steady state the delivered Secret is its home. Ephemeral is a query
	// suffix on top of it, re-derived below so spec changes propagate.
	baseKey := ""
	if secretFound {
		baseKey, _, _ = strings.Cut(string(secret.Data[oauthSecretKey]), "?")
	}
	reason := "Provisioned"

	switch {
	case clientID == "" && secretFound && len(secret.Data[oauthIDKey]) > 0 && baseKey != "":
		// A Secret from the pre-operator injector (or a hand-made one):
		// adopt it — trust its client, take ownership, skip the API.
		clientID = string(secret.Data[oauthIDKey])
		reason = "Adopted"

	case clientID == "" || !secretFound || string(secret.Data[oauthIDKey]) != clientID || baseKey == "" || provisionedName != tailnetName:
		// Never provisioned — or the delivered Secret is gone or at odds
		// with the recorded client and the plaintext cannot be recovered —
		// or the credential moved tailnets (a client lives in exactly one).
		// Revoke what we know about and mint fresh.
		//
		// But not for a credential being deleted. Its owned Secret goes as
		// soon as the deletion starts, while the cache may not show the
		// deletion yet: this branch then minted a client the finalizer never
		// heard of, and nothing ever revoked it. Check live.
		live := &tsv1alpha1.TailscaleCredential{}
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(cred), live); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		if !live.DeletionTimestamp.IsZero() {
			return r.finalize(ctx, live)
		}
		if clientID != "" {
			if err := provisionedAPI.DeleteKey(ctx, clientID); err != nil && !tailscale.IsNotFound(err) {
				return r.setNotReady(ctx, cred, "ProvisioningFailed",
					fmt.Sprintf("revoking OAuth client %s in tailnet %s before re-provisioning: %v", clientID, provisionedName, err))
			}
			logger.Info("revoked OAuth client before re-provisioning", "clientID", clientID, "tailnet", provisionedName)
		}
		key, err := api.CreateOAuthClient(ctx, tailscale.CreateOAuthClientRequest{
			Scopes:      oauthClientScopes,
			Tags:        spec.Tags,
			Description: spec.Description,
		})
		if err != nil {
			return r.setNotReady(ctx, cred, "ProvisioningFailed",
				fmt.Sprintf("creating Tailscale OAuth client in tailnet %s: %v", tailnetName, err))
		}
		clientID, baseKey = key.ID, key.Key
		// Record the ID (and where it lives) before writing the Secret: if
		// the write fails, the next reconcile revokes and re-mints instead
		// of leaking the client.
		cred.Status.OAuthClientID = clientID
		cred.Status.Tailnet = tailnetName
		cred.Status.ProvisionedTags = spec.Tags
		if err := r.Status().Update(ctx, cred); err != nil {
			// Unrecorded, nothing would ever revoke it: revoke it now, and
			// let the retry mint again.
			if derr := api.DeleteKey(ctx, clientID); derr != nil && !tailscale.IsNotFound(derr) {
				logger.Error(derr, "an OAuth client whose ID could not be recorded is still live; revoke it by hand",
					"clientID", clientID, "tailnet", tailnetName)
			} else {
				logger.Info("revoked an OAuth client whose ID could not be recorded", "clientID", clientID, "tailnet", tailnetName)
			}
			return ctrl.Result{}, err
		}

	case !slices.Equal(spec.Tags, cred.Status.ProvisionedTags):
		// Tag drift: update the OAuth client in place — the secret (and so
		// every running node) is unaffected.
		if _, err := api.SetOAuthClient(ctx, clientID, tailscale.SetOAuthClientRequest{
			Scopes:      oauthClientScopes,
			Tags:        spec.Tags,
			Description: spec.Description,
		}); err != nil {
			return r.setNotReady(ctx, cred, "ProvisioningFailed",
				fmt.Sprintf("updating OAuth client %s tags: %v", clientID, err))
		}
		logger.Info("updated OAuth client tags", "clientID", clientID, "tags", spec.Tags)
	}

	if err := r.ensureSecret(ctx, cred, spec, secretFound, secret, clientID, baseKey); err != nil {
		return ctrl.Result{}, fmt.Errorf("ensuring secret %s/%s: %w", cred.Namespace, spec.SecretName, err)
	}

	meta.SetStatusCondition(&cred.Status.Conditions, metav1.Condition{
		Type:               condReady,
		Status:             metav1.ConditionTrue,
		Reason:             reason,
		Message:            fmt.Sprintf("secret %s holds OAuth client %s (tailnet %s)", spec.SecretName, clientID, tailnetName),
		ObservedGeneration: cred.Generation,
	})
	cred.Status.OAuthClientID = clientID
	cred.Status.Tailnet = tailnetName
	cred.Status.SecretName = spec.SecretName
	cred.Status.ProvisionedTags = spec.Tags
	cred.Status.ObservedGeneration = cred.Generation
	return ctrl.Result{}, r.Status().Update(ctx, cred)
}

func (r *TailscaleCredentialReconciler) setNotReady(ctx context.Context, cred *tsv1alpha1.TailscaleCredential, reason, message string) (ctrl.Result, error) {
	logf.FromContext(ctx).Info("credential not ready", "reason", reason, "message", message)
	meta.SetStatusCondition(&cred.Status.Conditions, metav1.Condition{
		Type:               condReady,
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: cred.Generation,
	})
	cred.Status.ObservedGeneration = cred.Generation
	if err := r.Status().Update(ctx, cred); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: waitRequeue}, nil
}

// finalize revokes the OAuth client this credential minted (or adopted —
// the CR owns the client's lifecycle either way). The delivered Secret is
// ownerReferenced and garbage-collected by Kubernetes.
func (r *TailscaleCredentialReconciler) finalize(ctx context.Context, cred *tsv1alpha1.TailscaleCredential) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(cred, finalizerName) {
		return ctrl.Result{}, nil
	}
	if id := cred.Status.OAuthClientID; id != "" {
		// A tailnet dropped from the operator's config blocks deletion here
		// rather than silently leaking a live OAuth client: restore the
		// config entry, or remove the finalizer by hand if the tailnet
		// itself is gone (deleting a tailnet revokes everything in it).
		api, tailnetName, err := r.Tailnets.API(cred.Status.Tailnet)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("cannot revoke OAuth client %s: %w", id, err)
		}
		if err := api.DeleteKey(ctx, id); err != nil && !tailscale.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("revoking OAuth client %s in tailnet %s: %w", id, tailnetName, err)
		}
		logf.FromContext(ctx).Info("revoked OAuth client", "clientID", id, "tailnet", tailnetName)
	}
	controllerutil.RemoveFinalizer(cred, finalizerName)
	return ctrl.Result{}, r.Update(ctx, cred)
}

// ensureSecret writes the delivered Secret: oauth.id plus oauth.secret with
// the ephemeral suffix re-derived from spec. Pre-existing Secrets of the
// same name are adopted (labels and ownerReference added). No-op writes are
// skipped so the Owns watch does not feed back into reconciliation.
func (r *TailscaleCredentialReconciler) ensureSecret(ctx context.Context, cred *tsv1alpha1.TailscaleCredential, spec tsv1alpha1.TailscaleCredentialSpec, found bool, existing *corev1.Secret, clientID, baseKey string) error {
	secretValue := baseKey
	if spec.Ephemeral != nil {
		secretValue += "?ephemeral=" + strconv.FormatBool(*spec.Ephemeral)
	}
	data := map[string][]byte{
		oauthIDKey:     []byte(clientID),
		oauthSecretKey: []byte(secretValue),
	}

	if !found {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: cred.Namespace,
				Name:      spec.SecretName,
				Labels: map[string]string{
					managedByLabel:                managedByValue,
					credentialLabel:               cred.Name,
					tsv1alpha1.WatchedSecretLabel: tsv1alpha1.WatchedSecretLabelValue,
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: data,
		}
		if err := controllerutil.SetControllerReference(cred, secret, r.Scheme()); err != nil {
			return err
		}
		return r.Create(ctx, secret)
	}

	updated := existing.DeepCopy()
	if updated.Labels == nil {
		updated.Labels = map[string]string{}
	}
	updated.Labels[managedByLabel] = managedByValue
	updated.Labels[credentialLabel] = cred.Name
	// The label the scoped Secret informer selects on — without it the
	// Owns watch never sees this Secret.
	updated.Labels[tsv1alpha1.WatchedSecretLabel] = tsv1alpha1.WatchedSecretLabelValue
	updated.Data = data
	if err := controllerutil.SetControllerReference(cred, updated, r.Scheme()); err != nil {
		return err
	}
	if maps.Equal(updated.Labels, existing.Labels) &&
		maps.EqualFunc(updated.Data, existing.Data, slices.Equal) &&
		len(updated.OwnerReferences) == len(existing.OwnerReferences) {
		return nil
	}
	return r.Update(ctx, updated)
}

// SetupWithManager wires the watches: the CRs themselves and the delivered
// Secrets (owned → drift repair and ownerRef GC).
func (r *TailscaleCredentialReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&tsv1alpha1.TailscaleCredential{}).
		Owns(&corev1.Secret{}).
		Named("tailscalecredential").
		Complete(r)
}
