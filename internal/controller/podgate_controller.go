package controller

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsv1alpha1 "github.com/davefinster/tsinject/api/v1alpha1"
)

// PodGateReconciler serves pods the admission webhook parked behind the
// tsinject scheduling gate. It plays the role the workload author plays in
// a hand-driven operator: it materializes the demand the pod's annotations
// express — the TailscaleCredential itself (created on first use), the
// serve/config ConfigMaps, the tailscaled state-secret RBAC — and removes
// the gate once the credential is Ready. This is the async half of the
// "admit now, proceed when provisioned" deferral: admission never waits and
// never writes.
//
// A pod of a federated tailnet has no credential: it is gated only for its
// state Secret's RBAC, which is provisioned for it (owned by its Deployment,
// when it has one), and then released.
type PodGateReconciler struct {
	client.Client
	// APIReader reads live where the cache would mislead: workload owner
	// chains and ensure-style existence checks on uncached kinds.
	APIReader client.Reader
	// Tailnets says which tailnets are federated; nil means none are.
	Tailnets *TailnetRegistry
}

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;create;update;patch
// +kubebuilder:rbac:groups="rbac.authorization.k8s.io",resources=roles;rolebindings,verbs=get;create;update;patch
// +kubebuilder:rbac:groups="apps",resources=deployments;replicasets,verbs=get
// +kubebuilder:rbac:groups=tsinject.dmf.zone,resources=tailscalecredentials,verbs=get;list;watch;create

func hasTailscaleGate(pod *corev1.Pod) bool {
	for _, gate := range pod.Spec.SchedulingGates {
		if gate.Name == tsv1alpha1.PodGateName {
			return true
		}
	}
	return false
}

// owningDeployment walks pod → ReplicaSet → Deployment. A broken or absent
// chain is not an error — the pod simply is not Deployment-managed.
func owningDeployment(ctx context.Context, reader client.Reader, namespace string, pod *corev1.Pod) (*appsv1.Deployment, error) {
	var rsName string
	for _, owner := range pod.OwnerReferences {
		if owner.Kind == "ReplicaSet" {
			rsName = owner.Name
		}
	}
	if rsName == "" {
		return nil, nil
	}
	rs := &appsv1.ReplicaSet{}
	if err := reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: rsName}, rs); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("fetching owning ReplicaSet %s: %w", rsName, err)
	}
	var depName string
	for _, owner := range rs.OwnerReferences {
		if owner.Kind == "Deployment" {
			depName = owner.Name
		}
	}
	if depName == "" {
		return nil, nil
	}
	dep := &appsv1.Deployment{}
	if err := reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: depName}, dep); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("fetching owning Deployment %s: %w", depName, err)
	}
	return dep, nil
}

// ResolveWorkloadIdentity returns the shared identifier a pod groups under
// — the name of its TailscaleCredential, Secrets and ConfigMaps: the
// tailscale-shared-name annotation, else the owning Deployment, else the
// pod itself. The Deployment is returned when it was resolved so callers
// can tie lifecycles to it.
func ResolveWorkloadIdentity(ctx context.Context, reader client.Reader, namespace string, pod *corev1.Pod) (string, *appsv1.Deployment, error) {
	if name := pod.Annotations[tsv1alpha1.SharedNameAnnotation]; name != "" {
		return name, nil, nil
	}
	dep, err := owningDeployment(ctx, reader, namespace, pod)
	if err != nil {
		return "", nil, err
	}
	if dep != nil {
		return dep.Name, dep, nil
	}
	if pod.Name != "" {
		return pod.Name, nil, nil
	}
	return strings.TrimSuffix(pod.GenerateName, "-"), nil, nil
}

func (r *PodGateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	pod := &corev1.Pod{}
	if err := r.Get(ctx, req.NamespacedName, pod); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !hasTailscaleGate(pod) || !pod.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	name := pod.Annotations[tsv1alpha1.CredentialAnnotation]
	var dep *appsv1.Deployment
	if name == "" {
		// The webhook always stamps the annotation; tolerate its absence by
		// re-deriving the identity the same way it would have.
		var err error
		if name, dep, err = ResolveWorkloadIdentity(ctx, r.APIReader, pod.Namespace, pod); err != nil {
			return ctrl.Result{}, err
		}
		if name == "" {
			return ctrl.Result{}, nil // nothing to bind to; stays gated
		}
	}

	if r.Tailnets != nil && r.Tailnets.Federated(TailnetForPod(pod)) {
		return r.releaseFederated(ctx, pod, name, dep)
	}

	cred := &tsv1alpha1.TailscaleCredential{}
	err := r.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: name}, cred)
	switch {
	case apierrors.IsNotFound(err):
		if cred, err = r.createCredential(ctx, pod, name, dep); err != nil {
			return ctrl.Result{}, err
		}
	case err != nil:
		return ctrl.Result{}, err
	default:
		// An existing credential must follow the pod's annotations, not just
		// seed from them: a workload changing its tailscale-tailnet or
		// tailscale-tags rolls new (gated) pods, and without this sync the
		// stale-but-Ready credential ungates them onto the old tailnet.
		// Updating the spec hands the drift to the credential
		// controller — a tailnet move revokes and re-mints, a tag change
		// updates the OAuth client in place — and the pod stays gated until
		// Ready reflects the new spec.
		if synced, err := r.syncCredentialSpec(ctx, pod, cred); err != nil {
			return ctrl.Result{}, err
		} else if synced {
			return ctrl.Result{}, nil // the credential watch re-enqueues on Ready
		}
	}

	if err := r.ensureConfigMaps(ctx, pod, cred); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.ensureStateRBAC(ctx, pod, cred.Name, cred); err != nil {
		return ctrl.Result{}, err
	}

	if !CredentialReady(cred) {
		return ctrl.Result{}, nil // the credential watch re-enqueues on Ready
	}

	if err := r.releaseGate(ctx, pod); err != nil {
		return ctrl.Result{}, err
	}
	logf.FromContext(ctx).Info("released scheduling gate", "pod", req.NamespacedName, "tailscaleCredential", cred.Name)
	return ctrl.Result{}, nil
}

// releaseFederated provisions what a federated pod needs -- its state
// Secret's RBAC, if any; never a TailscaleCredential -- and releases it.
func (r *PodGateReconciler) releaseFederated(ctx context.Context, pod *corev1.Pod, name string, dep *appsv1.Deployment) (ctrl.Result, error) {
	var owner client.Object
	if NeedsStateSecret(pod) {
		if dep == nil {
			var err error
			if dep, err = owningDeployment(ctx, r.APIReader, pod.Namespace, pod); err != nil {
				return ctrl.Result{}, err
			}
		}
		if dep != nil && dep.Name == name {
			owner = dep
		}
	}
	if err := r.ensureStateRBAC(ctx, pod, name, owner); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.releaseGate(ctx, pod); err != nil {
		return ctrl.Result{}, err
	}
	logf.FromContext(ctx).Info("released scheduling gate (federated)", "pod", client.ObjectKeyFromObject(pod), "identity", pod.Annotations[tsv1alpha1.ClientIDAnnotation])
	return ctrl.Result{}, nil
}

func (r *PodGateReconciler) releaseGate(ctx context.Context, pod *corev1.Pod) error {
	pod.Spec.SchedulingGates = slices.DeleteFunc(pod.Spec.SchedulingGates, func(gate corev1.PodSchedulingGate) bool {
		return gate.Name == tsv1alpha1.PodGateName
	})
	return r.Update(ctx, pod)
}

// syncCredentialSpec folds a gated pod's annotation-derived demands into its
// existing TailscaleCredential, reporting whether an update was written. All
// comparisons are canonical so a sync is one-shot: the update event re-enqueues
// the gated pods, and the next reconcile finds no drift.
func (r *PodGateReconciler) syncCredentialSpec(ctx context.Context, pod *corev1.Pod, cred *tsv1alpha1.TailscaleCredential) (bool, error) {
	if !applyPodDemands(pod, &cred.Spec) {
		return false, nil
	}
	if err := r.Update(ctx, cred); err != nil {
		return false, err
	}
	logf.FromContext(ctx).Info("synced credential spec from pod annotations",
		"tailscaleCredential", cred.Name, "namespace", cred.Namespace,
		"tags", cred.Spec.Tags, "tailnet", cred.Spec.Tailnet)
	return true, nil
}

// applyPodDemands folds the tags, tailnet and ephemeral flag a pod's
// annotations demand into spec, reporting whether anything changed. The
// ephemeral flag only folds in when the pod expresses one — an absent
// annotation means unset, not false.
func applyPodDemands(pod *corev1.Pod, spec *tsv1alpha1.TailscaleCredentialSpec) bool {
	changed := false
	if tags := TagsForPod(pod); !slices.Equal(normalizeTags(spec.Tags), tags) {
		spec.Tags = tags
		changed = true
	}
	if tailnet := TailnetForPod(pod); spec.Tailnet != tailnet {
		spec.Tailnet = tailnet
		changed = true
	}
	if ephemeral := EphemeralForPod(pod); ephemeral != nil && (spec.Ephemeral == nil || *spec.Ephemeral != *ephemeral) {
		spec.Ephemeral = ephemeral
		changed = true
	}
	return changed
}

// CredentialMatchesPod reports whether cred's spec already carries what the
// pod's annotations demand. Admission gates a pod when it does not: the
// sidecar advertises the pod's tags, not the credential's, and an OAuth
// client minted for other tags or another tailnet refuses it.
func CredentialMatchesPod(pod *corev1.Pod, cred *tsv1alpha1.TailscaleCredential) bool {
	return !applyPodDemands(pod, cred.Spec.DeepCopy())
}

// CredentialReady reports whether cred is Ready for the spec it has now, not
// an earlier one. A spec update leaves the previous generation's Ready=True in
// place until the credential controller has re-provisioned, and the update
// that syncCredentialSpec writes re-enqueues the gated pod at once — trusting
// that condition released pods onto the OAuth client the spec had just left.
func CredentialReady(cred *tsv1alpha1.TailscaleCredential) bool {
	cond := meta.FindStatusCondition(cred.Status.Conditions, tsv1alpha1.ReadyCondition)
	return cond != nil && cond.Status == metav1.ConditionTrue && cond.ObservedGeneration == cred.Generation
}

// createCredential materializes the TailscaleCredential a pod's annotations
// demand. When the credential is named after the pod's Deployment, an
// ownerReference ties their lifecycles: deleting the workload revokes the
// OAuth client (via the credential finalizer) and its Secret.
func (r *PodGateReconciler) createCredential(ctx context.Context, pod *corev1.Pod, name string, dep *appsv1.Deployment) (*tsv1alpha1.TailscaleCredential, error) {
	if dep == nil {
		var err error
		if dep, err = owningDeployment(ctx, r.APIReader, pod.Namespace, pod); err != nil {
			return nil, err
		}
	}
	cred := &tsv1alpha1.TailscaleCredential{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: pod.Namespace,
			Name:      name,
			Labels:    map[string]string{managedByLabel: managedByValue},
		},
		Spec: tsv1alpha1.TailscaleCredentialSpec{
			Tags:      TagsForPod(pod),
			Tailnet:   TailnetForPod(pod),
			Ephemeral: EphemeralForPod(pod),
		},
	}
	if dep != nil && dep.Name == name {
		if err := controllerutil.SetOwnerReference(dep, cred, r.Scheme()); err != nil {
			return nil, err
		}
	}
	if err := r.Create(ctx, cred); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// A sibling replica won the race (or the cache lagged): use the
			// live object.
			existing := &tsv1alpha1.TailscaleCredential{}
			if gerr := r.APIReader.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: name}, existing); gerr == nil {
				return existing, nil
			}
		}
		return nil, err
	}
	logf.FromContext(ctx).Info("created TailscaleCredential for pod",
		"tailscaleCredential", name, "namespace", pod.Namespace, "tags", cred.Spec.Tags, "tailnet", cred.Spec.Tailnet)
	return cred, nil
}

// ensureConfigMaps materializes the serve.json / config.json ConfigMaps the
// webhook mounted, keyed off the same annotations. Content follows the
// annotation (last reconciled pod wins, as with the pre-operator injector).
func (r *PodGateReconciler) ensureConfigMaps(ctx context.Context, pod *corev1.Pod, cred *tsv1alpha1.TailscaleCredential) error {
	if value, ok := pod.Annotations[tsv1alpha1.ServeConfigAnnotation]; ok {
		if err := r.ensureConfigMap(ctx, cred, ServeConfigMapName(cred.Name), "serve.json", value); err != nil {
			return err
		}
	}
	if value, ok := pod.Annotations[tsv1alpha1.ConfigJSONAnnotation]; ok {
		if err := r.ensureConfigMap(ctx, cred, JSONConfigMapName(cred.Name), "config.json", value); err != nil {
			return err
		}
	}
	return nil
}

func (r *PodGateReconciler) ensureConfigMap(ctx context.Context, cred *tsv1alpha1.TailscaleCredential, name, key, value string) error {
	cm := &corev1.ConfigMap{}
	err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: cred.Namespace, Name: name}, cm)
	if apierrors.IsNotFound(err) {
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: cred.Namespace,
				Name:      name,
				Labels:    map[string]string{managedByLabel: managedByValue, credentialLabel: cred.Name},
			},
			Data: map[string]string{key: value},
		}
		if err := controllerutil.SetControllerReference(cred, cm, r.Scheme()); err != nil {
			return err
		}
		return r.Create(ctx, cm)
	}
	if err != nil {
		return err
	}
	if cm.Data[key] == value && cm.Labels[credentialLabel] == cred.Name {
		return nil
	}
	updated := cm.DeepCopy()
	if updated.Labels == nil {
		updated.Labels = map[string]string{}
	}
	updated.Labels[managedByLabel] = managedByValue
	updated.Labels[credentialLabel] = cred.Name
	if updated.Data == nil {
		updated.Data = map[string]string{}
	}
	updated.Data[key] = value
	if err := controllerutil.SetControllerReference(cred, updated, r.Scheme()); err != nil {
		return err
	}
	return r.Update(ctx, updated)
}

// ensureStateRBAC grants the pod's ServiceAccount access to its tailscaled
// state Secret (create, then read/update by name) — the permissions
// containerboot needs for TS_KUBE_SECRET. The rules also repair Roles
// mangled by the pre-operator injector, which scoped them to the Role's own
// name instead of the Secret's. The objects are named for identifier and
// controlled by owner (the credential, or a federated pod's Deployment);
// a nil owner leaves them unowned.
func (r *PodGateReconciler) ensureStateRBAC(ctx context.Context, pod *corev1.Pod, identifier string, owner client.Object) error {
	if !NeedsStateSecret(pod) {
		return nil
	}
	setOwner := func(obj client.Object) error {
		if owner == nil || reflect.ValueOf(owner).IsNil() {
			return nil
		}
		return controllerutil.SetControllerReference(owner, obj, r.Scheme())
	}
	roleName := StateRoleName(identifier)
	desiredRules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups:     []string{""},
			ResourceNames: []string{StateSecretName(identifier)},
			Resources:     []string{"secrets"},
			Verbs:         []string{"get", "update", "patch"},
		},
	}

	role := &rbacv1.Role{}
	err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: roleName}, role)
	switch {
	case apierrors.IsNotFound(err):
		role = &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: pod.Namespace,
				Name:      roleName,
				Labels:    map[string]string{managedByLabel: managedByValue, credentialLabel: identifier},
			},
			Rules: desiredRules,
		}
		if err := setOwner(role); err != nil {
			return err
		}
		if err := r.Create(ctx, role); err != nil {
			return err
		}
	case err != nil:
		return err
	case !reflect.DeepEqual(role.Rules, desiredRules):
		updated := role.DeepCopy()
		updated.Rules = desiredRules
		if err := r.Update(ctx, updated); err != nil {
			return err
		}
	}

	bindingName := StateRoleBindingName(identifier)
	subject := rbacv1.Subject{
		Kind:      rbacv1.ServiceAccountKind,
		Name:      pod.Spec.ServiceAccountName,
		Namespace: pod.Namespace,
	}
	binding := &rbacv1.RoleBinding{}
	err = r.APIReader.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: bindingName}, binding)
	switch {
	case apierrors.IsNotFound(err):
		binding = &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: pod.Namespace,
				Name:      bindingName,
				Labels:    map[string]string{managedByLabel: managedByValue, credentialLabel: identifier},
			},
			Subjects: []rbacv1.Subject{subject},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "Role",
				Name:     roleName,
			},
		}
		if err := setOwner(binding); err != nil {
			return err
		}
		return r.Create(ctx, binding)
	case err != nil:
		return err
	case !slices.Contains(binding.Subjects, subject):
		// Another ServiceAccount under the same shared identifier: add it
		// (roleRef is immutable, so only subjects are reconciled).
		updated := binding.DeepCopy()
		updated.Subjects = append(updated.Subjects, subject)
		return r.Update(ctx, updated)
	}
	return nil
}

// mapCredentialToGatedPods re-enqueues every gated pod bound to a
// credential when it changes (typically: becomes Ready).
func (r *PodGateReconciler) mapCredentialToGatedPods(ctx context.Context, obj client.Object) []reconcile.Request {
	pods := &corev1.PodList{}
	if err := r.List(ctx, pods, client.InNamespace(obj.GetNamespace())); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range pods.Items {
		pod := &pods.Items[i]
		if hasTailscaleGate(pod) && pod.Annotations[tsv1alpha1.CredentialAnnotation] == obj.GetName() {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: pod.Namespace, Name: pod.Name,
			}})
		}
	}
	return reqs
}

func (r *PodGateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	onlyGated := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		pod, ok := obj.(*corev1.Pod)
		return ok && hasTailscaleGate(pod)
	})
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}, builder.WithPredicates(onlyGated)).
		Watches(&tsv1alpha1.TailscaleCredential{}, handler.EnqueueRequestsFromMapFunc(r.mapCredentialToGatedPods)).
		Named("podgate").
		Complete(r)
}
