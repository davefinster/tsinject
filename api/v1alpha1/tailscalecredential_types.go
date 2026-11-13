package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Pod-facing contract shared by the admission webhook and the controllers.
const (
	// InjectLabel opts a pod into webhook mutation (objectSelector match,
	// value InjectLabelValue). Kept from the pre-operator injector so
	// existing workloads keep working unchanged.
	InjectLabel      = "inject-tailscale"
	InjectLabelValue = "true"

	// CredentialAnnotation names the TailscaleCredential a pod binds to;
	// stamped by the webhook from the resolved shared identifier
	// (tailscale-shared-name annotation, else owning Deployment, else pod).
	CredentialAnnotation = "tsinject.dmf.zone/credential"

	// PodGateName is the scheduling gate the webhook injects while the
	// cluster state a pod depends on (credential Secret, config ConfigMaps,
	// state-secret RBAC) is not in place yet; the gate controller removes it.
	PodGateName = "tsinject.dmf.zone/awaiting-credential"

	// WatchedSecretLabel (value WatchedSecretLabelValue) marks the few
	// Secrets the operator watches: delivered credentials and the webhook
	// cert. The manager's cluster-wide Secret informer is scoped to this
	// label so cache memory is bounded by what the operator owns, not by
	// every Secret in the cluster (helm release blobs, etc.).
	WatchedSecretLabel      = "tsinject.dmf.zone/watched"
	WatchedSecretLabelValue = "true"

	// ReadyCondition is the TailscaleCredential status condition type.
	ReadyCondition = "Ready"
)

// Author-facing pod annotations — the pre-operator injection contract,
// preserved verbatim.
const (
	// TagsAnnotation is a comma-separated list of Tailscale tags (without
	// the "tag:" prefix); tag:injected is always added.
	TagsAnnotation = "tailscale-tags"
	// EphemeralAnnotation ("true"/"false") controls node ephemerality: the
	// value is appended to the OAuth secret as ?ephemeral=... and switches
	// the sidecar to in-memory state.
	EphemeralAnnotation = "tailscale-ephemeral"
	// TailnetAnnotation names the operator-configured tailnet the workload's
	// OAuth client is minted in; absent means the nominated default.
	TailnetAnnotation = "tailscale-tailnet"
	// CustomImageAnnotation overrides the injected tailscale image.
	CustomImageAnnotation = "tailscale-custom-image"
	// PrivilegedAnnotation ("true") runs the tailscale container privileged.
	PrivilegedAnnotation = "tailscale-privileged"
	// SharedNameAnnotation overrides the shared identifier pods group under
	// (one TailscaleCredential, Secret and config set per identifier).
	SharedNameAnnotation = "tailscale-shared-name"
	// EnvAnnotation carries newline-separated NAME=VALUE pairs merged into
	// the tailscale container env (values append space-separated when the
	// name already exists, e.g. to extend TS_EXTRA_ARGS).
	EnvAnnotation = "tailscale-env"
	// ServeConfigAnnotation holds a serve.json document materialized as a
	// ConfigMap and mounted via TS_SERVE_CONFIG.
	ServeConfigAnnotation = "tailscale-serve-config"
	// ConfigJSONAnnotation holds a tailscaled config.json document
	// materialized as a ConfigMap and passed via --config.
	ConfigJSONAnnotation = "tailscale-config-json"
	// SharedSocketMountAnnotation names an author-defined volume to share
	// the tailscaled socket through (mounted at /socket).
	SharedSocketMountAnnotation = "tailscale-shared-socket-mount"
	// AdvertiseServicesAnnotation is a comma-separated list of Tailscale
	// services an injected helper container advertises.
	AdvertiseServicesAnnotation = "tailscale-advertise-services"
	// ServiceHostProbeAnnotation set to "false" leaves out the sidecar's service-host liveness probe, which a pod
	// that advertises Tailscale Services otherwise gets (see the webhook's serviceHostProbe).
	ServiceHostProbeAnnotation = "tailscale-service-host-probe"
	// SkipAdvertiseContainerAnnotation ("true") suppresses the advertise
	// helper container even when services are listed.
	SkipAdvertiseContainerAnnotation = "tailscale-advertise-services-skip-advertise-container"
	// ResourcesAnnotation overrides the injected sidecar's resources with a
	// JSON ResourceRequirements document:
	//
	//	{"requests":{"cpu":"500m","memory":"512Mi"},"limits":{"memory":"2Gi"}}
	//
	// Whichever of requests and limits it names replaces that map whole
	// rather than merging, so a value can also *remove* a default: limits
	// naming only memory leaves the sidecar's CPU uncapped. That is what a
	// pod moving data at line rate wants, because the tunnel's encryption
	// is this container's CPU and a ceiling on it is a ceiling on
	// throughput. A document that does not parse, or that carries a
	// quantity Kubernetes will not accept, is refused at admission rather
	// than quietly ignored.
	ResourcesAnnotation = "tailscale-resources"

	// ClientIDAnnotation names the workload's Tailscale federated identity --
	// its client ID -- for a tailnet in federated credential mode. The
	// sidecar exchanges the pod's own service-account token for that
	// identity when it joins, so nothing is minted, delivered or revoked:
	// no TailscaleCredential, no Secret, no scheduling gate. Required on
	// every pod of a federated tailnet. The ?ephemeral= attribute is not
	// part of it; tailscale-ephemeral decides that, as it always has.
	ClientIDAnnotation = "tailscale-client-id"
	// AudienceAnnotation is that identity's audience: the projected
	// service-account token the sidecar presents is issued for it, and
	// Tailscale refuses a token for any other. Required with
	// ClientIDAnnotation.
	AudienceAnnotation = "tailscale-audience"
)

// TailscaleCredentialSpec declares a Tailscale OAuth client scoped to a
// workload identity. The operator materializes it: an OAuth client minted
// via the Tailscale API, delivered as a Secret in this namespace in the
// shape the injected sidecar expects (oauth.id / oauth.secret).
type TailscaleCredentialSpec struct {
	// Tags are the full Tailscale ACL tags ("tag:...") the OAuth client may
	// assign. tag:injected is always included; defaults to exactly that.
	// +optional
	Tags []string `json:"tags,omitempty"`

	// Tailnet names the operator-configured tailnet the OAuth client is
	// minted in. Empty selects the operator's nominated default (and stays
	// pinned to whatever status records, so re-nominating the default never
	// re-homes existing clients). Changing it revokes the client and mints a
	// replacement in the new tailnet.
	// +optional
	Tailnet string `json:"tailnet,omitempty"`

	// Ephemeral appends ?ephemeral=<value> to the delivered OAuth secret so
	// nodes register (non-)ephemeral explicitly. Unset leaves the tailscaled
	// default.
	// +optional
	Ephemeral *bool `json:"ephemeral,omitempty"`

	// SecretName is the name of the Secret created in this namespace.
	// Defaults to "<name>-ts-credential", which is what the webhook mounts.
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// Description labels the OAuth client in the Tailscale admin console.
	// Defaults to the object name.
	// +optional
	Description string `json:"description,omitempty"`
}

// TailscaleCredentialStatus is the operator's view of how far provisioning
// has converged.
type TailscaleCredentialStatus struct {
	// Conditions — the standard Ready condition carries the state machine:
	// ProvisioningFailed while the Tailscale API call errors, Provisioned
	// (or Adopted) once the namespace Secret is in place.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// OAuthClientID is the Tailscale key ID of the minted OAuth client —
	// what the finalizer revokes on deletion.
	// +optional
	OAuthClientID string `json:"oauthClientID,omitempty"`

	// Tailnet is the configured tailnet the OAuth client was provisioned in
	// — where revocations (finalizer, re-mints) are sent. Empty on
	// credentials provisioned before multi-tailnet support; treated as the
	// default.
	// +optional
	Tailnet string `json:"tailnet,omitempty"`

	// SecretName is the resolved name of the delivered Secret.
	// +optional
	SecretName string `json:"secretName,omitempty"`

	// ProvisionedTags are the tags the OAuth client currently carries;
	// drift against spec.tags triggers an in-place update.
	// +optional
	ProvisionedTags []string `json:"provisionedTags,omitempty"`

	// ObservedGeneration is the spec generation last acted upon.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=tscred
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.status.secretName`
// +kubebuilder:printcolumn:name="ClientID",type=string,JSONPath=`.status.oauthClientID`
// +kubebuilder:printcolumn:name="Tailnet",type=string,JSONPath=`.status.tailnet`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TailscaleCredential provisions a Tailscale OAuth client for one workload
// identity, delivered as a Secret consumable by the injected sidecar.
// Normally created on demand by the pod gate controller from pod
// annotations; may also be authored directly.
type TailscaleCredential struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TailscaleCredentialSpec   `json:"spec,omitempty"`
	Status TailscaleCredentialStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TailscaleCredentialList contains a list of TailscaleCredential.
type TailscaleCredentialList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TailscaleCredential `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TailscaleCredential{}, &TailscaleCredentialList{})
}
