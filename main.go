// Command tsinject runs the Tailscale injection operator:
//
//   - the pod admission webhook (opt-in via the inject-tailscale=true
//     label): injects the tailscale sidecar machinery driven by the
//     tailscale-* pod annotations and, while the workload's credential is
//     still being provisioned, parks the pod behind a scheduling gate —
//     admission itself never writes and never calls the Tailscale API;
//   - the TailscaleCredential controller: mints a per-workload OAuth client
//     via the Tailscale API and delivers it as a namespace-local Secret
//     (revoking the client again when the credential is deleted);
//   - the pod gate controller: creates TailscaleCredentials (and config
//     ConfigMaps and state-secret RBAC) on demand for gated pods, then
//     lifts the gate once the credential is Ready and the scheduler takes
//     over;
//   - a cert-controller rotator (the Gatekeeper pattern): the webhook's CA
//     and serving certificate are self-managed in a Secret and the CA
//     bundle is patched into the webhook configuration — no cert-manager
//     needed.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	crwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	tailscale "tailscale.com/client/tailscale/v2"

	tsv1alpha1 "github.com/davefinster/tsinject/api/v1alpha1"
	"github.com/davefinster/tsinject/internal/controller"
	tswebhook "github.com/davefinster/tsinject/internal/webhook"
)

// Names wired to config/install.yaml.
const (
	webhookCertSecret     = "tsinject-webhook-cert"
	mutatingWebhookConfig = "tsinject-mutating"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(tsv1alpha1.AddToScheme(scheme))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// loadTailnets reads the operator's credential file and builds the tailnet
// registry: one admin API client per configured tailnet, one nominated as
// the default. Both file shapes are accepted — the pre-operator single
// client ({"client_id": ..., "client_secret": ...}, addressed at
// legacyTailnet) and the multi-tailnet map (see controller.ParseTailnetsConfig).
func loadTailnets(path, legacyTailnet string) (*controller.TailnetRegistry, error) {
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading credentials file %q: %w", path, err)
	}
	defaultName, configs, err := controller.ParseTailnetsConfig(fileBytes, legacyTailnet)
	if err != nil {
		return nil, fmt.Errorf("credentials file %q: %w", path, err)
	}
	apis := map[string]controller.TailscaleAPI{}
	federated := map[string]bool{}
	for _, tc := range configs {
		if tc.Federated {
			federated[tc.Name] = true
		}
		if tc.ClientID == "" {
			continue // federated, with no admin client
		}
		apis[tc.Name] = controller.KeysAPI{Client: &tailscale.Client{
			Tailnet: tc.Tailnet,
			Auth: &tailscale.OAuth{
				ClientID:     tc.ClientID,
				ClientSecret: tc.ClientSecret,
				Scopes:       []string{"all:write"},
			},
		}}
	}
	return controller.NewTailnetRegistry(defaultName, apis, federated)
}

func main() {
	var (
		metricsAddr    string
		probeAddr      string
		leaderElect    bool
		enableWebhook  bool
		tailnet        string
		credentialPath string
		tailscaleImage string
		kataTun        string
		webhookService string
		certDir        string
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0",
		"Metrics endpoint bind address (\"0\" disables metrics).")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081",
		"Health/readiness probe bind address.")
	flag.BoolVar(&leaderElect, "leader-elect", false,
		"Enable leader election (needed only when running more than one replica).")
	flag.BoolVar(&enableWebhook, "enable-webhook", true,
		"Serve the pod admission webhook (requires the Service and webhook configuration from install.yaml).")
	flag.StringVar(&tailnet, "tailnet", envOr("TAILNET", "-"),
		"Tailnet to attach workloads to when the credential file is the legacy single-client shape (\"-\" is the credential's own tailnet); ignored when it configures tailnets explicitly.")
	flag.StringVar(&credentialPath, "tailscale-credential-path", envOr("TAILSCALE_CREDENTIAL_PATH", "/tailscale/secret.json"),
		"Path to the JSON credentials file: either the operator's single Tailscale OAuth client_id/client_secret, or a map of named tailnets each with its own tailnet and OAuth client plus a nominated default.")
	flag.StringVar(&tailscaleImage, "tailscale-image", envOr("TAILSCALE_IMAGE", "ghcr.io/tailscale/tailscale:latest"),
		"Tailscale image the webhook injects (pods override via the tailscale-custom-image annotation).")
	flag.StringVar(&kataTun, "kata-tun-resource", envOr("KATA_TUN_RESOURCE", ""),
		"Extended resource the sidecar of a pod under a Kata runtime class (runtimeClassName kata*) requests, so that a device plugin hands /dev/net/tun into the guest VM (e.g. squat.ai/tun from squat's generic-device-plugin). Empty requests nothing.")
	flag.StringVar(&webhookService, "webhook-service-name", "tsinject-webhook",
		"Service name in front of the webhook (drives the serving cert's DNS name).")
	flag.StringVar(&certDir, "cert-dir", "/certs",
		"Directory the cert rotator writes the webhook serving certificate to.")
	zapOpts := zap.Options{}
	zapOpts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapOpts)))
	setupLog := ctrl.Log.WithName("setup")
	operatorNamespace := envOr("OPERATOR_NAMESPACE", "tsinject-system")
	// A malformed name would get every Kata pod's patch refused by the API
	// server, so it fails here instead.
	if kataTun != "" && (!strings.Contains(kataTun, "/") || len(validation.IsQualifiedName(kataTun)) > 0) {
		setupLog.Error(fmt.Errorf("%q is not an extended resource name (domain/name)", kataTun), "invalid kata-tun-resource")
		os.Exit(1)
	}

	tailnets, err := loadTailnets(credentialPath, tailnet)
	if err != nil {
		setupLog.Error(err, "unable to read tailscale credentials")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         leaderElect,
		LeaderElectionID:       "tsinject-operator.dmf.zone",
		WebhookServer:          crwebhook.NewServer(crwebhook.Options{Port: 9443, CertDir: certDir}),
		Cache: cache.Options{
			// Every pod this operator touches carries the inject label (the
			// webhook's objectSelector), and every Secret it watches carries
			// the watched label (delivered credentials, the webhook cert), so
			// both cluster-wide informers are scoped down to just those.
			// Secrets especially: an unscoped informer hydrates every helm
			// release blob in the cluster and can OOM the pod on startup.
			// All reads of other people's Secrets go through the uncached
			// APIReader.
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Pod{}: {Label: labels.SelectorFromSet(labels.Set{
					tsv1alpha1.InjectLabel: tsv1alpha1.InjectLabelValue,
				})},
				&corev1.Secret{}: {Label: labels.SelectorFromSet(labels.Set{
					tsv1alpha1.WatchedSecretLabel: tsv1alpha1.WatchedSecretLabelValue,
				})},
			},
		},
	})
	if err != nil {
		setupLog.Error(err, "unable to create manager")
		os.Exit(1)
	}

	if err := (&controller.TailscaleCredentialReconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Tailnets:  tailnets,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "TailscaleCredential")
		os.Exit(1)
	}
	if err := (&controller.PodGateReconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Tailnets:  tailnets,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PodGate")
		os.Exit(1)
	}

	// Gatekeeper pattern: the rotator materializes CA + serving cert into a
	// Secret and certDir, patches caBundle into the webhook configuration,
	// and closes certsReady — only then is the admission handler
	// registered, so the server never serves with missing certs.
	certsReady := make(chan struct{})
	if enableWebhook {
		// cert-controller rotates an existing Secret but never creates one —
		// install.yaml ships a placeholder; create it here too so the
		// operator self-heals under hand-rolled installs instead of
		// crash-looping on "Secret not found". The rotator reads and watches
		// the Secret through the label-scoped manager cache, so the watched
		// label must be guaranteed here — including on placeholders that
		// pre-date it.
		bootstrapClient, err := client.New(mgr.GetConfig(), client.Options{})
		if err != nil {
			setupLog.Error(err, "unable to create bootstrap client")
			os.Exit(1)
		}
		certSecretKey := types.NamespacedName{Namespace: operatorNamespace, Name: webhookCertSecret}
		placeholder := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Namespace: certSecretKey.Namespace,
			Name:      certSecretKey.Name,
			Labels: map[string]string{
				tsv1alpha1.WatchedSecretLabel: tsv1alpha1.WatchedSecretLabelValue,
			},
		}}
		if err := bootstrapClient.Create(context.Background(), placeholder); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				setupLog.Error(err, "unable to ensure webhook cert secret", "secret", webhookCertSecret)
				os.Exit(1)
			}
			existing := &corev1.Secret{}
			if err := bootstrapClient.Get(context.Background(), certSecretKey, existing); err != nil {
				setupLog.Error(err, "unable to read webhook cert secret", "secret", webhookCertSecret)
				os.Exit(1)
			}
			if existing.Labels[tsv1alpha1.WatchedSecretLabel] != tsv1alpha1.WatchedSecretLabelValue {
				if existing.Labels == nil {
					existing.Labels = map[string]string{}
				}
				existing.Labels[tsv1alpha1.WatchedSecretLabel] = tsv1alpha1.WatchedSecretLabelValue
				if err := bootstrapClient.Update(context.Background(), existing); err != nil {
					setupLog.Error(err, "unable to label webhook cert secret", "secret", webhookCertSecret)
					os.Exit(1)
				}
				setupLog.Info("labeled pre-existing webhook cert secret for the scoped cache", "secret", webhookCertSecret)
			}
		}

		if err := rotator.AddRotator(mgr, &rotator.CertRotator{
			SecretKey:      types.NamespacedName{Namespace: operatorNamespace, Name: webhookCertSecret},
			CertDir:        certDir,
			CAName:         "tsinject-ca",
			CAOrganization: "tsinject",
			DNSName:        fmt.Sprintf("%s.%s.svc", webhookService, operatorNamespace),
			IsReady:        certsReady,
			// With >1 replica only the leader rotates; every replica still
			// serves admission with the shared Secret's cert.
			RequireLeaderElection: leaderElect,
			Webhooks: []rotator.WebhookInfo{
				{Name: mutatingWebhookConfig, Type: rotator.Mutating},
			},
		}); err != nil {
			setupLog.Error(err, "unable to set up cert rotator")
			os.Exit(1)
		}
		go func() {
			<-certsReady
			mgr.GetWebhookServer().Register("/mutate-pods", &crwebhook.Admission{Handler: &tswebhook.PodMutator{
				Client:          mgr.GetClient(),
				APIReader:       mgr.GetAPIReader(),
				Decoder:         admission.NewDecoder(mgr.GetScheme()),
				TailscaleImage:  tailscaleImage,
				KataTunResource: corev1.ResourceName(kataTun),
				Tailnets:        tailnets,
			}})
			setupLog.Info("webhook handler registered", "tailscaleImage", tailscaleImage, "kataTunResource", kataTun)
		}()
	} else {
		close(certsReady)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("webhook-certs", func(_ *http.Request) error {
		select {
		case <-certsReady:
			return nil
		default:
			return errors.New("webhook certificates not ready")
		}
	}); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager",
		"tailnets", tailnets.Names(), "defaultTailnet", tailnets.DefaultName(), "webhook", enableWebhook)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "manager exited with error")
		os.Exit(1)
	}
}
