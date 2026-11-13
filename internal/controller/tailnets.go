package controller

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Multi-tailnet support. With the Tailnets API one account holds several
// tailnets, and each API-only tailnet is administered only by its own scoped
// OAuth client — the org-level client that created it cannot. So "a tailnet"
// to this operator is a (name, API path segment, admin OAuth client) triple,
// and the operator carries a set of them with one nominated as the default.
//
// Workloads pick one by name (the tailscale-tailnet annotation /
// spec.tailnet); the delivered per-workload OAuth clients are minted inside
// that tailnet, so the injected sidecar keeps addressing its own tailnet as
// "-" and needs no awareness of any of this.
//
// A tailnet can instead be in federated credential mode: its workloads join
// with their own service-account tokens, exchanged for a Tailscale federated
// identity declared outside this operator (tailscale-client-id), so nothing
// is minted for them and the tailnet needs no admin client at all. One may
// still be configured, so that TailscaleCredentials left from before the
// switch can be revoked.

// TailnetConfig is one configured tailnet: the name workloads select it by,
// the API path segment its admin client addresses it as (a tailnet name, an
// API-only tailnet ID, or "-" for the client's own tailnet), and that admin
// OAuth client.
type TailnetConfig struct {
	Name         string
	Tailnet      string
	ClientID     string
	ClientSecret string
	// Federated is credential_mode "federated": workloads join as federated
	// identities, and ClientID/ClientSecret are optional.
	Federated bool
}

// Credential modes a tailnet entry can name.
const (
	CredentialModeOAuth     = "oauth"
	CredentialModeFederated = "federated"
)

// LegacyTailnetName is the name the single-credential secret.json shape's
// tailnet is registered under.
const LegacyTailnetName = "default"

// ParseTailnetsConfig reads the operator credential file (secret.json). Two
// shapes are accepted:
//
//	{"client_id": "...", "client_secret": "..."}
//
// the pre-multi-tailnet format: a single tailnet registered as
// LegacyTailnetName whose API path segment is legacyTailnet (the -tailnet
// flag), nominated the default. And:
//
//	{
//	  "default": "homelab",
//	  "tailnets": {
//	    "homelab": {"tailnet": "-", "client_id": "...", "client_secret": "..."},
//	    "global-infrastructure": {"tailnet": "<tailnet-id>", "client_id": "...", "client_secret": "..."},
//	    "config-plane": {"credential_mode": "federated"}
//	  }
//	}
//
// where each entry's tailnet defaults to "-", credential_mode to "oauth"
// (which needs the admin client; "federated" makes it optional), and
// "default" nominates the tailnet unnamed credentials resolve to — omit it
// only when exactly one tailnet is configured. Configs are returned
// name-sorted.
func ParseTailnetsConfig(data []byte, legacyTailnet string) (string, []TailnetConfig, error) {
	var file struct {
		// Legacy single-credential shape.
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		// Multi-tailnet shape.
		Default  string `json:"default"`
		Tailnets map[string]struct {
			Tailnet        string `json:"tailnet"`
			ClientID       string `json:"client_id"`
			ClientSecret   string `json:"client_secret"`
			CredentialMode string `json:"credential_mode"`
		} `json:"tailnets"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return "", nil, fmt.Errorf("parsing credentials: %w", err)
	}

	if file.Tailnets == nil {
		if file.ClientID == "" || file.ClientSecret == "" {
			return "", nil, fmt.Errorf("credentials carry neither client_id/client_secret nor a tailnets map")
		}
		return LegacyTailnetName, []TailnetConfig{{
			Name:         LegacyTailnetName,
			Tailnet:      legacyTailnet,
			ClientID:     file.ClientID,
			ClientSecret: file.ClientSecret,
		}}, nil
	}

	if len(file.Tailnets) == 0 {
		return "", nil, fmt.Errorf("tailnets map is empty")
	}
	var configs []TailnetConfig
	for _, name := range slices.Sorted(maps.Keys(file.Tailnets)) {
		entry := file.Tailnets[name]
		if name == "" {
			return "", nil, fmt.Errorf("a tailnet entry has an empty name")
		}
		var federated bool
		switch entry.CredentialMode {
		case "", CredentialModeOAuth:
		case CredentialModeFederated:
			federated = true
		default:
			return "", nil, fmt.Errorf("tailnet %q: credential_mode %q is neither %q nor %q",
				name, entry.CredentialMode, CredentialModeOAuth, CredentialModeFederated)
		}
		if (entry.ClientID == "") != (entry.ClientSecret == "") {
			return "", nil, fmt.Errorf("tailnet %q must carry both client_id and client_secret, or neither", name)
		}
		if !federated && entry.ClientID == "" {
			return "", nil, fmt.Errorf("tailnet %q must carry client_id and client_secret (credential_mode %q)", name, CredentialModeOAuth)
		}
		if entry.Tailnet == "" {
			entry.Tailnet = "-"
		}
		configs = append(configs, TailnetConfig{
			Name:         name,
			Tailnet:      entry.Tailnet,
			ClientID:     entry.ClientID,
			ClientSecret: entry.ClientSecret,
			Federated:    federated,
		})
	}
	defaultName := file.Default
	if defaultName == "" {
		if len(configs) > 1 {
			return "", nil, fmt.Errorf("more than one tailnet configured but none nominated as \"default\"")
		}
		defaultName = configs[0].Name
	}
	if _, ok := file.Tailnets[defaultName]; !ok {
		return "", nil, fmt.Errorf("default tailnet %q is not in the tailnets map", defaultName)
	}
	return defaultName, configs, nil
}

// TailnetRegistry maps configured tailnet names to their admin API clients,
// with one nominated default that the empty name resolves to. A federated
// tailnet need not have an admin client.
type TailnetRegistry struct {
	defaultName string
	apis        map[string]TailscaleAPI
	federated   map[string]bool
}

// NewTailnetRegistry builds the registry from each oauth or federated
// tailnet's admin client (apis) and the set of federated tailnets, which may
// have none. Every oauth tailnet must be in apis.
func NewTailnetRegistry(defaultName string, apis map[string]TailscaleAPI, federated map[string]bool) (*TailnetRegistry, error) {
	r := &TailnetRegistry{defaultName: defaultName, apis: maps.Clone(apis), federated: map[string]bool{}}
	if r.apis == nil {
		r.apis = map[string]TailscaleAPI{}
	}
	for name, f := range federated {
		if f {
			r.federated[name] = true
		}
	}
	if len(r.apis) == 0 && len(r.federated) == 0 {
		return nil, fmt.Errorf("no tailnets configured")
	}
	if !r.Has(defaultName) || defaultName == "" {
		return nil, fmt.Errorf("default tailnet %q is not configured", defaultName)
	}
	return r, nil
}

// DefaultName is the nominated default tailnet's name.
func (r *TailnetRegistry) DefaultName() string { return r.defaultName }

// Names lists the configured tailnet names, sorted — for logs and messages.
func (r *TailnetRegistry) Names() []string {
	names := maps.Clone(r.federated)
	for name := range r.apis {
		names[name] = true
	}
	return slices.Sorted(maps.Keys(names))
}

// Has reports whether name is configured; the empty name (the default)
// always is.
func (r *TailnetRegistry) Has(name string) bool {
	if name == "" {
		return true
	}
	_, ok := r.apis[name]
	return ok || r.federated[name]
}

// Federated reports whether the tailnet name ("" means the default) is in
// federated credential mode.
func (r *TailnetRegistry) Federated(name string) bool {
	if name == "" {
		name = r.defaultName
	}
	return r.federated[name]
}

// API resolves a tailnet name ("" means the default) to its admin API client
// and the resolved name.
func (r *TailnetRegistry) API(name string) (TailscaleAPI, string, error) {
	if name == "" {
		name = r.defaultName
	}
	api, ok := r.apis[name]
	if !ok {
		if r.federated[name] {
			return nil, "", fmt.Errorf("tailnet %q is federated and has no admin client to mint or revoke OAuth clients with", name)
		}
		return nil, "", fmt.Errorf("tailnet %q is not configured (configured: %s)",
			name, strings.Join(r.Names(), ", "))
	}
	return api, name, nil
}
