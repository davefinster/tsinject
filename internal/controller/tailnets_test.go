package controller

import (
	"strings"
	"testing"
)

func TestParseLegacyCredentials(t *testing.T) {
	defaultName, configs, err := ParseTailnetsConfig(
		[]byte(`{"client_id": "id", "client_secret": "sec"}`), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if defaultName != LegacyTailnetName {
		t.Errorf("default = %q, want %q", defaultName, LegacyTailnetName)
	}
	if len(configs) != 1 {
		t.Fatalf("configs = %+v, want one", configs)
	}
	want := TailnetConfig{Name: LegacyTailnetName, Tailnet: "example.com", ClientID: "id", ClientSecret: "sec"}
	if configs[0] != want {
		t.Errorf("config = %+v, want %+v", configs[0], want)
	}
}

func TestParseMultiTailnets(t *testing.T) {
	data := []byte(`{
		"default": "homelab",
		"tailnets": {
			"homelab": {"client_id": "a", "client_secret": "as"},
			"global-infrastructure": {"tailnet": "tn-1234", "client_id": "b", "client_secret": "bs"}
		}
	}`)
	defaultName, configs, err := ParseTailnetsConfig(data, "-")
	if err != nil {
		t.Fatal(err)
	}
	if defaultName != "homelab" {
		t.Errorf("default = %q, want homelab", defaultName)
	}
	if len(configs) != 2 {
		t.Fatalf("configs = %+v, want two", configs)
	}
	// Name-sorted; an omitted tailnet segment means "-" (the client's own).
	if configs[0].Name != "global-infrastructure" || configs[0].Tailnet != "tn-1234" {
		t.Errorf("configs[0] = %+v", configs[0])
	}
	if configs[1].Name != "homelab" || configs[1].Tailnet != "-" {
		t.Errorf("configs[1] = %+v, tailnet must default to \"-\"", configs[1])
	}
}

func TestParseSingleTailnetImpliesDefault(t *testing.T) {
	defaultName, _, err := ParseTailnetsConfig(
		[]byte(`{"tailnets": {"only": {"client_id": "a", "client_secret": "b"}}}`), "-")
	if err != nil {
		t.Fatal(err)
	}
	if defaultName != "only" {
		t.Errorf("default = %q, want the sole tailnet", defaultName)
	}
}

func TestParseRejectsBadConfigs(t *testing.T) {
	for name, data := range map[string]string{
		"empty object":          `{}`,
		"empty tailnets map":    `{"tailnets": {}}`,
		"no default among many": `{"tailnets": {"a": {"client_id": "x", "client_secret": "y"}, "b": {"client_id": "x", "client_secret": "y"}}}`,
		"default not in map":    `{"default": "c", "tailnets": {"a": {"client_id": "x", "client_secret": "y"}}}`,
		"entry missing secret":  `{"tailnets": {"a": {"client_id": "x"}}}`,
		"legacy missing secret": `{"client_id": "x"}`,
		"not json":              `nope`,
	} {
		if _, _, err := ParseTailnetsConfig([]byte(data), "-"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestRegistryResolution(t *testing.T) {
	def, global := &fakeTailscale{}, &fakeTailscale{}
	reg, err := NewTailnetRegistry("homelab", map[string]TailscaleAPI{"homelab": def, "global": global}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if api, name, err := reg.API(""); err != nil || api != TailscaleAPI(def) || name != "homelab" {
		t.Errorf("API(\"\") = %v/%q/%v, want the default", api, name, err)
	}
	if api, name, err := reg.API("global"); err != nil || api != TailscaleAPI(global) || name != "global" {
		t.Errorf("API(global) = %v/%q/%v", api, name, err)
	}
	if _, _, err := reg.API("nope"); err == nil {
		t.Error("API(nope) must fail")
	}
	if !reg.Has("") || !reg.Has("global") || reg.Has("nope") {
		t.Error("Has: empty and configured names are known, others are not")
	}
	if _, err := NewTailnetRegistry("missing", map[string]TailscaleAPI{"homelab": def}, nil); err == nil {
		t.Error("registry must reject an unconfigured default")
	}
}

// A federated tailnet needs no admin client; one may still be given (to
// revoke credentials left from before the switch), but never half of one.
func TestParseFederatedTailnets(t *testing.T) {
	data := []byte(`{
		"default": "homelab",
		"tailnets": {
			"homelab": {"client_id": "a", "client_secret": "as"},
			"config-plane": {"tailnet": "tn-cp", "credential_mode": "federated"},
			"global": {"tailnet": "tn-g", "client_id": "b", "client_secret": "bs", "credential_mode": "federated"}
		}
	}`)
	_, configs, err := ParseTailnetsConfig(data, "-")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]TailnetConfig{}
	for _, c := range configs {
		got[c.Name] = c
	}
	if !got["config-plane"].Federated || got["config-plane"].ClientID != "" {
		t.Errorf("config-plane = %+v, want federated with no admin client", got["config-plane"])
	}
	if !got["global"].Federated || got["global"].ClientID != "b" {
		t.Errorf("global = %+v, want federated keeping its admin client", got["global"])
	}
	if got["homelab"].Federated {
		t.Error("credential_mode defaults to oauth")
	}
	for name, bad := range map[string]string{
		"oauth without a client": `{"tailnets": {"a": {"credential_mode": "oauth"}}}`,
		"half a client":          `{"tailnets": {"a": {"credential_mode": "federated", "client_id": "x"}}}`,
		"unknown mode":           `{"tailnets": {"a": {"credential_mode": "magic", "client_id": "x", "client_secret": "y"}}}`,
	} {
		if _, _, err := ParseTailnetsConfig([]byte(bad), "-"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestRegistryFederated(t *testing.T) {
	def := &fakeTailscale{}
	reg, err := NewTailnetRegistry("homelab", map[string]TailscaleAPI{"homelab": def}, map[string]bool{"config-plane": true})
	if err != nil {
		t.Fatal(err)
	}
	if !reg.Has("config-plane") || !reg.Federated("config-plane") || reg.Federated("") || reg.Federated("homelab") {
		t.Error("config-plane is known and federated; the default is not")
	}
	if _, _, err := reg.API("config-plane"); err == nil || !strings.Contains(err.Error(), "federated") {
		t.Errorf("a federated tailnet without an admin client has no API: %v", err)
	}
	if names := reg.Names(); len(names) != 2 || names[0] != "config-plane" || names[1] != "homelab" {
		t.Errorf("Names() = %v", names)
	}
	// A federated tailnet can be the default, and the only one.
	only, err := NewTailnetRegistry("config-plane", nil, map[string]bool{"config-plane": true})
	if err != nil || !only.Federated("") {
		t.Errorf("federated-only registry: %v", err)
	}
}
