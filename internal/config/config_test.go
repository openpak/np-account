package config

import (
	"errors"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoad(t *testing.T) {
	good := map[string]string{
		"NP_CORE_KEY": "k", "NP_CLIENT_ID": "id", "NP_CLIENT_SECRET": "secret",
		"NP_TOKEN_KEY": strings.Repeat("t", 32),
	}
	with := func(kv ...string) map[string]string {
		m := map[string]string{}
		for k, v := range good {
			m[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	for _, tc := range []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{"ok", good, ""},
		{"nothing set", map[string]string{}, "NP_CORE_KEY, NP_CLIENT_ID, NP_CLIENT_SECRET, NP_TOKEN_KEY"},
		{"no client secret", with("NP_CLIENT_SECRET", ""), "NP_CLIENT_SECRET"},
		{"short token key", with("NP_TOKEN_KEY", "short"), "at least 32"},
		{"bad ttl", with("NP_ACCESS_TTL", "soon"), "NP_ACCESS_TTL"},
		{"ttl too short", with("NP_ACCESS_TTL", "5s"), "NP_ACCESS_TTL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Load(env(tc.env))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				if c.HTTPListenAddr != ":8002" || c.CoreAddress != "localhost:7000" || c.AutoOnlineID || c.RequireConsoleToken ||
					len(c.RedirectPrefixes) != 1 || c.RedirectPrefixes[0] != "orbis://" {
					t.Fatalf("defaults: %+v", c)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if tc.name == "nothing set" && !errors.Is(err, ErrMissingConfig) {
				t.Fatalf("not ErrMissingConfig: %v", err)
			}
		})
	}
	c, err := Load(env(with("NP_AUTO_ONLINE_ID", "true", "NP_REDIRECT_PREFIXES", "orbis://, ps3://", "NP_ACCESS_TTL", "30m")))
	if err != nil || !c.AutoOnlineID || len(c.RedirectPrefixes) != 2 || c.AccessTTL.Minutes() != 30 {
		t.Fatalf("overrides: %+v %v", c, err)
	}
}
