// Package config loads adapter configuration from the environment. Secrets
// have no defaults: a missing required value fails startup.
package config

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrMissingConfig wraps the list of required variables that were not set.
var ErrMissingConfig = errors.New("missing required configuration")

// MinKeyLen is the shortest accepted NP_TOKEN_KEY and NP_CORE_KEY, in bytes.
const MinKeyLen = 32

type Config struct {
	TicketKeyPath string // owner-local Ed25519 PKCS8 PEM; enables /nav/auth

	HTTPListenAddr string // NP_HTTP_ADDR, default :8002

	CoreAddress string // NP_CORE_ADDR, default localhost:7000
	CoreKey     string // NP_CORE_KEY, required: bearer key for the core's internal gRPC

	// Sony's OAuth client credentials, embedded in the firmware. Operator
	// supplied; never committed.
	ClientID     string // NP_CLIENT_ID, required
	ClientSecret string // NP_CLIENT_SECRET, required

	// TokenKey signs every token issued here (grant codes, access tokens,
	// the npsso session, console tokens, id_token). Required.
	TokenKey string // NP_TOKEN_KEY, required, at least 32 bytes

	EnvIssID     string // NP_ENV_ISS_ID, default "1": id_token env_iss_id claim
	CommDomain   string // NP_COMM_DOMAIN, default "00": id_token comm_domain claim
	AutoOnlineID bool   // NP_AUTO_ONLINE_ID: derive an online ID from the display name on first sign-in
	// RequireConsoleToken refuses token requests without a valid
	// X-NP-CONSOLE-TOKEN. Off by default: whether the firmware always sends
	// it is UNCONFIRMED.
	RequireConsoleToken bool // NP_REQUIRE_CONSOLE_TOKEN
	// RedirectPrefixes are the redirect_uri prefixes /2.0/oauth/authorize may
	// send a grant code to.
	RedirectPrefixes []string // NP_REDIRECT_PREFIXES, default "orbis://"

	AccessTTL time.Duration // NP_ACCESS_TTL, default 1h
}

// Load reads the environment through getenv (os.Getenv in production).
func Load(getenv func(string) string) (*Config, error) {
	c := &Config{
		TicketKeyPath:       getenv("NP_TICKET_KEY"),
		HTTPListenAddr:      orDefault(getenv("NP_HTTP_ADDR"), ":8002"),
		CoreAddress:         orDefault(getenv("NP_CORE_ADDR"), "localhost:7000"),
		CoreKey:             getenv("NP_CORE_KEY"),
		ClientID:            getenv("NP_CLIENT_ID"),
		ClientSecret:        getenv("NP_CLIENT_SECRET"),
		TokenKey:            getenv("NP_TOKEN_KEY"),
		EnvIssID:            orDefault(getenv("NP_ENV_ISS_ID"), "1"),
		CommDomain:          orDefault(getenv("NP_COMM_DOMAIN"), "00"),
		AutoOnlineID:        isTrue(getenv("NP_AUTO_ONLINE_ID")),
		RequireConsoleToken: isTrue(getenv("NP_REQUIRE_CONSOLE_TOKEN")),
		RedirectPrefixes:    splitList(orDefault(getenv("NP_REDIRECT_PREFIXES"), "orbis://")),
		AccessTTL:           time.Hour,
	}
	if v := getenv("NP_ACCESS_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute {
			return nil, fmt.Errorf("NP_ACCESS_TTL must be a duration of at least 1m, got %q", v)
		}
		c.AccessTTL = d
	}

	var missing []string
	for _, kv := range [][2]string{
		{"NP_CORE_KEY", c.CoreKey},
		{"NP_CLIENT_ID", c.ClientID},
		{"NP_CLIENT_SECRET", c.ClientSecret},
		{"NP_TOKEN_KEY", c.TokenKey},
	} {
		if kv[1] == "" {
			missing = append(missing, kv[0])
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrMissingConfig, strings.Join(missing, ", "))
	}
	if len(c.TokenKey) < MinKeyLen {
		return nil, fmt.Errorf("NP_TOKEN_KEY must be at least %d bytes", MinKeyLen)
	}
	return c, nil
}

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func isTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
