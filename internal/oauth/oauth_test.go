package oauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"openpak/np-account/internal/config"
	"openpak/np-account/internal/oauth"
	accountv1 "github.com/openpak/account-api/openpak/account/v1"
	"openpak/np-common/coreclient"
	"openpak/np-common/fakecore"
	"openpak/np-common/onlineid"
)

// All values below are fake test values, not Sony's.
const (
	coreKey      = "fake-core-key-fake-core-key-fake-core-key"
	clientID     = "test-client-id"
	clientSecret = "test-client-secret"
)

type env struct {
	t    *testing.T
	core *fakecore.Core
	svc  *oauth.Service
	h    http.Handler
	now  time.Time
	cfg  *config.Config
}

func newEnv(t *testing.T, mutate func(*config.Config)) *env {
	t.Helper()
	core := fakecore.New(coreKey)
	core.AddAccount(fakecore.Account{ID: "acc-1", Email: "leia@example.org", Password: "pw1", DisplayName: "Leia Organa", Country: "SE"})
	core.AddAccount(fakecore.Account{ID: "acc-2", Email: "han@example.org", Password: "pw2", DisplayName: "Han", Country: "US", TOTP: "123456"})
	core.AddAccount(fakecore.Account{ID: "acc-3", Email: "ban@example.org", Password: "pw3", DisplayName: "Ban", Status: accountv1.AccountStatus_ACCOUNT_STATUS_BANNED})
	core.AddAccount(fakecore.Account{ID: "acc-4", Email: "luke@example.org", Password: "pw4", DisplayName: "Luke", Country: ""})
	cli, err := coreclient.Dial("passthrough:///core", coreKey, core.Serve(t)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close() })

	cfg := &config.Config{
		ClientID: clientID, ClientSecret: clientSecret,
		TokenKey: "0123456789abcdef0123456789abcdef-test",
		EnvIssID: "1", CommDomain: "00", RedirectPrefixes: []string{"orbis://"},
		AccessTTL: time.Hour,
	}
	if mutate != nil {
		mutate(cfg)
	}
	e := &env{t: t, core: core, now: time.Unix(1_700_000_000, 0), cfg: cfg}
	e.svc = oauth.New(cfg, cli, func() time.Time { return e.now }, nil)
	mux := http.NewServeMux()
	e.svc.Register(mux)
	e.h = mux
	return e
}

func (e *env) do(method, target string, form url.Values, hdr map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	e.t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func passwordForm(user, pw string, extra ...string) url.Values {
	f := url.Values{
		"client_id": {clientID}, "client_secret": {clientSecret},
		"redirect_uri": {"orbis://games"}, "response_type": {"code"}, "prompt": {"always"},
		"grant_type": {"password"}, "username": {user}, "password": {pw}, "scope": {"openid"},
	}
	for i := 0; i+1 < len(extra); i += 2 {
		f.Set(extra[i], extra[i+1])
	}
	return f
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body is not JSON: %q", rec.Body.String())
	}
	return m
}

func wantError(t *testing.T, rec *httptest.ResponseRecorder, status int, slug string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d (%s)", rec.Code, status, rec.Body.String())
	}
	m := decode(t, rec)
	code, isNum := m["error_code"].(float64)
	desc, isStr := m["error_description"].(string)
	if m["error"] != slug || !isNum || code == 0 || !isStr || desc == "" {
		t.Fatalf("error shape = %v, want slug %q with error_code and error_description", m, slug)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("error headers: %v", rec.Header())
	}
	if rec.Header().Get("X-NP-GRANT-CODE") != "" {
		t.Fatal("an error reply must not carry a grant code")
	}
}

func (e *env) idClaims(rec *httptest.ResponseRecorder) map[string]any {
	e.t.Helper()
	m := decode(e.t, rec)
	idt, _ := m["id_token"].(string)
	claims, err := e.svc.Signer().VerifyIDToken(idt)
	if err != nil {
		e.t.Fatalf("id_token: %v", err)
	}
	return claims
}

func TestPasswordGrant(t *testing.T) {
	type tc struct {
		name   string
		form   url.Values
		hdr    map[string]string
		cfg    func(*config.Config)
		setup  func(*env)
		status int
		slug   string // error slug; empty = success
		online string // expected online_id on success
	}
	cases := []tc{
		{name: "first sign-in with chosen online ID", form: passwordForm("leia@example.org", "pw1", "online_id", "Leia_B"), status: 200, online: "Leia_B"},
		{name: "first sign-in derives ID when enabled", form: passwordForm("leia@example.org", "pw1"), cfg: func(c *config.Config) { c.AutoOnlineID = true }, status: 200, online: "Leia_Organa"},
		{name: "first sign-in without an ID", form: passwordForm("leia@example.org", "pw1"), status: 403, slug: "online_id_required"},
		{name: "invalid online ID", form: passwordForm("leia@example.org", "pw1", "online_id", "1bad id"), status: 400, slug: "invalid_online_id"},
		{name: "online ID taken by another account", form: passwordForm("leia@example.org", "pw1", "online_id", "Taken_1"), status: 409, slug: "online_id_taken",
			setup: func(e *env) { e.mustClaim("acc-4", "taken_1") }},
		{name: "existing link, no ID needed", form: passwordForm("leia@example.org", "pw1"), status: 200, online: "Princess",
			setup: func(e *env) { e.mustClaim("acc-1", "Princess") }},
		{name: "wrong password", form: passwordForm("leia@example.org", "bad"), status: 401, slug: "invalid_grant"},
		{name: "unknown user", form: passwordForm("nobody@example.org", "pw1"), status: 401, slug: "invalid_grant"},
		{name: "wrong client secret", form: passwordForm("leia@example.org", "pw1", "client_secret", "nope"), status: 401, slug: "invalid_client"},
		{name: "wrong client id", form: passwordForm("leia@example.org", "pw1", "client_id", "nope"), status: 401, slug: "invalid_client"},
		{name: "missing password", form: passwordForm("leia@example.org", ""), status: 400, slug: "invalid_request"},
		{name: "missing grant_type", form: passwordForm("leia@example.org", "pw1", "grant_type", ""), status: 400, slug: "invalid_request"},
		{name: "unsupported grant_type", form: passwordForm("leia@example.org", "pw1", "grant_type", "implicit"), status: 400, slug: "unsupported_grant_type"},
		{name: "two-factor account without a code", form: passwordForm("han@example.org", "pw2", "online_id", "Han_S"), status: 401, slug: "second_factor_required"},
		{name: "two-factor account with a wrong code", form: passwordForm("han@example.org", "pw2", "online_id", "Han_S", "second_factor", "000000"), status: 401, slug: "invalid_second_factor"},
		{name: "two-factor account with the right code", form: passwordForm("han@example.org", "pw2", "online_id", "Han_S", "second_factor", "123456"), status: 200, online: "Han_S"},
		{name: "banned account", form: passwordForm("ban@example.org", "pw3", "online_id", "Banned1"), status: 403, slug: "account_disabled"},
		{name: "core down fails closed", form: passwordForm("leia@example.org", "pw1", "online_id", "Leia_B"), setup: func(e *env) { e.core.Down = true }, status: 503, slug: "server_error"},
		{name: "console token required but missing", form: passwordForm("leia@example.org", "pw1", "online_id", "Leia_B"), cfg: func(c *config.Config) { c.RequireConsoleToken = true }, status: 401, slug: "invalid_console_token"},
		{name: "garbage console token", form: passwordForm("leia@example.org", "pw1", "online_id", "Leia_B"), hdr: map[string]string{"X-NP-CONSOLE-TOKEN": "garbage"}, status: 401, slug: "invalid_console_token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, c.cfg)
			if c.setup != nil {
				c.setup(e)
			}
			rec := e.do("POST", "/2.0/oauth/token", c.form, c.hdr)
			if c.slug != "" {
				wantError(t, rec, c.status, c.slug)
				return
			}
			if rec.Code != 200 {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			m := decode(t, rec)
			if m["token_type"] != "bearer" || m["access_token"] == "" || m["expires_in"] != float64(3600) || m["scope"] != "openid" {
				t.Fatalf("token reply: %v", m)
			}
			if rec.Header().Get("X-NP-GRANT-CODE") == "" {
				t.Fatal("no X-NP-GRANT-CODE header")
			}
			cookie := rec.Result().Cookies()
			if len(cookie) != 1 || cookie[0].Name != "npsso_token" || cookie[0].Value == "" || !cookie[0].HttpOnly || !cookie[0].Secure {
				t.Fatalf("npsso_token cookie: %v", cookie)
			}
			cl := e.idClaims(rec)
			if cl["online_id"] != c.online {
				t.Fatalf("online_id = %v, want %s", cl["online_id"], c.online)
			}
			for _, k := range []string{"auth_time", "env_iss_id", "user_id", "acct_id", "ctry_code", "comm_domain", "online_id"} {
				if _, ok := cl[k]; !ok {
					t.Errorf("id_token lacks claim %s", k)
				}
			}
			if cl["auth_time"] != float64(e.now.Unix()) || cl["env_iss_id"] != "1" || cl["comm_domain"] != "00" {
				t.Fatalf("claims = %v", cl)
			}
			_, acct, _, _ := e.core.Link(c.online)
			if cl["acct_id"] != acct {
				t.Fatalf("acct_id = %v, core link says %s", cl["acct_id"], acct)
			}
			if strings.Contains(rec.Body.String(), "pw1") {
				t.Fatal("password echoed")
			}
		})
	}
}

func (e *env) mustClaim(account, onlineID string) {
	e.t.Helper()
	cli, err := coreclient.Dial("passthrough:///core", coreKey, e.core.Serve(e.t)...)
	if err != nil {
		e.t.Fatal(err)
	}
	defer cli.Close()
	if _, err := cli.ClaimOnlineID(context.Background(), account, onlineID); err != nil {
		e.t.Fatal(err)
	}
}

func TestClaims(t *testing.T) {
	e := newEnv(t, nil)
	e.mustClaim("acc-1", "Princess")
	e.mustClaim("acc-4", "Farmboy")

	first := e.idClaims(e.do("POST", "/2.0/oauth/token", passwordForm("leia@example.org", "pw1"), nil))
	e.now = e.now.Add(10 * time.Minute)
	second := e.idClaims(e.do("POST", "/2.0/oauth/token", passwordForm("leia@example.org", "pw1"), nil))
	if first["user_id"] != second["user_id"] || first["user_id"] == "" {
		t.Fatalf("user_id must be stable: %v vs %v", first["user_id"], second["user_id"])
	}
	linkID, _, _, _ := e.core.Link("Princess")
	if first["user_id"] != onlineid.UserID(linkID) {
		t.Fatalf("user_id %v is not derived from the link %s", first["user_id"], linkID)
	}
	if second["auth_time"] == first["auth_time"] {
		t.Fatal("auth_time must be the sign-in time")
	}
	if first["ctry_code"] != "se" {
		t.Fatalf("ctry_code = %v", first["ctry_code"])
	}
	luke := e.idClaims(e.do("POST", "/2.0/oauth/token", passwordForm("luke@example.org", "pw4"), nil))
	if luke["ctry_code"] != "us" || luke["user_id"] == first["user_id"] {
		t.Fatalf("luke claims = %v", luke)
	}
}

func TestGrantCodeExchange(t *testing.T) {
	signIn := func(e *env) (code string, rec *httptest.ResponseRecorder) {
		rec = e.do("POST", "/2.0/oauth/token", passwordForm("leia@example.org", "pw1", "online_id", "Leia_B"), nil)
		if rec.Code != 200 {
			t.Fatalf("sign-in: %s", rec.Body)
		}
		return rec.Header().Get("X-NP-GRANT-CODE"), rec
	}
	exchange := func(e *env, code string, extra ...string) *httptest.ResponseRecorder {
		f := url.Values{"client_id": {clientID}, "client_secret": {clientSecret}, "grant_type": {"authorization_code"}, "code": {code}}
		for i := 0; i+1 < len(extra); i += 2 {
			f.Set(extra[i], extra[i+1])
		}
		return e.do("POST", "/2.0/oauth/token", f, nil)
	}

	t.Run("success then replay", func(t *testing.T) {
		e := newEnv(t, nil)
		code, signed := signIn(e)
		rec := exchange(e, code)
		if rec.Code != 200 {
			t.Fatalf("exchange: %d %s", rec.Code, rec.Body)
		}
		if got, want := e.idClaims(rec)["user_id"], e.idClaims(signed)["user_id"]; got != want {
			t.Fatalf("user_id differs: %v vs %v", got, want)
		}
		if rec.Header().Get("X-NP-GRANT-CODE") != "" || len(rec.Result().Cookies()) != 0 {
			t.Fatal("an exchange must not mint a new grant code or session")
		}
		wantError(t, exchange(e, code), 400, "invalid_grant")
	})
	t.Run("expired", func(t *testing.T) {
		e := newEnv(t, nil)
		code, _ := signIn(e)
		e.now = e.now.Add(oauth.GrantTTL + time.Second)
		wantError(t, exchange(e, code), 400, "invalid_grant")
	})
	t.Run("an access token is not a grant code", func(t *testing.T) {
		e := newEnv(t, nil)
		_, signed := signIn(e)
		wantError(t, exchange(e, decode(t, signed)["access_token"].(string)), 400, "invalid_grant")
	})
	t.Run("garbage and empty", func(t *testing.T) {
		e := newEnv(t, nil)
		wantError(t, exchange(e, "garbage"), 400, "invalid_grant")
		wantError(t, exchange(e, ""), 400, "invalid_request")
	})
	t.Run("wrong client secret", func(t *testing.T) {
		e := newEnv(t, nil)
		code, _ := signIn(e)
		wantError(t, exchange(e, code, "client_secret", "nope"), 401, "invalid_client")
	})
	t.Run("banned after issue", func(t *testing.T) {
		e := newEnv(t, nil)
		code, _ := signIn(e)
		e.core.SetStatus("acc-1", accountv1.AccountStatus_ACCOUNT_STATUS_BANNED)
		wantError(t, exchange(e, code), 403, "account_disabled")
	})
}

func TestAuthorize(t *testing.T) {
	e := newEnv(t, nil)
	rec := e.do("POST", "/2.0/oauth/token", passwordForm("leia@example.org", "pw1", "online_id", "Leia_B"), nil)
	npsso := rec.Result().Cookies()[0]
	q := func(extra ...string) string {
		v := url.Values{"client_id": {clientID}, "response_type": {"code"}, "redirect_uri": {"orbis://games"}, "state": {"st-1"}}
		for i := 0; i+1 < len(extra); i += 2 {
			v.Set(extra[i], extra[i+1])
		}
		return "/2.0/oauth/authorize?" + v.Encode()
	}

	t.Run("session gives a redirect with a code", func(t *testing.T) {
		rec := e.do("GET", q(), nil, nil, npsso)
		if rec.Code != http.StatusFound {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
		loc, _ := url.Parse(rec.Header().Get("Location"))
		code := loc.Query().Get("code")
		if loc.Scheme != "orbis" || loc.Host != "games" || code == "" || loc.Query().Get("state") != "st-1" || code != rec.Header().Get("X-NP-GRANT-CODE") {
			t.Fatalf("Location = %s", rec.Header().Get("Location"))
		}
		f := url.Values{"client_id": {clientID}, "client_secret": {clientSecret}, "grant_type": {"authorization_code"}, "code": {code}}
		if ex := e.do("POST", "/2.0/oauth/token", f, nil); ex.Code != 200 {
			t.Fatalf("exchange of authorize code: %s", ex.Body)
		}
	})
	t.Run("no session redirects with error and state", func(t *testing.T) {
		rec := e.do("GET", q(), nil, nil)
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if rec.Code != http.StatusFound || loc.Query().Get("error") != "login_required" || loc.Query().Get("state") != "st-1" || loc.Query().Get("error_description") == "" {
			t.Fatalf("%d Location = %s", rec.Code, rec.Header().Get("Location"))
		}
	})
	t.Run("forged session", func(t *testing.T) {
		rec := e.do("GET", q(), nil, nil, &http.Cookie{Name: "npsso_token", Value: "a.b"})
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=login_required") {
			t.Fatalf("Location = %q", loc)
		}
	})
	t.Run("disallowed redirect_uri is never followed", func(t *testing.T) {
		wantError(t, e.do("GET", q("redirect_uri", "https://evil.example/cb"), nil, nil, npsso), 400, "invalid_request")
	})
	t.Run("no redirect_uri answers JSON", func(t *testing.T) {
		rec := e.do("GET", q("redirect_uri", ""), nil, nil, npsso)
		if rec.Code != 200 || decode(t, rec)["code"] != rec.Header().Get("X-NP-GRANT-CODE") || rec.Header().Get("X-NP-GRANT-CODE") == "" {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	t.Run("wrong client", func(t *testing.T) {
		rec := e.do("GET", q("client_id", "nope"), nil, nil, npsso)
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=invalid_client") {
			t.Fatalf("Location = %q", loc)
		}
	})
	t.Run("expired session", func(t *testing.T) {
		old := e.now
		e.now = e.now.Add(oauth.NPSSOTTL + time.Second)
		defer func() { e.now = old }()
		rec := e.do("GET", q(), nil, nil, npsso)
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=login_required") {
			t.Fatalf("Location = %q", loc)
		}
	})
	t.Run("banned session", func(t *testing.T) {
		e.core.SetStatus("acc-1", accountv1.AccountStatus_ACCOUNT_STATUS_BANNED)
		defer e.core.SetStatus("acc-1", accountv1.AccountStatus_ACCOUNT_STATUS_ACTIVE)
		rec := e.do("GET", q(), nil, nil, npsso)
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=account_disabled") {
			t.Fatalf("Location = %q", loc)
		}
	})
}

func TestConsoleToken(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.RequireConsoleToken = true })
	rec := e.do("GET", "/csla/np/console/lwConsoleToken", nil, nil)
	ct, _ := decode(t, rec)["consoleToken"].(string)
	if rec.Code != 200 || ct == "" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	hdr := map[string]string{"X-NP-CONSOLE-TOKEN": ct}
	form := passwordForm("leia@example.org", "pw1", "online_id", "Leia_B")
	if r := e.do("POST", "/2.0/oauth/token", form, hdr); r.Code != 200 {
		t.Fatalf("sign-in with console token: %s", r.Body)
	}
	e.now = e.now.Add(oauth.ConsoleTTL + time.Second)
	wantError(t, e.do("POST", "/2.0/oauth/token", form, hdr), 401, "invalid_console_token")
	if r := e.do("POST", "/csla/np/console/lwConsoleToken", nil, nil); r.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST console token = %d", r.Code)
	}
}

func TestTokenEndpointMethodAndBody(t *testing.T) {
	e := newEnv(t, nil)
	if r := e.do("GET", "/2.0/oauth/token", nil, nil); r.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET token = %d", r.Code)
	}
	big := url.Values{"password": {strings.Repeat("x", 100<<10)}, "grant_type": {"password"}}
	wantError(t, e.do("POST", "/2.0/oauth/token", big, nil), 400, "invalid_request")
}
