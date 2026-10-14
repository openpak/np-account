package oauth

import (
	"net/http"
	"net/url"
	"strings"
)

const maxFormBytes = 64 << 10

// Register adds the sign-in routes to mux.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /2.0/oauth/authorize", s.handleAuthorize)
	mux.HandleFunc("POST /2.0/oauth/token", s.handleToken)
	mux.HandleFunc("GET /csla/{x}/console/lwConsoleToken", s.handleConsoleToken)
}

func (s *Service) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		writeError(w, errInvalidRequest("malformed form body"))
		return
	}
	if e := s.CheckConsoleToken(r.Header.Get("X-NP-CONSOLE-TOKEN")); e != nil {
		writeError(w, e)
		return
	}
	f := r.PostForm
	var (
		t *Tokens
		e *Error
	)
	switch f.Get("grant_type") {
	case "password":
		t, e = s.PasswordGrant(r.Context(), PasswordInput{
			ClientID: f.Get("client_id"), ClientSecret: f.Get("client_secret"),
			Username: f.Get("username"), Password: f.Get("password"), Scope: f.Get("scope"),
			SecondFactor: f.Get("second_factor"), RecoveryCode: f.Get("recovery_code"), OnlineID: f.Get("online_id"),
		})
	case "authorization_code":
		t, e = s.CodeGrant(r.Context(), CodeInput{
			ClientID: f.Get("client_id"), ClientSecret: f.Get("client_secret"),
			Code: f.Get("code"), Scope: f.Get("scope"),
		})
	case "":
		e = errInvalidRequest("grant_type is required")
	default:
		e = errUnsupportedGrant()
	}
	if e != nil {
		writeError(w, e)
		return
	}
	if t.GrantCode != "" {
		w.Header().Set("X-NP-GRANT-CODE", t.GrantCode)
	}
	if t.NPSSO != "" {
		http.SetCookie(w, &http.Cookie{
			Name: "npsso_token", Value: t.NPSSO, Path: "/",
			MaxAge: int(NPSSOTTL.Seconds()), Secure: true, HttpOnly: true,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": t.AccessToken,
		"token_type":   "bearer",
		"expires_in":   t.ExpiresIn,
		"scope":        t.Scope,
		"id_token":     t.IDToken,
	})
}

// redirectAllowed reports whether a grant code may be sent to uri.
func (s *Service) redirectAllowed(uri string) bool {
	if uri == "" {
		return false
	}
	if _, err := url.Parse(uri); err != nil {
		return false
	}
	for _, p := range s.cfg.RedirectPrefixes {
		if strings.HasPrefix(uri, p) {
			return true
		}
	}
	return false
}

func (s *Service) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, state := q.Get("redirect_uri"), q.Get("state")
	canRedirect := s.redirectAllowed(redirect)
	if redirect != "" && !canRedirect {
		writeError(w, errInvalidRequest("redirect_uri is not allowed"))
		return
	}
	fail := func(e *Error) {
		if canRedirect {
			redirectError(w, r, redirect, state, e)
			return
		}
		writeError(w, e)
	}
	if e := s.CheckConsoleToken(r.Header.Get("X-NP-CONSOLE-TOKEN")); e != nil {
		fail(e)
		return
	}
	if rt := q.Get("response_type"); rt != "" && rt != "code" {
		fail(errInvalidRequest("unsupported response_type"))
		return
	}
	var npsso string
	if c, err := r.Cookie("npsso_token"); err == nil {
		npsso = c.Value
	}
	code, e := s.Authorize(r.Context(), q.Get("client_id"), npsso)
	if e != nil {
		fail(e)
		return
	}
	w.Header().Set("X-NP-GRANT-CODE", code)
	if !canRedirect {
		writeJSON(w, http.StatusOK, map[string]any{"code": code})
		return
	}
	u, _ := url.Parse(redirect)
	rq := u.Query()
	rq.Set("code", code)
	if state != "" {
		rq.Set("state", state)
	}
	u.RawQuery = rq.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Service) handleConsoleToken(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"consoleToken": s.ConsoleToken()})
}
