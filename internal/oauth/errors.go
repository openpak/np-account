package oauth

import (
	"encoding/json"
	"net/http"
	"net/url"
)

// Error is an OAuth error reply. On the wire it is
//
//	{"error": <slug>, "error_code": <number>, "error_description": <text>}
//
// error_code and error_description are the field names the firmware module
// reads; their value types and the numbers are UNCONFIRMED. The numbers are
// assigned here, not Sony's.
type Error struct {
	Status int    // HTTP status
	Slug   string // OAuth-style error name
	Code   int    // error_code
	Desc   string // error_description
}

func (e *Error) Error() string { return e.Slug + ": " + e.Desc }

func newErr(status int, slug string, code int, desc string) *Error {
	return &Error{Status: status, Slug: slug, Code: code, Desc: desc}
}

var (
	errInvalidRequest = func(d string) *Error { return newErr(400, "invalid_request", 1001, d) }
	errInvalidClient  = func() *Error { return newErr(401, "invalid_client", 1002, "client authentication failed") }
	errBadCredentials = func() *Error { return newErr(401, "invalid_grant", 1003, "invalid username or password") }
	errBadGrant       = func() *Error {
		return newErr(400, "invalid_grant", 1003, "grant code invalid, expired or already used")
	}
	errUnsupportedGrant = func() *Error { return newErr(400, "unsupported_grant_type", 1004, "unsupported grant_type") }
	errSecondFactor     = func() *Error { return newErr(401, "second_factor_required", 1005, "second factor required") }
	errBadSecondFactor  = func() *Error { return newErr(401, "invalid_second_factor", 1006, "second factor invalid") }
	errDisabled         = func() *Error { return newErr(403, "account_disabled", 1007, "account is not available") }
	errOnlineIDRequired = func() *Error { return newErr(403, "online_id_required", 1008, "account has no online ID yet") }
	errInvalidOnlineID  = func() *Error {
		return newErr(400, "invalid_online_id", 1009, "online ID must be 3-16 characters: letters, digits, - and _, starting with a letter")
	}
	errOnlineIDTaken = func() *Error { return newErr(409, "online_id_taken", 1010, "online ID is already taken") }
	errRateLimited   = func() *Error { return newErr(429, "too_many_attempts", 1011, "too many attempts, try again later") }
	errConsoleToken  = func() *Error { return newErr(401, "invalid_console_token", 1012, "console token missing or invalid") }
	errLoginRequired = func() *Error { return newErr(401, "login_required", 1013, "no valid sign-in session") }
	errServer        = func(status int) *Error { return newErr(status, "server_error", 1099, "temporary server error") }
)

// writeJSON writes v with no-store caching.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, e *Error) {
	writeJSON(w, e.Status, map[string]any{
		"error":             e.Slug,
		"error_code":        e.Code,
		"error_description": e.Desc,
	})
}

// redirectError answers with a 302 to redirect_uri carrying error= and state=.
func redirectError(w http.ResponseWriter, r *http.Request, redirect, state string, e *Error) {
	u, err := url.Parse(redirect)
	if err != nil {
		writeError(w, e)
		return
	}
	q := u.Query()
	q.Set("error", e.Slug)
	q.Set("error_description", e.Desc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusFound)
}
