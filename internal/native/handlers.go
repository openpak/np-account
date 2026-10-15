package native

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"net/http"

	"openpak/np-account/internal/oauth"
)

const maxFormBytes = 64 << 10

// Result bytes the firmware maps to on-screen messages (docs/ps3/psn-signin-findings.md).
const (
	resWrongIDPW  = 0x14 // "The sign-in ID or password is incorrect"
	resSuspended  = 0x1b // account suspended or banned
	resBadTextEtc = 0x46
)

// SignIn is what the handlers need from the sign-in service; *oauth.Service implements it.
type SignIn interface {
	NativeSignIn(ctx context.Context, username, password string) (*oauth.NativeIdentity, *oauth.Error)
}

// Handler serves /native/reg/*.action. Unknown actions get an empty OK reply so the firmware
// reports its own "missing element" error rather than an HTTP failure, and are logged.
type Handler struct {
	Auth      SignIn
	Countries []Country
	Log       *slog.Logger
}

// Register adds the routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /native/reg/getCountries.action", h.getCountries)
	mux.HandleFunc("POST /native/reg/bindAccount.action", h.bindAccount)
	mux.HandleFunc("POST /native/", h.unknown)
}

func (h *Handler) reply(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

func (h *Handler) getCountries(w http.ResponseWriter, r *http.Request) {
	cs := h.Countries
	if cs == nil {
		cs = DefaultCountries
	}
	h.reply(w, Countries(cs))
}

func (h *Handler) unknown(w http.ResponseWriter, r *http.Request) {
	log := h.Log
	if log == nil {
		log = slog.Default()
	}
	log.Warn("native: unhandled action", "path", r.URL.Path)
	h.reply(w, Reply())
}

func (h *Handler) bindAccount(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		h.reply(w, ErrorReply(resBadTextEtc))
		return
	}
	id, e := h.Auth.NativeSignIn(r.Context(), r.PostForm.Get("username"), r.PostForm.Get("password"))
	if e != nil {
		switch {
		case e.Status >= 500:
			http.Error(w, "temporary error", e.Status) // firmware shows 0x80023016/17, retryable
		case e.Slug == "account_disabled":
			h.reply(w, ErrorReply(resSuspended))
		default:
			h.reply(w, ErrorReply(resWrongIDPW))
		}
		return
	}
	h.reply(w, BindReply(id))
}

// BindReply is the bindAccount success reply: one element 0x5e holding the account struct followed
// by element 0x5d, the NP credential blob (layout in docs/ps3/psn-signin-findings.md).
func BindReply(id *oauth.NativeIdentity) []byte {
	sum := sha256.Sum256([]byte("openpak-np-native-account-id-v1\x00" + id.AccountID))
	v := make([]byte, 0x38)
	copy(v[0:8], sum[:8])
	copy(v[0x08:0x19], id.OnlineID) // 17 bytes, NUL padded
	copy(v[0x19:0x1c], id.Country)
	copy(v[0x1c:0x22], "en")
	v = append(v, Elem(0x5d, id.Credential)...)
	return Reply(Elem(0x5e, v))
}
