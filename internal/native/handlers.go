package native

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net/http"
	"strings"

	"openpak/np-account/internal/oauth"
	"openpak/np-common/onlineid"
)

const maxFormBytes = 64 << 10

// Result bytes the firmware maps to on-screen messages (internal research notes).
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
	// The store opens with the same country list (empty reply = 0x80023087, element 0x5b list missing).
	mux.HandleFunc("POST /native/store/getCountries.action", h.getCountries)
	mux.HandleFunc("POST /native/reg/bindAccount.action", h.bindAccount)
	// Authenticate also needs the CAM settings/service projection after identity.
	// The bindAccount-only reply is insufficient for the account-management UI.
	mux.HandleFunc("POST /native/cam/authenticate.action", h.bindAccount)
	mux.HandleFunc("POST /native/reg/authenticate.action", h.bindAccount)
	// No separate CAM server session exists yet. Deletion is idempotent and must
	// not terminate the user's independently authenticated NP/XMPP session.
	mux.HandleFunc("POST /native/cam/delSess.action", func(w http.ResponseWriter, r *http.Request) { h.reply(w, Reply()) })
	mux.HandleFunc("POST /native/reg/delSess.action", func(w http.ResponseWriter, r *http.Request) { h.reply(w, Reply()) })
	// Store guest session: the firmware's country/language/date-of-birth form posts here
	// (account.country, account.language, account.dob/mob/yob) and expects the authenticate-style
	// account element back. No server state: the guest has no identity, only the echoed region.
	mux.HandleFunc("POST /native/store/crGuestSess.action", h.crGuestSess)
	mux.HandleFunc("POST /native/store/delSess.action", func(w http.ResponseWriter, r *http.Request) { h.reply(w, Reply()) })
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
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	_ = r.ParseForm()
	form := r.PostForm
	for _, secret := range []string{"password", "username", "consoleId"} {
		if form.Has(secret) {
			form.Set(secret, "<redacted>")
		}
	}
	log.Warn("native: unhandled action", "path", r.URL.Path, "form", form.Encode(), "cookie", r.Header.Get("Cookie") != "")
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
	if strings.HasSuffix(r.URL.Path, "/authenticate.action") {
		h.reply(w, CAMReply(id))
		return
	}
	h.reply(w, BindReply(id))
}

// BindReply is the bindAccount success reply: one element 0x5e holding the account struct followed
// by element 0x5d, the NP credential blob (layout in internal research notes).
func BindReply(id *oauth.NativeIdentity) []byte {

	v := make([]byte, 0x38)
	binary.BigEndian.PutUint64(v[0:8], onlineid.AccountID(id.AccountID))
	copy(v[0x08:0x19], id.OnlineID) // 17 bytes, NUL padded
	copy(v[0x19:0x1c], id.Country)
	copy(v[0x1c:0x22], "en")
	v = append(v, Elem(0x5d, id.Credential)...)
	return Reply(Elem(0x5e, v))
}

// CAMReply adds the settings and service records required by regcam's account
// management loader (FUN_0006b1e0). OpenPak has no billing/payment backend here:
// settings are the default zero projection and service fields are absent/empty.
// Never populate this record with invented Sony wallet or billing information.
func CAMReply(id *oauth.NativeIdentity) []byte {
	reply := BindReply(id)
	reply = append(reply, Elem(0x5f, make([]byte, 0x3c))...)
	// Service entry: 0x1e fixed bytes, required empty list0x15 and strings7d/7e.
	// FUN_000da04c requires one entry at index0 even with no payment options.
	service := make([]byte, 0x1e)
	service = append(service, List(0x15)...)
	service = append(service, Elem(0x7d, nil)...)
	service = append(service, Elem(0x7e, nil)...)
	return append(reply, List(0x16, Elem(0x16, service))...)
}

// GuestReply is the crGuestSess success reply (vsh type 0x42 is parsed like authenticate): the
// 0x5e account struct with a zero account id and no online ID, carrying the country and language the
// form sent, followed by an empty 0x5d credential element (regcam FUN_000dd9ac needs 0x3c bytes).
func GuestReply(country, language string) []byte {
	v := make([]byte, 0x38)
	copy(v[0x19:0x1c], strings.ToLower(country))
	copy(v[0x1c:0x22], strings.ToLower(language))
	v = append(v, Elem(0x5d, nil)...)
	return Reply(Elem(0x5e, v))
}

func (h *Handler) crGuestSess(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		h.reply(w, ErrorReply(resBadTextEtc))
		return
	}
	h.reply(w, GuestReply(r.PostForm.Get("account.country"), r.PostForm.Get("account.language")))
}
