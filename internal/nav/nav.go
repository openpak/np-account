package nav

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"openpak/np-account/internal/oauth"
	"openpak/np-common/ticket"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Service struct {
	Auth    *oauth.Service
	Tickets *ticket.Signer
	TTL     time.Duration
}

var servicePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,24}$`)

func (s *Service) Register(m *http.ServeMux) { m.HandleFunc("POST /nav/auth", s.login) }
func navError(w http.ResponseWriter, reason byte) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-I-5-Status", fmt.Sprintf("NG; reason=%02x", reason))
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(200)
}
func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if r.ParseForm() != nil {
		navError(w, 1)
		return
	}
	f := r.PostForm
	console := f.Get("consoleid")
	raw, e := hex.DecodeString(console)
	if f.Get("type") != "0" || !servicePattern.MatchString(f.Get("serviceid")) || e != nil || len(raw) != 32 || len(f.Get("loginid")) > 254 || len(f.Get("password")) > 128 {
		navError(w, 1)
		return
	}
	id, err := s.Auth.NativeSignIn(r.Context(), f.Get("loginid"), f.Get("password"))
	if err != nil {
		if err.Status >= 500 {
			http.Error(w, "account service unavailable", 503)
		} else {
			navError(w, 0x14)
		}
		return
	}
	ttl := s.TTL
	if ttl == 0 {
		ttl = time.Hour
	}
	b, e := s.Tickets.Issue(ticket.Identity{AccountID: id.AccountID, LinkID: id.LinkID, OnlineID: id.OnlineID, Country: country(id.Country), Birthday: id.Birthday, Service: f.Get("serviceid"), ConsoleID: strings.ToLower(console)}, ttl)
	if e != nil {
		http.Error(w, "ticket issuance failed", 503)
		return
	}

	w.Header().Set("Content-Type", "application/x-i-5-ticket")
	w.Header().Set("X-I-5-Status", "OK")
	w.Header().Set("X-I-5-Version", "4.0")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

func country(v string) string {
	v = strings.ToLower(v)
	if len(v) != 2 || v[0] < 'a' || v[0] > 'z' || v[1] < 'a' || v[1] > 'z' {
		return "us"
	}
	return v
}
