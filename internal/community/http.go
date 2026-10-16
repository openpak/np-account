package community

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"openpak/np-account/internal/onlineid"
	"openpak/np-account/internal/ticket"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var servicePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,24}$`)
var profileDomainPattern = regexp.MustCompile(`^[a-z]{2}\.np\.(np|community)\.playstation\.net$`)

func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /np/resource/trophy/trophy-status.xml", s.trophyStatus)
	mux.HandleFunc("GET /np/resource/title/{title}/matching/{resource}", s.matchingResource)
	mux.HandleFunc("POST /trophy/sec/sync_trophies", s.trophySync)
	for _, op := range []string{"get_multi_user_info_privacy", "get_title_list_privacy", "get_modified_title_privacy", "get_latest_trophies_privacy"} {
		mux.HandleFunc("POST /trophy/sec/"+op, s.trophyRead)
	}
	mux.HandleFunc("POST /nav/auth", s.login)
	mux.HandleFunc("GET /a/{cap}", s.avatar)
	mux.HandleFunc("POST /basic_view/sec/get_self_profile", s.profile)
	mux.HandleFunc("POST /basic_view/func/get_profile", s.friendProfile)
	mux.HandleFunc("POST /basic_update/sec/update_ptl", s.update)
	mux.HandleFunc("POST /basic_update/sec/update_ci", s.update)
}
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
	b, e := s.Tickets.Issue(ticket.Identity{AccountID: id.AccountID, LinkID: id.LinkID, OnlineID: id.OnlineID, Country: Country(id.Country), Service: f.Get("serviceid"), ConsoleID: strings.ToLower(console)}, ttl)
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

type requestXML struct {
	XMLName    xml.Name
	Ticket     string           `xml:"ticket"`
	JID        string           `xml:"jid"`
	OnlineID   string           `xml:"online-id"`
	TrophyList nativeTrophyList `xml:"list"`
}

func (s *Service) identity(w http.ResponseWriter, r *http.Request) (ticket.Identity, requestXML, bool) {
	var req requestXML
	var id ticket.Identity
	decoder := xml.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10))
	if decoder.Decode(&req) != nil {
		http.Error(w, "invalid request", 400)
		return id, req, false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		http.Error(w, "invalid request", 400)
		return id, req, false
	}
	b, e := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(req.Ticket), ""))
	if e != nil {
		http.Error(w, "invalid ticket", 401)
		return id, req, false
	}
	id, e = s.Verify(r.Context(), b)
	if e != nil {
		http.Error(w, "invalid session", 401)
		return id, req, false
	}
	return id, req, true
}
func xmlReply(w http.ResponseWriter, name string, value any) {
	b, e := xml.Marshal(value)
	if e != nil {
		http.Error(w, "profile failed", 500)
		return
	}
	b = append([]byte(xml.Header), b...)
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

type profileXML struct {
	XMLName   xml.Name `xml:"profile"`
	Result    string   `xml:"result,attr"`
	JID       string   `xml:"jid"`
	Name      string   `xml:"onlinename"`
	Country   string   `xml:"country"`
	Language1 string   `xml:"language1"`
	Language2 string   `xml:"language2"`
	Language3 string   `xml:"language3"`
	About     string   `xml:"aboutme"`
	Avatar    string   `xml:"avatarurl"`
	PTLP      string   `xml:"ptlp"`
}

func (s *Service) profile(w http.ResponseWriter, r *http.Request) {
	id, _, ok := s.identity(w, r)
	if !ok {
		return
	}
	acct, e := s.Core.GetAccount(r.Context(), id.AccountID)
	if e != nil {
		http.Error(w, "account unavailable", 503)
		return
	}
	name := acct.DisplayName
	if name == "" {
		name = id.OnlineID
	}
	xmlReply(w, "profile", profileXML{Result: "00", JID: JID(id.OnlineID, id.Country), Name: profileName(name), Avatar: s.AvatarURL(r.Context(), id.AccountID), Country: id.Country, Language1: "1", PTLP: "0"})
}

// The captured func/get_profile operation is public: firmware sends a JID and
// avatar size without a ticket. Return only active users' public profile fields.
func (s *Service) friendProfile(w http.ResponseWriter, r *http.Request) {
	var req requestXML
	d := xml.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	if d.Decode(&req) != nil {
		http.Error(w, "invalid profile request", 400)
		return
	}
	bare := strings.SplitN(req.JID, "/", 2)[0]
	name, domain, ok := strings.Cut(bare, "@")
	if !ok || !onlineid.Valid(name) || len(domain) > 128 || !strings.HasSuffix(domain, ".playstation.net") {
		http.Error(w, "invalid JID", 400)
		return
	}
	link, e := s.Core.GetLinkByOnlineID(r.Context(), name)
	if e != nil {
		http.NotFound(w, r)
		return
	}
	acct, e := s.Core.GetAccount(r.Context(), link.AccountID)
	if e != nil {
		http.NotFound(w, r)
		return
	}
	// VSH may use the viewer's region when reserializing another user's JID.
	// The region routes the request; it is not the target account's country.
	country := Country(acct.Country)
	if !profileDomainPattern.MatchString(domain) {
		http.Error(w, "invalid JID domain", 400)
		return
	}
	display := acct.DisplayName
	if display == "" {
		display = link.OnlineID
	}
	xmlReply(w, "profile", profileXML{Result: "00", JID: bare, Name: profileName(display), Country: country, Avatar: s.AvatarURL(r.Context(), acct.ID), Language1: "1", PTLP: "0"})
}

// These captured background updates are acknowledged, but telemetry is not
// authoritative presence/playtime. Presence belongs to the leased XMPP session.
func (s *Service) update(w http.ResponseWriter, r *http.Request) {
	_, req, ok := s.identity(w, r)
	if !ok {
		return
	}
	if req.XMLName.Local != "userplaytime" && req.XMLName.Local != "consoleinfo" {
		http.Error(w, "invalid update", 400)
		return
	}
	xmlReply(w, req.XMLName.Local, struct {
		XMLName xml.Name
		Result  string `xml:"result,attr"`
	}{req.XMLName, "00"})
}

func profileName(name string) string {
	for len(name) > 48 {
		_, n := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-n]
	}
	return name
}
