package native

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"openpak/np-common/coreclient"
	"openpak/np-common/ticket"
	"strconv"
	"strings"
)

type Core interface {
	GetAccount(context.Context, string) (*coreclient.Account, error)
	GetLinkByAccount(context.Context, string) (*coreclient.Link, error)
	GetLinkByOnlineID(context.Context, string) (*coreclient.Link, error)
	CanInteract(context.Context, string, string) (bool, error)
}
type Service struct {
	Core              Core
	Tickets           *ticket.Signer
	Trophies          Backend
	TrophyResourceKey []byte
}
type requestXML struct {
	XMLName    xml.Name
	Ticket     string           `xml:"ticket"`
	JID        string           `xml:"jid"`
	TrophyList nativeTrophyList `xml:"list"`
}

func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /np/resource/trophy/trophy-status.xml", s.trophyStatus)
	mux.HandleFunc("POST /trophy/sec/sync_trophies", s.trophySync)
	for _, op := range []string{"get_multi_user_info_privacy", "get_title_list_privacy", "get_modified_title_privacy", "get_latest_trophies_privacy"} {
		mux.HandleFunc("POST /trophy/sec/"+op, s.trophyRead)
	}
}
func (s *Service) Verify(ctx context.Context, raw []byte) (ticket.Identity, error) {
	return ticket.VerifyAccount(ctx, s.Core, s.Tickets, raw)
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

type Backend interface {
	Games(context.Context, string) ([]TrophyGame, error)
	Exchange(context.Context, string, []byte) ([]TrophyGame, error)
}
