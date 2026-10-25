// Command np-account-lab runs the np-account routes against an in-process fake account core with
// test accounts, for driving the PS3 firmware in the Pier lab without any real identity. Plain HTTP
// on 127.0.0.1:8002 (or -addr); the lab's TLS terminator forwards to it. Never deploy this.
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"openpak/np-account/internal/nav"
	"openpak/np-common/ticket"
	"os"
	"testing"
	"time"

	"openpak/np-account/internal/config"
	"openpak/np-account/internal/oauth"
	"openpak/np-account/internal/server"
	"openpak/np-common/coreclient"
	"openpak/np-common/fakecore"
)

// labTB is the minimum of testing.TB that fakecore.Serve uses.
type labTB struct{ testing.TB }

func (labTB) Helper()        {}
func (labTB) Cleanup(func()) {}

func main() {
	addr := flag.String("addr", "127.0.0.1:8002", "listen address")
	ticketPath := flag.String("ticket-key", os.Getenv("NP_TICKET_KEY"), "owner-local Ed25519 ticket key (enables native ticket issuance)")
	flag.Parse()
	const key = "lab-core-key-lab-core-key-lab-core-key"
	core := fakecore.New(key)
	core.AddAccount(fakecore.Account{ID: "lab-1", Email: "lab1@example.org", Password: "lab-password-1", DisplayName: "Lab One", Country: "US"})
	core.AddAccount(fakecore.Account{ID: "lab-2", Email: "lab2@example.org", Password: "lab-password-2", DisplayName: "Lab Two", Country: "GB"})
	core.AddFriend("lab-1", "lab-2")
	cli, err := coreclient.Dial("passthrough:///core", key, core.Serve(labTB{})...)
	if err != nil {
		log.Fatal(err)
	}
	cfg := &config.Config{ClientID: "lab", ClientSecret: "lab", TokenKey: "lab-token-key-lab-token-key-lab-token-key", EnvIssID: "1", CommDomain: "00",
		RedirectPrefixes: []string{"orbis://"}, AccessTTL: time.Hour, AutoOnlineID: true}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("np-account-lab on", *addr, "(accounts lab1@example.org / lab-password-1, lab2@example.org / lab-password-2)")
	auth := oauth.New(cfg, cli, nil, nil)
	var comm *nav.Service
	if *ticketPath != "" {
		signer, e := ticket.Load(*ticketPath)
		if e != nil {
			log.Fatal(e)
		}
		comm = &nav.Service{Auth: auth, Tickets: signer, TTL: time.Hour}
	}
	log.Fatal(server.New(*addr, logged(server.Handler(auth, comm))).Serve(ln))
}

func logged(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method, r.Host, r.URL.Path)
		h.ServeHTTP(w, r)
	})
}
