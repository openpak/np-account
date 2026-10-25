package community_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"openpak/np-community/xmpp"
)

func TestAccountRestartDoesNotEndAuthenticatedXMPP(t *testing.T) {
	fixture, _, _, handler := setup(t)
	account := httptest.NewServer(handler)
	defer account.Close()
	resp, err := http.PostForm(account.URL+"/nav/auth", url.Values{"type": {"0"}, "loginid": {"a@example.org"}, "password": {"pw"}, "serviceid": {"IV0001-NPXS01001_00"}, "consoleid": {strings.Repeat("0", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.Header.Get("X-I-5-Status") != "OK" {
		t.Fatal("account login failed", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- (&xmpp.Server{Service: fixture.Service}).Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		ln.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("community did not shut down")
		}
	})
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	decoder := xml.NewDecoder(reader)
	send := func(body string) {
		t.Helper()
		if _, err := io.WriteString(conn, body); err != nil {
			t.Fatal(err)
		}
	}
	receive := func(want string) {
		t.Helper()
		for i := 0; i < 100; i++ {
			token, err := decoder.Token()
			if err != nil {
				t.Fatal("reading", want, err)
			}
			if start, ok := token.(xml.StartElement); ok && start.Name.Local == want {
				if err := decoder.Skip(); err != nil {
					t.Fatal(err)
				}
				return
			}
		}
		t.Fatal("missing", want)
	}
	open := `<stream:stream xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams" to="us.us.np.playstation.net" version="1.0">`
	send(open)
	receive("features")
	send(`<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="I5R-TICKET-AUTH">` + base64.StdEncoding.EncodeToString(raw) + `</auth>`)
	receive("success")
	account.Close() // Independent deployment: terminate the complete account HTTP server.
	decoder = xml.NewDecoder(reader)
	send(open)
	receive("features")
	send(`<iq type="set" id="after-account-stop"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"><resource>ps3</resource></bind></iq>`)
	receive("iq")
}
