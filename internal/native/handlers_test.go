package native_test

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	accountv1 "openpak/np-account/internal/accountpb"
	"openpak/np-account/internal/config"
	"openpak/np-account/internal/coreclient"
	"openpak/np-account/internal/fakecore"
	"openpak/np-account/internal/native"
	"openpak/np-account/internal/oauth"
)

const coreKey = "fake-core-key-fake-core-key-fake-core-key"

func handler(t *testing.T) http.Handler {
	core := fakecore.New(coreKey)
	core.AddAccount(fakecore.Account{ID: "acc-1", Email: "leia@example.org", Password: "pw1", DisplayName: "Leia Organa", Country: "SE"})
	core.AddAccount(fakecore.Account{ID: "acc-3", Email: "ban@example.org", Password: "pw3", DisplayName: "Ban", Status: accountv1.AccountStatus_ACCOUNT_STATUS_BANNED})
	cli, err := coreclient.Dial("passthrough:///core", coreKey, core.Serve(t)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close() })
	cfg := &config.Config{ClientID: "c", ClientSecret: "s", TokenKey: "0123456789abcdef0123456789abcdef-test", AccessTTL: time.Hour, AutoOnlineID: true}
	mux := http.NewServeMux()
	(&native.Handler{Auth: oauth.New(cfg, cli, nil, nil), Log: nil}).Register(mux)
	return mux
}

func post(h http.Handler, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestBindAccount(t *testing.T) {
	h := handler(t)
	form := func(u, p string) string {
		return url.Values{"version": {"25"}, "username": {u}, "password": {p}, "consoleId": {"00"}}.Encode()
	}

	b := post(h, "/native/reg/bindAccount.action", form("leia@example.org", "pw1")).Body.Bytes()
	// prefix 00 00 00 00, element 0x5e with length 0x38 + 4 + 32, then the struct
	if len(b) != 4+4+0x38+4+32 || !bytes.Equal(b[:4], []byte{0, 0, 0, 0}) || binary.BigEndian.Uint16(b[4:]) != 0x5e || binary.BigEndian.Uint16(b[6:]) != 0x38+4+32 {
		t.Fatalf("bad reply header: % x", b[:12])
	}
	v := b[8:]
	if got := strings.TrimRight(string(v[8:0x19]), "\x00"); got != "Leia_Organa" {
		t.Fatalf("online id %q", got)
	}
	if string(v[0x19:0x1b]) != "se" || string(v[0x1c:0x1e]) != "en" {
		t.Fatalf("country/lang %q %q", v[0x19:0x1c], v[0x1c:0x22])
	}
	if binary.BigEndian.Uint16(v[0x38:]) != 0x5d || binary.BigEndian.Uint16(v[0x3a:]) != 32 {
		t.Fatalf("credential element missing: % x", v[0x38:0x3c])
	}

	if b := post(h, "/native/reg/bindAccount.action", form("leia@example.org", "wrong")).Body.Bytes(); !bytes.Equal(b, []byte{0, 0x14, 0, 0}) {
		t.Fatalf("bad password: % x", b)
	}
	if b := post(h, "/native/reg/bindAccount.action", form("ban@example.org", "pw3")).Body.Bytes(); !bytes.Equal(b, []byte{0, 0x1b, 0, 0}) {
		t.Fatalf("banned: % x", b)
	}
}
