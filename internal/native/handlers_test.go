package native_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

func TestCAMAuthenticateUsesCoreIdentity(t *testing.T) {
	h := handler(t)
	for _, prefix := range []string{"cam", "reg"} {
		path := "/native/" + prefix + "/authenticate.action"
		form := url.Values{"version": {"25"}, "username": {"leia@example.org"}, "password": {"pw1"}}.Encode()
		b := post(h, path, form).Body.Bytes()
		if len(b) < 8+0x3c || binary.BigEndian.Uint16(b[4:]) != 0x5e || binary.BigEndian.Uint16(b[6:]) < 0x3c {
			t.Fatalf("CAM identity missing for %s", prefix)
		}
		if got := strings.TrimRight(string(b[16:8+0x19]), "\x00"); got != "Leia_Organa" {
			t.Fatalf("wrong core identity: %q", got)
		}
		bad := post(h, path, url.Values{"username": {"leia@example.org"}, "password": {"wrong"}}.Encode()).Body.Bytes()
		if !bytes.Equal(bad, []byte{0, 0x14, 0, 0}) {
			t.Fatalf("CAM accepted wrong password: %x", bad)
		}
		if got := post(h, "/native/"+prefix+"/delSess.action", "").Body.Bytes(); !bytes.Equal(got, []byte{0, 0, 0, 0}) {
			t.Fatalf("delete session: %x", got)
		}
	}
}

// These bounds follow regcam FUN_000dd9ac, FUN_000d8f58 and FUN_000da04c,
// rather than comparing the response against the encoder that produced it.
func validateCAMLoader(b []byte) error {
	find := func(data []byte, wanted uint16, minimum int) ([]byte, error) {
		for len(data) >= 4 {
			tag, n := binary.BigEndian.Uint16(data), int(binary.BigEndian.Uint16(data[2:]))
			if n > len(data)-4 {
				return nil, fmt.Errorf("truncated element %x", tag)
			}
			value := data[4 : 4+n]
			if tag&0xfff == wanted {
				if len(value) < minimum {
					return nil, fmt.Errorf("short element %x", wanted)
				}
				return value, nil
			}
			data = data[4+n:]
		}
		return nil, fmt.Errorf("missing element %x", wanted)
	}
	if len(b) < 4 || b[1] != 0 {
		return fmt.Errorf("failed reply")
	}
	identity, err := find(b[4:], 0x5e, 0x3c)
	if err != nil {
		return err
	}
	if _, err = find(identity[0x38:], 0x5d, 1); err != nil {
		return err
	}
	if _, err = find(b[4:], 0x5f, 0x3c); err != nil {
		return err
	}
	// A list is tag1, id+count; find the service list by id, then index0.
	data := b[4:]
	var services []byte
	for len(data) >= 4 {
		n := int(binary.BigEndian.Uint16(data[2:]))
		if n > len(data)-4 {
			return fmt.Errorf("truncated list")
		}
		if binary.BigEndian.Uint16(data)&0xfff == 1 && n >= 4 && binary.BigEndian.Uint16(data[4:]) == 0x16 {
			services = data[4 : 4+n]
			break
		}
		data = data[4+n:]
	}
	if len(services) < 4 || binary.BigEndian.Uint16(services[2:]) < 1 {
		return fmt.Errorf("service index0 unavailable")
	}
	service, err := find(services[4:], 0x16, 0x2a)
	if err != nil {
		return err
	}
	nested := service[0x1e:]
	options, err := find(nested, 1, 4)
	if err != nil {
		return err
	}
	if binary.BigEndian.Uint16(options) != 0x15 || binary.BigEndian.Uint16(options[2:]) != 0 {
		return fmt.Errorf("expected empty payment option list")
	}
	for _, tag := range []uint16{0x7d, 0x7e} {
		value, err := find(nested, tag, 0)
		if err != nil {
			return err
		}
		if len(value) != 0 {
			return fmt.Errorf("unexpected billing value")
		}
	}
	return nil
}

func TestCAMReplyPassesAccountLoaderBounds(t *testing.T) {
	h := handler(t)
	form := url.Values{"username": {"leia@example.org"}, "password": {"pw1"}}.Encode()
	for _, prefix := range []string{"cam", "reg"} {
		b := post(h, "/native/"+prefix+"/authenticate.action", form).Body.Bytes()
		if err := validateCAMLoader(b); err != nil {
			t.Fatalf("%s: %v", prefix, err)
		}
		for _, n := range []int{0, 3, 8, len(b) - 1} {
			if validateCAMLoader(b[:n]) == nil {
				t.Fatalf("accepted truncated reply length%d", n)
			}
		}
	}
	b := post(h, "/native/reg/bindAccount.action", form).Body.Bytes()
	if validateCAMLoader(b) == nil {
		t.Fatal("old bind-only reply must fail CAM settings/service requirements")
	}
}

func TestGuestReplyPassesAccountLoaderBounds(t *testing.T) {
	b := native.GuestReply("PT", "pt")
	if len(b) != 4+4+0x3c || binary.BigEndian.Uint16(b[4:]) != 0x5e || binary.BigEndian.Uint16(b[6:]) != 0x3c {
		t.Fatalf("shape %x", b)
	}
	if string(b[8+0x19:8+0x1b]) != "pt" || string(b[8+0x1c:8+0x1e]) != "pt" {
		t.Fatalf("region %x", b)
	}
}
