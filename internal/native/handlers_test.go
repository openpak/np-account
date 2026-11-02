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

	"openpak/np-account/internal/config"
	"openpak/np-account/internal/native"
	"openpak/np-account/internal/oauth"
	accountv1 "github.com/openpak/account-api/openpak/account/v1"
	"openpak/np-common/coreclient"
	"openpak/np-common/fakecore"
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

// Account Information sends getCountries on the CAM session right after cam/authenticate
// (regcam 4.93 FUN_0006b044 -> FUN_00079474; the URL prefix comes from the handle kind, table
// 0x108514 index 6 = "cam/"). FUN_000db718 requires the tag-1 list 0x5b; the old catch-all
// empty reply failed that lookup and the CAM job posted the error, closing the screen.
func TestGetCountriesOnEveryService(t *testing.T) {
	h := handler(t)
	for _, svc := range []string{"cam", "reg", "store", "upgrade", "pwd"} {
		b := post(h, "/native/"+svc+"/getCountries.action", "").Body.Bytes()
		if len(b) < 12 || b[1] != 0 || binary.BigEndian.Uint16(b[4:]) != 1 || binary.BigEndian.Uint16(b[8:]) != 0x5b {
			t.Fatalf("%s/getCountries: no 0x5b list: % x", svc, b)
		}
		if n := binary.BigEndian.Uint16(b[10:]); n == 0 {
			t.Fatalf("%s/getCountries: empty country list", svc)
		}
		if got := post(h, "/native/"+svc+"/delSess.action", "").Body.Bytes(); !bytes.Equal(got, []byte{0, 0, 0, 0}) {
			t.Fatalf("%s/delSess: % x", svc, got)
		}
	}
}

// elemAt mirrors regcam FUN_000ddf38: walk elements (tag & 0xfff) and require the found one to
// hold at least min bytes; a missing element is 0x80023087 on the console.
func elemAt(t *testing.T, b []byte, tag uint16, min int) []byte {
	t.Helper()
	for len(b) >= 4 {
		g, n := binary.BigEndian.Uint16(b)&0xfff, int(binary.BigEndian.Uint16(b[2:]))
		if n > len(b)-4 {
			t.Fatalf("element %x truncated", g)
		}
		if g == tag {
			if n < min {
				t.Fatalf("element %x has %d bytes, firmware needs %d", tag, n, min)
			}
			return b[4 : 4+n]
		}
		b = b[4+n:]
	}
	t.Fatalf("element %x missing", tag)
	return nil
}

// Account Information loads name, mail opt-in and wallet options together (regcam job 0x10c,
// completion FUN_0006d7e8). Parsers: getName FUN_000d8c18 (0x67 >= 0x46, then required 0x65 and
// 0x66 after the fixed part), getOptIn FUN_000d8b18 (0x68 >= 8), getWalOpt FUN_000d89f0 (0x69 >= 8).
func TestAccountInformationLoads(t *testing.T) {
	h := handler(t)
	for _, svc := range []string{"cam", "reg"} {
		get := func(action string) []byte {
			w := post(h, "/native/"+svc+"/"+action+".action", "")
			b := w.Body.Bytes()
			if w.Code != 200 || len(b) < 4 || b[1] != 0 {
				t.Fatalf("%s/%s: status %d reply % x", svc, action, w.Code, b)
			}
			return b[4:]
		}
		name := elemAt(t, get("getName"), 0x67, 0x46)
		elemAt(t, name[0x46:], 0x65, 0)
		elemAt(t, name[0x46:], 0x66, 0)
		opt := elemAt(t, get("getOptIn"), 0x68, 8)
		if binary.BigEndian.Uint32(opt) == 2 || binary.BigEndian.Uint32(opt[4:]) == 2 {
			t.Fatalf("%s/getOptIn: opt-in on by default: % x", svc, opt)
		}
		wal := elemAt(t, get("getWalOpt"), 0x69, 8)
		if !bytes.Equal(wal[:8], make([]byte, 8)) {
			t.Fatalf("%s/getWalOpt: wallet option set: % x", svc, wal)
		}
	}
	name := elemAt(t, native.NameReply("Leia", "Organa")[4:], 0x67, 0x46)
	if string(elemAt(t, name[0x46:], 0x65, 0)) != "Leia" || string(elemAt(t, name[0x46:], 0x66, 0)) != "Organa" ||
		string(name[4:8]) != "Leia" || string(name[0x25:0x2b]) != "Organa" {
		t.Fatalf("name layout % x", name)
	}
}
