package community_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"openpak/np-account/internal/config"
	"openpak/np-account/internal/native"
	"openpak/np-account/internal/nav"
	"openpak/np-account/internal/oauth"
	"openpak/np-account/internal/server"
	accountv1 "openpak/np-common/accountpb"
	"openpak/np-common/coreclient"
	"openpak/np-common/fakecore"
	"openpak/np-common/ticket"
	"openpak/np-community/community"
	trophynative "openpak/np-trophy/native"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	*community.Service
	Trophies *trophynative.TrophyBackend
}

func setup(t *testing.T) (*fixture, *fakecore.Core, *coreclient.Client, http.Handler) {
	t.Helper()
	const key = "core-key-core-key-core-key-core-key"
	f := fakecore.New(key)
	for _, a := range []fakecore.Account{{ID: "a", Email: "a@example.org", Password: "pw", DisplayName: "Alice", Country: "US"}, {ID: "b", Email: "b@example.org", Password: "pw", DisplayName: "Bob", Country: "GB"}, {ID: "c", DisplayName: "Alice", Country: "US"}, {ID: "d", Email: "2fa@example.org", Password: "pw", DisplayName: "TwoFactor", TOTP: "123456"}} {
		f.AddAccount(a)
	}
	c, e := coreclient.Dial("passthrough:///core", key, f.Serve(t)...)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	auth := oauth.New(&config.Config{ClientID: "c", ClientSecret: "s", TokenKey: "token-key-token-key-token-key-token-key", AccessTTL: time.Hour}, c, nil, nil)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ticket.New(priv, nil)
	s := &fixture{Service: &community.Service{Core: c, Tickets: signer}}
	communityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux := http.NewServeMux()
		s.Service.Register(mux)
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(communityServer.Close)
	trophyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux := http.NewServeMux()
		(&trophynative.Service{Core: c, Tickets: signer, Trophies: s.Trophies, TrophyResourceKey: s.ResourceKey}).Register(mux)
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(trophyServer.Close)
	handler, e := server.RemoteHandler(auth, &nav.Service{Auth: auth, Tickets: signer}, communityServer.URL, trophyServer.URL)
	if e != nil {
		t.Fatal(e)
	}

	return s, f, c, handler
}
func login(h http.Handler, email, pw string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/nav/auth", strings.NewReader(url.Values{"type": {"0"}, "loginid": {email}, "password": {pw}, "serviceid": {"IV0001-NPXS01001_00"}, "consoleid": {strings.Repeat("0", 64)}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestLoginProfileAndCoreRevocation(t *testing.T) {
	s, f, _, h := setup(t)
	for _, email := range []string{"a@example.org", "b@example.org"} {
		w := login(h, email, "pw")
		if w.Header().Get("X-I-5-Status") != "OK" {
			t.Fatalf("login %d %s", w.Code, w.Body.String())
		}
	}
	for _, tc := range [][2]string{{"a@example.org", "wrong"}, {"2fa@example.org", "pw"}} {
		if login(h, tc[0], tc[1]).Header().Get("X-I-5-Status") == "OK" {
			t.Fatal("invalid credentials/2FA accepted")
		}
	}
	w := login(h, "a@example.org", "pw")
	raw := w.Body.Bytes()
	id, e := s.Tickets.Verify(raw)
	if e != nil {
		t.Fatal(e)
	}
	// Native account binding and nav/auth must identify the same local XMB account.
	nativeBody := native.BindReply(&oauth.NativeIdentity{AccountID: id.AccountID, OnlineID: id.OnlineID, Country: id.Country})
	cursor := 10
	for i := 0; i < 4; i++ {
		cursor += 4 + int(binary.BigEndian.Uint16(raw[cursor+2:]))
	}
	if !bytes.Equal(nativeBody[8:16], raw[cursor+4:cursor+12]) {
		t.Fatal("account IDs differ")
	}
	body := `<profile><ticket>` + base64.StdEncoding.EncodeToString(append(append([]byte(nil), raw...), []byte("device-block")...)) + `</ticket></profile>`
	request := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/basic_view/sec/get_self_profile", strings.NewReader(body)))
		return w
	}
	result := request()
	if result.Code != 200 {
		t.Fatal(result.Code, result.Body.String())
	}
	var p struct {
		Result string `xml:"result,attr"`
		JID    string `xml:"jid"`
	}
	if e = xml.Unmarshal(result.Body.Bytes(), &p); e != nil || p.Result != "00" || p.JID != "Alice@us.np.community.playstation.net" {
		t.Fatal(p, e)
	}
	f.SetStatus("a", accountv1.AccountStatus_ACCOUNT_STATUS_BANNED)
	if request().Code == 200 {
		t.Fatal("banned account ticket accepted")
	}
}
func TestAllOpenPakFriendsProvisionedWithoutConsoleLogin(t *testing.T) {
	s, f, c, _ := setup(t)
	ctx := context.Background()
	f.AddFriend("a", "b")
	f.AddFriend("a", "c")
	// Neither friend has ever signed in on PS3. Roster reads must provision both.
	roster, e := s.Roster(ctx, "a")
	if e != nil || len(roster) != 2 {
		t.Fatal(roster, e)
	}
	ids := map[string]string{}
	for _, p := range roster {
		ids[p.AccountID] = p.OnlineID
		if _, e = c.GetLinkByAccount(ctx, p.AccountID); e != nil {
			t.Fatal("no real core NP link", e)
		}
	}
	if ids["b"] != "Bob" || ids["c"] != "Alice" {
		t.Fatal(ids)
	}
	// Full migration preserves existing IDs, resolves a display-name collision,
	// includes users with no friends, and is safe to run repeatedly.
	n, e := s.ProvisionAll(ctx, c)
	if e != nil || n != 4 {
		t.Fatal(n, e)
	}
	a, e := c.GetLinkByAccount(ctx, "a")
	if e != nil || a.OnlineID == "Alice" {
		t.Fatal("collision not resolved", a, e)
	}
	n, e = s.ProvisionAll(ctx, c)
	if e != nil || n != 4 {
		t.Fatal(n, e)
	}
	again, _ := c.GetLinkByAccount(ctx, "a")
	if again.OnlineID != a.OnlineID {
		t.Fatal("migration renamed account")
	}
	f.SetBlocked("b", "a", true)
	roster, e = s.Roster(ctx, "a")
	if e != nil || len(roster) != 1 || roster[0].AccountID != "c" {
		t.Fatal("block policy not respected", roster, e)
	}
	f.SetStatus("c", accountv1.AccountStatus_ACCOUNT_STATUS_DELETED)
	roster, e = s.Roster(ctx, "a")
	if e != nil || len(roster) != 0 {
		t.Fatal("deleted friend leaked", roster, e)
	}
}

func TestCoreAvatarInSelfAndPublicFriendProfile(t *testing.T) {
	s, f, c, h := setup(t)
	f.SetAvatar("a", []byte("validated-core-png"))
	w := login(h, "a@example.org", "pw")
	if w.Header().Get("X-I-5-Status") != "OK" {
		t.Fatal("login failed")
	}
	body := `<profile><ticket>` + base64.StdEncoding.EncodeToString(w.Body.Bytes()) + `</ticket></profile>`
	out := httptest.NewRecorder()
	h.ServeHTTP(out, httptest.NewRequest("POST", "/basic_view/sec/get_self_profile", strings.NewReader(body)))
	var p struct {
		Avatar string `xml:"avatarurl"`
	}
	if e := xml.Unmarshal(out.Body.Bytes(), &p); e != nil || p.Avatar == "" || len(p.Avatar) > 127 {
		t.Fatal("missing avatar URL", p, e)
	}
	image := httptest.NewRecorder()
	h.ServeHTTP(image, httptest.NewRequest("GET", p.Avatar, nil))
	if image.Code != 200 || image.Header().Get("Content-Type") != "image/png" || image.Body.String() != "validated-core-png" {
		t.Fatal("avatar fetch failed", image.Code)
	}
	request := httptest.NewRequest("GET", p.Avatar, nil)
	request.Header.Set("If-None-Match", image.Header().Get("ETag"))
	cached := httptest.NewRecorder()
	h.ServeHTTP(cached, request)
	if cached.Code != 304 {
		t.Fatal("conditional avatar fetch", cached.Code)
	}
	// The firmware's public friend-profile operation carries no ticket.
	if _, e := s.EnsureLink(context.Background(), &coreclient.Account{ID: "b", DisplayName: "Bob", Country: "GB"}); e != nil {
		t.Fatal(e)
	}
	friend := httptest.NewRecorder()
	h.ServeHTTP(friend, httptest.NewRequest("POST", "/basic_view/func/get_profile", strings.NewReader(`<profile><jid>Bob@gb.np.np.playstation.net</jid><avatar size="l"/></profile>`)))
	if friend.Code != 200 {
		t.Fatal("captured public profile request rejected", friend.Code)
	}
	for _, domain := range []string{"ie.np.np.playstation.net", "us.np.community.playstation.net", "ie.evil.playstation.net"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/basic_view/func/get_profile", strings.NewReader(`<profile><jid>Bob@`+domain+`</jid></profile>`)))
		want := 200
		if domain == "ie.evil.playstation.net" {
			want = 400
		}
		if w.Code != want {
			t.Fatalf("viewer region %s: status %d", domain, w.Code)
		}
	}
	if _, e := c.GetLinkByAccount(context.Background(), "b"); e != nil {
		t.Fatal(e)
	}
	f.SetStatus("a", accountv1.AccountStatus_ACCOUNT_STATUS_DELETED)
	image = httptest.NewRecorder()
	h.ServeHTTP(image, httptest.NewRequest("GET", p.Avatar, nil))
	if image.Code != 404 {
		t.Fatal("inactive account avatar exposed", image.Code)
	}
}

func TestTrophyDiscoveryReportsUnavailable(t *testing.T) {
	s, _, _, h := setup(t)
	s.ResourceKey = bytes.Repeat([]byte{0x42}, 20)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/np/resource/trophy/trophy-status.xml", nil))
	var metadata struct {
		XMLName xml.Name
		Status  string `xml:"status,attr"`
	}
	if w.Code != 200 || xml.Unmarshal(w.Body.Bytes(), &metadata) != nil || metadata.XMLName.Local != "nptrophy" || metadata.Status != "maintenance" {
		t.Fatalf("invalid trophy discovery: %d %s", w.Code, w.Body.String())
	}
}

func TestNativeTrophyReadRequiresSessionAndPersistentBackend(t *testing.T) {
	s, _, _, h := setup(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("k", 32) {
			t.Error("missing private backend authentication")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"games":[]}`))
	}))
	defer backend.Close()
	s.Trophies = &trophynative.TrophyBackend{URL: backend.URL, Key: strings.Repeat("k", 32)}
	path := "/trophy/sec/get_multi_user_info_privacy"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(`<nptrophy/>`)))
	if w.Code != 401 {
		t.Fatalf("unauthenticated trophy read: %d", w.Code)
	}
	session := login(h, "a@example.org", "pw")
	body := `<nptrophy><ticket>` + base64.StdEncoding.EncodeToString(session.Body.Bytes()) + `</ticket></nptrophy>`
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(body)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `<types platinum="0" gold="0" silver="0" bronze="0">`) {
		t.Fatalf("empty persisted trophy profile: %d %s", w.Code, w.Body.String())
	}
	backend.Close()
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(body)))
	if w.Code != 503 {
		t.Fatalf("backend failure became success: %d", w.Code)
	}
}

func TestNativeTrophySyncUsesSignedAccountAndWireIDs(t *testing.T) {
	s, _, _, h := setup(t)
	var uploaded struct {
		CommunicationID string `json:"communication_id"`
		Trophies        []struct {
			ID       int    `json:"id"`
			EarnedAt int64  `json:"earned_at"`
			Grade    string `json:"grade"`
		} `json:"trophies"`
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/users/a/trophies" || r.Method != "POST" {
			t.Errorf("wrong identity or method: %s %s", r.Method, r.URL.Path)
		}
		if e := json.NewDecoder(r.Body).Decode(&uploaded); e != nil {
			t.Error(e)
		}
		w.Write([]byte(`{"games":[{"communication_id":"NPWR04270_00","trophies":[{"id":0,"earned_at":1792065600,"grade":"B"}]}]}`))
	}))
	defer backend.Close()
	s.Trophies = &trophynative.TrophyBackend{URL: backend.URL, Key: strings.Repeat("k", 32)}
	session := login(h, "a@example.org", "pw")
	body := `<nptrophy><ticket>` + base64.StdEncoding.EncodeToString(session.Body.Bytes()) + `</ticket><jid>Bob@gb.np.np.playstation.net</jid><list><info npcommid="NPWR04270_00"><trophies><trophy id="1" type="0">2026-10-15T12:00:00Z</trophy></trophies></info></list></nptrophy>`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/trophy/sec/sync_trophies", strings.NewReader(body)))
	if w.Code != 200 || len(uploaded.Trophies) != 1 || uploaded.Trophies[0].ID != 0 || uploaded.Trophies[0].Grade != "B" {
		t.Fatalf("sync: %d %s %+v", w.Code, w.Body.String(), uploaded)
	}
	if !strings.Contains(w.Body.String(), `<trophy id="1" type="0">2026-10-15T12:00:00Z</trophy>`) {
		t.Fatalf("invalid return IDs/time: %s", w.Body.String())
	}
}

func TestTrophyDiscoveryUsesTextFQDN(t *testing.T) {
	s, _, _, h := setup(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"games":[]}`)) }))
	defer backend.Close()
	s.Trophies = &trophynative.TrophyBackend{URL: backend.URL, Key: strings.Repeat("k", 32)}
	s.ResourceKey = bytes.Repeat([]byte("k"), 20)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/np/resource/trophy/trophy-status.xml", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `<trophy-fqdn>trophy.ww.np.community.playstation.net</trophy-fqdn>`) || strings.Contains(w.Body.String(), "<fqdn>") {
		t.Fatalf("bad discovery: %d %s", w.Code, w.Body.String())
	}
}
