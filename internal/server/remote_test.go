package server_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"openpak/np-account/internal/config"
	"openpak/np-account/internal/oauth"
	"openpak/np-account/internal/server"
	"strings"
	"testing"
)

func TestRemoteRoutingAndUnavailableServices(t *testing.T) {
	upstream := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("X-Owner", name)
			w.Header().Set("X-Original-Host", r.Host)
			w.Write(body)
		}))
	}
	community, trophy, tus, score, update := upstream("community"), upstream("trophy"), upstream("tus"), upstream("score"), upstream("update")
	uploader := upstream("uploader")
	defer uploader.Close()
	defer update.Close()
	defer tus.Close()
	defer score.Close()
	defer community.Close()
	defer trophy.Close()
	auth := oauth.New(&config.Config{TokenKey: strings.Repeat("k", 32)}, nil, nil, nil)
	h, err := server.RemoteHandler(auth, nil, community.URL, trophy.URL, tus.URL, score.URL, update.URL, uploader.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/basic_view/sec/get_self_profile", "/basic_update/sec/update_ci", "/a/cap.png", "/np/resource/title/NPXX00001_00/NPXX00001_00-matching.xml", "/nsx/sec/x/c/NSXWSV/feed.xml", "/user_storage/sec/get_data", "/tss/np/NPWR01234_00/NPWR01234_00-0.tss", "/np/resource/title/NPWR01234_00/storage/NPWR01234_00-storage.xml", "/ranking_update/sec/record_score", "/ranking_view/func/get_ranking", "/ranking_clan_view/func/get_clan_ranking_by_id", "/np/resource/title/NPWR01234_00/ranking/NPWR01234_00-ranking.xml", "/tpl/np/BLUS30001/BLUS30001-ver.xml", "/uploader/sec/upload_data", "/uploader/sec/download_data", "/trophy/sec/sync_trophies", "/np/resource/trophy/trophy-status.xml"} {
		r := httptest.NewRequest("POST", "http://firmware.playstation.net"+path, strings.NewReader("native body"))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		owner := "community"
		if strings.Contains(path, "/trophy/") {
			owner = "trophy"
		}
		if strings.Contains(path, "/user_storage/") || strings.Contains(path, "/tss/") || strings.Contains(path, "/storage/") {
			owner = "tus"
		}
		if strings.HasPrefix(path, "/tpl/") {
			owner = "update"
		}
		if strings.HasPrefix(path, "/uploader/") {
			owner = "uploader"
		}
		if strings.Contains(path, "ranking") {
			owner = "score"
		}
		if w.Code != 200 || w.Header().Get("X-Owner") != owner || w.Header().Get("X-Original-Host") != "firmware.playstation.net" || w.Body.String() != "native body" {
			t.Fatalf("%s: %d %v %s", path, w.Code, w.Header(), w.Body)
		}
	}
	trophy.Close()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/trophy/sec/sync_trophies", nil))
	if w.Code != 503 {
		t.Fatalf("dead trophy backend: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != 200 {
		t.Fatal("upstream failure broke account health")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/a/cap.png", nil))
	if w.Code != 200 {
		t.Fatal("trophy failure broke community")
	}
	for _, bad := range []string{"", "file:///etc/passwd", "http://user:pass@localhost", "http://localhost/path", "http://localhost?query=x"} {
		if _, err = server.RemoteHandler(auth, nil, bad, trophy.URL, "", "", "", ""); err == nil {
			t.Errorf("accepted invalid origin %q", bad)
		}
	}
}
func TestAccountDoesNotOwnExtractedRoutes(t *testing.T) {
	h := server.Handler(oauth.New(&config.Config{TokenKey: strings.Repeat("k", 32)}, nil, nil, nil))
	for _, path := range []string{"/basic_view/sec/get_self_profile", "/trophy/sec/sync_trophies", "/np/resource/trophy/trophy-status.xml"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", path, nil))
		if w.Code != 404 {
			t.Errorf("account still owns %s: %d", path, w.Code)
		}
	}
}
