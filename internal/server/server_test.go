package server_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"openpak/np-account/internal/config"
	"openpak/np-account/internal/coreclient"
	"openpak/np-account/internal/fakecore"
	"openpak/np-account/internal/oauth"
	"openpak/np-account/internal/server"
)

func TestRoutes(t *testing.T) {
	core := fakecore.New("fake-core-key-fake-core-key-fake-core-key")
	cli, err := coreclient.Dial("passthrough:///core", "fake-core-key-fake-core-key-fake-core-key", core.Serve(t)...)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	cfg := &config.Config{ClientID: "id", ClientSecret: "secret", TokenKey: "0123456789abcdef0123456789abcdef", AccessTTL: time.Hour}
	h := server.Handler(oauth.New(cfg, cli, nil, nil))

	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/healthz", 200},
		{"GET", "/csla/np/console/lwConsoleToken", 200},
		{"GET", "/networktest/get_2m", 200},
		{"POST", "/networktest/post", 200},
		{"POST", "/networktest/post_128", 200},
		{"GET", "/networktest/trial.txt", 200},
		{"GET", "/2.0/oauth/authorize", 401}, // no client_id: invalid_client
		{"POST", "/2.0/oauth/token", 400},
		{"GET", "/nope", 404},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
}
