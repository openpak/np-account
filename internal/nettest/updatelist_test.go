package nettest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUpdateListSaysLatest(t *testing.T) {
	mux := http.NewServeMux()
	Register(mux)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://feu01.ps3.update.playstation.net/update/ps3/list/eu/ps3-updatelist.txt", nil)
	mux.ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != 200 || rec.Header().Get("Content-Length") == "" || len(body) >= 64<<10 {
		t.Fatalf("status %d, length %q, %d bytes", rec.Code, rec.Header().Get("Content-Length"), len(body))
	}
	if !strings.Contains(body, "Dest=83;ImageVersion=00000001;SystemSoftwareVersion=4.93;CDN=http://feu01.ps3.update.playstation.net/") {
		t.Fatal("missing Dest line")
	}
}
