package nettest_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openpak/np-account/internal/nettest"
)

func handler() http.Handler {
	mux := http.NewServeMux()
	nettest.Register(mux)
	return mux
}

func TestGet2M(t *testing.T) {
	for _, path := range []string{"/networktest/get_2m"} {
		rec := httptest.NewRecorder()
		handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || rec.Body.Len() != 2<<20 {
			t.Fatalf("%s: %d, %d bytes", path, rec.Code, rec.Body.Len())
		}
		if rec.Header().Get("Content-Length") != "2097152" {
			t.Fatalf("Content-Length = %q", rec.Header().Get("Content-Length"))
		}
		again := httptest.NewRecorder()
		handler().ServeHTTP(again, httptest.NewRequest("GET", path, nil))
		if !bytes.Equal(rec.Body.Bytes(), again.Body.Bytes()) {
			t.Fatal("get_2m body is not fixed")
		}
	}
}

func TestEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
		status                   int
		reply                    string
	}{
		{"post empty", "POST", "/networktest/post", "", 200, ""},
		{"post body", "POST", "/networktest/post", strings.Repeat("x", 1<<20), 200, ""},
		{"post_128", "POST", "/networktest/post_128", strings.Repeat("y", 128), 200, ""},
		{"trial", "GET", "/networktest/trial.txt", "", 200, nettest.TrialText},
		{"GET on post", "GET", "/networktest/post", "", 405, ""},
		{"POST on get_2m", "POST", "/networktest/get_2m", "z", 405, ""},
		{"unknown", "GET", "/networktest/nope", "", 404, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler().ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			if tc.status == 200 && rec.Body.String() != tc.reply {
				t.Fatalf("body = %q, want %q", rec.Body.String(), tc.reply)
			}
		})
	}
}

func TestPostOverLimitIsStillAnswered(t *testing.T) {
	srv := httptest.NewServer(handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/networktest/post", "application/octet-stream", io.LimitReader(zeros{}, 20<<20))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }
