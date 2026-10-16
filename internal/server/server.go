// Package server assembles np-account's HTTP surface. The firmware reaches
// these routes through several Sony hostnames (auth.api.*, csla.*,
// get/post.net.*); they all point at this one listener and are told apart by
// path, so TLS and host routing belong to the reverse proxy in front.
package server

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"openpak/np-account/internal/community"
	"openpak/np-account/internal/native"
	"openpak/np-account/internal/nettest"
	"openpak/np-account/internal/oauth"
)

// Handler returns the full route set.
func Handler(svc *oauth.Service, communities ...*community.Service) http.Handler {
	mux := http.NewServeMux()
	svc.Register(mux)
	for _, c := range communities {
		if c != nil {
			c.Register(mux)
		}
	}
	nettest.Register(mux)
	(&native.Handler{Auth: svc, Log: slog.Default()}).Register(mux)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ok\n"))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/trophy/") && r.URL.Path != "/entry" {
			mux.ServeHTTP(w, r)
			return
		}
		status := &trophyResponse{ResponseWriter: w, status: 200}
		mux.ServeHTTP(status, r)
		slog.Info("NP trophy HTTP", "method", r.Method, "path", r.URL.Path, "status", status.status)
	})
}

// New returns an http.Server for addr with conservative timeouts.
func New(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

type trophyResponse struct {
	http.ResponseWriter
	status int
}

func (w *trophyResponse) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
