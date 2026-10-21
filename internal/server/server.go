// Package server assembles np-account's HTTP surface. The firmware reaches
// these routes through several Sony hostnames (auth.api.*, csla.*,
// get/post.net.*); they all point at this one listener and are told apart by
// path, so TLS and host routing belong to the reverse proxy in front.
package server

import (
	"log/slog"
	"net/http"
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
		if r.URL.Path == "/healthz" {
			mux.ServeHTTP(w, r)
			return
		}
		// Every request is logged: the firmware reports failures only as an opaque error code,
		// and the server used to say nothing about sign-ins it rejected or paths it did not know.
		status := &trophyResponse{ResponseWriter: w, status: 200}
		mux.ServeHTTP(status, r)
		slog.Info("NP HTTP", "method", r.Method, "host", r.Host, "path", r.URL.Path, "status", status.status, "ps3_status", w.Header().Get("X-I-5-Status"))
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
