// Package server assembles account routes and forwards extracted service paths.
package server

import (
	"log/slog"
	"net/http"
	"time"

	"openpak/np-account/internal/native"
	"openpak/np-account/internal/nav"
	"openpak/np-account/internal/nettest"
	"openpak/np-account/internal/oauth"
)

// Handler returns the full route set.
func Handler(svc *oauth.Service, tickets ...*nav.Service) http.Handler {
	mux := http.NewServeMux()
	svc.Register(mux)
	for _, issuer := range tickets {
		if issuer != nil {
			issuer.Register(mux)
		}
	}
	nettest.Register(mux)
	(&native.Handler{Auth: svc, Log: slog.Default()}).Register(mux)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ok\n"))
	})
	return mux
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
