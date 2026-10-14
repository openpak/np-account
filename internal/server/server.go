// Package server assembles np-account's HTTP surface. The firmware reaches
// these routes through several Sony hostnames (auth.api.*, csla.*,
// get/post.net.*); they all point at this one listener and are told apart by
// path, so TLS and host routing belong to the reverse proxy in front.
package server

import (
	"net/http"
	"time"

	"openpak/np-account/internal/nettest"
	"openpak/np-account/internal/oauth"
)

// Handler returns the full route set.
func Handler(svc *oauth.Service) http.Handler {
	mux := http.NewServeMux()
	svc.Register(mux)
	nettest.Register(mux)
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
