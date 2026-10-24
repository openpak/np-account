// Command np-account is OpenPak's PlayStation 3 account and sign-in adapter.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"openpak/np-account/internal/community"
	"openpak/np-account/internal/events"
	"openpak/np-account/internal/ticket"
	"openpak/np-account/internal/tlsfront"
	"openpak/np-account/internal/xmpp"
	"os"
	"os/signal"
	"syscall"
	"time"

	"openpak/np-account/internal/config"
	"openpak/np-account/internal/coreclient"
	"openpak/np-account/internal/oauth"
	"openpak/np-account/internal/server"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	core, err := coreclient.Dial(cfg.CoreAddress, cfg.CoreKey)
	if err != nil {
		log.Error("core client", "err", err)
		os.Exit(1)
	}
	defer core.Close()

	// Bans and deletions from the core's event stream: denied here at once and
	// their open streams cut (internal/events).
	standing := events.NewState()
	gate := events.Gate{Client: core, State: standing}
	svc := oauth.New(cfg, gate, nil, log)
	var comm *community.Service
	if cfg.TicketKeyPath != "" {
		signer, e := ticket.Load(cfg.TicketKeyPath)
		if e != nil {
			log.Error("ticket key", "err", e)
			os.Exit(2)
		}
		comm = &community.Service{Auth: svc, Core: gate, Tickets: signer, TTL: cfg.AccessTTL, Client: cfg.SessionClient, OS: cfg.SessionOS}

		if path := os.Getenv("NP_TROPHY_RESOURCE_KEY"); path != "" {
			key, e := os.ReadFile(path)
			if e != nil || len(key) != 20 {
				log.Error("invalid trophy resource key file")
				os.Exit(2)
			}
			comm.TrophyResourceKey = key
		}
		if endpoint := os.Getenv("NP_TROPHY_BACKEND"); endpoint != "" {
			comm.Trophies = &community.TrophyBackend{URL: endpoint, Key: os.Getenv("NP_TROPHY_BACKEND_KEY")}
		}
	}
	handler := server.Handler(svc, comm)
	srv := server.New(cfg.HTTPListenAddr, handler)

	// The firmware's own TLS (RSA key exchange, leaf per SNI from the PS3 CA),
	// enabled with NP_TLS_ADDR. Traefik passes the PS3 SNIs through to it.
	var front *tlsfront.Front
	if addr := os.Getenv("NP_TLS_ADDR"); addr != "" {
		front, err = tlsfront.Load(os.Getenv("NP_TLS_CA_CERT"), os.Getenv("NP_TLS_CA_KEY"))
		if err != nil {
			log.Error("PS3 TLS CA", "err", err)
			os.Exit(2)
		}
		tsrv := front.Serve(server.New(addr, handler))
		go func() {
			if e := tsrv.ListenAndServeTLS("", ""); e != nil && !errors.Is(e, http.ErrServerClosed) {
				log.Error("PS3 TLS serve", "err", e)
				os.Exit(1)
			}
		}()
		log.Info("PS3 TLS listening", "addr", addr)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	consumer := &events.Consumer{Core: core, State: standing, Log: log}
	if comm != nil {
		ln, e := net.Listen("tcp", cfg.XMPPListenAddr)
		if e != nil {
			log.Error("XMPP listen", "err", e)
			os.Exit(1)
		}
		// NP_XMPP_TLS=1 serves XMPP behind the same PS3 TLS instead of a separate terminator.
		if front != nil && os.Getenv("NP_XMPP_TLS") == "1" {
			cfgTLS := front.Config()
			front.Fallback = "us.us.np.communication.playstation.net"
			ln = tls.NewListener(ln, cfgTLS)
		}
		xs := &xmpp.Server{Service: comm, Log: log}
		consumer.Cut = xs.Disconnect
		go func() {
			if e := xs.Serve(ctx, ln); e != nil {
				log.Error("XMPP serve", "err", e)
				stop()
			}
		}()
		if cfg.ProvisionAccounts {
			go comm.Reconcile(ctx, core, log)
		}
		log.Info("NP community enabled", "xmpp_addr", cfg.XMPPListenAddr)
	}
	go consumer.Run(ctx, 5*time.Second)
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()

	log.Info("np-account listening", "addr", cfg.HTTPListenAddr, "core", cfg.CoreAddress)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
