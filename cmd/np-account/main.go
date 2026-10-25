package main

import (
	"context"
	"log/slog"
	"openpak/np-account/internal/config"
	"openpak/np-account/internal/nav"
	"openpak/np-account/internal/oauth"
	"openpak/np-account/internal/server"
	"openpak/np-common/coreclient"
	"openpak/np-common/events"
	"openpak/np-common/nphttp"
	"openpak/np-common/ticket"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		slog.Error("np-account stopped", "err", err)
		os.Exit(1)
	}
}
func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	core, err := coreclient.Dial(cfg.CoreAddress, cfg.CoreKey)
	if err != nil {
		return err
	}
	defer core.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	standing := events.NewState()
	gate := events.Gate{Client: core, State: standing}
	svc := oauth.New(cfg, gate, nil, slog.Default())
	var issuer *nav.Service
	if cfg.TicketKeyPath != "" {
		signer, e := ticket.Load(cfg.TicketKeyPath)
		if e != nil {
			return e
		}
		issuer = &nav.Service{Auth: svc, Tickets: signer, TTL: cfg.AccessTTL}
	}
	consumer := &events.Consumer{Core: core, State: standing, Log: slog.Default()}
	go consumer.Run(ctx, 5*time.Second)
	handler, err := server.RemoteHandler(svc, issuer, os.Getenv("NP_COMMUNITY_URL"), os.Getenv("NP_TROPHY_URL"))
	if err != nil {
		return err
	}
	front, err := nphttp.Front()
	if err != nil {
		return err
	}
	slog.Info("np-account listening", "addr", cfg.HTTPListenAddr)
	return nphttp.Run(ctx, handler, cfg.HTTPListenAddr, os.Getenv("NP_TLS_ADDR"), front)
}
