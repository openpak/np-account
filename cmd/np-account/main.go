// Command np-account is OpenPak's PlayStation 3 account and sign-in adapter.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
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

	svc := oauth.New(cfg, core, nil, log)
	srv := server.New(cfg.HTTPListenAddr, server.Handler(svc))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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
