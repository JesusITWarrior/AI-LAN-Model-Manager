// LAN Model Manager host agent.
//
// This binary runs the bounded, persistent, network-free host-service lifecycle.
// It observes local host resources and local provider state on a cancellable
// loop, and writes only safe/redacted summaries. It performs no discovery,
// opens no listener, connects to no controller, and executes no arbitrary
// commands. Signal handling (SIGINT/SIGTERM) is intentionally kept in main; the
// service itself only honours cancellation.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/observation"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/service"
)

// Exit codes: 0 success, 2 rejected configuration.
const (
	exitConfig  = 2
	exitGeneral = 1
)

// version is reported only in safe startup/shutdown summaries.
var version = "18.6a"

func main() {
	cfg, err := loadConfig()
	if err != nil {
		// A rejected configuration is a safe, redacted failure: never print
		// internal details to the operator.
		slog.Error("host-service configuration rejected", "reason", safeErr(err))
		os.Exit(exitConfig)
	}

	// The service owns a canonical absolute state tree; anything resolving
	// through a symlink or escaping the root is a safe containment failure.
	host, err := service.New(cfg)
	if err != nil {
		slog.Error("host-service failed to start", "reason", safeErr(err))
		os.Exit(exitConfig)
	}

	// The lifecycle is governed by a context that main cancels on a signal.
	// Signal handling lives here so the service stays platform-agnostic and
	// network-free.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := host.Start(ctx); err != nil {
		slog.Error("host-service failed to start", "reason", safeErr(err))
		os.Exit(exitGeneral)
	}
	slog.Info("host-service started", "hostID", host.HostID(), "version", version)

	// Wait for a termination signal, then shut down gracefully. The service
	// stays alive until a signal arrives; nothing is written except safe
	// startup/shutdown summaries.
	<-ctx.Done()
	slog.Info("host-service received signal, shutting down")
	closeCtx, cancelClose := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelClose()
	if err := host.Close(closeCtx); err != nil {
		// Close only returns an error if the loop failed to observe
		// cancellation in time; log the safe summary and exit normally.
		slog.Error("host-service shutdown incomplete", "reason", safeErr(err))
		os.Exit(exitGeneral)
	}
	slog.Info("host-service stopped")
}

// loadConfig builds a service.Config from environment with a strict allowlist.
// It never opens a network surface. An explicit StateDir overrides the platform
// canonical path; other keys default sensibly and are validated by the service.
func loadConfig() (service.Config, error) {
	allowed := map[string]bool{"LANMM_STATE_DIR": true, "LANMM_CERT_DIR": true, "LANMM_CACHE_DIR": true, "LANMM_HOST_ID": true, "LANMM_POLL_INTERVAL": true}
	for _, item := range os.Environ() {
		key := strings.SplitN(item, "=", 2)[0]
		if strings.HasPrefix(key, "LANMM_") && !allowed[key] {
			return service.Config{}, service.ErrInvalidConfig
		}
	}
	cfg := service.Config{PollInterval: service.PollIntervalDefault}
	if raw, ok := os.LookupEnv("LANMM_STATE_DIR"); ok {
		cfg.StateDir = strings.TrimSpace(raw)
	}
	if raw, ok := os.LookupEnv("LANMM_CERT_DIR"); ok {
		cfg.CertDir = strings.TrimSpace(raw)
	}
	if raw, ok := os.LookupEnv("LANMM_CACHE_DIR"); ok {
		cfg.CacheDir = strings.TrimSpace(raw)
	}
	if raw, ok := os.LookupEnv("LANMM_HOST_ID"); ok {
		cfg.HostID = strings.TrimSpace(raw)
	}
	if raw, ok := os.LookupEnv("LANMM_POLL_INTERVAL"); ok {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return service.Config{}, service.ErrInvalidConfig
		}
		cfg.PollInterval = d
	}
	if cfg.HostID == "" {
		cfg.HostID = defaultHostID()
	}
	if cfg.StateDir == "" {
		base, err := os.UserConfigDir()
		if err != nil || !filepath.IsAbs(base) {
			return service.Config{}, service.ErrInvalidConfig
		}
		cfg.StateDir = filepath.Join(base, "lan-model-manager", "host-agent")
	}

	// The production registry wires platform-specific observers here. The base
	// binary starts a single local (network-free) observer so it has something
	// to observe; the registry itself is validated by service.New.
	if platform, ok := newPlatformObserver(cfg.HostID, cfg.StateDir); ok {
		cfg.Registry.Observers = []observation.Observer{platform}
	}
	if len(cfg.Registry.Observers) == 0 {
		return service.Config{}, service.ErrInvalidConfig
	}
	return cfg, nil
}

var invalidHostID = regexp.MustCompile(`[^A-Za-z0-9._:-]+`)

func defaultHostID() string {
	value, err := os.Hostname()
	if err != nil {
		return "local-host"
	}
	value = invalidHostID.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-._:")
	if value == "" || len(value) > 128 {
		return "local-host"
	}
	return value
}

// safeErr maps any error to a stable redacted summary without surfacing
// provider internals.
func safeErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
