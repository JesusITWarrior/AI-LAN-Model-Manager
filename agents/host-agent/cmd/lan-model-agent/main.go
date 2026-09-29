// LAN Model Manager host agent.
//
// This binary runs the bounded, persistent host-service lifecycle. It observes
// local host resources and local provider state on a cancellable loop, and
// writes only safe/redacted summaries. By default it is network-free; an
// explicit all-or-none enrollment configuration enables one bounded outbound
// HTTPS flow. It performs no discovery, opens no listener, and executes no
// arbitrary commands. Signal handling (SIGINT/SIGTERM) is intentionally kept in
// main; the service itself only honours cancellation.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/enrollment"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/observation"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/service"
)

// Exit codes: 0 success, 2 rejected configuration.
const (
	exitConfig  = 2
	exitGeneral = 1
)

// version is reported only in safe startup/shutdown summaries.
var version = "18.8c"

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
// It never opens a listener. An explicit StateDir overrides the platform
// canonical path; enrollment remains disabled unless every trust and candidate
// binding value is provided.
func loadConfig() (service.Config, error) {
	allowed := map[string]bool{
		"LANMM_STATE_DIR": true, "LANMM_CERT_DIR": true, "LANMM_CACHE_DIR": true,
		"LANMM_HOST_ID": true, "LANMM_POLL_INTERVAL": true,
		"LANMM_ENROLLMENT_CONTROLLER_URL": true, "LANMM_ENROLLMENT_CA_CERT_FILE": true,
		"LANMM_ENROLLMENT_CA_CERT_PEM": true, "LANMM_ENROLLMENT_CA_FINGERPRINT_SHA256": true,
		"LANMM_ENROLLMENT_CANDIDATE_ADDRESS": true, "LANMM_ENROLLMENT_CANDIDATE_PORT": true,
		"LANMM_ENROLLMENT_PROTOCOL_MAJOR": true, "LANMM_ENROLLMENT_PROTOCOL_MINOR": true,
	}
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
	if err := configureEnrollment(&cfg); err != nil {
		return service.Config{}, service.ErrInvalidConfig
	}
	return cfg, nil
}

var enrollmentEnvironment = []string{
	"LANMM_ENROLLMENT_CONTROLLER_URL", "LANMM_ENROLLMENT_CA_CERT_FILE",
	"LANMM_ENROLLMENT_CA_CERT_PEM", "LANMM_ENROLLMENT_CA_FINGERPRINT_SHA256",
	"LANMM_ENROLLMENT_CANDIDATE_ADDRESS", "LANMM_ENROLLMENT_CANDIDATE_PORT",
	"LANMM_ENROLLMENT_PROTOCOL_MAJOR", "LANMM_ENROLLMENT_PROTOCOL_MINOR",
}

func configureEnrollment(cfg *service.Config) error {
	values := make(map[string]string, len(enrollmentEnvironment))
	configured := false
	for _, key := range enrollmentEnvironment {
		if value, ok := os.LookupEnv(key); ok {
			configured = true
			values[key] = value
		}
	}
	if !configured {
		return nil
	}
	for _, key := range []string{"LANMM_ENROLLMENT_CONTROLLER_URL", "LANMM_ENROLLMENT_CA_FINGERPRINT_SHA256", "LANMM_ENROLLMENT_CANDIDATE_ADDRESS", "LANMM_ENROLLMENT_CANDIDATE_PORT", "LANMM_ENROLLMENT_PROTOCOL_MAJOR", "LANMM_ENROLLMENT_PROTOCOL_MINOR"} {
		if values[key] == "" {
			return service.ErrInvalidConfig
		}
	}
	file, fileSet := values["LANMM_ENROLLMENT_CA_CERT_FILE"]
	pemValue, pemSet := values["LANMM_ENROLLMENT_CA_CERT_PEM"]
	if fileSet == pemSet {
		return service.ErrInvalidConfig
	}
	if fileSet {
		var err error
		pemValue, err = readPinnedCAFile(file)
		if err != nil {
			return service.ErrInvalidConfig
		}
	}
	port, err := parseUint16(values["LANMM_ENROLLMENT_CANDIDATE_PORT"])
	if err != nil || port == 0 {
		return service.ErrInvalidConfig
	}
	major, err := parseUint16(values["LANMM_ENROLLMENT_PROTOCOL_MAJOR"])
	if err != nil {
		return service.ErrInvalidConfig
	}
	minor, err := parseUint16(values["LANMM_ENROLLMENT_PROTOCOL_MINOR"])
	if err != nil {
		return service.ErrInvalidConfig
	}
	certDir := cfg.CertDir
	if certDir == "" {
		certDir = filepath.Join(cfg.StateDir, "cert")
	}
	enrollmentConfig := enrollment.Config{
		ControllerURL: values["LANMM_ENROLLMENT_CONTROLLER_URL"], PinnedCACertificatePEM: pemValue,
		PinnedCAFingerprintSHA256: values["LANMM_ENROLLMENT_CA_FINGERPRINT_SHA256"], CandidateID: cfg.HostID,
		Address: values["LANMM_ENROLLMENT_CANDIDATE_ADDRESS"], Port: port,
		ProtocolMajor: major, ProtocolMinor: minor, CertDir: certDir,
	}
	transport, err := enrollment.NewHTTPTransport(enrollmentConfig)
	if err != nil {
		return service.ErrInvalidConfig
	}
	client, err := enrollment.New(enrollmentConfig, transport, nil)
	if err != nil {
		return service.ErrInvalidConfig
	}
	cfg.Enroller = enrollment.PollingEnroller{Client: client, Present: func(code string) {
		slog.Info("host-service enrollment pending; confirm this code in the controller", "operatorCode", code)
	}}
	return nil
}

func parseUint16(value string) (uint16, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.HasPrefix(value, "+") {
		return 0, fmt.Errorf("invalid unsigned integer")
	}
	parsed, err := strconv.ParseUint(value, 10, 16)
	return uint16(parsed), err
}

func readPinnedCAFile(path string) (string, error) {
	if path == "" || strings.TrimSpace(path) != path || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.Contains(path, "..") {
		return "", service.ErrInvalidConfig
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 64<<10 {
		return "", service.ErrInvalidConfig
	}
	file, err := os.Open(path)
	if err != nil {
		return "", service.ErrInvalidConfig
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return "", service.ErrInvalidConfig
	}
	value, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(value) == 0 || len(value) > 64<<10 || int64(len(value)) != opened.Size() {
		return "", service.ErrInvalidConfig
	}
	return string(value), nil
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
