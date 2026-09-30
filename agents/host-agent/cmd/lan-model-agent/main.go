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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/command"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/discovery"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/enrollment"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/fleet"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/observation"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider/ollama"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/service"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/snapshot"
)

// Exit codes: 0 success, 2 rejected configuration.
const (
	exitConfig  = 2
	exitGeneral = 1
)

// version is reported only in safe startup/shutdown summaries.
var version = "18.9b"

type snapshotSource interface{ LatestSnapshot() (snapshot.State, bool) }
type fleetCollector struct {
	source snapshotSource
	ollama *ollama.Client
}

func (c fleetCollector) Collect(ctx context.Context) (fleet.Snapshot, error) {
	if ctx.Err() != nil {
		return fleet.Snapshot{}, fleet.ErrFleet
	}
	state, ok := c.source.LatestSnapshot()
	if !ok {
		return fleet.Snapshot{}, fleet.ErrFleet
	}
	result := fleet.Snapshot{Platform: state.Record.Platform, Idle: true}
	if c.ollama != nil {
		probe, probeErr := c.ollama.Probe(ctx)
		models, modelsErr := c.ollama.ListInstalled(ctx)
		if probeErr == nil && modelsErr == nil {
			result.Providers, result.Models = fleet.MapInventory([]provider.ProviderProbe{probe}, models, time.Now().UTC().Format("2006-01-02T15:04:05.000Z"))
		}
	}
	return result, nil
}

func main() {
	if code, handled := handleCommandLine(os.Args[1:], os.Stdout); handled {
		os.Exit(code)
	}
	os.Exit(runPlatformService(runHost))
}

func handleCommandLine(args []string, out io.Writer) (int, bool) {
	if len(args) == 0 {
		return 0, false
	}
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		_, _ = fmt.Fprintln(out, "Usage: lan-model-agent [--help] [--version]")
		_, _ = fmt.Fprintln(out, "Runs the LAN Model Manager host agent; configuration is read from LANMM_* environment variables.")
		return 0, true
	}
	if len(args) == 1 && args[0] == "--version" {
		_, _ = fmt.Fprintf(out, "lan-model-agent %s\n", version)
		return 0, true
	}
	_, _ = fmt.Fprintln(out, "lan-model-agent: unsupported argument; use --help")
	return exitConfig, true
}

// runHost owns one cancellable service lifetime. Platform adapters provide the
// cancellation source (signals on Unix and SCM control messages on Windows).
func runHost(ctx context.Context) int {
	cfg, err := loadConfig()
	if err != nil {
		// A rejected configuration is a safe, redacted failure: never print
		// internal details to the operator.
		slog.Error("host-service configuration rejected", "reason", safeErr(err))
		return exitConfig
	}

	// The service owns a canonical absolute state tree; anything resolving
	// through a symlink or escaping the root is a safe containment failure.
	host, err := service.New(cfg)
	if err != nil {
		slog.Error("host-service failed to start", "reason", safeErr(err))
		return exitConfig
	}

	if advertisement, advertErr := discoveryAdvertisement(cfg.HostID); advertErr == nil {
		if sender, sendErr := discovery.NewUDPMulticastSender(); sendErr == nil {
			if advertiser, newErr := discovery.NewAdvertiser(sender, advertisement); newErr == nil {
				go func() { _ = advertiser.Run(ctx) }()
			}
		}
	}
	if err := host.Start(ctx); err != nil {
		slog.Error("host-service failed to start", "reason", safeErr(err))
		return exitGeneral
	}
	// Enrollment is the only switch that enables the outbound fleet plane. A
	// missing/incomplete enrollment remains network-free; the fleet client has
	// no management or inference credentials to fall back to.
	certDir := cfg.CertDir
	if certDir == "" {
		certDir = filepath.Join(cfg.StateDir, "cert")
	}
	var ollamaClient *ollama.Client
	if endpoint := os.Getenv("LANMM_OLLAMA_ENDPOINT"); endpoint != "" {
		ollamaClient, _ = ollama.New(ollama.Config{ProviderID: "ollama-local", Endpoint: endpoint})
	}
	go maintainFleetSessions(ctx, certDir, cfg.StateDir, host, ollamaClient)
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
		return exitGeneral
	}
	slog.Info("host-service stopped")
	return 0
}

func maintainFleetSessions(ctx context.Context, certDir, stateDir string, host *service.Service, ollamaClient *ollama.Client) {
	for ctx.Err() == nil {
		// Rotation is attempted before every session generation. A durable pending
		// CSR allows this call to recover when the prior process was interrupted
		// after the controller atomically replaced/revoked the old certificate.
		if _, rotateErr := fleet.RotateIdentityIfNeeded(ctx, certDir, 7*24*time.Hour); rotateErr != nil {
			// Do not run a possibly revoked predecessor after a lost rotation
			// response. Retry the durable pending CSR promptly and cancellation-aware.
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Minute):
				continue
			}
		}
		client, err := fleet.NewHTTPSClient(certDir)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Minute):
				continue
			}
		}
		sessionCtx, cancel := context.WithCancel(ctx)
		var workers sync.WaitGroup
		workers.Add(1)
		go func() {
			defer workers.Done()
			_ = client.Run(sessionCtx, fleetCollector{source: host, ollama: ollamaClient}, runtime.GOOS, "")
		}()
		if ollamaClient != nil {
			registry := command.NewRegistry(time.Now)
			registry.RegisterOllama("ollama-local", ollamaClient)
			if executor, e := command.NewPersistent(host.HostID(), registry, time.Now, filepath.Join(stateDir, "command-replay.json")); e == nil {
				workers.Add(1)
				go func() { defer workers.Done(); _ = client.RunCommands(sessionCtx, executor) }()
			}
		}
		timer := time.NewTimer(12 * time.Hour)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			cancel()
			client.CloseIdleConnections()
			workers.Wait()
			return
		case <-timer.C:
			cancel()
			client.CloseIdleConnections()
			workers.Wait()
		}
	}
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
		"LANMM_DISCOVERY_DISPLAY_NAME": true, "LANMM_DISCOVERY_ADDRESS": true, "LANMM_DISCOVERY_PORT": true, "LANMM_DISCOVERY_TTL_SECONDS": true, "LANMM_OLLAMA_ENDPOINT": true,
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
	if err := prepareExplicitReEnrollment(&cfg); err != nil {
		return service.Config{}, service.ErrInvalidConfig
	}
	if err := configureEnrollment(&cfg); err != nil {
		return service.Config{}, service.ErrInvalidConfig
	}
	discoveryConfigured := false
	for _, key := range []string{"LANMM_DISCOVERY_DISPLAY_NAME", "LANMM_DISCOVERY_ADDRESS", "LANMM_DISCOVERY_PORT", "LANMM_DISCOVERY_TTL_SECONDS"} {
		if _, ok := os.LookupEnv(key); ok {
			discoveryConfigured = true
		}
	}
	if discoveryConfigured {
		if _, err := discoveryAdvertisement(cfg.HostID); err != nil {
			return service.Config{}, service.ErrInvalidConfig
		}
	}
	if endpoint, ok := os.LookupEnv("LANMM_OLLAMA_ENDPOINT"); ok {
		if _, err := ollama.New(ollama.Config{ProviderID: "ollama-local", Endpoint: endpoint}); err != nil {
			return service.Config{}, service.ErrInvalidConfig
		}
	}
	return cfg, nil
}

// prepareExplicitReEnrollment consumes a local-admin marker written while the
// service is stopped. The old certificate directory is atomically archived,
// never overwritten, before normal owner-confirmed enrollment starts.
func prepareExplicitReEnrollment(cfg *service.Config) error {
	stateDir := cfg.StateDir
	if stateDir == "" {
		return nil
	}
	marker := filepath.Join(stateDir, "reenroll.request")
	info, err := os.Lstat(marker)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) || info.Size() != int64(len("owner-authorized-reenroll\n")) {
		return service.ErrInvalidConfig
	}
	raw, err := os.ReadFile(marker)
	if err != nil || string(raw) != "owner-authorized-reenroll\n" {
		return service.ErrInvalidConfig
	}
	certDir := cfg.CertDir
	if certDir == "" {
		certDir = filepath.Join(stateDir, "cert")
	}
	if existing, statErr := os.Lstat(certDir); statErr == nil {
		if !existing.IsDir() || existing.Mode()&os.ModeSymlink != 0 {
			return service.ErrInvalidConfig
		}
		archive := fmt.Sprintf("%s.retired-%s", certDir, time.Now().UTC().Format("20060102T150405.000000000Z"))
		if err = os.Rename(certDir, archive); err != nil {
			return service.ErrInvalidConfig
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return service.ErrInvalidConfig
	}
	if err = os.MkdirAll(certDir, 0700); err != nil {
		return service.ErrInvalidConfig
	}
	if err = os.Remove(marker); err != nil {
		return service.ErrInvalidConfig
	}
	if dir, openErr := os.Open(stateDir); openErr == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
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

func discoveryAdvertisement(hostID string) (discovery.Advertisement, error) {
	name, address, portText, ttlText := os.Getenv("LANMM_DISCOVERY_DISPLAY_NAME"), os.Getenv("LANMM_DISCOVERY_ADDRESS"), os.Getenv("LANMM_DISCOVERY_PORT"), os.Getenv("LANMM_DISCOVERY_TTL_SECONDS")
	if name == "" && address == "" && portText == "" && ttlText == "" {
		return discovery.Advertisement{}, service.ErrInvalidConfig
	}
	port, err := parseUint16(portText)
	if err != nil {
		return discovery.Advertisement{}, service.ErrInvalidConfig
	}
	ttl, err := strconv.ParseUint(ttlText, 10, 32)
	if err != nil {
		return discovery.Advertisement{}, service.ErrInvalidConfig
	}
	value := discovery.Advertisement{ID: hostID, DisplayName: name, ProtocolVersion: discovery.ProtocolVersion{Major: 1, Minor: 0}, AgentPort: port, Platform: runtime.GOOS, Addresses: []string{address}, TTLSeconds: uint32(ttl)}
	if _, err = discovery.BuildAdvertisement(value); err != nil {
		return discovery.Advertisement{}, service.ErrInvalidConfig
	}
	return value, nil
}
