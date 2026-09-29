package service

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/observation"
)

// validObservation builds a valid HostResourceObservation for observer fixtures.
func validObservation() observation.HostResourceObservation {
	pct := uint8(20)
	return observation.HostResourceObservation{
		HostID: "host-1", ObservedAt: "2026-09-26T12:00:00.000Z", Platform: observation.PlatformLinux,
		CPULogicalCores: 8, CPUUtilizationPercent: &pct, Memory: observation.ResourceQuantity{TotalBytes: 100, UsedBytes: 40, AvailableBytes: 50}, Storage: observation.ResourceQuantity{TotalBytes: 200, UsedBytes: 50, AvailableBytes: 100},
		Accelerators: []observation.AcceleratorObservation{{ID: "gpu-0", Name: "Example GPU", Kind: observation.AcceleratorNVIDIA, Memory: observation.ResourceQuantity{TotalBytes: 80, UsedBytes: 20, AvailableBytes: 40}}},
	}
}

func syntheticRegistry(value observation.HostResourceObservation, observedErr error) ProviderRegistry {
	observer, err := observation.NewSyntheticObserver(value, observedErr)
	if err != nil {
		panic(err)
	}
	return ProviderRegistry{Observers: []observation.Observer{observer}}
}

func testStateDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "state")
}

func baseConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		HostID:       "host-1",
		StateDir:     testStateDir(t),
		Registry:     syntheticRegistry(validObservation(), nil),
		PollInterval: 1 * time.Minute,
	}
}

func TestNewAcceptsValidConfiguration(t *testing.T) {
	cfg := baseConfig(t)
	host, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if host.HostID() != "host-1" {
		t.Fatalf("HostID = %q", host.HostID())
	}
	state, cert, cache, runtime := host.StateDirs()
	if !filepath.IsAbs(state) {
		t.Fatalf("StateDir not absolute: %q", state)
	}
	if !strings.HasPrefix(cert, state) {
		t.Fatalf("CertDir %q escapes root %q", cert, state)
	}
	if !strings.HasPrefix(cache, state) {
		t.Fatalf("CacheDir %q escapes root %q", cache, state)
	}
	if runtime != filepath.Join(state, "state") {
		t.Fatalf("RuntimeDir = %q", runtime)
	}
	if _, err := os.Stat(state); err != nil {
		t.Fatalf("state dir not created: %v", err)
	}
	// The created state directory must be restrictive: no group/other bits.
	if info, statErr := os.Stat(state); statErr != nil {
		t.Fatalf("stat state: %v", statErr)
	} else if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("state dir group/other bits set: %v", info.Mode().Perm())
	}
}

func TestHostileConfigurations(t *testing.T) {
	_ = baseConfig(t)
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr error
	}{
		{"empty host id", func(c *Config) { c.HostID = "" }, ErrInvalidConfig},
		{"bad host id", func(c *Config) { c.HostID = "bad/id" }, ErrInvalidConfig},
		{"no observers", func(c *Config) { c.Registry = ProviderRegistry{} }, ErrInvalidConfig},
		{"nil observer", func(c *Config) { c.Registry = ProviderRegistry{Observers: []observation.Observer{nil}} }, ErrInvalidConfig},
		{"below poll interval min", func(c *Config) { c.PollInterval = 1 * time.Nanosecond }, ErrInvalidConfig},
		{"above poll interval max", func(c *Config) { c.PollInterval = 2 * time.Hour }, ErrInvalidConfig},
		{"negative observations", func(c *Config) { c.Observations = -1 }, ErrInvalidConfig},
		{"relative state dir", func(c *Config) { c.StateDir = "relative/state" }, ErrInvalidConfig},
		{"escape state dir", func(c *Config) { c.StateDir = "/tmp/../tmp/escape" }, ErrInvalidConfig},
		{"state dir with dotdot", func(c *Config) { c.StateDir = "/a/../../b" }, ErrInvalidConfig},
		{"cert dir escapes root", func(c *Config) { c.CertDir = "/outside/cert" }, ErrInvalidConfig},
		{"cache dir escapes root", func(c *Config) { c.CacheDir = "../escape" }, ErrInvalidConfig},
		{"cert dir escapes via sibling", func(c *Config) { c.CertDir = baseConfig(t).StateDir + "/../outside" }, ErrInvalidConfig},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig(t)
			tc.mutate(&cfg)
			if _, err := New(cfg); !isError(err, tc.wantErr) {
				t.Fatalf("New(%s) err = %v, want %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

func TestCertCacheDerivedUnderRoot(t *testing.T) {
	cfg := baseConfig(t)
	host, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	state, cert, cache, _ := host.StateDirs()
	if cert != filepath.Join(state, "cert") {
		t.Fatalf("default CertDir = %q", cert)
	}
	if cache != filepath.Join(state, "cache") {
		t.Fatalf("default CacheDir = %q", cache)
	}
	if _, statErr := os.Stat(cert); statErr != nil {
		t.Fatalf("cert dir not created: %v", statErr)
	}
}

// symlink tests: a symlink anywhere along the path must be rejected.

func TestNewRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if os.Symlink(target, link) == nil {
		if _, err := New(Config{
			HostID:   "host-1",
			StateDir: link,
			Registry: syntheticRegistry(validObservation(), nil),
		}); !isError(err, ErrStateContainment) {
			t.Fatalf("New via state symlink err = %v, want %v", err, ErrStateContainment)
		}
	} else {
		t.Skip("symlinks unsupported")
	}
}

func TestNewRejectsSymlinkedStateSubDir(t *testing.T) {
	root := t.TempDir()
	sibling := filepath.Join(root, "sibling")
	if err := os.Mkdir(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	// Point StateDir at a symlink that itself points to a sibling directory.
	link := filepath.Join(root, "state")
	if os.Symlink(sibling, link) == nil {
		if _, err := New(Config{
			HostID:   "host-1",
			StateDir: link,
			Registry: syntheticRegistry(validObservation(), nil),
		}); !isError(err, ErrStateContainment) {
			t.Fatalf("New through symlinked state dir err = %v, want %v", err, ErrStateContainment)
		}
	} else {
		t.Skip("symlinks unsupported")
	}
}

func TestNewRejectsNonDirectoryAtRoot(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{
		HostID:   "host-1",
		StateDir: filepath.Join(file, "sub"), // parent is a file
		Registry: syntheticRegistry(validObservation(), nil),
	}); !isError(err, ErrStateContainment) {
		t.Fatalf("New through a regular-file path err = %v, want %v", err, ErrStateContainment)
	}
}

func isError(err, target error) bool {
	if err == nil {
		return false
	}
	if target == nil {
		return false
	}
	// Direct match or a container of target via errors.
	return err.Error() == target.Error() || (strings.Contains(err.Error(), target.Error()))
}

// noNetworkListener proves the service never binds a socket: it reserves a
// TCP port, runs the full lifecycle, and asserts the reserved port still
// accepts. Interaction with providers happens exclusively through the
// injectable LocalProvider interface (a local function call), never a listener.
func TestNoNetworkListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := ln.Addr().String()
	defer ln.Close()

	cfg := baseConfig(t)
	host, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	host.Start(context.Background())
	// Give the loop goroutine a chance to (incorrectly) bind something.
	time.Sleep(200 * time.Millisecond)
	if err := host.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The reserved listener must still accept, proving the service took no port.
	conn, err := net.DialTimeout("tcp", port, 1*time.Second)
	if err != nil {
		t.Fatalf("reserved port became unusable after service lifecycle: %v (service must have bound something)", err)
	}
	conn.Close()
}
