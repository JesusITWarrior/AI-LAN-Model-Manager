package command

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/provider"
)

type observationAdapter struct {
	streamAdapter
	rows   []provider.RunningModel
	err    error
	during func()
}

func (a *observationAdapter) ListRunning(context.Context) ([]provider.RunningModel, error) {
	if a.during != nil {
		a.during()
	}
	return a.rows, a.err
}
func observationFixture() (*Registry, *observationAdapter, []provider.InstalledModel) {
	digest := strings.Repeat("a", 64)
	sum := sha256.Sum256([]byte("synthetic-provider\x00synthetic-model:fixture\x00" + digest))
	id := hex.EncodeToString(sum[:])
	installed := []provider.InstalledModel{{ProviderID: "synthetic-provider", CanonicalName: "synthetic-model:fixture", Digest: digest, ModelID: "ollama-" + id}}
	a := &observationAdapter{rows: []provider.RunningModel{{ProviderID: "synthetic-provider", CanonicalName: "synthetic-model:fixture", Digest: digest, RuntimeID: "ollama-runtime-" + id, ObservedAt: streamClock().Format(time.RFC3339Nano)}}}
	r := NewHostRegistry("synthetic-host", streamClock)
	r.clients["synthetic-provider"] = a
	return r, a, installed
}
func TestRuntimeObservationSafety(t *testing.T) {
	ctx := context.Background()
	r, a, installed := observationFixture()
	check := func(state string, count uint64, wantErr bool) {
		t.Helper()
		rows, err := r.ObserveRuntime(ctx, "synthetic-host", "synthetic-provider", installed)
		if (err != nil) != wantErr || len(rows) != 1 || rows[0].RuntimeState != state || rows[0].ActiveRequests != count {
			t.Fatalf("observation=%+v err=%v", rows, err)
		}
	}
	check("serving", 0, false)
	// Read-only projection cannot itself enable admission.
	if _, err := r.Acquire(ctx, "synthetic-provider", "synthetic-model:fixture"); !errors.Is(err, ErrModelNotLoaded) {
		t.Fatal(err)
	}
	r.syncRunning(a.rows)
	handle, err := r.Acquire(ctx, "synthetic-provider", "synthetic-model:fixture")
	if err != nil {
		t.Fatal(err)
	}
	check("serving", 1, false)
	a.err = errors.New("private-provider-response")
	check("unknown", 1, true)
	a.err = nil
	if _, err = r.runDrain(ctx, "synthetic-provider", "synthetic-model:fixture"); !errors.Is(err, ErrServingActive) {
		t.Fatal(err)
	}
	check("draining", 1, false)
	a.rows = []provider.RunningModel{}
	r.syncRunning(a.rows)
	check("draining", 1, false)
	_ = r.Complete(ctx, handle)
	_ = r.Complete(ctx, handle)
	r.syncRunning(a.rows)
	check("draining", 0, false)
	// Explicit unload completion, not projection, clears drain protection.
	r.markRunning("synthetic-provider", "synthetic-model:fixture", false)
	check("unloaded", 0, false)
	a.err = errors.New("failure")
	check("unknown", 0, true)
}
func TestRuntimeObservationRejectsInvalidEvidence(t *testing.T) {
	for _, mode := range []string{"stale", "future", "foreign-provider", "foreign-id", "foreign-digest", "duplicate", "oversize", "invalid-time", "overlap", "host", "installed", "provider"} {
		t.Run(mode, func(t *testing.T) {
			r, a, installed := observationFixture()
			host, pid := "synthetic-host", "synthetic-provider"
			switch mode {
			case "stale":
				a.rows[0].ObservedAt = streamClock().Add(-time.Minute).Format(time.RFC3339Nano)
			case "future":
				a.rows[0].ObservedAt = streamClock().Add(time.Minute).Format(time.RFC3339Nano)
			case "foreign-provider":
				a.rows[0].ProviderID = "other"
			case "foreign-id":
				a.rows[0].RuntimeID = "other"
			case "foreign-digest":
				a.rows[0].Digest = strings.Repeat("b", 64)
			case "duplicate":
				a.rows = append(a.rows, a.rows[0])
			case "oversize":
				a.rows[0].SizeBytes = 9_007_199_254_740_992
			case "invalid-time":
				a.rows[0].ObservedAt = "bad"
			case "overlap":
				a.during = func() { r.mu.Lock(); r.inventoryEpoch++; r.mu.Unlock() }
			case "host":
				host = "other"
			case "installed":
				installed[0].ModelID = "other"
			case "provider":
				pid = "other"
			}
			rows, err := r.ObserveRuntime(context.Background(), host, pid, installed)
			if !errors.Is(err, ErrRuntimeObservation) {
				t.Fatal("invalid observation accepted")
			}
			for _, row := range rows {
				if row.RuntimeState != "unknown" {
					t.Fatal("false authority", row)
				}
			}
		})
	}
}

func TestRuntimeObservationMissingInstalledCannotClaimIdle(t *testing.T) {
	r, a, _ := observationFixture()
	r.syncRunning(a.rows)
	handle, err := r.Acquire(context.Background(), "synthetic-provider", "synthetic-model:fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Complete(context.Background(), handle)
	a.rows = []provider.RunningModel{}
	if _, err = r.ObserveRuntime(context.Background(), "synthetic-host", "synthetic-provider", nil); err == nil {
		t.Fatal("missing installed identity claimed idle")
	}
}
