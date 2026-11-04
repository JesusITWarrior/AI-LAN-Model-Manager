package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/fleet"
)

func TestCommandReporterIndependentStateAndRedaction(t *testing.T) {
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	var raw []byte
	r := &commandReporter{now: func() time.Time { return now }, save: func(_, name string, b []byte) error {
		if name != "command-status.json" {
			t.Fatal(name)
		}
		raw = append([]byte(nil), b...)
		return nil
	}}
	emit := func(d fleet.CommandDomain, s fleet.CommandStage) {
		_ = r.record(fleet.CommandEvent{Domain: d, Stage: s})
	}
	emit(fleet.DomainExecution, fleet.StageEntered)
	_ = r.record(fleet.CommandEvent{Domain: fleet.DomainExecution, Stage: fleet.StageCompleted, Outcome: fleet.OutcomeFailed, ErrorClass: fleet.ErrorIndeterminate, Persistence: fleet.PersistenceUncertain})
	emit(fleet.DomainPending, fleet.StageCaptured)
	emit(fleet.DomainPending, fleet.StageUncertain)
	emit(fleet.DomainPending, fleet.StageExpired)
	_ = r.record(fleet.CommandEvent{Domain: fleet.DomainDelivery, Stage: fleet.StageHTTP, HTTPStatus: 400})
	prior := r.status.LastResultFailure
	emit(fleet.DomainPoll, fleet.StageVerified)
	if r.status.LastResultFailure != prior || !r.status.Pending.Present || !r.status.Pending.Uncertain || !r.status.Pending.Expired || r.status.Persistence != "uncertain" {
		t.Fatal("poll erased independent failure/hold")
	}
	// Every scalar is explicitly cast from a hostile input; no raw enum may escape.
	secret := "CANARY-model-provider-body-error-path-key-prompt-nonce-envelope-host-job-request-digest"
	_ = r.record(fleet.CommandEvent{Domain: fleet.DomainPoll, Stage: fleet.CommandStage(secret), HTTPStatus: 9999, Outcome: fleet.CommandOutcome(secret), ErrorClass: fleet.CommandErrorClass(secret), Acknowledged: true})
	_ = r.record(fleet.CommandEvent{Domain: fleet.DomainExecution, Stage: fleet.StageCompleted, Outcome: fleet.CommandOutcome(secret), ErrorClass: fleet.CommandErrorClass(secret)})
	if len(raw) >= 4096 || !json.Valid(raw) || strings.Contains(string(raw), "CANARY") || strings.Contains(string(raw), "9999") {
		t.Fatal("unbounded or raw diagnostic", string(raw))
	}
	if r.status.LastResultAcknowledgedAt != "" {
		t.Fatal("fabricated ACK")
	}
	// Stream one-shot release is not proof of delivery or acknowledgement.
	_ = r.record(fleet.CommandEvent{Domain: fleet.DomainDelivery, Stage: fleet.StageTransport, Stream: true})
	_ = r.record(fleet.CommandEvent{Domain: fleet.DomainPending, Stage: fleet.StageReleased, Stream: true})
	if r.status.Pending.Present || r.status.LastResultAcknowledgedAt != "" || r.status.Delivery.Stage == fleet.StageACKValidated {
		t.Fatal("failed stream asserted delivery")
	}
	now = now.Add(time.Second)
	_ = r.record(fleet.CommandEvent{Domain: fleet.DomainPending, Stage: fleet.StageReleased, Acknowledged: true})
	if r.status.LastResultAcknowledgedAt == "" || r.status.LastResultFailure.Stage != fleet.StageTransport {
		t.Fatal("ACK hid independent failure")
	}
}

func TestCommandReporterThrottleDirtyRetryAndFixedWarnings(t *testing.T) {
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	calls := 0
	fail := true
	var warnings []string
	var saved commandStatus
	r := &commandReporter{now: func() time.Time { return now }, warn: func(s string) { warnings = append(warnings, s) }, save: func(_, _ string, raw []byte) error {
		calls++
		if fail {
			return errors.New("CANARY-private-filesystem-path")
		}
		return json.Unmarshal(raw, &saved)
	}}
	emit := func(d fleet.CommandDomain, s fleet.CommandStage) {
		_ = r.record(fleet.CommandEvent{Domain: d, Stage: s})
	}
	emit(fleet.DomainSession, fleet.StageStarted)
	for i := 0; i < 1000; i++ {
		emit(fleet.DomainPoll, fleet.StageVerified)
		emit(fleet.DomainDelivery, fleet.StageSendStarted)
		emit(fleet.DomainDelivery, fleet.StageTransport)
	}
	if calls != 1 || len(warnings) != 1 || !r.dirty || !r.unavailable {
		t.Fatal("failure flooded or lost dirty state", calls, warnings)
	}
	now = now.Add(time.Minute)
	emit(fleet.DomainPoll, fleet.StageVerified)
	if calls != 2 || len(warnings) != 1 {
		t.Fatal("retry interval or warning suppression")
	}
	fail = false
	now = now.Add(time.Minute)
	emit(fleet.DomainPoll, fleet.StageVerified)
	if calls != 3 || len(warnings) != 2 || r.dirty || r.unavailable || saved.Delivery.Attempts != 1000 || saved.LastResultFailure.Stage != fleet.StageTransport {
		t.Fatal("did not save latest dirty snapshot")
	}
	if warnings[0] != "host service command diagnostic unavailable" || warnings[1] != "host service command diagnostic recovered" {
		t.Fatal("nonfixed warnings", warnings)
	}
	before := calls
	for i := 0; i < 1000; i++ {
		emit(fleet.DomainPoll, fleet.StageVerified)
	}
	if calls != before {
		t.Fatal("writes every poll")
	}
	// Ordinary repeated retries write first/power-of-two milestones, not twice/attempt.
	for i := 0; i < 1000; i++ {
		emit(fleet.DomainDelivery, fleet.StageSendStarted)
		emit(fleet.DomainDelivery, fleet.StageTransport)
	}
	if calls-before > 2 {
		t.Fatal("repeated delivery failure floods storage", calls-before)
	}
	r.status.Delivery.Attempts = math.MaxUint64
	emit(fleet.DomainDelivery, fleet.StageSendStarted)
	if r.status.Delivery.Attempts != math.MaxUint64 {
		t.Fatal("counter overflow")
	}
	// Backwards/hostile clocks cannot bypass retry throttling or JSON time bounds.
	now = time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC)
	emit(fleet.DomainPoll, fleet.StageVerified)
	if r.lastNow.Year() != 2026 {
		t.Fatal("clock regressed")
	}
	for _, year := range []int{-999999, 10000, 999999} {
		parsed := boundedCommandTime(time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC))
		if _, err := time.Parse(time.RFC3339Nano, parsed.Format(time.RFC3339Nano)); err != nil {
			t.Fatal("unbounded local timestamp")
		}
	}
}

func TestCommandReporterConcurrentBoundedProtectedReplacement(t *testing.T) {
	root := diagnosticTestRoot(t)
	// A prior lifetime is replaced, never restored or interpreted as admission state.
	if err := saveDiagnostic(root, "command-status.json", []byte(`{"CANARY":"old-lifetime"}`)); err != nil {
		t.Fatal(err)
	}
	r := newCommandReporter(root)
	var wg sync.WaitGroup
	for g := 0; g < 12; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				_ = r.record(fleet.CommandEvent{Domain: fleet.DomainPoll, Stage: fleet.StageVerified})
				_ = r.record(fleet.CommandEvent{Domain: fleet.DomainDelivery, Stage: fleet.StageSendStarted})
				_ = r.record(fleet.CommandEvent{Domain: fleet.DomainDelivery, Stage: fleet.StageHTTP, HTTPStatus: 400})
			}
		}()
	}
	wg.Wait()
	// Force a final critical snapshot after all concurrent events.
	_ = r.record(fleet.CommandEvent{Domain: fleet.DomainSession, Stage: fleet.StageHandoffWaiting})
	raw, err := os.ReadFile(filepath.Join(root, "command-status.json"))
	if err != nil || len(raw) > 4096 || !json.Valid(raw) || strings.Contains(string(raw), "CANARY") {
		t.Fatal("protected replacement", err, string(raw))
	}
	var got commandStatus
	if json.Unmarshal(raw, &got) != nil || got.Delivery.Attempts != 360 || got.LastResultFailure.HTTPStatus != 400 || got.Session != fleet.StageHandoffWaiting {
		t.Fatal("lost concurrent progress", fmt.Sprint(got))
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary files remain")
	}
}
