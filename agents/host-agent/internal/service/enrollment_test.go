package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/enrollment"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/observation"
)

type fakeEnroller struct {
	mu    *sync.Mutex
	order *[]string
	out   enrollment.Outcome
	err   error
}

func (f fakeEnroller) Enroll(context.Context) (enrollment.Outcome, error) {
	f.mu.Lock()
	*f.order = append(*f.order, "enroll")
	f.mu.Unlock()
	return f.out, f.err
}

func TestConfiguredEnrollmentRunsBeforeObservationAndFailureDegrades(t *testing.T) {
	var mu sync.Mutex
	var order []string
	obs := baseObserver()
	obs.onObserve = func() { mu.Lock(); order = append(order, "observe"); mu.Unlock() }
	cfg := testConfig(t, []observation.Observer{obs}, nil, time.Minute)
	cfg.Enroller = fakeEnroller{mu: &mu, order: &order, out: enrollment.Outcome{Status: enrollment.StatusDegraded, OperatorCode: "23456789"}, err: errors.New("controller secret")}
	var logs []LogEntry
	cfg.Log = func(entry LogEntry) { logs = append(logs, entry) }
	host, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close(context.Background())
	if err := host.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := append([]string(nil), order...)
	mu.Unlock()
	if len(got) < 2 || got[0] != "enroll" || got[1] != "observe" {
		t.Fatalf("order=%v", got)
	}
	if len(logs) == 0 || logs[0].Fields["status"] != enrollment.StatusDegraded {
		t.Fatalf("logs=%+v", logs)
	}
	for _, entry := range logs {
		if entry.Fields["operatorCode"] != nil || entry.Fields["error"] != nil {
			t.Fatalf("sensitive log: %+v", entry)
		}
	}
}
