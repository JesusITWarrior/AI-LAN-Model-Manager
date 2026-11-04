package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func replayClock() time.Time { return time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC) }
func freshReplayRequest(key string) Request {
	r := req()
	r.IdempotencyKey = key
	r.Capability.RequestDigest, _ = authorizationDigest(r)
	return r
}

func TestReplayPersistenceUncertaintyRetainsOutcomeAndBlocksAdapter(t *testing.T) {
	for _, published := range []bool{false, true} {
		for _, status := range []string{"failed", "succeeded", "running"} {
			t.Run(status+"/published="+map[bool]string{true: "yes", false: "no"}[published], func(t *testing.T) {
				calls := 0
				a := adapterFunc(func(context.Context, string, json.RawMessage) (any, error) {
					calls++
					switch status {
					case "failed":
						return nil, errors.New("synthetic adapter error")
					case "running":
						return nil, ErrServingActive
					default:
						return map[string]any{"activeRequests": 0}, nil
					}
				})
				path := filepath.Join(t.TempDir(), "replay.json")
				e, err := NewPersistent("host-1", a, replayClock, path)
				if err != nil {
					t.Fatal(err)
				}
				if err := e.persist(); err != nil {
					t.Fatal(err)
				}
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				writes := 0
				e.writeReplay = func(path string, raw []byte) (bool, error) {
					writes++
					if !published {
						return false, errors.New("injected prepublication failure")
					}
					return writeReplayStoreWithFinish(path, raw, func(string) error { return errors.New("injected postpublication directory sync failure") })
				}
				r := freshReplayRequest("uncertain")
				r.Operation = "drain"
				r.Capability.Operation = "model-drain"
				r.Capability.RequestDigest, _ = authorizationDigest(r)
				one, err := e.Execute(context.Background(), r)
				var persistenceErr *replayPersistenceError
				if !errors.Is(err, ErrReplayPersistence) || !errors.As(err, &persistenceErr) || persistenceErr.published != published || one.Status != status {
					t.Fatalf("outcome/uncertainty=%#v, %v", one, err)
				}
				if status == "failed" && (one.ErrorCode == nil || *one.ErrorCode != "ADAPTER_FAILED") {
					t.Fatal(one)
				}
				if !reflect.DeepEqual(e.seen[r.IdempotencyKey].Response, one) {
					t.Fatal("known outcome lost")
				}
				// Even concurrent identical running-drain retries cannot execute or clear
				// uncertainty automatically.
				var wg sync.WaitGroup
				for range 8 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						two, err := e.Execute(context.Background(), r)
						if !errors.Is(err, ErrReplayPersistence) || !reflect.DeepEqual(two, one) {
							t.Errorf("retained replay=%#v, %v", two, err)
						}
					}()
				}
				wg.Wait()
				if _, err := e.Execute(context.Background(), freshReplayRequest("unrelated")); !errors.Is(err, ErrReplayPersistence) {
					t.Fatal("new adapter admission not blocked", err)
				}
				divergent := r
				divergent.Params = json.RawMessage(`{"changed":true}`)
				divergent.Capability.RequestDigest, _ = authorizationDigest(divergent)
				if _, err := e.Execute(context.Background(), divergent); !errors.Is(err, ErrCommand) {
					t.Fatal("divergent replay accepted", err)
				}
				if calls != 1 || writes != 1 {
					t.Fatalf("calls=%d writes=%d", calls, writes)
				}
				after, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !published {
					if !bytes.Equal(before, after) {
						t.Fatal("prepublication changed disk")
					}
				} else {
					var disk map[string]entry
					if err := json.Unmarshal(after, &disk); err != nil {
						t.Fatal(err)
					}
					want, _ := json.Marshal(e.seen)
					got, _ := json.Marshal(disk)
					if !bytes.Equal(want, got) {
						t.Fatal("postpublication disk/map mismatch")
					}
					// Terminal visible outcomes survive reopen. Running drain retries after
					// restart remain the preexisting semantics, not crash-proof idempotency.
					if status != "running" {
						reopened, err := NewPersistent("host-1", a, replayClock, path)
						if err != nil {
							t.Fatal(err)
						}
						got, err := reopened.Execute(context.Background(), r)
						if err != nil || got.Status != status || calls != 1 {
							t.Fatal("published replay lost", got, err, calls)
						}
					}
				}
				leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".command-replay-*"))
				if err != nil || len(leftovers) != 0 {
					t.Fatal("temp leaked", leftovers, err)
				}
			})
		}
	}
}

func TestReplayPrepublicationRenameFailurePreservesTargetAndCleansTemp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory-not-file")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	published, err := writeReplayStore(path, []byte("{}\n"))
	if err == nil || published {
		t.Fatal("rename failure misclassified", published, err)
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		t.Fatal("target changed", info, err)
	}
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".command-replay-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatal("temp leaked", leftovers, err)
	}
}

func TestReplayCapacityCheckedBeforeAdapter(t *testing.T) {
	a := &adapter{}
	e := New("host-1", a, replayClock)
	for i := range maxReplayEntries {
		e.seen[time.Unix(int64(i), 0).String()] = entry{}
	}
	if _, err := e.Execute(context.Background(), req()); !errors.Is(err, ErrCommand) || a.calls != 0 {
		t.Fatal("capacity admitted adapter", err, a.calls)
	}
}

func TestReplaySerializationFailureRetainsExecutedOutcome(t *testing.T) {
	calls := 0
	a := adapterFunc(func(context.Context, string, json.RawMessage) (any, error) { calls++; return make(chan int), nil })
	e, err := NewPersistent("host-1", a, replayClock, filepath.Join(t.TempDir(), "replay.json"))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		got, err := e.Execute(context.Background(), req())
		if got.Status != "succeeded" || !errors.Is(err, ErrReplayPersistence) {
			t.Fatal(got, err)
		}
	}
	if calls != 1 {
		t.Fatal("serialization failure repeated execution", calls)
	}
}

func TestReplayInferenceMarkerFailurePreventsExecution(t *testing.T) {
	for _, published := range []bool{false, true} {
		t.Run(map[bool]string{true: "published", false: "not-published"}[published], func(t *testing.T) {
			a := &adapter{}
			r := inferenceRequest()
			e, err := NewPersistent("host-1", a, func() time.Time { return time.Date(2026, 9, 29, 11, 0, 0, 0, time.UTC) }, filepath.Join(t.TempDir(), "replay.json"))
			if err != nil {
				t.Fatal(err)
			}
			e.writeReplay = func(path string, raw []byte) (bool, error) {
				if !published {
					return false, errors.New("prepublication failure")
				}
				return writeReplayStoreWithFinish(path, raw, func(string) error { return errors.New("postpublication failure") })
			}
			for range 2 {
				if _, err := e.Execute(context.Background(), r); !errors.Is(err, ErrReplayPersistence) {
					t.Fatal(err)
				}
			}
			if a.calls != 0 || e.seen[r.IdempotencyKey].Response.Status != "running" {
				t.Fatal("uncertain marker admitted execution", a.calls)
			}
		})
	}
}

type replayStreamAdapter struct {
	adapter
	streamCalls int
}

func (a *replayStreamAdapter) ExecuteStream(context.Context, Request, StreamEmitter) error {
	a.streamCalls++
	return errors.New("synthetic stream adapter failure")
}

func TestReplayStreamMarkerFailurePreventsExecution(t *testing.T) {
	for _, published := range []bool{false, true} {
		t.Run(map[bool]string{true: "published", false: "not-published"}[published], func(t *testing.T) {
			r, _ := streamFixture(t)
			a := &replayStreamAdapter{}
			e, err := NewPersistent(r.HostID, a, streamClock, filepath.Join(t.TempDir(), "replay.json"))
			if err != nil {
				t.Fatal(err)
			}
			e.writeReplay = func(path string, raw []byte) (bool, error) {
				if !published {
					return false, errors.New("prepublication failure")
				}
				return writeReplayStoreWithFinish(path, raw, func(string) error { return errors.New("postpublication failure") })
			}
			for range 2 {
				if _, err := e.ExecuteStream(context.Background(), r, func(context.Context, []byte) error { t.Fatal("unexpected output"); return nil }); !errors.Is(err, ErrReplayPersistence) {
					t.Fatal(err)
				}
			}
			if a.calls != 0 || a.streamCalls != 0 {
				t.Fatal("uncertain marker admitted adapter", a.calls, a.streamCalls)
			}
		})
	}
}

func TestReplayInferenceFinalFailureDoesNotRestoreRunningMarker(t *testing.T) {
	for _, published := range []bool{false, true} {
		for _, interrupted := range []bool{false, true} {
			name := map[bool]string{true: "published", false: "not-published"}[published] + "/" + map[bool]string{true: "interrupted", false: "executed"}[interrupted]
			t.Run(name, func(t *testing.T) {
				r := inferenceRequest()
				a := &adapter{fail: true}
				e, err := NewPersistent(r.HostID, a, func() time.Time { return time.Date(2026, 9, 29, 11, 0, 0, 0, time.UTC) }, filepath.Join(t.TempDir(), "replay.json"))
				if err != nil {
					t.Fatal(err)
				}
				if interrupted {
					e.seen[r.IdempotencyKey] = entry{Digest: r.Capability.RequestDigest, Response: Response{Status: "running"}}
					if err := e.persist(); err != nil {
						t.Fatal(err)
					}
				}
				writes := 0
				e.writeReplay = func(path string, raw []byte) (bool, error) {
					writes++
					if !interrupted && writes == 1 {
						return writeReplayStore(path, raw)
					}
					if !published {
						return false, errors.New("prepublication failure")
					}
					return writeReplayStoreWithFinish(path, raw, func(string) error { return errors.New("postpublication failure") })
				}
				wantCode := "ADAPTER_FAILED"
				wantCalls := 1
				if interrupted {
					wantCode = "INDETERMINATE"
					wantCalls = 0
				}
				for range 2 {
					got, err := e.Execute(context.Background(), r)
					if !errors.Is(err, ErrReplayPersistence) || got.Status != "failed" || got.ErrorCode == nil || *got.ErrorCode != wantCode {
						t.Fatal("terminal outcome lost", got, err)
					}
				}
				if a.calls != wantCalls || e.seen[r.IdempotencyKey].Response.Status != "failed" {
					t.Fatal("restored running marker", a.calls)
				}
			})
		}
	}
}
