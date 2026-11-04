package main

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/command"
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/fleet"
)

func TestFleetSessionLifetimeAcceptsRunnerOnceAndRetriesConstructionFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var runner *fleet.CommandRunner
	path := filepath.Join(t.TempDir(), "replay.json")
	constructions, rotations, clients := 0, 0, 0
	used := make(chan *fleet.CommandRunner, 4)
	maintainFleetSessionLoop(ctx, fleetSessionHooks{
		rotate: func(context.Context) error {
			rotations++
			if rotations == 5 {
				cancel()
			}
			return nil
		},
		newClient: func() (*fleet.HTTPSClient, error) { clients++; return &fleet.HTTPSClient{}, nil },
		newRunner: func() (*fleet.CommandRunner, error) {
			constructions++
			candidatePath := path
			if constructions == 1 {
				candidatePath = "invalid-relative-replay-path"
			}
			executor, err := command.NewPersistent("synthetic-host", nil, time.Now, candidatePath)
			if err != nil {
				return nil, err
			}
			runner, err = fleet.NewCommandRunner(executor)
			return runner, err
		},
		runInventory:    func(ctx context.Context, _ *fleet.HTTPSClient) { <-ctx.Done() },
		runCommands:     func(ctx context.Context, r *fleet.CommandRunner, _ *fleet.HTTPSClient) { used <- r; <-ctx.Done() },
		closeIdle:       func(*fleet.HTTPSClient) {},
		commandsEnabled: true, sessionDuration: time.Millisecond, retryDelay: time.Millisecond,
	})
	close(used)
	count := 0
	for actual := range used {
		count++
		if actual != runner {
			t.Fatal("runner replaced across generations")
		}
	}
	if constructions != 2 || clients < 4 || count < 3 {
		t.Fatalf("constructions=%d clients=%d accepted uses=%d", constructions, clients, count)
	}
}

func TestFleetSessionRootCancellationDoesNotReplaceOwner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner, err := fleet.NewCommandRunner(command.New("synthetic-host", nil, time.Now))
	if err != nil {
		t.Fatal(err)
	}
	constructions, rotations := 0, 0
	maintainFleetSessionLoop(ctx, fleetSessionHooks{
		rotate:       func(context.Context) error { rotations++; return nil },
		newClient:    func() (*fleet.HTTPSClient, error) { return &fleet.HTTPSClient{}, nil },
		newRunner:    func() (*fleet.CommandRunner, error) { constructions++; return runner, nil },
		runInventory: func(ctx context.Context, _ *fleet.HTTPSClient) { <-ctx.Done() },
		runCommands:  func(ctx context.Context, _ *fleet.CommandRunner, _ *fleet.HTTPSClient) { cancel(); <-ctx.Done() },
		closeIdle:    func(*fleet.HTTPSClient) {}, commandsEnabled: true, sessionDuration: time.Hour, retryDelay: time.Millisecond,
	})
	if constructions != 1 || rotations != 1 {
		t.Fatalf("replacement after root cancellation: constructions=%d rotations=%d", constructions, rotations)
	}
}

// The real adapter/completion join is covered in fleet. This test isolates the
// supervisor's ordering: workers joined, handoff joined, then and only then
// identity/sequence reload; cancellation during handoff never replaces the owner.
func TestFleetSessionHandoffBlocksReplacementUntilJoined(t *testing.T) {
	for _, cancelDuringHandoff := range []bool{false, true} {
		t.Run(map[bool]string{false: "release-before-replacement", true: "root-cancel-no-replacement"}[cancelDuringHandoff], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			owner, err := fleet.NewCommandRunner(command.New("synthetic-host", nil, time.Now))
			if err != nil {
				t.Fatal(err)
			}
			var rotations, constructions, clients, workerExits, closes atomic.Int32
			entered := make(chan struct{})
			release := make(chan struct{})
			done := make(chan struct{})
			var joined atomic.Bool
			go func() {
				defer close(done)
				maintainFleetSessionLoop(ctx, fleetSessionHooks{
					rotate: func(context.Context) error {
						n := rotations.Add(1)
						if n > 1 {
							if !joined.Load() || workerExits.Load() != 2 || closes.Load() != 2 {
								t.Error("identity rotation before old workers/client quiesced")
							}
							cancel()
						}
						return nil
					},
					newClient:    func() (*fleet.HTTPSClient, error) { clients.Add(1); return &fleet.HTTPSClient{}, nil },
					newRunner:    func() (*fleet.CommandRunner, error) { constructions.Add(1); return owner, nil },
					runInventory: func(ctx context.Context, _ *fleet.HTTPSClient) { <-ctx.Done(); workerExits.Add(1) },
					runCommands: func(ctx context.Context, r *fleet.CommandRunner, _ *fleet.HTTPSClient) {
						if r != owner {
							t.Error("owner replaced")
						}
						<-ctx.Done()
						workerExits.Add(1)
					},
					closeIdle: func(*fleet.HTTPSClient) { closes.Add(1) },
					quiesce: func(ctx context.Context, r *fleet.CommandRunner) error {
						if r != owner || workerExits.Load() != 2 {
							t.Error("handoff raced old worker")
						}
						close(entered)
						select {
						case <-ctx.Done():
							return ctx.Err()
						case <-release:
							joined.Store(true)
							return r.Quiesce(ctx)
						}
					},
					commandsEnabled: true, sessionDuration: time.Millisecond, retryDelay: time.Millisecond,
				})
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("handoff not reached")
			}
			if rotations.Load() != 1 || clients.Load() != 1 || constructions.Load() != 1 || closes.Load() != 1 {
				t.Fatal("replacement occurred before handoff")
			}
			if cancelDuringHandoff {
				cancel()
			} else {
				close(release)
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("supervisor did not finish")
			}
			wantRotations := int32(2)
			if cancelDuringHandoff {
				wantRotations = 1
			}
			if rotations.Load() != wantRotations || clients.Load() != 1 || constructions.Load() != 1 {
				t.Fatal("unexpected replacement or reopened executor")
			}
		})
	}
}
