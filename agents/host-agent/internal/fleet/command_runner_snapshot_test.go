package fleet

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/command"
)

func snapshotFixture(request command.Request, response command.Response, uncertain, stream bool) *CommandRunner {
	requestCopy := detachedRequestCopy(request)
	r := &CommandRunner{
		heldRequest:  &requestCopy,
		activeStream: stream,
		activeDigest: request.Capability.RequestDigest,
		done:         make(chan commandCompletion, 1),
	}
	r.capture(commandCompletion{response: response, persistenceUncertain: uncertain})
	return r
}

func TestHeldSnapshotUnavailableUntilCaptureAndAfterACK(t *testing.T) {
	request := runnerRequest("snapshot-lifecycle", time.Now().Add(time.Minute))
	r := &CommandRunner{}
	if got := r.heldSnapshot(); got != nil {
		t.Fatal("snapshot available before admission")
	}
	requestCopy := detachedRequestCopy(request)
	r.heldRequest = &requestCopy
	r.done = make(chan commandCompletion, 1)
	r.done <- commandCompletion{response: command.Response{RequestID: request.RequestID, JobID: request.JobID}}
	if got := r.heldSnapshot(); got != nil {
		t.Fatal("snapshot available before sequential owner captured completion")
	}
	if err := r.Quiesce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.heldSnapshot(); got == nil {
		t.Fatal("snapshot unavailable after completion capture")
	}

	ctx, cancel := context.WithCancel(context.Background())
	client := signedCommandClient(t, nil, func(int) *command.Request { return nil }, func(command.Response) int {
		cancel()
		return 200
	})
	if err := r.Run(ctx, client); err != nil {
		t.Fatal(err)
	}
	cancel()
	if r.pending != nil || r.heldRequest != nil {
		t.Fatal("ordinary ACK did not clear pending response and retained request together")
	}
	if got := r.heldSnapshot(); got != nil {
		t.Fatal("snapshot available after ordinary ACK release")
	}
}

func TestHeldSnapshotDetachedTupleAndFailClosedObservation(t *testing.T) {
	request := runnerRequest("snapshot-detached", time.Now().Add(time.Minute))
	wantRequest := detachedRequestCopy(request)
	progress, errorCode := uint8(73), "ADAPTER_FAILED"
	response := command.Response{
		RequestID: request.RequestID, JobID: request.JobID, HostID: request.HostID,
		Sequence: request.Sequence, Status: "failed", Progress: &progress,
		ObservedAt: "2026-11-25T18:00:00.000Z", ErrorCode: &errorCode,
		Observation: map[string]any{"outer": []any{map[string]any{"value": "kept"}}},
	}
	wantResponse := response
	r := snapshotFixture(request, response, true, true)

	// Caller-side mutation after admission cannot change the retained tuple.
	request.Params[0] = ' '
	*request.Capability.ModelID = "mutated-model"
	first := r.heldSnapshot()
	if first == nil {
		t.Fatal("snapshot unavailable after capture")
	}
	if !reflect.DeepEqual(first.request, wantRequest) {
		t.Fatalf("snapshot request differs: got %#v want %#v", first.request, wantRequest)
	}
	if !reflect.DeepEqual(first.response, wantResponse) {
		t.Fatalf("snapshot response differs: got %#v want %#v", first.response, wantResponse)
	}
	if !first.persistenceUncertain || !first.stream || first.digest != wantRequest.Capability.RequestDigest {
		t.Fatal("snapshot classifications or authorization digest differ")
	}

	// Mutate every returned pointer and nested mutable value; the next read must
	// be a fresh detached copy and the runner's authoritative values must survive.
	first.request.Params[0] = 'x'
	*first.request.Capability.ModelID = "snapshot-mutated-model"
	*first.response.Progress = 0
	*first.response.ErrorCode = "snapshot-mutated-error"
	first.response.Observation.(map[string]any)["outer"].([]any)[0].(map[string]any)["value"] = "snapshot-mutated"
	second := r.heldSnapshot()
	if second == nil || !reflect.DeepEqual(second.request, wantRequest) || !reflect.DeepEqual(second.response, wantResponse) {
		t.Fatal("mutating a returned snapshot changed runner state or a later snapshot")
	}
	if second.request.Params == nil || &second.request.Params[0] == &r.heldRequest.Params[0] {
		t.Fatal("returned request params alias retained request")
	}
	if second.request.Capability.ModelID == r.heldRequest.Capability.ModelID || second.response.Progress == r.pending.Progress || second.response.ErrorCode == r.pending.ErrorCode {
		t.Fatal("returned pointer field aliases retained runner state")
	}

	for name, observation := range map[string]any{
		"function": map[string]any{"nested": func() {}},
		"channel":  []any{make(chan int)},
		"cycle": func() any {
			cycle := map[string]any{}
			cycle["self"] = cycle
			return cycle
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			bad := *r.pending
			bad.Observation = observation
			r.pending = &bad
			if got := r.heldSnapshot(); got != nil {
				t.Fatal("unsupported mutable observation returned a partial snapshot")
			}
			r.pending = &response
		})
	}
}

func TestHeldSnapshotStreamAndOrdinaryClassification(t *testing.T) {
	request := runnerRequest("snapshot-classification", time.Now().Add(time.Minute))
	response := command.Response{RequestID: request.RequestID, JobID: request.JobID, Status: "failed"}
	ordinary := snapshotFixture(request, response, false, false).heldSnapshot()
	stream := snapshotFixture(request, response, false, true).heldSnapshot()
	uncertain := snapshotFixture(request, response, true, false).heldSnapshot()
	if ordinary == nil || ordinary.persistenceUncertain || ordinary.stream {
		t.Fatal("ordinary completion classification incorrect")
	}
	if stream == nil || stream.persistenceUncertain || !stream.stream {
		t.Fatal("stream completion classification incorrect")
	}
	if uncertain == nil || !uncertain.persistenceUncertain || uncertain.stream {
		t.Fatal("persistence-uncertain classification incorrect")
	}
}

func TestHeldSnapshotRetainsOrdinaryFailureWithoutReexecution(t *testing.T) {
	request := runnerRequest("snapshot-held-failure", time.Now().Add(time.Minute))
	adapter := &ordinaryFailureAdapter{}
	r := lifetimeRunner(t, command.New("host-1", adapter, time.Now))
	ctx, cancel := context.WithCancel(context.Background())
	client := signedCommandClient(t, nil, func(int) *command.Request { return &request }, func(command.Response) int {
		cancel()
		return 400
	})
	if err := r.Run(ctx, client); err != nil {
		t.Fatal(err)
	}
	if err := r.Quiesce(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot := r.heldSnapshot()
	if snapshot == nil || snapshot.persistenceUncertain || snapshot.stream || snapshot.request.JobID != request.JobID || snapshot.response.Status != "failed" {
		t.Fatal("ordinary failed completion was not retained as a complete snapshot")
	}
	if r.pending == nil || adapter.calls != 1 {
		t.Fatal("snapshot retrieval released the failure or caused another execution")
	}
	if again := r.heldSnapshot(); again == nil || !reflect.DeepEqual(again.request, snapshot.request) || !reflect.DeepEqual(again.response, snapshot.response) || adapter.calls != 1 {
		t.Fatal("repeated read changed or re-executed the held failure")
	}
}

type mutatingParamsAdapter struct{ calls int }

func (a *mutatingParamsAdapter) Execute(_ context.Context, _ string, params json.RawMessage) (any, error) {
	a.calls++
	if len(params) > 0 {
		params[0] = 'x'
	}
	return map[string]any{"ok": true}, nil
}

func TestHeldSnapshotAdmissionRequestDoesNotAliasExecutorInput(t *testing.T) {
	request := runnerRequest("snapshot-admission-copy", time.Now().Add(time.Minute))
	wantParams := append([]byte(nil), request.Params...)
	adapter := &mutatingParamsAdapter{}
	r := lifetimeRunner(t, command.New("host-1", adapter, time.Now))
	ctx, cancel := context.WithCancel(context.Background())
	client := signedCommandClient(t, nil, func(int) *command.Request { return &request }, func(command.Response) int {
		cancel()
		return 400
	})
	if err := r.Run(ctx, client); err != nil {
		t.Fatal(err)
	}
	if err := r.Quiesce(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot := r.heldSnapshot()
	if snapshot == nil || !reflect.DeepEqual([]byte(snapshot.request.Params), wantParams) || adapter.calls != 1 {
		t.Fatal("executor mutation changed retained admission request or duplicated execution")
	}
}

func TestHeldSnapshotActualPersistenceUncertaintyRetainsFullTuple(t *testing.T) {
	request := runnerRequest("snapshot-actual-uncertainty", time.Now().Add(time.Minute))
	later := runnerRequest("snapshot-no-admit-while-uncertain", time.Now().Add(time.Minute))
	adapter := &persistenceFailureAdapter{path: filepath.Join(t.TempDir(), "replay.json")}
	executor, err := command.NewPersistent("host-1", adapter, time.Now, adapter.path)
	if err != nil {
		t.Fatal(err)
	}
	r := lifetimeRunner(t, executor)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	client := signedCommandClient(t, nil, func(n int) *command.Request {
		if n >= 3 {
			cancel()
		}
		if n == 1 {
			return &request
		}
		return &later
	}, func(command.Response) int { t.Fatal("uncertain response must not be sent"); return 200 })
	if err := r.Run(ctx, client); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := r.Quiesce(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := r.heldSnapshot()
	if first == nil || !first.persistenceUncertain || first.stream || !reflect.DeepEqual(first.request.Params, request.Params) || first.response.RequestID != request.RequestID || adapter.calls != 1 {
		t.Fatal("actual persistence-uncertain completion was not retained exactly")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	client2 := signedCommandClient(t, nil, func(int) *command.Request { cancel2(); return &later }, func(command.Response) int { t.Fatal("uncertain response must remain unsent"); return 200 })
	if err := r.Run(ctx2, client2); err != nil {
		t.Fatal(err)
	}
	cancel2()
	if err := r.Quiesce(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := r.heldSnapshot()
	if second == nil || !reflect.DeepEqual(second.request, first.request) || !reflect.DeepEqual(second.response, first.response) || !second.persistenceUncertain || adapter.calls != 1 {
		t.Fatal("uncertain completion changed or was re-executed across runner generation")
	}
}

func TestHeldSnapshotQuiesceCapturesOnceAndRetainsRequest(t *testing.T) {
	adapter := &lateRunnerAdapter{entered: make(chan context.Context, 1), release: make(chan struct{})}
	executor := command.New("host-1", adapter, time.Now)
	r := lifetimeRunner(t, executor)
	request := runnerRequest("snapshot-quiesce", time.Now().Add(time.Minute))
	ctx, cancel := context.WithCancel(context.Background())
	client := signedCommandClient(t, nil, func(int) *command.Request { return &request }, func(command.Response) int {
		t.Fatal("unexpected result before completion")
		return 400
	})
	runDone := make(chan error, 1)
	go func() { runDone <- r.Run(ctx, client) }()
	<-adapter.entered
	if got := r.heldSnapshot(); got != nil {
		t.Fatal("in-flight execution exposed an uncaptured completion")
	}
	cancel()
	if err := <-runDone; err != nil {
		t.Fatal(err)
	}
	quiesceDone := make(chan error, 1)
	go func() { quiesceDone <- r.Quiesce(context.Background()) }()
	select {
	case err := <-quiesceDone:
		t.Fatalf("Quiesce failed to join the adapter: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(adapter.release)
	if err := <-quiesceDone; err != nil {
		t.Fatal(err)
	}
	snapshot := r.heldSnapshot()
	if snapshot == nil || snapshot.request.JobID != request.JobID || !reflect.DeepEqual(snapshot.request.Params, request.Params) || adapter.calls.Load() != 1 {
		t.Fatal("Quiesce did not retain the exact request and single captured execution")
	}
}

func TestHeldSnapshotSeamHasNoSideEffectCalls(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate snapshot test source")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "command_runner.go"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "command_runner.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	functions := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			functions[fn.Name.Name] = fn
		}
	}
	allowed := map[string]bool{
		"heldSnapshot": true, "detachedRequestCopy": true, "detachedResponseCopy": true,
		"cloneObservable": true, "cloneDeep": true,
	}
	for name := range allowed {
		fn := functions[name]
		if fn == nil {
			t.Fatalf("missing snapshot helper %s", name)
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if _, ok := node.(*ast.GoStmt); ok {
				t.Errorf("snapshot helper %s starts a goroutine", name)
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			called := ""
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				called = fun.Name
			case *ast.SelectorExpr:
				called = fun.Sel.Name
			}
			forbidden := map[string]bool{
				"Execute": true, "ExecuteStream": true, "LookupReplay": true,
				"SendCommandResult": true, "SendStreamResult": true, "SendStreamEvent": true,
				"ExecuteDirective": true, "Persist": true, "Quiesce": true,
				"release": true, "Release": true, "Now": true, "timeNow": true,
				"Journal": true, "Transport": true, "Provider": true, "Model": true,
				"Peer": true, "Send": true, "Write": true, "Append": true,
			}
			if forbidden[called] {
				t.Errorf("snapshot helper %s calls forbidden side-effect function %s", name, called)
			}
			if name == "heldSnapshot" && !allowed[called] {
				t.Errorf("heldSnapshot calls unreviewed helper %s", called)
			}
			return true
		})
	}
}
