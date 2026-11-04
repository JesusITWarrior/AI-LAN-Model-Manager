package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	agenttransport "github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/transport"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/command"
)

func TestCommandPipelinePresendFailures(t *testing.T) {
	for _, poll := range []bool{false, true} {
		for _, stage := range []CommandStage{StageSequence, StageEnvelope} {
			t.Run(string(stage)+map[bool]string{true: "-poll", false: "-result"}[poll], func(t *testing.T) {
				posts := 0
				c := signedCommandClient(t, nil, func(int) *command.Request { posts++; return nil }, func(command.Response) int { posts++; return 200 })
				if stage == StageSequence {
					c.sequence = ^uint64(0)
				} else {
					c.privateKey = []byte("CANARY-private-key")
				}
				var events []CommandEvent
				c.SetCommandSink(func(e CommandEvent) error { events = append(events, e); return errors.New("CANARY-sink-error") })
				var err error
				if poll {
					_, _, err = c.PollCommand(context.Background(), 0)
				} else {
					err = c.SendCommandResult(context.Background(), command.Response{})
				}
				if err == nil || posts != 0 || len(events) == 0 || events[len(events)-1].Stage != stage {
					t.Fatalf("missing pre-send evidence: %v %d %+v", err, posts, events)
				}
			})
		}
	}
}

func TestCommandPipelineACKClassificationAndSinkFailure(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		stage  CommandStage
	}{
		{200, `{"ok":true}`, StageACKValidated}, {200, `{"ok":false}`, StageACKInvalid}, {200, `{}`, StageACKInvalid}, {200, `CANARY-provider-body`, StageACKInvalid}, {400, `CANARY-error`, StageHTTP}, {503, `CANARY-endpoint`, StageHTTP}, {200, strings.Repeat("x", maxResponseBody+1), StageCodec},
	} {
		t.Run(string(tc.stage), func(t *testing.T) {
			c := signedCommandClient(t, nil, func(int) *command.Request { return nil }, func(command.Response) int { return 200 })
			c.http = &http.Client{Transport: commandRoundTrip(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}
			var events []CommandEvent
			c.SetCommandSink(func(e CommandEvent) error { events = append(events, e); panic("CANARY-sink-panic") })
			err := c.SendCommandResult(context.Background(), command.Response{})
			if (err == nil) != (tc.stage == StageACKValidated) || events[len(events)-1].Stage != tc.stage {
				t.Fatalf("ACK semantics changed: %v %+v", err, events)
			}
			raw, _ := json.Marshal(events)
			if strings.Contains(string(raw), "CANARY") {
				t.Fatal("raw value leaked")
			}
		})
	}
	c := signedCommandClient(t, nil, func(int) *command.Request { return nil }, func(command.Response) int { return 200 })
	c.http = &http.Client{Transport: commandRoundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("CANARY-transport") })}
	var got CommandEvent
	c.SetCommandSink(func(e CommandEvent) error { got = e; return nil })
	if c.SendCommandResult(context.Background(), command.Response{}) == nil || got.Stage != StageTransport {
		t.Fatal("transport classification")
	}
}

func TestCommandPipelineRunnerReleaseAndUncertainty(t *testing.T) {
	for _, mode := range []string{"ack", "reject", "stream-failure", "uncertain"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := signedCommandClient(t, nil, func(int) *command.Request { cancel(); return nil }, func(command.Response) int {
				if mode == "ack" {
					return 200
				}
				return 400
			})
			r := lifetimeRunner(t, command.New("host-1", &ordinaryFailureAdapter{}, time.Now))
			response := command.Response{Status: "failed", Observation: map[string]any{"CANARY-model": "CANARY-provider-body"}}
			r.activeStream = mode == "stream-failure"
			if r.activeStream {
				response.Observation = nil
			}
			r.activeDeadline = time.Now().Add(-time.Minute)
			var events []CommandEvent
			sink := func(e CommandEvent) error { events = append(events, e); return errors.New("CANARY-path") }
			c.SetCommandSink(sink)
			r.SetCommandSink(sink)
			r.capture(commandCompletion{response: response, persistenceUncertain: mode == "uncertain"})
			if err := r.Run(ctx, c); err != nil {
				t.Fatal(err)
			}
			held := mode == "reject" || mode == "uncertain"
			if (r.pending != nil) != held {
				t.Fatal("release semantics changed")
			}
			if held && !reflect.DeepEqual(*r.pending, response) {
				t.Fatal("full response changed")
			}
			released, ack, uncertain, expired, delivered := false, false, false, false, false
			for _, e := range events {
				if e.Stage == StageReleased {
					released = true
					ack = e.Acknowledged
				}
				uncertain = uncertain || e.Stage == StageUncertain
				expired = expired || e.Stage == StageExpired
				delivered = delivered || e.Stage == StageACKValidated
			}
			if released == held || ack != (mode == "ack") || uncertain != (mode == "uncertain") || !expired || (mode == "stream-failure" && delivered) {
				t.Fatalf("incorrect diagnostic assertions %+v", events)
			}
			raw, _ := json.Marshal(events)
			if strings.Contains(string(raw), "CANARY") {
				t.Fatal("response leaked")
			}
		})
	}
}

func TestCommandPipelinePollSinkVerifierCompatibility(t *testing.T) {
	for _, bad := range []bool{false, true} {
		var mutate func([]byte) []byte
		if bad {
			mutate = func(raw []byte) []byte { return append([]byte(`{"CANARY":true,`), raw[1:]...) }
		}
		c := signedCommandClient(t, mutate, func(int) *command.Request { return nil }, func(command.Response) int { return 200 })
		var got CommandEvent
		c.SetCommandSink(func(e CommandEvent) error { got = e; return nil })
		_, _, err := c.PollCommand(context.Background(), 0)
		expected := StageVerified
		if bad {
			expected = StageCodec
		}
		if got.Stage != expected || (err != nil) != bad {
			t.Fatalf("typed verifier: %+v %v", got, err)
		}
	}
}

func FuzzCommandEventSanitize(f *testing.F) {
	f.Add("CANARY", "CANARY", 9999, "CANARY", "CANARY")
	f.Fuzz(func(t *testing.T, domain, stage string, status int, outcome, class string) {
		e := (CommandEvent{Domain: CommandDomain(domain), Stage: CommandStage(stage), HTTPStatus: status, Outcome: CommandOutcome(outcome), ErrorClass: CommandErrorClass(class), Acknowledged: true}).Sanitize()
		if e != e.Sanitize() {
			t.Fatal("not idempotent")
		}
		raw, err := json.Marshal(e)
		if err != nil || len(raw) > 400 || e.HTTPStatus != 0 && (e.HTTPStatus < 100 || e.HTTPStatus > 599) {
			t.Fatal("unbounded diagnostic")
		}
	})
}

func TestCommandPipelineSignedExecutionSinkFailureIsNonAuthoritative(t *testing.T) {
	for _, panicSink := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "panic"}[panicSink], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var logs bytes.Buffer
			prior := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
			defer slog.SetDefault(prior)
			request := runnerRequest("CANARY-job", time.Now().Add(time.Minute))
			adapter := &ordinaryFailureAdapter{}
			r := lifetimeRunner(t, command.New("host-1", adapter, time.Now))
			posts := 0
			c := signedCommandClient(t, nil, func(n int) *command.Request {
				if n == 1 {
					return &request
				}
				return nil
			}, func(value command.Response) int {
				posts++
				if value.JobID != request.JobID || value.Status != "failed" || value.ErrorCode == nil || *value.ErrorCode != "ADAPTER_FAILED" {
					t.Fatal("authoritative outcome changed")
				}
				cancel()
				return 200
			})
			var events []CommandEvent
			sink := func(e CommandEvent) error {
				events = append(events, e)
				if panicSink {
					panic("CANARY-provider-error")
				}
				return errors.New("CANARY-sink-path")
			}
			c.SetCommandSink(sink)
			r.SetCommandSink(sink)
			if err := r.Run(ctx, c); err != nil {
				t.Fatal(err)
			}
			if err := r.Quiesce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if posts != 1 || adapter.calls != 1 || r.pending != nil {
				t.Fatal("sink changed execution or release")
			}
			entered, completed, released := false, false, false
			for _, e := range events {
				entered = entered || e.Domain == DomainExecution && e.Stage == StageEntered
				completed = completed || e.Domain == DomainExecution && e.Stage == StageCompleted && e.ErrorClass == ErrorAdapter && e.Persistence == PersistenceNoFailure
				released = released || e.Domain == DomainPending && e.Stage == StageReleased && e.Acknowledged
			}
			if !entered || !completed || !released {
				t.Fatal("incomplete lifecycle", events)
			}
			raw, _ := json.Marshal(events)
			raw = append(raw, logs.Bytes()...)
			for _, secret := range []string{"CANARY", "host-1", "ollama-main", "acme/bert", "synthetic.invalid"} {
				if strings.Contains(string(raw), secret) {
					t.Fatal("raw command data escaped")
				}
			}
		})
	}
}

func TestCommandPipelineAllTypedPollFailures(t *testing.T) {
	for _, stage := range []CommandStage{StageHTTP, StageCodec, StageCertificate, StageSignature, StageClock, StagePayload, StageControllerSequence, StageTransport} {
		t.Run(string(stage), func(t *testing.T) {
			c := signedCommandClient(t, nil, func(int) *command.Request { return nil }, func(command.Response) int { return 200 })
			transport := c.http.Transport
			c.http.Transport = commandRoundTrip(func(req *http.Request) (*http.Response, error) {
				if stage == StageTransport {
					return nil, errors.New("CANARY-path-provider-error")
				}
				response, err := transport.RoundTrip(req)
				if err != nil {
					return response, err
				}
				raw, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				var env agenttransport.Envelope
				if json.Unmarshal(raw, &env) != nil {
					t.Fatal("fixture")
				}
				switch stage {
				case StageHTTP:
					response.StatusCode = 400
					raw = []byte("CANARY-provider-body")
				case StageCodec:
					raw = []byte("CANARY-envelope")
				case StageCertificate:
					env.CertSerial = "12"
				case StageSignature:
					env.Signature = "CANARY-signature"
				case StageClock:
					env.SentAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
				case StagePayload:
					env.Payload = json.RawMessage(`{"CANARY":true}`)
				}
				if stage == StageCertificate || stage == StageClock || stage == StagePayload {
					if agenttransport.Sign(&env, c.privateKey) != nil {
						t.Fatal("sign")
					}
				}
				if stage != StageHTTP && stage != StageCodec {
					raw, _ = json.Marshal(env)
				}
				response.Body = io.NopCloser(strings.NewReader(string(raw)))
				return response, nil
			})
			if stage == StageControllerSequence {
				if os.WriteFile(filepath.Join(c.store.CertDir, "controller-command-sequence"), []byte("99999\n"), 0600) != nil {
					t.Fatal("fixture sequence")
				}
			}
			var got CommandEvent
			c.SetCommandSink(func(e CommandEvent) error { got = e; return nil })
			if _, _, err := c.PollCommand(context.Background(), 0); err == nil || got.Domain != DomainPoll || got.Stage != stage {
				t.Fatalf("missing typed poll failure %+v %v", got, err)
			}
		})
	}
}

func TestCommandPipelineSequenceStoreFailureBeforePOST(t *testing.T) {
	c := signedCommandClient(t, nil, func(int) *command.Request { t.Fatal("posted poll"); return nil }, func(command.Response) int { t.Fatal("posted result"); return 200 })
	blocked := filepath.Join(t.TempDir(), "regular-file")
	if os.WriteFile(blocked, []byte("synthetic"), 0600) != nil {
		t.Fatal("fixture")
	}
	c.store.CertDir = blocked
	var got CommandEvent
	c.SetCommandSink(func(e CommandEvent) error { got = e; return nil })
	if c.SendCommandResult(context.Background(), command.Response{}) == nil || got.Stage != StageSequence {
		t.Fatal("reservation failure not observable")
	}
}
