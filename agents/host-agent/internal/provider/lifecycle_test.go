package provider

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const lifecycleModel = "acme/bert:latest"

func TestLifecycleConstructorsAndBoundaries(t *testing.T) {
	for _, keepAlive := range []time.Duration{time.Second, 24 * time.Hour} {
		command, err := NewLoadModelCommand(strings.Repeat("a", 128), strings.Repeat("p", 128), "Acme/Bert:Latest", keepAlive, Metadata{})
		if err != nil {
			t.Fatalf("boundary command: %v", err)
		}
		if command.CanonicalName() != lifecycleModel || command.KeepAlive() != keepAlive || command.ContextLengthKnown() || command.ContextLength() != 0 {
			t.Fatalf("unexpected command: %#v", command)
		}
	}
	validMetadata := Metadata{ContextLength: MaximumContextLength, Known: true}
	load, err := NewLoadModelCommand("cmd-1", "ollama-main", lifecycleModel, time.Second, validMetadata)
	if err != nil || load.Action() != ActionLoad || load.ContextLength() != MaximumContextLength || !load.ContextLengthKnown() {
		t.Fatalf("valid load = %#v, %v", load, err)
	}
	unload, err := NewUnloadModelCommand("cmd-2", "ollama-main", lifecycleModel, Metadata{ContextLength: 1, Known: true})
	if err != nil || unload.Action() != ActionUnload || unload.KeepAlive() != 0 {
		t.Fatalf("valid unload = %#v, %v", unload, err)
	}
}

func TestLifecycleConstructorsRejectInvalidValues(t *testing.T) {
	valid := func(id, providerID, model string, keep time.Duration, metadata Metadata) error {
		_, err := NewLoadModelCommand(id, providerID, model, keep, metadata)
		return err
	}
	cases := []struct {
		name string
		err  error
	}{
		{"empty command id", valid("", "p", lifecycleModel, time.Second, Metadata{})},
		{"long command id", valid(strings.Repeat("a", 129), "p", lifecycleModel, time.Second, Metadata{})},
		{"bad command id", valid("bad id", "p", lifecycleModel, time.Second, Metadata{})},
		{"empty provider", valid("c", "", lifecycleModel, time.Second, Metadata{})},
		{"long provider", valid("c", strings.Repeat("p", 129), lifecycleModel, time.Second, Metadata{})},
		{"bad provider", valid("c", "bad/provider", lifecycleModel, time.Second, Metadata{})},
		{"bad model", valid("c", "p", "../model", time.Second, Metadata{})},
		{"zero keep alive", valid("c", "p", lifecycleModel, 0, Metadata{})},
		{"subsecond", valid("c", "p", lifecycleModel, 1500*time.Millisecond, Metadata{})},
		{"over 24h", valid("c", "p", lifecycleModel, 24*time.Hour+time.Second, Metadata{})},
		{"known zero context", valid("c", "p", lifecycleModel, time.Second, Metadata{Known: true})},
		{"context too large", valid("c", "p", lifecycleModel, time.Second, Metadata{Known: true, ContextLength: MaximumContextLength + 1})},
		{"unknown nonzero context", valid("c", "p", lifecycleModel, time.Second, Metadata{ContextLength: 1})},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if !errors.Is(test.err, ErrInvalidCommand) {
				t.Fatalf("error = %v, want ErrInvalidCommand", test.err)
			}
		})
	}
	if _, err := NewUnloadModelCommand("", "p", lifecycleModel, Metadata{}); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("invalid unload = %v", err)
	}
}

func TestValidateRejectsTamperedCommands(t *testing.T) {
	for _, command := range []LoadModelCommand{
		{commandID: "c", providerID: "p", canonicalName: "Acme/Bert:Latest", keepAlive: time.Second},
		{commandID: "c", providerID: "p", canonicalName: lifecycleModel, keepAlive: time.Second + time.Nanosecond},
		{commandID: "c", providerID: "p", canonicalName: lifecycleModel, keepAlive: time.Second, contextLength: 1},
	} {
		if !errors.Is(command.Validate(), ErrInvalidCommand) {
			t.Fatalf("Validate accepted %#v", command)
		}
	}
}

func TestLifecycleResultJSONShape(t *testing.T) {
	result := LifecycleResult{CommandID: "cmd", ProviderID: "ollama-main", CanonicalModelName: lifecycleModel, Action: ActionLoad, Outcome: OutcomeSucceeded, Changed: true, RuntimeState: RuntimeLoaded, ObservedAt: "2026-09-27T03:01:02.987Z"}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"commandId":"cmd","providerId":"ollama-main","canonicalModelName":"acme/bert:latest","action":"load","outcome":"succeeded","changed":true,"runtimeState":"loaded","observedAt":"2026-09-27T03:01:02.987Z"}`
	if string(encoded) != want {
		t.Fatalf("json = %s, want %s", encoded, want)
	}
}
