//go:build linux

package observation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func amdWith(output string, err error) *AMDObserver {
	value, newErr := NewAMDObserverWithRunner(&mockCommandRunner{output: []byte(output), err: err})
	if newErr != nil {
		panic(newErr)
	}
	return value
}

func TestAMDParsesRepresentativeCards(t *testing.T) {
	input := `{"card0":{"Unique ID":"0xabc","Card series":"AMD Radeon RX 7900","VRAM Total Memory (B)":1000,"VRAM Total Used Memory (B)":"250","GPU use (%)":"75"},"card1":{"Card model":"AMD Instinct","VRAM Total Memory (MiB)":2,"VRAM Total Used Memory (MiB)":1,"GPU use (%)":0}}`
	values, err := amdWith(input, nil).ObserveAccelerators(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 || values[0].ID != "0xabc" || values[1].ID != "amd-1" || values[1].Memory.TotalBytes != 2*1024*1024 || values[0].Kind != AcceleratorAMD {
		t.Fatalf("unexpected: %#v", values)
	}
	if *values[0].UtilizationPercent != 75 || values[0].Memory.AvailableBytes != 750 {
		t.Fatalf("bad normalization: %#v", values[0])
	}
}

func TestAMDUsesFixedCommand(t *testing.T) {
	runner := &mockCommandRunner{}
	observer, _ := NewAMDObserverWithRunner(runner)
	_, _ = observer.ObserveAccelerators(context.Background())
	if runner.path != "/usr/bin/rocm-smi" || strings.Join(runner.args, "|") != strings.Join(amdArgs, "|") {
		t.Fatalf("command: %q %#v", runner.path, runner.args)
	}
}

func TestAMDGracefulAbsence(t *testing.T) {
	missing := &AMDObserver{runner: &mockCommandRunner{}}
	values, err := missing.ObserveAccelerators(context.Background())
	if err != nil || values == nil || len(values) != 0 {
		t.Fatalf("missing: %#v %v", values, err)
	}
	values, err = amdWith("{}", nil).ObserveAccelerators(context.Background())
	if err != nil || values == nil || len(values) != 0 {
		t.Fatalf("empty: %#v %v", values, err)
	}
	values, err = amdWith("No supported adapters", errors.New("exit")).ObserveAccelerators(context.Background())
	if err != nil || values == nil || len(values) != 0 {
		t.Fatalf("absence: %#v %v", values, err)
	}
}

func TestAMDRejectsMalformedAmbiguousAndInvalidData(t *testing.T) {
	base := func(fields string) string { return `{"card0":{` + fields + `}}` }
	cases := []string{
		`not-json`, base(`"Card series":"AMD","VRAM Total Memory":10,"VRAM Total Used Memory (B)":1,"GPU use (%)":1`),
		base(`"Card series":"AMD","VRAM Total Memory (B)":10,"VRAM Total Memory (MiB)":1,"VRAM Total Used Memory (B)":1,"GPU use (%)":1`),
		base(`"Card series":"AMD","VRAM Total Memory (B)":10,"VRAM Total Used Memory (B)":11,"GPU use (%)":1`),
		base(`"Card series":"AMD","VRAM Total Memory (B)":10,"VRAM Total Used Memory (B)":1,"GPU use (%)":101`),
		base(`"Card series":"bad\nname","VRAM Total Memory (B)":10,"VRAM Total Used Memory (B)":1,"GPU use (%)":1`),
		base(`"Card series":"AMD","VRAM Total Memory (MiB)":17592186044416,"VRAM Total Used Memory (MiB)":0,"GPU use (%)":1`),
	}
	for _, input := range cases {
		if _, err := amdWith(input, nil).ObserveAccelerators(context.Background()); !errors.Is(err, ErrAcceleratorProbe) {
			t.Fatalf("expected rejection for %s: %v", input, err)
		}
	}
}

func TestAMDDuplicateLimitCapCancellationAndRedaction(t *testing.T) {
	card := func(index int, id string) string {
		return fmt.Sprintf(`"card%d":{"Unique ID":"%s","Card series":"AMD","VRAM Total Memory (B)":10,"VRAM Total Used Memory (B)":1,"GPU use (%%)":1}`, index, id)
	}
	duplicate := `{` + card(0, "same") + `,` + card(1, "same") + `}`
	if _, err := amdWith(duplicate, nil).ObserveAccelerators(context.Background()); !errors.Is(err, ErrDuplicateID) {
		t.Fatal(err)
	}
	rows := make([]string, 33)
	for index := range rows {
		rows[index] = card(index, fmt.Sprintf("id-%d", index))
	}
	if _, err := amdWith(`{`+strings.Join(rows, ",")+`}`, nil).ObserveAccelerators(context.Background()); !errors.Is(err, ErrAcceleratorProbe) {
		t.Fatal(err)
	}
	if _, err := amdWith(strings.Repeat("x", maxCommandOutput+1), nil).ObserveAccelerators(context.Background()); !errors.Is(err, ErrAcceleratorOutput) {
		t.Fatal(err)
	}
	secret := "secret-output"
	_, err := amdWith(secret, errors.New("exit")).ObserveAccelerators(context.Background())
	if !errors.Is(err, ErrAcceleratorProbe) || strings.Contains(err.Error(), secret) {
		t.Fatalf("redaction: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := amdWith("{}", nil).ObserveAccelerators(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestAMDResultAndCompositionIsolation(t *testing.T) {
	input := `{"card0":{"Card series":"AMD","VRAM Total Memory (B)":10,"VRAM Total Used Memory (B)":1,"GPU use (%)":10}}`
	observer := amdWith(input, nil)
	first, err := observer.ObserveAccelerators(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first[0].Name = "changed"
	*first[0].UtilizationPercent = 99
	second, err := observer.ObserveAccelerators(context.Background())
	if err != nil || second[0].Name != "AMD" || *second[0].UtilizationPercent != 10 {
		t.Fatalf("alias: %#v %v", second, err)
	}
	base, _ := NewSyntheticObserver(validObservation(), nil)
	nvidia := AcceleratorObservation{ID: "nvidia-extra", Name: "NVIDIA", Kind: AcceleratorNVIDIA, Memory: quantity(10, 1, 9)}
	composite := CompositeObserver{Base: base, Accelerators: []AcceleratorObserver{acceleratorFixture{[]AcceleratorObservation{nvidia}}, observer}}
	combined, err := composite.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(combined.Accelerators) != 3 || combined.Accelerators[1].Kind != AcceleratorNVIDIA || combined.Accelerators[2].Kind != AcceleratorAMD {
		t.Fatalf("order: %#v", combined.Accelerators)
	}
}
