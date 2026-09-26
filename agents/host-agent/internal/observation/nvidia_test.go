//go:build linux

package observation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type mockCommandRunner struct {
	output []byte
	err    error
	path   string
	args   []string
}

func (m *mockCommandRunner) Run(ctx context.Context, path string, args []string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.path, m.args = path, append([]string(nil), args...)
	return append([]byte(nil), m.output...), m.err
}
func nvidiaWith(output string, err error) *NVIDIAObserver {
	result, newErr := NewNVIDIAObserverWithRunner(&mockCommandRunner{output: []byte(output), err: err})
	if newErr != nil {
		panic(newErr)
	}
	return result
}

func TestNVIDIAValidRowsAndQuotedNames(t *testing.T) {
	observer := nvidiaWith("0,GPU-abc,\"GPU, Model X\",100,25,75\n1,,Other GPU,80,0,0\n", nil)
	values, err := observer.ObserveAccelerators(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 || values[0].Name != "GPU, Model X" || values[1].ID != "nvidia-1" {
		t.Fatalf("unexpected: %#v", values)
	}
	if values[0].Memory.AvailableBytes != ByteAmount(75*1024*1024) || *values[0].UtilizationPercent != 75 {
		t.Fatalf("bad normalization: %#v", values[0])
	}
}

func TestNVIDIAUsesFixedCommand(t *testing.T) {
	runner := &mockCommandRunner{}
	observer, _ := NewNVIDIAObserverWithRunner(runner)
	_, _ = observer.ObserveAccelerators(context.Background())
	if runner.path != "/usr/bin/nvidia-smi" || len(runner.args) != 2 || runner.args[0] != nvidiaArgs[0] || runner.args[1] != nvidiaArgs[1] {
		t.Fatalf("unexpected command: %q %#v", runner.path, runner.args)
	}
}

func TestNVIDIAGracefulAbsence(t *testing.T) {
	missing := &NVIDIAObserver{runner: &mockCommandRunner{}}
	values, err := missing.ObserveAccelerators(context.Background())
	if err != nil || values == nil || len(values) != 0 {
		t.Fatalf("missing: %#v %v", values, err)
	}
	values, err = nvidiaWith("", nil).ObserveAccelerators(context.Background())
	if err != nil || values == nil || len(values) != 0 {
		t.Fatalf("empty: %#v %v", values, err)
	}
	values, err = nvidiaWith("No devices were found", errors.New("exit")).ObserveAccelerators(context.Background())
	if err != nil || values == nil || len(values) != 0 {
		t.Fatalf("absence: %#v %v", values, err)
	}
}

func TestNVIDIARejectsMalformedAndUnsafeData(t *testing.T) {
	cases := []string{
		"0,GPU-a,Name,100,20\n", "0,GPU-a,\"Name,100,20,10\n", "x,,Name,100,20,10\n",
		"0,GPU-a,Name,no,20,10\n", "0,GPU-a,Name,10,20,10\n", "0,GPU-a,Name,10,2,101\n",
		"0,GPU-a,bad\nname,10,2,10\n", "0,GPU-a,Name,17592186044416,0,0\n",
	}
	for _, input := range cases {
		if _, err := nvidiaWith(input, nil).ObserveAccelerators(context.Background()); !errors.Is(err, ErrAcceleratorProbe) {
			t.Fatalf("expected error for %q: %v", input, err)
		}
	}
	duplicate := "0,GPU-a,One,10,1,1\n1,GPU-a,Two,10,1,1\n"
	if _, err := nvidiaWith(duplicate, nil).ObserveAccelerators(context.Background()); !errors.Is(err, ErrDuplicateID) {
		t.Fatal(err)
	}
	var rows []string
	for index := 0; index < 33; index++ {
		rows = append(rows, fmt.Sprintf("%d,GPU-%d,Name,10,1,1", index, index))
	}
	if _, err := nvidiaWith(strings.Join(rows, "\n"), nil).ObserveAccelerators(context.Background()); !errors.Is(err, ErrAcceleratorProbe) {
		t.Fatal(err)
	}
}

func TestNVIDIAOutputCapAndFailureRedaction(t *testing.T) {
	oversized := strings.Repeat("x", maxCommandOutput+1)
	if _, err := nvidiaWith(oversized, nil).ObserveAccelerators(context.Background()); !errors.Is(err, ErrAcceleratorOutput) {
		t.Fatal(err)
	}
	secret := "very-secret-command-output"
	_, err := nvidiaWith(secret, errors.New("exit status 1")).ObserveAccelerators(context.Background())
	if !errors.Is(err, ErrAcceleratorProbe) || strings.Contains(err.Error(), secret) {
		t.Fatalf("unredacted error: %v", err)
	}
}

func TestNVIDIACancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := nvidiaWith("0,GPU-a,Name,10,1,1", nil).ObserveAccelerators(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type acceleratorFixture struct{ values []AcceleratorObservation }

func (f acceleratorFixture) ObserveAccelerators(context.Context) ([]AcceleratorObservation, error) {
	return append([]AcceleratorObservation(nil), f.values...), nil
}

func TestCompositeObserverAndCopyIsolation(t *testing.T) {
	base, err := NewSyntheticObserver(validObservation(), nil)
	if err != nil {
		t.Fatal(err)
	}
	gpu := AcceleratorObservation{ID: "gpu-extra", Name: "Extra", Kind: AcceleratorNVIDIA, Memory: quantity(10, 1, 9), UtilizationPercent: percent(10)}
	composite := CompositeObserver{Base: base, Accelerators: []AcceleratorObserver{acceleratorFixture{values: []AcceleratorObservation{gpu}}}}
	first, err := composite.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Accelerators) != 2 {
		t.Fatalf("expected base plus extra: %#v", first.Accelerators)
	}
	first.Accelerators[1].Name = "changed"
	*first.Accelerators[1].UtilizationPercent = 90
	second, err := composite.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.Accelerators[1].Name != "Extra" || *second.Accelerators[1].UtilizationPercent != 10 {
		t.Fatalf("alias leak: %#v", second.Accelerators[1])
	}
}

func TestCompositeRejectsDuplicateIDs(t *testing.T) {
	base, _ := NewSyntheticObserver(validObservation(), nil)
	gpu := AcceleratorObservation{ID: "same", Name: "GPU", Kind: AcceleratorNVIDIA, Memory: quantity(10, 1, 9)}
	composite := CompositeObserver{Base: base, Accelerators: []AcceleratorObserver{acceleratorFixture{[]AcceleratorObservation{gpu}}, acceleratorFixture{[]AcceleratorObservation{gpu}}}}
	if _, err := composite.Observe(context.Background()); !errors.Is(err, ErrDuplicateID) {
		t.Fatal(err)
	}
}
