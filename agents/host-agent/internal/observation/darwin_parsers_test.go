package observation

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestParseDarwinCPUUsesFinalSample(t *testing.T) {
	output := []byte("CPU usage: 1.0% user, 2.0% sys, 97.0% idle\nother\nCPU usage: 12.4% user, 7.6% sys, 80.0% idle\n")
	value, ok := parseDarwinCPU(output)
	if !ok || value == nil || *value != 20 {
		t.Fatalf("value=%v ok=%v", value, ok)
	}
	for _, malformed := range []string{"", "CPU usage: nan% user, 1% sys, 99% idle", "CPU usage: 20% user, 20% sys, 20% idle", "CPU usage: 101% user, 0% sys, 0% idle", "CPU usage: 1% user, 1% sys, 98% idle\nCPU usage: malformed"} {
		if value, ok := parseDarwinCPU([]byte(malformed)); ok || value != nil {
			t.Fatalf("accepted %q", malformed)
		}
	}
	if _, ok := parseDarwinCPU([]byte(strings.Repeat("x", maxCommandOutput+1))); ok {
		t.Fatal("accepted oversized output")
	}
}

func TestParseDarwinMemory(t *testing.T) {
	vm := []byte("Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages free: 10.\nPages active: 50.\nPages inactive: 20.\nPages speculative: 5.\n")
	value, err := parseDarwinMemory([]byte("409600\n"), vm)
	if err != nil || value.TotalBytes != 409600 || value.AvailableBytes != 143360 || value.UsedBytes != 266240 {
		t.Fatalf("value=%#v err=%v", value, err)
	}

	cases := [][]byte{
		[]byte("Pages free: 1.\nPages inactive: 1.\nPages speculative: 1.\n"),
		[]byte("Mach Virtual Memory Statistics: (page size of 0 bytes)\nPages free: 1.\nPages inactive: 1.\nPages speculative: 1.\n"),
		[]byte("Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages free: 1.\nPages inactive: 1.\n"),
		[]byte("Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages free: 1.\nPages free: 2.\nPages inactive: 1.\nPages speculative: 1.\n"),
	}
	for _, input := range cases {
		if _, err := parseDarwinMemory([]byte("409600"), input); !errors.Is(err, ErrDarwinMemory) {
			t.Fatalf("expected memory error: %v", err)
		}
	}
	overflow := []byte("Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages free: 18446744073709551615.\nPages inactive: 1.\nPages speculative: 0.\n")
	if _, err := parseDarwinMemory([]byte("409600"), overflow); !errors.Is(err, ErrDarwinMemory) {
		t.Fatalf("overflow: %v", err)
	}
	inconsistent := []byte("Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages free: 1000.\nPages inactive: 0.\nPages speculative: 0.\n")
	if _, err := parseDarwinMemory([]byte("4096"), inconsistent); !errors.Is(err, ErrDarwinMemory) {
		t.Fatalf("inconsistent: %v", err)
	}
	if _, err := parseDarwinMemory([]byte(strings.Repeat("1", maxCommandOutput+1)), vm); !errors.Is(err, ErrAcceleratorOutput) {
		t.Fatalf("cap: %v", err)
	}
}

func TestParseDarwinGPUs(t *testing.T) {
	input := []byte(`{"_items":[{"id":"gpu-2","name":"Apple M3 Max","vendor":"Apple Inc.","_items":[{"_name":"Built-in Liquid Retina XDR Display"}]},{"id":"other","name":"Radeon","vendor":"AMD"},{"id":"gpu-1","name":"Apple M2","vendor":"Apple"}]}`)
	values, err := parseDarwinGPUs(input)
	if err != nil || len(values) != 2 {
		t.Fatalf("values=%#v err=%v", values, err)
	}
	if values[0].ID != "gpu-2" || values[0].Kind != AcceleratorApple || values[0].Memory != (ResourceQuantity{}) || values[0].UtilizationPercent != nil {
		t.Fatalf("bad value: %#v", values[0])
	}
	if empty, err := parseDarwinGPUs([]byte(`{"_items":[]}`)); err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty=%#v err=%v", empty, err)
	}
	if empty, err := parseDarwinGPUs([]byte(`{"SPDisplaysDataType":[{"name":"Intel Iris","vendor":"Intel"}]}`)); err != nil || len(empty) != 0 {
		t.Fatalf("non-apple=%#v err=%v", empty, err)
	}
	for _, bad := range []string{
		`not json`,
		`{"_items":[{"id":"bad/id","name":"Apple M2","vendor":"Apple"}]}`,
		"{\"_items\":[{\"id\":\"x\",\"name\":\"Apple\\nM2\",\"vendor\":\"Apple\"}]}",
		`{"_items":[{"id":"same","name":"Apple M2","vendor":"Apple"},{"id":"same","name":"Apple M3","vendor":"Apple"}]}`,
	} {
		if _, err := parseDarwinGPUs([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	var items []string
	for i := 0; i < 33; i++ {
		items = append(items, `{"id":"gpu-`+string(rune('A'+i))+`","name":"Apple GPU","vendor":"Apple"}`)
	}
	if _, err := parseDarwinGPUs([]byte(`{"_items":[` + strings.Join(items, ",") + `]}`)); !errors.Is(err, ErrDarwinGPU) {
		t.Fatalf(">32: %v", err)
	}
	if _, err := parseDarwinGPUs([]byte(strings.Repeat("x", maxCommandOutput+1))); !errors.Is(err, ErrAcceleratorOutput) {
		t.Fatalf("cap: %v", err)
	}
}

type commandRunnerFunc func(context.Context, string, []string) ([]byte, error)

func (f commandRunnerFunc) Run(ctx context.Context, path string, args []string) ([]byte, error) {
	return f(ctx, path, args)
}

func TestBoundedBufferAndCommandCancellationContract(t *testing.T) {
	buffer := &boundedBuffer{limit: 2}
	if n, err := buffer.Write([]byte("abc")); n != 3 || !errors.Is(err, ErrAcceleratorOutput) || !buffer.exceeded || buffer.String() != "ab" {
		t.Fatalf("n=%d err=%v buffer=%q", n, err, buffer.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := execRunner{}.Run(ctx, "/definitely/not/executed", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}
