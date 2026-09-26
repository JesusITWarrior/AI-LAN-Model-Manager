package observation

import (
	"context"
	"errors"
	"math"
	"testing"
)

func percent(value uint8) *uint8 { return &value }
func quantity(total, used, available uint64) ResourceQuantity {
	return ResourceQuantity{ByteAmount(total), ByteAmount(used), ByteAmount(available)}
}
func validObservation() HostResourceObservation {
	return HostResourceObservation{
		HostID: "host-1", ObservedAt: "2026-09-26T12:00:00.000Z", Platform: PlatformLinux,
		CPULogicalCores: 16, CPUUtilizationPercent: percent(20), Memory: quantity(100, 40, 50), Storage: quantity(200, 50, 100),
		Accelerators: []AcceleratorObservation{{ID: "gpu-0", Name: "Example GPU", Kind: AcceleratorNVIDIA, Memory: quantity(80, 20, 40), UtilizationPercent: percent(25)}},
	}
}

func TestResourceQuantityValidation(t *testing.T) {
	for _, value := range []ResourceQuantity{quantity(100, 40, 50), quantity(math.MaxUint64, math.MaxUint64, 0)} {
		if err := value.Validate(); err != nil {
			t.Fatalf("valid quantity: %v", err)
		}
	}
	for _, value := range []ResourceQuantity{quantity(100, 101, 0), quantity(100, 0, 101), quantity(math.MaxUint64, math.MaxUint64, 1)} {
		if !errors.Is(value.Validate(), ErrInvalidResource) {
			t.Fatalf("expected resource error for %#v", value)
		}
	}
}

func TestObservationBounds(t *testing.T) {
	base := validObservation()
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, platform := range []HostPlatform{PlatformLinux, PlatformDarwin, PlatformWindows} {
		value := base
		value.Platform = platform
		if err := value.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, cores := range []uint16{1, 4096} {
		value := base
		value.CPULogicalCores = cores
		if err := value.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	bad := base
	bad.CPULogicalCores = 0
	if !errors.Is(bad.Validate(), ErrInvalidObservation) {
		t.Fatal("expected core error")
	}
	bad = base
	bad.HostID = "bad/id"
	if !errors.Is(bad.Validate(), ErrInvalidObservation) {
		t.Fatal("expected id error")
	}
	bad = base
	bad.ObservedAt = "bad"
	if !errors.Is(bad.Validate(), ErrInvalidObservation) {
		t.Fatal("expected timestamp error")
	}
	bad = base
	bad.CPUUtilizationPercent = percent(101)
	if !errors.Is(bad.Validate(), ErrInvalidObservation) {
		t.Fatal("expected percent error")
	}
}

func TestAcceleratorBoundsAndDuplicates(t *testing.T) {
	base := validObservation()
	for _, kind := range []AcceleratorKind{AcceleratorNVIDIA, AcceleratorAMD, AcceleratorIntel, AcceleratorApple, AcceleratorOther} {
		value := base.Accelerators[0]
		value.Kind = kind
		if err := value.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	duplicate := base
	duplicate.Accelerators = append(duplicate.Accelerators, duplicate.Accelerators[0])
	if !errors.Is(duplicate.Validate(), ErrDuplicateID) {
		t.Fatal("expected duplicate")
	}
	tooMany := base
	tooMany.Accelerators = make([]AcceleratorObservation, 33)
	if !errors.Is(tooMany.Validate(), ErrInvalidObservation) {
		t.Fatal("expected count error")
	}
	bad := base.Accelerators[0]
	bad.Name = "bad\nname"
	if !errors.Is(bad.Validate(), ErrInvalidObservation) {
		t.Fatal("expected name error")
	}
}

func TestSyntheticObserverDeepCopies(t *testing.T) {
	input := validObservation()
	observer, err := NewSyntheticObserver(input, nil)
	if err != nil {
		t.Fatal(err)
	}
	input.Accelerators[0].Name = "mutated"
	*input.CPUUtilizationPercent = 99
	first, err := observer.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Accelerators[0].Name != "Example GPU" || *first.CPUUtilizationPercent != 20 {
		t.Fatal("constructor alias leaked")
	}
	first.Accelerators[0].Name = "changed"
	*first.Accelerators[0].UtilizationPercent = 90
	second, err := observer.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.Accelerators[0].Name != "Example GPU" || *second.Accelerators[0].UtilizationPercent != 25 {
		t.Fatal("observe alias leaked")
	}
}

func TestSyntheticObserverCancellationAndConfiguredError(t *testing.T) {
	observer, err := NewSyntheticObserver(validObservation(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := observer.Observe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation: %v", err)
	}
	configured := errors.New("configured")
	failing, err := NewSyntheticObserver(HostResourceObservation{}, configured)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failing.Observe(context.Background()); !errors.Is(err, configured) {
		t.Fatalf("expected configured error: %v", err)
	}
}

func TestSyntheticObserverRejectsInvalidConfiguration(t *testing.T) {
	bad := validObservation()
	bad.Memory = quantity(10, 9, 9)
	if _, err := NewSyntheticObserver(bad, nil); !errors.Is(err, ErrInvalidConfig) || !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("expected joined errors: %v", err)
	}
}
