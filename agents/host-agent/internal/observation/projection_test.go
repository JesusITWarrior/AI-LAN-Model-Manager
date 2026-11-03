package observation

import (
	"testing"
	"time"
)

func TestProjectionAgeAndSafeIntegerBoundaries(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)
	h := HostResourceObservation{HostID: "synthetic-host", Platform: PlatformLinux, ObservedAt: now.Format("2006-01-02T15:04:05.000Z"), CPULogicalCores: 1}
	for _, age := range []time.Duration{-time.Millisecond, 0, time.Minute - time.Millisecond, time.Minute} {
		h.ObservedAt = now.Add(-age).Format("2006-01-02T15:04:05.000Z")
		err := h.ValidateFresh(h.HostID, h.Platform, now)
		if (err == nil) != (age >= 0 && age < time.Minute) {
			t.Fatalf("age %v: %v", age, err)
		}
	}
	h.ObservedAt = now.Format("2006-01-02T15:04:05.000Z")
	for _, amount := range []ByteAmount{1<<53 - 1, 1 << 53, 1<<53 + 1, ^ByteAmount(0)} {
		for _, field := range []string{"total", "used", "available"} {
			h.Memory = ResourceQuantity{TotalBytes: amount}
			if field == "used" {
				h.Memory.UsedBytes = amount
			}
			if field == "available" {
				h.Memory.AvailableBytes = amount
			}
			if (h.ValidateFresh(h.HostID, h.Platform, now) == nil) != (amount <= 1<<53-1) {
				t.Fatalf("unsafe %s %d", field, amount)
			}
		}
	}
}
