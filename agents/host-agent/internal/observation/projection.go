package observation

import "time"

// ValidateFresh applies the controller's strict one-minute authority window and
// JavaScript integer transport bounds without changing any observed values.
func (h HostResourceObservation) ValidateFresh(hostID string, platform HostPlatform, now time.Time) error {
	if err := h.Validate(); err != nil {
		return err
	}
	at, _ := time.Parse("2006-01-02T15:04:05.000Z", h.ObservedAt)
	if h.HostID != hostID || h.Platform != platform || now.Before(at) || now.Sub(at) >= time.Minute {
		return ErrInvalidObservation
	}
	quantities := []ResourceQuantity{h.Memory, h.Storage}
	for _, a := range h.Accelerators {
		quantities = append(quantities, a.Memory)
	}
	const maxSafeInteger = 1<<53 - 1
	for _, q := range quantities {
		if q.TotalBytes > maxSafeInteger || q.UsedBytes > maxSafeInteger || q.AvailableBytes > maxSafeInteger {
			return ErrInvalidResource
		}
	}
	return nil
}

// Clone isolates all mutable fields and encodes absent accelerators as an array.
func (h HostResourceObservation) Clone() HostResourceObservation {
	if h.CPUUtilizationPercent != nil {
		v := *h.CPUUtilizationPercent
		h.CPUUtilizationPercent = &v
	}
	accelerators := make([]AcceleratorObservation, len(h.Accelerators))
	copy(accelerators, h.Accelerators)
	for i := range accelerators {
		if accelerators[i].UtilizationPercent != nil {
			v := *accelerators[i].UtilizationPercent
			accelerators[i].UtilizationPercent = &v
		}
	}
	h.Accelerators = accelerators
	return h
}
