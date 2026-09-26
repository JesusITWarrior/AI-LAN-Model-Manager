package observation

import (
	"context"
	"errors"
)

var ErrInvalidConfig = errors.New("invalid synthetic observer configuration")

type Observer interface {
	Observe(context.Context) (HostResourceObservation, error)
}

type SyntheticObserver struct {
	observation HostResourceObservation
	err         error
}

func NewSyntheticObserver(value HostResourceObservation, configuredErr error) (*SyntheticObserver, error) {
	if configuredErr == nil {
		if err := value.Validate(); err != nil {
			return nil, errors.Join(ErrInvalidConfig, err)
		}
	}
	return &SyntheticObserver{observation: clone(value), err: configuredErr}, nil
}

func (s *SyntheticObserver) Observe(ctx context.Context) (HostResourceObservation, error) {
	if err := ctx.Err(); err != nil {
		return HostResourceObservation{}, err
	}
	if s.err != nil {
		return HostResourceObservation{}, s.err
	}
	if err := s.observation.Validate(); err != nil {
		return HostResourceObservation{}, err
	}
	return clone(s.observation), nil
}

func clone(value HostResourceObservation) HostResourceObservation {
	result := value
	if value.CPUUtilizationPercent != nil {
		copied := *value.CPUUtilizationPercent
		result.CPUUtilizationPercent = &copied
	}
	result.Accelerators = make([]AcceleratorObservation, len(value.Accelerators))
	for index, accelerator := range value.Accelerators {
		result.Accelerators[index] = accelerator
		if accelerator.UtilizationPercent != nil {
			copied := *accelerator.UtilizationPercent
			result.Accelerators[index].UtilizationPercent = &copied
		}
	}
	return result
}
