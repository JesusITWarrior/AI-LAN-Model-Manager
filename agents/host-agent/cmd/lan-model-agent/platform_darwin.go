//go:build darwin

package main

import (
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/observation"
)

// newPlatformObserver returns a local (network-free) Darwin observer, or
// ok=false when configuration is invalid. It never binds a listener, performs
// discovery, or connects to a controller.
func newPlatformObserver(hostID, stateDir string) (observation.Observer, bool) {
	if stateDir == "" {
		return nil, false
	}
	observer, err := observation.NewDarwinObserver(
		observation.DarwinObserverConfig{HostID: hostID, StoragePath: stateDir},
	)
	if err != nil {
		return nil, false
	}
	return observer, true
}
