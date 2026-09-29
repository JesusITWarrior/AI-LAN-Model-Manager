//go:build linux

package main

import (
	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/observation"
)

// newPlatformObserver returns a local (network-free) Linux observer, or
// ok=false when configuration is invalid. It never binds a listener, performs
// discovery, or connects to a controller; it reads only local /proc filesystem
// state.
func newPlatformObserver(hostID, stateDir string) (observation.Observer, bool) {
	if stateDir == "" {
		return nil, false
	}
	observer, err := observation.NewLinuxObserver(
		observation.LinuxObserverConfig{HostID: hostID, StoragePath: stateDir},
	)
	if err != nil {
		return nil, false
	}
	return observer, true
}
