//go:build windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

const (
	serviceWin32OwnProcess              = 0x10
	serviceStartPending                 = 2
	serviceStopPending                  = 3
	serviceRunning                      = 4
	serviceStopped                      = 1
	serviceAcceptStop                   = 1
	serviceAcceptShutdown               = 4
	serviceControlStop                  = 1
	serviceControlInterrogate           = 4
	serviceControlShutdown              = 5
	errorFailedServiceControllerConnect = syscall.Errno(1063)
)

type serviceTableEntry struct {
	name *uint16
	proc uintptr
}
type serviceStatus struct{ serviceType, currentState, controlsAccepted, win32ExitCode, serviceSpecificExitCode, checkPoint, waitHint uint32 }

var (
	advapi          = syscall.NewLazyDLL("advapi32.dll")
	startDispatcher = advapi.NewProc("StartServiceCtrlDispatcherW")
	registerHandler = advapi.NewProc("RegisterServiceCtrlHandlerExW")
	setStatus       = advapi.NewProc("SetServiceStatus")
)

// runPlatformService uses the native Service Control Manager protocol. Error
// 1063 means an operator launched the binary interactively, so console mode is
// retained for diagnostics without weakening SCM behavior.
func runPlatformService(run func(context.Context) int) int {
	name, _ := syscall.UTF16PtrFromString("LANModelAgent")
	var exit int
	mainCallback := syscall.NewCallback(func(_ uint32, _ **uint16) uintptr {
		ctx, cancel := context.WithCancel(context.Background())
		var handle uintptr
		handler := syscall.NewCallback(func(control, _ uint32, _ unsafe.Pointer, _ unsafe.Pointer) uintptr {
			switch control {
			case serviceControlStop, serviceControlShutdown:
				reportServiceStatus(handle, serviceStopPending, 0, 1, 10000)
				cancel()
			case serviceControlInterrogate:
			}
			return 0
		})
		handle, _, _ = registerHandler.Call(uintptr(unsafe.Pointer(name)), handler, 0)
		if handle == 0 {
			exit = exitGeneral
			cancel()
			return 0
		}
		reportServiceStatus(handle, serviceStartPending, 0, 1, 10000)
		reportServiceStatus(handle, serviceRunning, serviceAcceptStop|serviceAcceptShutdown, 0, 0)
		exit = run(ctx)
		if exit == 0 {
			reportServiceStatus(handle, serviceStopped, 0, 0, 0)
		} else {
			reportServiceFailure(handle, uint32(exit))
		}
		return 0
	})
	table := [...]serviceTableEntry{{name: name, proc: mainCallback}, {}}
	ok, _, callErr := startDispatcher.Call(uintptr(unsafe.Pointer(&table[0])))
	if ok != 0 {
		return exit
	}
	if errno, ok := callErr.(syscall.Errno); ok && errno == errorFailedServiceControllerConnect {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return run(ctx)
	}
	return exitGeneral
}

func reportServiceStatus(handle uintptr, state, accepted, checkpoint, wait uint32) {
	status := serviceStatus{serviceType: serviceWin32OwnProcess, currentState: state, controlsAccepted: accepted, checkPoint: checkpoint, waitHint: wait}
	setStatus.Call(handle, uintptr(unsafe.Pointer(&status)))
}
func reportServiceFailure(handle uintptr, code uint32) {
	status := serviceStatus{serviceType: serviceWin32OwnProcess, currentState: serviceStopped, win32ExitCode: 1066, serviceSpecificExitCode: code}
	setStatus.Call(handle, uintptr(unsafe.Pointer(&status)))
}
