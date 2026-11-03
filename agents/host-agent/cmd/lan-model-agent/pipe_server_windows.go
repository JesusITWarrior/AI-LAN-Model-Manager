//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var errPipeServer = errors.New("enrollment presentation server rejected")
var errPipeServerPath = errors.New("unsafe enrollment service executable configuration")

// SCM BinaryPath is a command line, not a path. Require one quoted, canonical
// local-drive executable with no arguments. In particular, do not repair an
// unquoted path with spaces here: SCM may have launched a different executable.
func configuredServiceExecutable(command string) (string, error) {
	if len(command) < 3 || command[0] != '"' || command[len(command)-1] != '"' {
		return "", errPipeServerPath
	}
	path := command[1 : len(command)-1]
	if len(path) < 7 || !((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) || path[1:3] != `:\` || !filepath.IsAbs(path) || filepath.Clean(path) != path || !strings.EqualFold(filepath.Ext(path), ".exe") || strings.ContainsAny(path[2:], "\"\x00\r\n\t:/") {
		return "", errPipeServerPath
	}
	for _, c := range path {
		if c < 32 || c == 127 {
			return "", errPipeServerPath
		}
	}
	for _, part := range strings.Split(path[3:], `\`) {
		if part == "" || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return "", errPipeServerPath
		}
	}
	return path, nil
}

var getPipeServerPID = pipeKernel.NewProc("GetNamedPipeServerProcessId")
var queryProcessImage = pipeKernel.NewProc("QueryFullProcessImageNameW")
var openSCManager = advapi.NewProc("OpenSCManagerW")
var openService = advapi.NewProc("OpenServiceW")
var closeServiceHandle = advapi.NewProc("CloseServiceHandle")
var queryServiceStatus = advapi.NewProc("QueryServiceStatusEx")
var queryServiceConfig = advapi.NewProc("QueryServiceConfigW")

type pipeServiceStatus struct{ ServiceType, State, Accepted, Win32Exit, ServiceExit, Checkpoint, Wait, PID, Flags uint32 }
type pipeServiceConfig struct {
	ServiceType, StartType, ErrorControl uint32
	BinaryPath, LoadGroup                *uint16
	Tag                                  uint32
	Dependencies, Account, DisplayName   *uint16
}

// Authenticate the connected handle, not the global pipe name: only the SCM's
// currently running LANModelAgent PID under its virtual service account and
// exact configured executable (also this reader's executable) may present codes.
// This excludes user-created lookalike servers even if they race pipe startup.
func verifyEnrollmentPipeServer(pipe syscall.Handle) error {
	var pid uint32
	ok, _, _ := getPipeServerPID.Call(uintptr(pipe), uintptr(unsafe.Pointer(&pid)))
	if ok == 0 || pid == 0 {
		return errPipeServer
	}
	manager, _, _ := openSCManager.Call(0, 0, 1)
	if manager == 0 {
		return errPipeServer
	}
	defer closeServiceHandle.Call(manager)
	name, _ := syscall.UTF16PtrFromString("LANModelAgent")
	service, _, _ := openService.Call(manager, uintptr(unsafe.Pointer(name)), 1|4)
	if service == 0 {
		return errPipeServer
	}
	defer closeServiceHandle.Call(service)
	var status pipeServiceStatus
	var needed uint32
	ok, _, _ = queryServiceStatus.Call(service, 0, uintptr(unsafe.Pointer(&status)), unsafe.Sizeof(status), uintptr(unsafe.Pointer(&needed)))
	if ok == 0 || status.State != serviceRunning || status.PID != pid || status.ServiceType != serviceWin32OwnProcess {
		return errPipeServer
	}
	// Query into a bounded aligned buffer; all returned strings must be inside it.
	buffer := make([]uintptr, 8192/unsafe.Sizeof(uintptr(0)))
	ok, _, _ = queryServiceConfig.Call(service, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer))*unsafe.Sizeof(uintptr(0)), uintptr(unsafe.Pointer(&needed)))
	if ok == 0 {
		return errPipeServer
	}
	config := (*pipeServiceConfig)(unsafe.Pointer(&buffer[0]))
	stringInBuffer := func(pointer *uint16) (string, bool) {
		base := uintptr(unsafe.Pointer(&buffer[0]))
		at := uintptr(unsafe.Pointer(pointer))
		end := base + uintptr(len(buffer))*unsafe.Sizeof(uintptr(0))
		if at < base || at >= end || at%2 != 0 {
			return "", false
		}
		chars := unsafe.Slice(pointer, int((end-at)/2))
		for i, c := range chars {
			if c == 0 {
				return syscall.UTF16ToString(chars[:i]), true
			}
		}
		return "", false
	}
	account, valid := stringInBuffer(config.Account)
	if !valid || !strings.EqualFold(account, `NT SERVICE\LANModelAgent`) {
		return errPipeServer
	}
	command, valid := stringInBuffer(config.BinaryPath)
	if !valid {
		return errPipeServerPath
	}
	binary, err := configuredServiceExecutable(command)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil || !strings.EqualFold(filepath.Clean(binary), filepath.Clean(executable)) {
		return errPipeServer
	}
	process, err := syscall.OpenProcess(0x1000, false, pid)
	if err != nil {
		return errPipeServer
	}
	defer syscall.CloseHandle(process)
	var token syscall.Token
	if syscall.OpenProcessToken(process, syscall.TOKEN_QUERY, &token) != nil {
		return errPipeServer
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return errPipeServer
	}
	expected, _, _, err := syscall.LookupSID("", `NT SERVICE\LANModelAgent`)
	if err != nil {
		return errPipeServer
	}
	actualSID, err := user.User.Sid.String()
	if err != nil {
		return errPipeServer
	}
	expectedSID, err := expected.String()
	if err != nil || actualSID != expectedSID {
		return errPipeServer
	}
	image := make([]uint16, 32768)
	size := uint32(len(image))
	ok, _, _ = queryProcessImage.Call(uintptr(process), 0, uintptr(unsafe.Pointer(&image[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 || size == 0 || size >= uint32(len(image)) || !strings.EqualFold(filepath.Clean(syscall.UTF16ToString(image[:size])), filepath.Clean(binary)) {
		return errPipeServer
	}
	// Recheck the SCM binding after opening/inspecting the process to reject a
	// stopped/replaced generation. Reverification occurs again before display.
	ok, _, _ = queryServiceStatus.Call(service, 0, uintptr(unsafe.Pointer(&status)), unsafe.Sizeof(status), uintptr(unsafe.Pointer(&needed)))
	if ok == 0 || status.State != serviceRunning || status.PID != pid {
		return errPipeServer
	}
	return nil
}
