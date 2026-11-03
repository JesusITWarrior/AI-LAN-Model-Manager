//go:build windows

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const enrollmentPipe = `\\.\pipe\LANModelManager-Enrollment`

var pipeKernel = syscall.NewLazyDLL("kernel32.dll")
var createNamedPipe = pipeKernel.NewProc("CreateNamedPipeW")
var connectNamedPipe = pipeKernel.NewProc("ConnectNamedPipe")
var disconnectNamedPipe = pipeKernel.NewProc("DisconnectNamedPipe")
var convertDescriptor = advapi.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")

// The code is held only in memory and a local named pipe, never in a log,
// registry value or disk file. A protected DACL admits SYSTEM, Administrators
// and the process account; remote pipe clients and a second server are refused.
func presentEnrollmentCode(ctx context.Context, code string, expires time.Time) (func(), error) {
	if !operatorCodePattern.MatchString(code) || !time.Now().Before(expires) {
		return nil, fmt.Errorf("enrollment presentation rejected")
	}
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return nil, err
	}
	sddl, _ := syscall.UTF16PtrFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + sid + ")")
	var descriptor uintptr
	ok, _, callErr := convertDescriptor.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if ok == 0 {
		return nil, callErr
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	attrs := syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: descriptor}
	name, _ := syscall.UTF16PtrFromString(enrollmentPipe)
	// DUPLEX | FIRST_PIPE_INSTANCE; byte mode | NOWAIT | REJECT_REMOTE_CLIENTS.
	handle, _, callErr := createNamedPipe.Call(uintptr(unsafe.Pointer(name)), 3|0x80000, 1|8, 1, 4096, 4096, 0, uintptr(unsafe.Pointer(&attrs)))
	if handle == uintptr(syscall.InvalidHandle) {
		return nil, callErr
	}
	pipe := syscall.Handle(handle)
	life, cancel := context.WithDeadline(ctx, expires)
	payload := []byte(expires.UTC().Format(time.RFC3339Nano) + " " + code + "\n")
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer syscall.CloseHandle(pipe)
		defer func() {
			for i := range payload {
				payload[i] = 0
			}
		}()
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		connected, sent := false, false
		for {
			select {
			case <-life.Done():
				return
			case <-ticker.C:
			}
			if !connected {
				ok, _, err := connectNamedPipe.Call(handle, 0)
				if ok != 0 || err == syscall.Errno(535) {
					connected = true
				} // ERROR_PIPE_CONNECTED
				if !connected {
					continue
				}
			}
			if !sent {
				var written uint32
				if err := syscall.WriteFile(pipe, payload, &written, nil); err != nil || int(written) != len(payload) {
					disconnectNamedPipe.Call(handle)
					connected = false
					continue
				}
				sent = true
			}
			// The reader acknowledges after reading the complete line. Do not flush a
			// synchronous handle (which could block shutdown) or discard unread data.
			var ack [1]byte
			var read uint32
			err := syscall.ReadFile(pipe, ack[:], &read, nil)
			if read > 0 || (err != nil && err != syscall.Errno(232)) {
				disconnectNamedPipe.Call(handle)
				connected, sent = false, false
			}
		}
	}()
	return func() { cancel(); <-done }, nil
}

func readEnrollmentCode(out io.Writer) int {
	return readEnrollmentCodeVerified(out, verifyEnrollmentPipeServer, 3*time.Second)
}

// Tests inject a verifier explicitly; production always uses SCM/account/image
// authentication. The read deadline is independent of untrusted server expiry.
func readEnrollmentCodeVerified(out io.Writer, verify func(syscall.Handle) error, timeout time.Duration) int {
	// The caller must launch an elevated console. Windows enforces the pipe DACL;
	// no privileged helper, code file, or alternate authentication is provided.
	// SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION prevents a pipe server
	// from impersonating the elevated reader.
	name, _ := syscall.UTF16PtrFromString(enrollmentPipe)
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, 0x00110000, 0)
	if err != nil {
		_, _ = fmt.Fprintln(out, "Enrollment code unavailable; use an elevated console while enrollment is pending.")
		return exitGeneral
	}
	file := os.NewFile(uintptr(handle), enrollmentPipe)
	defer file.Close()
	if verify == nil || verify(handle) != nil {
		return exitGeneral
	}
	// Switch the connected client handle to nonblocking byte mode. Never rely
	// on a malicious server to write or close; no orphan reader goroutine.
	mode := uint32(1) // PIPE_NOWAIT
	setMode := pipeKernel.NewProc("SetNamedPipeHandleState")
	ok, _, _ := setMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)), 0, 0)
	if ok == 0 {
		return exitGeneral
	}
	deadline := time.Now().Add(timeout)
	raw := make([]byte, 0, 160)
	for {
		if !time.Now().Before(deadline) {
			return exitGeneral
		}
		var chunk [160]byte
		var n uint32
		err := syscall.ReadFile(handle, chunk[:], &n, nil)
		if n > 0 {
			raw = append(raw, chunk[:n]...)
			if len(raw) > 160 {
				return exitGeneral
			}
			if strings.ContainsRune(string(raw), '\n') {
				break
			}
		}
		if err != nil && err != syscall.Errno(232) {
			return exitGeneral
		}
		time.Sleep(10 * time.Millisecond)
	}
	line := string(raw)
	if strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") {
		return exitGeneral
	}
	if verify(handle) != nil {
		return exitGeneral
	}
	fields := strings.Fields(line)
	if len(fields) != 2 {
		return exitGeneral
	}
	expires, err := time.Parse(time.RFC3339Nano, fields[0])
	if err != nil || !time.Now().Before(expires) || expires.After(time.Now().Add(2*time.Minute)) || !operatorCodePattern.MatchString(fields[1]) {
		return exitGeneral
	}
	if _, err := file.Write([]byte{1}); err != nil {
		return exitGeneral
	}
	_, _ = fmt.Fprintf(out, "Enrollment code (expires %s): %s\n", expires.UTC().Format(time.RFC3339), fields[1])
	return 0
}
