//go:build windows

package main

import (
	"bytes"
	"context"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestWindowsTransientCodePresentation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cleanup, err := presentEnrollmentCode(ctx, "23456789", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	// A second server must not replace the first instance.
	if duplicate, err := presentEnrollmentCode(ctx, "ABCDEFGH", time.Now().Add(time.Minute)); err == nil {
		duplicate()
		cleanup()
		t.Fatal("second pipe server was allowed")
	}
	var out bytes.Buffer
	if code := readEnrollmentCodeVerified(&out, func(syscall.Handle) error { return nil }, time.Second); code != 0 || !strings.Contains(out.String(), "23456789") {
		cleanup()
		t.Fatalf("admin code read failed: %d %q", code, out.String())
	}
	cleanup()
	out.Reset()
	if code := readEnrollmentCode(&out); code == 0 || strings.Contains(out.String(), "23456789") {
		t.Fatal("code remained available after cleanup")
	}
}
func TestWindowsCodePresentationExpires(t *testing.T) {
	cleanup, err := presentEnrollmentCode(context.Background(), "23456789", time.Now().Add(20*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	cleanup()
	var out bytes.Buffer
	if code := readEnrollmentCode(&out); code == 0 || strings.Contains(out.String(), "23456789") {
		t.Fatal("expired code available")
	}
}

func TestWindowsFakePresentationServerRejected(t *testing.T) {
	cleanup, err := presentEnrollmentCode(context.Background(), "23456789", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	var out bytes.Buffer
	started := time.Now()
	if code := readEnrollmentCode(&out); code == 0 || strings.Contains(out.String(), "23456789") {
		t.Fatal("non-service server displayed a forged code")
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("fake-server rejection exceeded bound")
	}
}

func TestWindowsSilentPresentationServerReadIsBounded(t *testing.T) {
	// A connected server that never writes must not pin the administrator CLI.
	// This synthetic server is accepted only through an explicit test verifier.
	name, _ := syscall.UTF16PtrFromString(enrollmentPipe)
	handle, _, err := createNamedPipe.Call(uintptr(unsafe.Pointer(name)), 3|0x80000, 1|8, 1, 4096, 4096, 0, 0)
	if handle == uintptr(syscall.InvalidHandle) {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(syscall.Handle(handle))
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			ok, _, err := connectNamedPipe.Call(handle, 0)
			if ok != 0 || err == syscall.Errno(535) {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	defer func() { close(stop); <-done }()
	var out bytes.Buffer
	started := time.Now()
	code := readEnrollmentCodeVerified(&out, func(syscall.Handle) error {
		select {
		case <-done:
			return nil
		case <-time.After(time.Second):
			return errPipeServer
		}
	}, 150*time.Millisecond)
	elapsed := time.Since(started)
	if code == 0 || out.Len() != 0 || elapsed < 100*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("silent server read not bounded: code=%d elapsed=%s", code, elapsed)
	}
}
