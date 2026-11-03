//go:build !windows

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"
)

// Interactive presentation is deliberately separate from structured telemetry.
// Existing Unix console presentation is retained; Windows uses a protected pipe.
func presentEnrollmentCode(_ context.Context, code string, expires time.Time) (func(), error) {
	_, err := fmt.Fprintf(os.Stderr, "Enrollment code (expires %s): %s\n", expires.UTC().Format(time.RFC3339), code)
	return func() {}, err
}
func readEnrollmentCode(out io.Writer) int {
	_, _ = fmt.Fprintln(out, "Enrollment code lookup is available on Windows; use the interactive agent terminal on this platform.")
	return exitGeneral
}
